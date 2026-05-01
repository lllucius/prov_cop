// provisioner.c - see provisioner.h for documentation.

#include "provisioner.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "mbedtls/base64.h"

static const char *TAG = "provisioner";

// Maximum size of one inbound line. SET line with two base64-encoded
// strings (max ~44 + ~88 chars) plus framing easily fits in 320 bytes.
#define PROV_LINE_MAX 320

// 802.11 limits.
#define PROV_MAX_SSID_LEN 32
#define PROV_MAX_PASS_LEN 63

// Frame strings.
static const char PROV_PROBE[]   = "<<PROV?>>";
static const char PROV_READY[]   = "<<PROV!>>\n";
static const char PROV_SET_PFX[] = "<<PROV:SET ";
static const char PROV_OK[]      = "<<PROV:OK>>\n";
static const char PROV_ERR_PFX[] = "<<PROV:ERR ";
static const char PROV_ERR_SFX[] = ">>\n";

// VFS base path used when share_with_console is enabled. We only support a
// single shared instance at a time (there is just one stdin to redirect).
#define PROV_VFS_BASE_PATH "/dev/prov_console"
#define PROV_STDIN_BUFFER_BYTES 512

// State machine for sharing the byte stream with the console.
enum prov_share_state {
    PSS_LINE_START = 0,   // start of a line; no bytes accumulated yet
    PSS_GOT_ONE_LT,       // saw a single '<' at line start
    PSS_BUFFER_FRAME,     // accumulating a possible "<<...>>" frame
    PSS_PASSTHROUGH,      // forwarding bytes verbatim until next '\n'
};

struct provisioner {
    provisioner_uart_config_t cfg;     // copy of caller's config
    TaskHandle_t              task;
    volatile bool             stop;
    volatile bool             running;
    bool                      installed_driver;
    char                      line[PROV_LINE_MAX];
    size_t                    line_len;
    bool                      overflow;
    enum prov_share_state     share_state;

    // Console-sharing state. Only used when cfg.share_with_console is true.
    StreamBufferHandle_t      stdin_stream;
    bool                      vfs_registered;
    int                       saved_stdin_fd;   // -1 if no redirection
};

// Single shared instance pointer used by the VFS callbacks.
static struct provisioner *s_share_instance;

// ---------------------------------------------------------------------------
// CRC-16/CCITT-FALSE
// ---------------------------------------------------------------------------
static uint16_t prov_crc16(const char *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= ((uint16_t)(uint8_t)data[i]) << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------
static void prov_write(struct provisioner *p, const char *s)
{
    uart_write_bytes(p->cfg.uart_num, s, strlen(s));
}

static void prov_send_err(struct provisioner *p, const char *reason)
{
    // Sanitise: tokens must not contain spaces, '>', or NL.
    char buf[48];
    size_t n = 0;
    for (const char *r = reason; *r && n + 1 < sizeof buf; r++) {
        char c = *r;
        if (c == ' ' || c == '>' || c == '\r' || c == '\n') c = '_';
        buf[n++] = c;
    }
    buf[n] = '\0';
    if (n == 0) {
        strcpy(buf, "fail");
    }
    uart_write_bytes(p->cfg.uart_num, PROV_ERR_PFX, sizeof(PROV_ERR_PFX) - 1);
    uart_write_bytes(p->cfg.uart_num, buf, strlen(buf));
    uart_write_bytes(p->cfg.uart_num, PROV_ERR_SFX, sizeof(PROV_ERR_SFX) - 1);
}

// ---------------------------------------------------------------------------
// Base64 decode (mbedtls). Returns true on success and writes a NUL-terminated
// string into `out` (size out_size, including NUL). Empty input yields "".
// ---------------------------------------------------------------------------
static bool prov_b64_decode(const char *in, size_t in_len,
                            char *out, size_t out_size)
{
    if (in_len == 0) {
        if (out_size == 0) return false;
        out[0] = '\0';
        return true;
    }
    size_t written = 0;
    int rc = mbedtls_base64_decode((unsigned char *)out, out_size - 1, &written,
                                   (const unsigned char *)in, in_len);
    if (rc != 0) {
        return false;
    }
    out[written] = '\0';
    return true;
}

// ---------------------------------------------------------------------------
// Protocol handling
// ---------------------------------------------------------------------------
static void prov_handle_set(struct provisioner *p, const char *args)
{
    // args = "ssid_b64 pass_b64 crc16hex" (pass_b64 may be empty).
    // We split on the two known spaces.
    const char *s1 = strchr(args, ' ');
    if (!s1) { prov_send_err(p, "fields"); return; }
    const char *s2 = strchr(s1 + 1, ' ');
    if (!s2) { prov_send_err(p, "fields"); return; }
    if (strchr(s2 + 1, ' ') != NULL) { prov_send_err(p, "fields"); return; }

    size_t      ssid_b64_len = (size_t)(s1 - args);
    size_t      pass_b64_len = (size_t)(s2 - (s1 + 1));
    const char *crc_str      = s2 + 1;

    // CRC over "ssid_b64 pass_b64".
    if (strlen(crc_str) != 4) { prov_send_err(p, "crc"); return; }
    uint16_t want = prov_crc16(args, (size_t)(s2 - args));
    uint16_t got  = 0;
    for (int i = 0; i < 4; i++) {
        char c = crc_str[i];
        uint8_t v;
        if      (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
        else if (c >= 'A' && c <= 'F') v = (uint8_t)(10 + c - 'A');
        else if (c >= 'a' && c <= 'f') v = (uint8_t)(10 + c - 'a');
        else { prov_send_err(p, "crc"); return; }
        got = (uint16_t)((got << 4) | v);
    }
    if (got != want) { prov_send_err(p, "crc"); return; }

    char ssid[PROV_MAX_SSID_LEN + 1];
    char pass[PROV_MAX_PASS_LEN + 1];

    if (!prov_b64_decode(args, ssid_b64_len, ssid, sizeof ssid)) {
        prov_send_err(p, "b64ssid");
        return;
    }
    if (!prov_b64_decode(s1 + 1, pass_b64_len, pass, sizeof pass)) {
        prov_send_err(p, "b64pass");
        return;
    }

    size_t ssid_len = strlen(ssid);
    size_t pass_len = strlen(pass);
    if (ssid_len == 0 || ssid_len > PROV_MAX_SSID_LEN ||
        pass_len > PROV_MAX_PASS_LEN) {
        prov_send_err(p, "length");
        return;
    }

    if (!p->cfg.on_credentials) {
        prov_send_err(p, "nocallback");
        return;
    }

    char err_buf[32] = {0};
    bool ok = p->cfg.on_credentials(ssid, pass, err_buf, sizeof err_buf,
                                    p->cfg.user_ctx);

    // Wipe local copies of the password before logging anything.
    volatile char *vp = (volatile char *)pass;
    for (size_t i = 0; i < sizeof pass; i++) vp[i] = 0;

    if (ok) {
        prov_write(p, PROV_OK);
        ESP_LOGI(TAG, "credentials accepted (ssid=\"%s\")", ssid);
    } else {
        const char *reason = err_buf[0] ? err_buf : "callback";
        prov_send_err(p, reason);
        ESP_LOGW(TAG, "credentials rejected: %s", reason);
    }
}

static bool prov_handle_line(struct provisioner *p, char *line, size_t len)
{
    // Only consider lines that look like our framing: "<<PROV...>>".
    // Returns true if the line was a recognised provisioner frame and was
    // consumed; false if the line should be passed through to the
    // console (or simply discarded when not sharing).
    if (len < 5 || line[0] != '<' || line[1] != '<') return false;

    if (len == sizeof(PROV_PROBE) - 1 &&
        memcmp(line, PROV_PROBE, len) == 0) {
        prov_write(p, PROV_READY);
        return true;
    }

    size_t pfx = sizeof(PROV_SET_PFX) - 1;
    if (len > pfx + 2 &&
        memcmp(line, PROV_SET_PFX, pfx) == 0 &&
        line[len - 1] == '>' && line[len - 2] == '>') {
        line[len - 2] = '\0';
        prov_handle_set(p, line + pfx);
        return true;
    }
    // Other framed lines are not ours.
    return false;
}

// ---------------------------------------------------------------------------
// Console-sharing helpers
// ---------------------------------------------------------------------------
static void prov_forward(struct provisioner *p, const char *data, size_t n)
{
    // Forward bytes to the redirected stdin if console sharing is enabled,
    // otherwise drop them (preserves the historical "discard non-frame
    // traffic" behaviour).
    if (!p->cfg.share_with_console || !p->stdin_stream || n == 0) return;
    // Non-blocking-ish push: if the consumer hasn't drained the buffer we
    // wait briefly, then drop the overflow rather than stalling the UART
    // reader (which would also stall any in-flight provisioning frame).
    xStreamBufferSend(p->stdin_stream, data, n, pdMS_TO_TICKS(20));
}

static void prov_forward_byte(struct provisioner *p, char c)
{
    prov_forward(p, &c, 1);
}

static void prov_feed(struct provisioner *p, const uint8_t *buf, size_t n)
{
    // When sharing is disabled this collapses to the original behaviour:
    // every byte is funnelled into p->line until '\n', then the line is
    // examined and either acted on or silently dropped.
    //
    // When sharing is enabled we run a tiny state machine that buffers
    // only candidate "<<..." frame openers; any byte that cannot be the
    // start of one of our frames is forwarded to the console immediately,
    // preserving interactive responsiveness for non-line-buffered
    // consumers (e.g. linenoise).
    const bool share = p->cfg.share_with_console;

    for (size_t i = 0; i < n; i++) {
        char c = (char)buf[i];

        if (!share) {
            // Original path: '\r' stripped, accumulate until '\n', then
            // try to interpret. Anything else is dropped.
            if (c == '\r') continue;
            if (c == '\n') {
                if (p->overflow) {
                    p->line_len = 0;
                    p->overflow = false;
                    continue;
                }
                p->line[p->line_len] = '\0';
                (void)prov_handle_line(p, p->line, p->line_len);
                p->line_len = 0;
                continue;
            }
            if (p->line_len + 1 > sizeof p->line) {
                p->overflow = true;
                continue;
            }
            p->line[p->line_len++] = c;
            continue;
        }

        // ---- shared mode ----
        switch (p->share_state) {
        case PSS_LINE_START:
            if (c == '<') {
                p->line[0] = c;
                p->line_len = 1;
                p->share_state = PSS_GOT_ONE_LT;
            } else if (c == '\n') {
                prov_forward_byte(p, c);
                // stay in PSS_LINE_START
            } else {
                prov_forward_byte(p, c);
                p->share_state = PSS_PASSTHROUGH;
            }
            break;

        case PSS_GOT_ONE_LT:
            if (c == '<') {
                p->line[1] = c;
                p->line_len = 2;
                p->overflow = false;
                p->share_state = PSS_BUFFER_FRAME;
            } else if (c == '\n') {
                // "<\n" -- not a frame, flush.
                prov_forward(p, p->line, p->line_len);
                prov_forward_byte(p, c);
                p->line_len = 0;
                p->share_state = PSS_LINE_START;
            } else {
                prov_forward(p, p->line, p->line_len);
                prov_forward_byte(p, c);
                p->line_len = 0;
                p->share_state = PSS_PASSTHROUGH;
            }
            break;

        case PSS_BUFFER_FRAME:
            if (c == '\r') {
                // Match the historical behaviour: '\r' inside a frame is
                // stripped so that CRLF and LF both work.
                break;
            }
            if (c == '\n') {
                if (p->overflow) {
                    // Buffered prefix already flushed; just emit the '\n'
                    // and reset.
                    prov_forward_byte(p, c);
                    p->line_len = 0;
                    p->overflow = false;
                    p->share_state = PSS_LINE_START;
                    break;
                }
                p->line[p->line_len] = '\0';
                bool consumed = prov_handle_line(p, p->line, p->line_len);
                if (!consumed) {
                    // Not one of ours; replay the line to the console.
                    prov_forward(p, p->line, p->line_len);
                    prov_forward_byte(p, '\n');
                }
                p->line_len = 0;
                p->share_state = PSS_LINE_START;
                break;
            }
            if (p->line_len + 1 > sizeof p->line) {
                // Frame too long to be ours -- flush what we have and
                // pass the rest through.
                if (!p->overflow) {
                    prov_forward(p, p->line, p->line_len);
                    p->overflow = true;
                }
                prov_forward_byte(p, c);
                p->share_state = PSS_PASSTHROUGH;
                break;
            }
            p->line[p->line_len++] = c;
            break;

        case PSS_PASSTHROUGH:
        default:
            prov_forward_byte(p, c);
            if (c == '\n') {
                p->line_len = 0;
                p->overflow = false;
                p->share_state = PSS_LINE_START;
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Background task
// ---------------------------------------------------------------------------
static void prov_task(void *arg)
{
    struct provisioner *p = (struct provisioner *)arg;
    uint8_t buf[128];

    ESP_LOGI(TAG, "provisioner task running on UART%d @ %d",
             (int)p->cfg.uart_num, p->cfg.baud_rate);

    while (!p->stop) {
        int n = uart_read_bytes(p->cfg.uart_num, buf, sizeof buf,
                                pdMS_TO_TICKS(100));
        if (n > 0) {
            prov_feed(p, buf, (size_t)n);
        } else if (n < 0) {
            // Transient error; brief pause to avoid a tight loop.
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    p->running = false;
    vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// VFS for redirected stdin (only used when share_with_console is true)
// ---------------------------------------------------------------------------
static int prov_vfs_open(void *ctx, const char *path, int flags, int mode)
{
    (void)ctx; (void)flags; (void)mode;
    // We expose a single device "/0" under our base path. Anything else
    // is rejected.
    if (path == NULL) return -1;
    if (path[0] == '/') path++;
    if (strcmp(path, "0") != 0) {
        errno = ENOENT;
        return -1;
    }
    return 0;   // local fd = 0
}

static ssize_t prov_vfs_read(void *ctx, int fd, void *dst, size_t size)
{
    struct provisioner *p = (struct provisioner *)ctx;
    if (fd != 0 || p == NULL || p->stdin_stream == NULL) {
        errno = EBADF;
        return -1;
    }
    if (size == 0) return 0;
    // Block until at least one byte is available, mirroring the semantics
    // of a TTY read. Stdio layers above expect blocking reads from stdin.
    size_t got = xStreamBufferReceive(p->stdin_stream, dst, size,
                                      portMAX_DELAY);
    if (got == 0) {
        // Should only happen if the stream buffer was deleted while we
        // were blocked; treat as EOF.
        return 0;
    }
    return (ssize_t)got;
}

static int prov_vfs_close(void *ctx, int fd)
{
    (void)ctx;
    if (fd != 0) { errno = EBADF; return -1; }
    return 0;
}

static int prov_vfs_fstat(void *ctx, int fd, struct stat *st)
{
    (void)ctx;
    if (fd != 0 || st == NULL) { errno = EBADF; return -1; }
    memset(st, 0, sizeof *st);
    st->st_mode = S_IFCHR;     // character device, like a TTY
    return 0;
}

static int prov_vfs_fcntl(void *ctx, int fd, int cmd, int arg)
{
    (void)ctx; (void)cmd; (void)arg;
    if (fd != 0) { errno = EBADF; return -1; }
    // No-op: we don't honour O_NONBLOCK, but report success so callers
    // (including newlib's stdio init) don't fail outright.
    return 0;
}

static esp_err_t prov_console_share_setup(struct provisioner *p)
{
    if (s_share_instance != NULL) {
        ESP_LOGE(TAG, "share_with_console: another instance already active");
        return ESP_ERR_INVALID_STATE;
    }

    p->saved_stdin_fd = -1;
    p->stdin_stream = xStreamBufferCreate(PROV_STDIN_BUFFER_BYTES, 1);
    if (p->stdin_stream == NULL) return ESP_ERR_NO_MEM;

    static const esp_vfs_t vfs = {
        .flags    = ESP_VFS_FLAG_CONTEXT_PTR,
        .open_p   = prov_vfs_open,
        .read_p   = prov_vfs_read,
        .close_p  = prov_vfs_close,
        .fstat_p  = prov_vfs_fstat,
        .fcntl_p  = prov_vfs_fcntl,
    };
    esp_err_t err = esp_vfs_register(PROV_VFS_BASE_PATH, &vfs, p);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_vfs_register: %s", esp_err_to_name(err));
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        return err;
    }
    p->vfs_registered = true;
    s_share_instance = p;

    // Route stdout/stderr through the UART driver so that prints from the
    // application (and from this component) coexist with the driver TX
    // path we now own.
    uart_vfs_dev_use_driver((int)p->cfg.uart_num);

    // Replace stdin with our filtered device. We dup() the existing fd 0
    // first so we can restore it on stop.
    int new_fd = open(PROV_VFS_BASE_PATH "/0", O_RDONLY);
    if (new_fd < 0) {
        ESP_LOGE(TAG, "open %s: %d", PROV_VFS_BASE_PATH "/0", errno);
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
        s_share_instance = NULL;
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        return ESP_FAIL;
    }
    p->saved_stdin_fd = dup(STDIN_FILENO);   // may be -1 if no stdin yet
    if (dup2(new_fd, STDIN_FILENO) < 0) {
        ESP_LOGE(TAG, "dup2 stdin: %d", errno);
        close(new_fd);
        if (p->saved_stdin_fd >= 0) close(p->saved_stdin_fd);
        p->saved_stdin_fd = -1;
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
        s_share_instance = NULL;
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        return ESP_FAIL;
    }
    close(new_fd);

    // Make sure stdio reads are unbuffered so a single-byte feed wakes the
    // console immediately. The IDF console normally does this itself but
    // we may run before it.
    setvbuf(stdin, NULL, _IONBF, 0);

    ESP_LOGI(TAG, "share_with_console: stdin redirected via %s",
             PROV_VFS_BASE_PATH);
    return ESP_OK;
}

static void prov_console_share_teardown(struct provisioner *p)
{
    if (p->saved_stdin_fd >= 0) {
        dup2(p->saved_stdin_fd, STDIN_FILENO);
        close(p->saved_stdin_fd);
        p->saved_stdin_fd = -1;
    }
    if (p->vfs_registered) {
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
    }
    if (p->stdin_stream) {
        // Wake any reader still blocked on the stream buffer so it can
        // observe the now-restored fd.
        xStreamBufferReset(p->stdin_stream);
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
    }
    if (s_share_instance == p) {
        s_share_instance = NULL;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
esp_err_t provisioner_start_uart(const provisioner_uart_config_t *cfg,
                                 provisioner_handle_t *out)
{
    ESP_RETURN_ON_FALSE(cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "cfg null");
    ESP_RETURN_ON_FALSE(cfg->on_credentials != NULL, ESP_ERR_INVALID_ARG,
                        TAG, "on_credentials required");
    ESP_RETURN_ON_FALSE(!cfg->share_with_console || cfg->install_driver,
                        ESP_ERR_INVALID_ARG, TAG,
                        "share_with_console requires install_driver=true");

    struct provisioner *p = calloc(1, sizeof *p);
    if (!p) return ESP_ERR_NO_MEM;
    p->cfg = *cfg;
    p->saved_stdin_fd = -1;
    p->share_state = PSS_LINE_START;
    if (p->cfg.baud_rate       <= 0)  p->cfg.baud_rate       = 115200;
    if (p->cfg.task_stack_size == 0)  p->cfg.task_stack_size = 4096;
    if (p->cfg.rx_buffer_size  == 0)  p->cfg.rx_buffer_size  = 1024;
    // In shared mode prints have to flow through the driver, so we need a
    // TX buffer to avoid blocking the application on the UART FIFO.
    if (p->cfg.share_with_console && p->cfg.tx_buffer_size == 0) {
        p->cfg.tx_buffer_size = 256;
    }

    esp_err_t err = ESP_OK;

    if (p->cfg.install_driver) {
        const uart_config_t uart_cfg = {
            .baud_rate           = p->cfg.baud_rate,
            .data_bits           = UART_DATA_8_BITS,
            .parity              = UART_PARITY_DISABLE,
            .stop_bits           = UART_STOP_BITS_1,
            .flow_ctrl           = UART_HW_FLOWCTRL_DISABLE,
            .source_clk          = UART_SCLK_DEFAULT,
        };
        err = uart_driver_install(p->cfg.uart_num,
                                  (int)p->cfg.rx_buffer_size,
                                  (int)p->cfg.tx_buffer_size,
                                  0, NULL, 0);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "uart_driver_install: %s", esp_err_to_name(err));
            free(p);
            return err;
        }
        err = uart_param_config(p->cfg.uart_num, &uart_cfg);
        if (err == ESP_OK) {
            err = uart_set_pin(p->cfg.uart_num,
                               p->cfg.tx_pin,  p->cfg.rx_pin,
                               p->cfg.rts_pin, p->cfg.cts_pin);
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "uart configure: %s", esp_err_to_name(err));
            uart_driver_delete(p->cfg.uart_num);
            free(p);
            return err;
        }
        p->installed_driver = true;
    }

    if (p->cfg.share_with_console) {
        err = prov_console_share_setup(p);
        if (err != ESP_OK) {
            if (p->installed_driver) uart_driver_delete(p->cfg.uart_num);
            free(p);
            return err;
        }
    }

    p->running = true;
    BaseType_t ok;
    if (p->cfg.task_core_id < 0) {
        ok = xTaskCreate(prov_task, "provisioner",
                         p->cfg.task_stack_size, p,
                         p->cfg.task_priority ? p->cfg.task_priority : 5,
                         &p->task);
    } else {
        ok = xTaskCreatePinnedToCore(prov_task, "provisioner",
                                     p->cfg.task_stack_size, p,
                                     p->cfg.task_priority ? p->cfg.task_priority : 5,
                                     &p->task, p->cfg.task_core_id);
    }
    if (ok != pdPASS) {
        if (p->cfg.share_with_console) prov_console_share_teardown(p);
        if (p->installed_driver) uart_driver_delete(p->cfg.uart_num);
        free(p);
        return ESP_ERR_NO_MEM;
    }

    if (out) *out = p;
    return ESP_OK;
}

esp_err_t provisioner_stop(provisioner_handle_t h)
{
    if (!h) return ESP_ERR_INVALID_ARG;
    h->stop = true;
    // Wait briefly for the task to exit.
    for (int i = 0; i < 100 && h->running; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (h->cfg.share_with_console) {
        prov_console_share_teardown(h);
    }
    if (h->installed_driver) {
        uart_driver_delete(h->cfg.uart_num);
    }
    free(h);
    return ESP_OK;
}
