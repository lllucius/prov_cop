// provisioner.c - see provisioner.h for documentation.

#include "provisioner.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
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

struct provisioner {
    provisioner_uart_config_t cfg;     // copy of caller's config
    TaskHandle_t              task;
    volatile bool             stop;
    volatile bool             running;
    bool                      installed_driver;
    char                      line[PROV_LINE_MAX];
    size_t                    line_len;
    bool                      overflow;
};

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

static void prov_handle_line(struct provisioner *p, char *line, size_t len)
{
    // Only consider lines that look like our framing: "<<...>>".
    if (len < 5 || line[0] != '<' || line[1] != '<') return;

    if (len == sizeof(PROV_PROBE) - 1 &&
        memcmp(line, PROV_PROBE, len) == 0) {
        prov_write(p, PROV_READY);
        return;
    }

    size_t pfx = sizeof(PROV_SET_PFX) - 1;
    if (len > pfx + 2 &&
        memcmp(line, PROV_SET_PFX, pfx) == 0 &&
        line[len - 1] == '>' && line[len - 2] == '>') {
        line[len - 2] = '\0';
        prov_handle_set(p, line + pfx);
        return;
    }
    // Other framed lines are silently ignored.
}

static void prov_feed(struct provisioner *p, const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = (char)buf[i];
        if (c == '\r') continue;
        if (c == '\n') {
            if (p->overflow) {
                p->line_len = 0;
                p->overflow = false;
                continue;
            }
            p->line[p->line_len] = '\0';
            prov_handle_line(p, p->line, p->line_len);
            p->line_len = 0;
            continue;
        }
        if (p->line_len + 1 > sizeof p->line) {
            p->overflow = true;
            continue;
        }
        p->line[p->line_len++] = c;
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
// Public API
// ---------------------------------------------------------------------------
esp_err_t provisioner_start_uart(const provisioner_uart_config_t *cfg,
                                 provisioner_handle_t *out)
{
    ESP_RETURN_ON_FALSE(cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "cfg null");
    ESP_RETURN_ON_FALSE(cfg->on_credentials != NULL, ESP_ERR_INVALID_ARG,
                        TAG, "on_credentials required");

    struct provisioner *p = calloc(1, sizeof *p);
    if (!p) return ESP_ERR_NO_MEM;
    p->cfg = *cfg;
    if (p->cfg.baud_rate       <= 0)  p->cfg.baud_rate       = 115200;
    if (p->cfg.task_stack_size == 0)  p->cfg.task_stack_size = 4096;
    if (p->cfg.rx_buffer_size  == 0)  p->cfg.rx_buffer_size  = 1024;

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
    if (h->installed_driver) {
        uart_driver_delete(h->cfg.uart_num);
    }
    free(h);
    return ESP_OK;
}
