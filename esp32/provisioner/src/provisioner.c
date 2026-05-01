// provisioner.c - see provisioner.h for documentation.
//
// This file is the ESP-IDF integration layer. The actual protocol parser
// lives in provisioner_proto.[ch] and is transport-agnostic so it can be
// unit-tested on a host. This file wires the parser to a UART driver and
// (optionally) a redirected stdin VFS.

#include "provisioner.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs.h"

#include "provisioner_proto.h"

static const char* TAG = "provisioner";

// VFS base path used when share_with_console is enabled. We only support a
// single shared instance at a time (there is just one stdin to redirect).
#define PROV_VFS_BASE_PATH "/dev/prov_console"
// Size of the buffer that holds bytes destined for the redirected stdin.
// 512 bytes comfortably exceeds typical console line lengths (incl. paste
// of a long command) so a brief stall in the consumer does not lose data.
#define PROV_STDIN_BUFFER_BYTES 512
// How long to block when handing a byte off to the redirected stdin
// before giving up. Kept short so a stuck consumer cannot wedge UART RX
// (which would also stall in-flight provisioning frames).
#define PROV_STDIN_SEND_TIMEOUT_MS 20
// Shared-console stdin reads poll for shutdown so provisioner_stop() can
// tear down the VFS without deleting a stream buffer under a blocked reader.
#define PROV_STDIN_READ_POLL_MS 100
// Maximum time provisioner_stop() waits for the background task or redirected
// stdin readers to quiesce before returning ESP_ERR_TIMEOUT.
#define PROV_STOP_TIMEOUT_MS 30000
// Minimum interval between successive `<<PROV!>>` probe responses, to
// rate-limit a flood of probes that would otherwise saturate the shared
// console UART. The browser's normal probe cadence is 500 ms so 200 ms
// keeps that fully responsive while still capping pathological floods.
#define PROV_PROBE_MIN_INTERVAL_MS 200

struct provisioner
{
    provisioner_uart_config_t cfg; // copy of caller's config
    TaskHandle_t              task;
    SemaphoreHandle_t         task_done;
    atomic_bool               stop;
    bool                      task_stopped;
    bool                      installed_driver;
    bool                      uart_vfs_redirected;

    prov_proto_t proto;

    // Console-sharing state. Only used when cfg.share_with_console is true.
    StreamBufferHandle_t stdin_stream;
    SemaphoreHandle_t    stdin_lock;
    int                  stdin_readers;
    atomic_bool          stdin_closing;
    bool                 vfs_registered;
    int                  saved_stdin_fd; // -1 if no redirection
};

// Single shared instance pointer used by the VFS callbacks.
static struct provisioner* s_share_instance;

// ---------------------------------------------------------------------------
// Protocol -> UART glue
// ---------------------------------------------------------------------------
static void prov_uart_write_cb(void* ctx, const char* data, size_t len)
{
    struct provisioner* p = (struct provisioner*)ctx;
    if (len == 0)
    {
        return;
    }
    uart_write_bytes(p->cfg.uart_num, data, len);
}

static void prov_uart_forward_cb(void* ctx, const char* data, size_t len)
{
    struct provisioner* p = (struct provisioner*)ctx;
    if (!p->stdin_stream || len == 0)
    {
        return;
    }
    // Non-blocking-ish push: if the consumer hasn't drained the buffer we
    // wait briefly, then drop the overflow rather than stalling the UART
    // reader (which would also stall any in-flight provisioning frame).
    xStreamBufferSend(p->stdin_stream, data, len, pdMS_TO_TICKS(PROV_STDIN_SEND_TIMEOUT_MS));
}

static uint32_t prov_now_ms_cb(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

// Wrapper that adapts the user's provisioner_credentials_cb_t to the
// protocol layer's prov_proto_credentials_cb_t. The two share an identical
// signature today; the wrapper exists so we control logging & sanitisation
// at one well-defined point.
static bool prov_credentials_trampoline(const char* ssid,
                                        const char* password,
                                        char*       err_out,
                                        size_t      err_out_len,
                                        void*       user_ctx)
{
    struct provisioner* p = (struct provisioner*)user_ctx;
    if (!p->cfg.on_credentials)
    {
        return false;
    }
    bool ok =
        p->cfg.on_credentials(ssid, password, err_out, err_out_len, p->cfg.user_ctx);
    // Avoid logging the SSID verbatim: it is user-controlled and may
    // contain terminal escape sequences or other content unsuitable for
    // the same UART that just delivered it. Log only its length.
    if (ok)
    {
        ESP_LOGI(TAG, "credentials accepted (ssid_len=%u)", (unsigned)strlen(ssid));
    }
    else
    {
        const char* reason = (err_out && err_out[0]) ? err_out : "callback";
        ESP_LOGW(TAG, "credentials rejected: %s", reason);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Background task
// ---------------------------------------------------------------------------
static void prov_task(void* arg)
{
    struct provisioner* p = (struct provisioner*)arg;
    uint8_t             buf[128];

    ESP_LOGI(TAG,
             "provisioner task running on UART%d @ %d",
             (int)p->cfg.uart_num,
             p->cfg.baud_rate);

    while (!atomic_load(&p->stop))
    {
        int n = uart_read_bytes(p->cfg.uart_num, buf, sizeof buf, pdMS_TO_TICKS(100));
        if (n > 0)
        {
            prov_proto_feed(&p->proto, buf, (size_t)n);
        }
        else if (n < 0)
        {
            // Transient error; brief pause to avoid a tight loop.
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    if (p->task_done)
    {
        xSemaphoreGive(p->task_done);
    }
    vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// VFS for redirected stdin (only used when share_with_console is true)
// ---------------------------------------------------------------------------
static int prov_vfs_open(void* ctx, const char* path, int flags, int mode)
{
    struct provisioner* p = (struct provisioner*)ctx;
    (void)flags;
    (void)mode;
    if (path == NULL)
    {
        return -1;
    }
    if (path[0] == '/')
    {
        path++;
    }
    if (strcmp(path, "0") != 0)
    {
        errno = ENOENT;
        return -1;
    }
    if (p == NULL || p->stdin_lock == NULL)
    {
        errno = ENODEV;
        return -1;
    }
    if (atomic_load(&p->stdin_closing))
    {
        errno = ENODEV;
        return -1;
    }
    return 0; // local fd = 0
}

static ssize_t prov_vfs_read(void* ctx, int fd, void* dst, size_t size)
{
    struct provisioner* p = (struct provisioner*)ctx;
    if (fd != 0 || p == NULL || p->stdin_stream == NULL || p->stdin_lock == NULL)
    {
        errno = EBADF;
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    if (atomic_load(&p->stdin_closing))
    {
        return 0;
    }

    // Track that a reader is in-flight so teardown can wait for us to
    // finish before deleting the underlying stream buffer / mutex.
    xSemaphoreTake(p->stdin_lock, portMAX_DELAY);
    p->stdin_readers++;
    xSemaphoreGive(p->stdin_lock);

    size_t got = 0;
    while (got == 0)
    {
        // FreeRTOS stream buffers are SPSC: serialize the actual receive
        // call across (rare) concurrent readers, but release the lock
        // between iterations so teardown can observe counter changes
        // promptly.
        xSemaphoreTake(p->stdin_lock, portMAX_DELAY);
        bool closing = atomic_load(&p->stdin_closing);
        if (!closing)
        {
            got = xStreamBufferReceive(p->stdin_stream,
                                       dst,
                                       size,
                                       pdMS_TO_TICKS(PROV_STDIN_READ_POLL_MS));
        }
        xSemaphoreGive(p->stdin_lock);
        if (got > 0 || closing)
        {
            break;
        }
        if (atomic_load(&p->stdin_closing))
        {
            break;
        }
    }

    xSemaphoreTake(p->stdin_lock, portMAX_DELAY);
    p->stdin_readers--;
    xSemaphoreGive(p->stdin_lock);
    return (ssize_t)got;
}

static int prov_vfs_close(void* ctx, int fd)
{
    (void)ctx;
    if (fd != 0)
    {
        errno = EBADF;
        return -1;
    }
    return 0;
}

static int prov_vfs_fstat(void* ctx, int fd, struct stat* st)
{
    (void)ctx;
    if (fd != 0 || st == NULL)
    {
        errno = EBADF;
        return -1;
    }
    memset(st, 0, sizeof *st);
    st->st_mode = S_IFCHR; // character device, like a TTY
    return 0;
}

static int prov_vfs_fcntl(void* ctx, int fd, int cmd, int arg)
{
    (void)ctx;
    (void)cmd;
    (void)arg;
    if (fd != 0)
    {
        errno = EBADF;
        return -1;
    }
    // No-op: we don't honour O_NONBLOCK, but report success so callers
    // (including newlib's stdio init) don't fail outright.
    return 0;
}

static esp_err_t prov_console_share_setup(struct provisioner* p)
{
    if (s_share_instance != NULL)
    {
        ESP_LOGE(TAG, "share_with_console: another instance already active");
        return ESP_ERR_INVALID_STATE;
    }

    p->saved_stdin_fd = -1;
    p->stdin_lock     = xSemaphoreCreateMutex();
    if (p->stdin_lock == NULL)
    {
        return ESP_ERR_NO_MEM;
    }
    p->stdin_stream = xStreamBufferCreate(PROV_STDIN_BUFFER_BYTES, 1);
    if (p->stdin_stream == NULL)
    {
        vSemaphoreDelete(p->stdin_lock);
        p->stdin_lock = NULL;
        return ESP_ERR_NO_MEM;
    }

    static const esp_vfs_t vfs = {
        .flags   = ESP_VFS_FLAG_CONTEXT_PTR,
        .open_p  = prov_vfs_open,
        .read_p  = prov_vfs_read,
        .close_p = prov_vfs_close,
        .fstat_p = prov_vfs_fstat,
        .fcntl_p = prov_vfs_fcntl,
    };
    esp_err_t err = esp_vfs_register(PROV_VFS_BASE_PATH, &vfs, p);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_vfs_register: %s", esp_err_to_name(err));
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        vSemaphoreDelete(p->stdin_lock);
        p->stdin_lock = NULL;
        return err;
    }
    p->vfs_registered = true;
    s_share_instance  = p;

    // Route stdout/stderr through the UART driver so that prints from the
    // application (and from this component) coexist with the driver TX
    // path we now own. Remember that we did this so teardown can revert
    // it before the driver is uninstalled.
    uart_vfs_dev_use_driver((int)p->cfg.uart_num);
    p->uart_vfs_redirected = true;

    // Replace stdin with our filtered device. We dup() the existing fd 0
    // first so we can restore it on stop.
    int new_fd = open(PROV_VFS_BASE_PATH "/0", O_RDONLY);
    if (new_fd < 0)
    {
        ESP_LOGE(TAG, "open %s: %d", PROV_VFS_BASE_PATH "/0", errno);
        if (p->uart_vfs_redirected)
        {
            uart_vfs_dev_use_nonblocking((int)p->cfg.uart_num);
            p->uart_vfs_redirected = false;
        }
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
        s_share_instance  = NULL;
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        vSemaphoreDelete(p->stdin_lock);
        p->stdin_lock = NULL;
        return ESP_FAIL;
    }
    p->saved_stdin_fd = dup(STDIN_FILENO); // may be -1 if no stdin yet
    if (dup2(new_fd, STDIN_FILENO) < 0)
    {
        ESP_LOGE(TAG, "dup2 stdin: %d", errno);
        close(new_fd);
        if (p->saved_stdin_fd >= 0)
        {
            close(p->saved_stdin_fd);
        }
        p->saved_stdin_fd = -1;
        if (p->uart_vfs_redirected)
        {
            uart_vfs_dev_use_nonblocking((int)p->cfg.uart_num);
            p->uart_vfs_redirected = false;
        }
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
        s_share_instance  = NULL;
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
        vSemaphoreDelete(p->stdin_lock);
        p->stdin_lock = NULL;
        return ESP_FAIL;
    }
    close(new_fd);

    // Make sure stdio reads are unbuffered so a single-byte feed wakes the
    // console immediately. The IDF console normally does this itself but
    // we may run before it.
    setvbuf(stdin, NULL, _IONBF, 0);

    ESP_LOGI(TAG, "share_with_console: stdin redirected via %s", PROV_VFS_BASE_PATH);
    return ESP_OK;
}

static esp_err_t prov_console_share_teardown(struct provisioner* p)
{
    if (p->stdin_lock)
    {
        atomic_store(&p->stdin_closing, true);

        for (int i = 0; i < PROV_STOP_TIMEOUT_MS / PROV_STDIN_READ_POLL_MS; i++)
        {
            xSemaphoreTake(p->stdin_lock, portMAX_DELAY);
            int readers = p->stdin_readers;
            xSemaphoreGive(p->stdin_lock);
            if (readers == 0)
            {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(PROV_STDIN_READ_POLL_MS));
        }

        xSemaphoreTake(p->stdin_lock, portMAX_DELAY);
        int readers = p->stdin_readers;
        xSemaphoreGive(p->stdin_lock);
        if (readers != 0)
        {
            ESP_LOGE(TAG, "share_with_console: timed out waiting for stdin readers");
            return ESP_ERR_TIMEOUT;
        }
    }

    if (p->saved_stdin_fd >= 0)
    {
        dup2(p->saved_stdin_fd, STDIN_FILENO);
        close(p->saved_stdin_fd);
        p->saved_stdin_fd = -1;
    }
    // Revert stdout/stderr back to the non-blocking VFS path *before* the
    // UART driver gets uninstalled by provisioner_stop, otherwise any
    // subsequent printf/ESP_LOGx would route through a deleted driver.
    if (p->uart_vfs_redirected)
    {
        uart_vfs_dev_use_nonblocking((int)p->cfg.uart_num);
        p->uart_vfs_redirected = false;
    }
    if (p->vfs_registered)
    {
        esp_vfs_unregister(PROV_VFS_BASE_PATH);
        p->vfs_registered = false;
    }
    if (p->stdin_stream)
    {
        vStreamBufferDelete(p->stdin_stream);
        p->stdin_stream = NULL;
    }
    if (p->stdin_lock)
    {
        vSemaphoreDelete(p->stdin_lock);
        p->stdin_lock = NULL;
    }
    if (s_share_instance == p)
    {
        s_share_instance = NULL;
    }
    return ESP_OK;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
esp_err_t provisioner_start_uart(const provisioner_uart_config_t* cfg, provisioner_handle_t* out)
{
    ESP_RETURN_ON_FALSE(cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "cfg null");
    ESP_RETURN_ON_FALSE(cfg->on_credentials != NULL,
                        ESP_ERR_INVALID_ARG,
                        TAG,
                        "on_credentials required");

    struct provisioner* p = calloc(1, sizeof *p);
    if (!p)
    {
        return ESP_ERR_NO_MEM;
    }
    p->cfg            = *cfg;
    p->saved_stdin_fd = -1;
    atomic_init(&p->stop, false);
    atomic_init(&p->stdin_closing, false);
    p->task_done = xSemaphoreCreateBinary();
    if (p->task_done == NULL)
    {
        free(p);
        return ESP_ERR_NO_MEM;
    }
    if (p->cfg.baud_rate <= 0)
    {
        p->cfg.baud_rate = 115200;
    }
    if (p->cfg.task_stack_size == 0)
    {
        p->cfg.task_stack_size = 4096;
    }
    if (p->cfg.rx_buffer_size == 0)
    {
        p->cfg.rx_buffer_size = 1024;
    }
    // share_with_console requires the component to install/manage the
    // driver: any other code that re-installs UART0 would steal the byte
    // stream. We auto-promote rather than fail to make the common case
    // ergonomic.
    if (p->cfg.share_with_console)
    {
        p->cfg.install_driver = true;
    }
    // In shared mode prints have to flow through the driver, so we need a
    // TX buffer to avoid blocking the application on the UART FIFO.
    if (p->cfg.share_with_console && p->cfg.tx_buffer_size == 0)
    {
        p->cfg.tx_buffer_size = 256;
    }

    // Wire up the protocol parser.
    prov_proto_config_t pcfg     = {0};
    pcfg.write                   = prov_uart_write_cb;
    pcfg.forward                 = prov_uart_forward_cb;
    pcfg.io_ctx                  = p;
    pcfg.on_credentials          = prov_credentials_trampoline;
    pcfg.user_ctx                = p;
    pcfg.device_name             = p->cfg.device_name;
    pcfg.share_with_console      = p->cfg.share_with_console;
    pcfg.min_probe_interval_ms   = PROV_PROBE_MIN_INTERVAL_MS;
    pcfg.now_ms                  = prov_now_ms_cb;
    prov_proto_init(&p->proto, &pcfg);

    esp_err_t err = ESP_OK;

    if (p->cfg.install_driver)
    {
        const uart_config_t uart_cfg = {
            .baud_rate  = p->cfg.baud_rate,
            .data_bits  = UART_DATA_8_BITS,
            .parity     = UART_PARITY_DISABLE,
            .stop_bits  = UART_STOP_BITS_1,
            .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
        };
        err = uart_driver_install(p->cfg.uart_num,
                                  (int)p->cfg.rx_buffer_size,
                                  (int)p->cfg.tx_buffer_size,
                                  0,
                                  NULL,
                                  0);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "uart_driver_install: %s", esp_err_to_name(err));
            vSemaphoreDelete(p->task_done);
            free(p);
            return err;
        }
        err = uart_param_config(p->cfg.uart_num, &uart_cfg);
        if (err == ESP_OK)
        {
            err = uart_set_pin(p->cfg.uart_num,
                               p->cfg.tx_pin,
                               p->cfg.rx_pin,
                               p->cfg.rts_pin,
                               p->cfg.cts_pin);
        }
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "uart configure: %s", esp_err_to_name(err));
            uart_driver_delete(p->cfg.uart_num);
            vSemaphoreDelete(p->task_done);
            free(p);
            return err;
        }
        p->installed_driver = true;
    }

    if (p->cfg.share_with_console)
    {
        err = prov_console_share_setup(p);
        if (err != ESP_OK)
        {
            if (p->installed_driver)
            {
                uart_driver_delete(p->cfg.uart_num);
            }
            vSemaphoreDelete(p->task_done);
            free(p);
            return err;
        }
    }

    BaseType_t ok;
    int        prio = p->cfg.task_priority > 0 ? p->cfg.task_priority : 5;
    if (p->cfg.task_core_id < 0)
    {
        ok = xTaskCreate(prov_task,
                         "provisioner",
                         p->cfg.task_stack_size,
                         p,
                         prio,
                         &p->task);
    }
    else
    {
        ok = xTaskCreatePinnedToCore(prov_task,
                                     "provisioner",
                                     p->cfg.task_stack_size,
                                     p,
                                     prio,
                                     &p->task,
                                     p->cfg.task_core_id);
    }
    if (ok != pdPASS)
    {
        if (p->cfg.share_with_console)
        {
            (void)prov_console_share_teardown(p);
        }
        if (p->installed_driver)
        {
            uart_driver_delete(p->cfg.uart_num);
        }
        vSemaphoreDelete(p->task_done);
        free(p);
        return ESP_ERR_NO_MEM;
    }

    if (out)
    {
        *out = p;
    }
    return ESP_OK;
}

esp_err_t provisioner_stop(provisioner_handle_t h)
{
    if (!h)
    {
        return ESP_ERR_INVALID_ARG;
    }
    if (xTaskGetCurrentTaskHandle() == h->task)
    {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store(&h->stop, true);
    if (!h->task_stopped)
    {
        if (xSemaphoreTake(h->task_done, pdMS_TO_TICKS(PROV_STOP_TIMEOUT_MS)) != pdTRUE)
        {
            ESP_LOGE(TAG, "timed out waiting for provisioner task to stop");
            return ESP_ERR_TIMEOUT;
        }
        h->task_stopped = true;
    }
    if (h->cfg.share_with_console)
    {
        esp_err_t err = prov_console_share_teardown(h);
        if (err != ESP_OK)
        {
            return err;
        }
    }
    if (h->installed_driver)
    {
        uart_driver_delete(h->cfg.uart_num);
    }
    vSemaphoreDelete(h->task_done);
    free(h);
    return ESP_OK;
}
