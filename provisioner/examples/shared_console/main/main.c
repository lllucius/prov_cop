// Shared-console example: run the provisioner on the same UART that the
// IDF console / printf use. Frames addressed to the provisioner are
// transparently consumed; everything else continues to behave like a
// normal serial console (you can paste commands, read log output, etc.).
//
// Build with ESP-IDF v6:
//
//   cd provisioner/examples/shared_console
//   idf.py set-target esp32
//   idf.py build flash monitor
//
// Make sure CONFIG_ESP_CONSOLE_UART is left at its default (UART0) so the
// console and the provisioner agree on which port to use. If you run a
// custom REPL via esp_console_new_repl_uart() you must NOT use this
// example unmodified -- see provisioner.h for details.

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "provisioner.h"

static const char* TAG = "prov_shared";

static bool on_credentials(const char* ssid,
                           const char* password,
                           char*       err_out,
                           size_t      err_out_len,
                           void*       ctx)
{
    (void)ctx;
    (void)password; // do not log the password
    ESP_LOGI(TAG, "received credentials (ssid_len=%u)", (unsigned)strlen(ssid));
    // A real application would hand these to esp_wifi here. For demo
    // purposes we just acknowledge.
    (void)err_out;
    (void)err_out_len;
    return true;
}

void app_main(void)
{
    provisioner_uart_config_t cfg = PROVISIONER_UART_CONFIG_DEFAULT();
    cfg.on_credentials            = on_credentials;
    cfg.share_with_console        = true; // implies install_driver = true
    cfg.device_name               = "Shared-Console Example";

    ESP_ERROR_CHECK(provisioner_start_uart(&cfg, NULL));
    ESP_LOGI(TAG, "provisioner running alongside the IDF console");

    // A trivial heartbeat so it's obvious that printf still reaches the
    // same UART that the provisioner is listening on.
    int tick = 0;
    while (1)
    {
        printf("heartbeat %d\n", tick++);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
