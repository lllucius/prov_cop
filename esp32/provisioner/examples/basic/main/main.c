// Basic example: receive Wi-Fi credentials over USB serial from the
// companion provisioning web page and connect to the network.
//
// Build with ESP-IDF v6:
//
//   cd esp32/provisioner/examples/basic
//   idf.py set-target esp32
//   idf.py build flash monitor
//
// Then open the prov_cop web page (`index.html` at the repo root) in
// Chrome/Edge over https:// or http://localhost, click "Send to ESP32",
// choose this board's port, and enter your Wi-Fi details.

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "provisioner.h"

static const char* TAG = "prov_basic";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_events;
static int s_retries;
static const int s_retry_max = 5;

static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED)
    {
        if (s_retries < s_retry_max)
        {
            esp_wifi_connect();
            s_retries++;
            ESP_LOGI(TAG, "retrying Wi-Fi connect (%d/%d)", s_retries, s_retry_max);
        }
        else
        {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* e = (ip_event_got_ip_t*)data;
        ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&e->ip_info.ip));
        s_retries = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_once(void)
{
    static bool inited;
    if (inited)
    {
        return;
    }
    inited = true;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wic));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    s_wifi_events = xEventGroupCreate();
}

static bool
on_credentials(const char* ssid, const char* password, char* err_out, size_t err_out_len, void* ctx)
{
    (void)ctx;
    ESP_LOGI(TAG, "received credentials, ssid=\"%s\"", ssid);

    wifi_init_once();

    wifi_config_t wc = {0};
    strlcpy((char*)wc.sta.ssid, ssid, sizeof wc.sta.ssid);
    strlcpy((char*)wc.sta.password, password, sizeof wc.sta.password);
    wc.sta.threshold.authmode = (password[0] == '\0') ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;

    s_retries = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wc);
    if (err == ESP_OK)
    {
        err = esp_wifi_disconnect();
        if (err == ESP_ERR_WIFI_NOT_CONNECT)
        {
            err = ESP_OK;
        }
    }
    if (err == ESP_OK)
    {
        err = esp_wifi_connect();
    }
    if (err != ESP_OK)
    {
        strlcpy(err_out, "wifi_api", err_out_len);
        return false;
    }

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdTRUE,
                                           pdFALSE,
                                           pdMS_TO_TICKS(20000));

    if (bits & WIFI_CONNECTED_BIT)
    {
        return true;
    }

    strlcpy(err_out, (bits & WIFI_FAIL_BIT) ? "auth_or_unreachable" : "timeout", err_out_len);
    return false;
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    provisioner_uart_config_t cfg = PROVISIONER_UART_CONFIG_DEFAULT();
    cfg.on_credentials = on_credentials;

    // The default config targets UART0, which on most ESP32 dev boards is
    // wired to the on-board USB-serial adapter that the web page connects
    // to. To take exclusive control of UART0 we let the component install
    // the driver -- this requires that the IDF console is NOT also using
    // UART0 (set `CONFIG_ESP_CONSOLE_NONE=y` or
    // `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y` in menuconfig). Alternatively
    // pick a dedicated UART here, e.g.:
    //
    //     cfg.uart_num = UART_NUM_1;
    //     cfg.tx_pin   = GPIO_NUM_17;
    //     cfg.rx_pin   = GPIO_NUM_16;
    //
    // and connect a separate USB-to-serial adapter to those pins.
    cfg.install_driver = true;

    ESP_ERROR_CHECK(provisioner_start_uart(&cfg, NULL));
    ESP_LOGI(TAG, "ready, waiting for provisioning over USB serial...");
}
