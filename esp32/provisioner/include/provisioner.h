// provisioner.h - drop-in Wi-Fi provisioning component for ESP-IDF v6.
//
// Listens on a UART for a small framed protocol spoken by the companion
// Web Serial provisioning page, and hands decoded SSID/password values to a
// user-supplied callback. The callback's return value is reported back to
// the web page as a success/failure ack.
//
// Wire protocol (ASCII, line-terminated with '\n'):
//
//   Web -> ESP   <<PROV?>>
//   ESP -> Web   <<PROV!>>
//   ESP -> Web   <<PROV:ID <name_b64>>>           (optional, see device_name)
//   Web -> ESP   <<PROV:SET <ssid_b64> <pass_b64> <crc16_hex>>>
//   ESP -> Web   <<PROV:OK>>
//   ESP -> Web   <<PROV:ERR <reason>>>
//
// CRC is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection,
// no xorout) computed over the ASCII string "<ssid_b64> <pass_b64>"
// (the two base64 strings joined by exactly one space). pass_b64 may be
// empty for an open Wi-Fi network.
//
// If the firmware sets `device_name`, the probe response is followed by an
// extra line `<<PROV:ID <name_b64>>>` whose payload is the base64 encoding
// of the configured human-readable name, so the web page can show the
// user *which* device is being provisioned. Older browsers that don't
// recognise the `:ID` line ignore it.
// Base64 and CRC are transport framing only, not secrecy or authentication;
// treat provisioning as a local serial-access operation.
//
// Typical usage:
//
//   #include "provisioner.h"
//
//   static bool on_creds(const char *ssid, const char *password,
//                        char *err_out, size_t err_out_len, void *ctx) {
//       wifi_config_t wc = { 0 };
//       strlcpy((char *)wc.sta.ssid,     ssid,     sizeof wc.sta.ssid);
//       strlcpy((char *)wc.sta.password, password, sizeof wc.sta.password);
//       esp_wifi_set_config(WIFI_IF_STA, &wc);
//       esp_wifi_connect();
//       /* ...wait for IP_EVENT_STA_GOT_IP... */
//       return true;
//   }
//
//   void app_main(void) {
//       provisioner_uart_config_t cfg = PROVISIONER_UART_CONFIG_DEFAULT();
//       cfg.on_credentials = on_creds;
//       provisioner_start_uart(&cfg, NULL);
//   }
//
// The component is non-intrusive: it only acts on lines beginning with
// "<<" that match its frame format, so other code can keep using the same
// UART for log output without conflicts.
//
// Sharing the UART with the IDF console
// -------------------------------------
//
// On most ESP32 boards the on-board USB-serial bridge is wired to UART0,
// which is also where the IDF console (`CONFIG_ESP_CONSOLE_UART`) lives.
// The provisioner can co-exist with that console on the *same* UART by
// setting `share_with_console = true` in `provisioner_uart_config_t`.
//
// In shared mode the provisioner takes ownership of the UART driver,
// reads every byte that arrives, transparently consumes lines that match
// its `<<PROV...>>` framing, and forwards everything else into a
// filtered stdin device that the IDF console (or any other code reading
// `stdin`) can read normally. Standard output keeps writing to the same
// UART, so `printf()` and `ESP_LOGx()` continue to work unchanged.
//
// In shared mode the application must NOT install the IDF console such
// that it tries to install or read the same UART driver itself. With
// the default `CONFIG_ESP_CONSOLE_UART=y` this is fine -- the IDF
// startup code only registers the stdio VFS, and the provisioner
// supplies the actual byte stream. Custom REPLs that call
// `esp_console_new_repl_uart()` re-install the UART driver and are
// therefore incompatible with shared mode; such applications should put
// the provisioner on a dedicated UART instead, or read `stdin`
// directly (e.g. via `linenoise()`).
//
// Call `provisioner_start_uart()` *before* starting the console REPL or
// before any code reads from `stdin`, so that stdin redirection is in
// place by the time the first read happens.

#ifndef PROV_COP_PROVISIONER_H
#define PROV_COP_PROVISIONER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "driver/uart.h"
#include "esp_err.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Callback invoked when a valid SSID/password pair is received.
 *
 * @param ssid       NUL-terminated SSID (1..32 bytes).
 * @param password   NUL-terminated password (0..63 bytes; empty for open).
 * @param err_out    Optional buffer the callback may fill with a short
 *                   reason token (no spaces, no '>', no NL) to report on
 *                   failure. May be left empty.
 * @param err_out_len Size of err_out in bytes, including the NUL.
 * @param user_ctx   The user_ctx value passed in the config.
 *
 * @return  true on success (browser sees `<<PROV:OK>>`),
 *          false on failure (browser sees `<<PROV:ERR <reason>>>`).
 */
typedef bool (*provisioner_credentials_cb_t)(const char* ssid,
                                             const char* password,
                                             char* err_out,
                                             size_t err_out_len,
                                             void* user_ctx);

/** Opaque handle to a running provisioner instance. */
typedef struct provisioner* provisioner_handle_t;

/**
 * Configuration for the UART convenience entry point.
 *
 * Use PROVISIONER_UART_CONFIG_DEFAULT() to start with sensible defaults,
 * then fill in the callback (and any pin overrides).
 */
typedef struct
{
    uart_port_t uart_num;                        /**< UART port to use (e.g. UART_NUM_0). */
    int tx_pin;                                  /**< TX pin, or UART_PIN_NO_CHANGE.      */
    int rx_pin;                                  /**< RX pin, or UART_PIN_NO_CHANGE.      */
    int rts_pin;                                 /**< RTS pin, or UART_PIN_NO_CHANGE.     */
    int cts_pin;                                 /**< CTS pin, or UART_PIN_NO_CHANGE.     */
    int baud_rate;                               /**< Baud rate (default 115200).         */
    bool install_driver;                         /**< If true, install the UART driver;
                                                      if false, assume it is already
                                                      installed (e.g. by the console).   */
    size_t rx_buffer_size;                       /**< UART RX ring buffer (bytes).        */
    size_t tx_buffer_size;                       /**< UART TX ring buffer (bytes), 0 for
                                                      blocking writes. Auto-promoted to
                                                      at least 256 bytes when
                                                      `share_with_console` is true so
                                                      log output through the driver
                                                      cannot block the UART consumer. */
    int task_priority;                           /**< FreeRTOS task priority.             */
    size_t task_stack_size;                      /**< FreeRTOS task stack (bytes).        */
    int task_core_id;                            /**< Core to pin task to, or
                                                      tskNO_AFFINITY (-1).                */
    provisioner_credentials_cb_t on_credentials; /**< Required.             */
    void* user_ctx;                              /**< Opaque pointer passed to callback.  */
    bool share_with_console;                     /**< If true, sniff `<<PROV...>>` frames
                                                      out of the byte stream and forward
                                                      everything else to `stdin` so the
                                                      IDF console can keep using the same
                                                      UART. Implies `install_driver=true`
                                                      (auto-promoted) and that no other
                                                      code installs or reads the UART
                                                      driver. See header comments for
                                                      details.                           */
    /**
     * Optional NUL-terminated human-readable device name (e.g. "Kitchen
     * Caller ID"). When set, the firmware advertises it to the web page
     * after a probe via `<<PROV:ID <name_b64>>>`, so the user can see
     * which device they are provisioning. May be NULL or "" to omit. The
     * pointer must remain valid for the lifetime of the provisioner.
     * Names longer than 64 bytes are silently truncated.
     */
    const char* device_name;
} provisioner_uart_config_t;

/** Static initializer with safe defaults (fill in `on_credentials`). */
#define PROVISIONER_UART_CONFIG_DEFAULT()                                                          \
((provisioner_uart_config_t){                                                                  \
    .uart_num = (uart_port_t)CONFIG_PROVISIONER_DEFAULT_UART_NUM,                              \
    .tx_pin = UART_PIN_NO_CHANGE,                                                              \
    .rx_pin = UART_PIN_NO_CHANGE,                                                              \
    .rts_pin = UART_PIN_NO_CHANGE,                                                             \
    .cts_pin = UART_PIN_NO_CHANGE,                                                             \
    .baud_rate = CONFIG_PROVISIONER_DEFAULT_BAUD_RATE,                                         \
    .install_driver = true,                                                                    \
    .rx_buffer_size = 1024,                                                                    \
    .tx_buffer_size = 0,                                                                       \
    .task_priority = CONFIG_PROVISIONER_DEFAULT_TASK_PRIORITY,                                 \
    .task_stack_size = CONFIG_PROVISIONER_DEFAULT_TASK_STACK,                                  \
    .task_core_id = -1,                                                                        \
    .on_credentials = NULL,                                                                    \
    .user_ctx = NULL,                                                                          \
    .share_with_console = false,                                                               \
    .device_name = NULL,                                                                       \
})

/**
 * Start the provisioner: install (or attach to) the given UART, spawn a
 * background task that watches for the protocol, and call the configured
 * callback when valid credentials arrive.
 *
 * @param[in]  cfg  Non-NULL configuration. cfg->on_credentials must be set.
 * @param[out] out  Optional. Receives a handle that can later be passed to
 *                  provisioner_stop().
 *
 * @return ESP_OK on success, or an esp_err_t describing the failure.
 */
esp_err_t provisioner_start_uart(const provisioner_uart_config_t* cfg,
                                 provisioner_handle_t* out);

/**
 * Stop a previously started provisioner. Joins its task, releases any
 * resources allocated by the component (the UART driver itself is only
 * uninstalled if `install_driver` was true at start). Returns
 * ESP_ERR_TIMEOUT without freeing the handle if the task or shared-console
 * readers do not quiesce in time; callers may retry later.
 */
esp_err_t provisioner_stop(provisioner_handle_t h);

#ifdef __cplusplus
}
#endif

#endif // PROV_COP_PROVISIONER_H
