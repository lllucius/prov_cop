# prov_cop

A tiny, accessible Wi-Fi provisioning system for ESP32 boards.

It has two parts:

1. **`index.html`** — a single self-contained web page that uses the
   [Web Serial API](https://developer.mozilla.org/docs/Web/API/Web_Serial_API)
   to send a Wi-Fi SSID and password to an ESP32 over its USB serial
   adapter. Designed for novices and fully usable with the JAWS screen
   reader (and other AT) using semantic HTML, real `<label>`s,
   `aria-live` regions, and visible focus styles.

2. **`provisioner/`** — a drop-in **ESP-IDF v6** component that
   sits in the background watching for the provisioning protocol on a
   UART (typically the one wired to the on-board USB-serial bridge).
   When valid credentials arrive, it hands them to a callback in the
   main project and reports success/failure back to the web page.

## Using the web page

The Web Serial API requires a Chromium-based browser (Chrome / Edge) on
desktop, and a secure context. The simplest options are:

- Open `index.html` from a web server reachable as `https://...`, or
- Serve it locally:

  ```sh
  python3 -m http.server 8000 --directory .
  # then open http://localhost:8000/
  ```

  `http://localhost` is treated as a secure context, so Web Serial works.

The page itself walks the user through three steps: plug in the board,
fill in the SSID and password, then choose **Send to ESP32**. The
browser's serial-port chooser appears, the user picks the ESP32, and the
status region announces progress and the final result.

## Using the ESP32 component

The component targets **ESP-IDF v6**. Add it to your project as a
component (e.g. copy or symlink `provisioner/` into your project's
`components/` directory, or reference it through
`EXTRA_COMPONENT_DIRS`), then in your application:

```c
#include "provisioner.h"

static bool on_creds(const char *ssid, const char *password,
                     char *err_out, size_t err_out_len, void *ctx) {
    wifi_config_t wc = { 0 };
    strlcpy((char *)wc.sta.ssid,     ssid,     sizeof wc.sta.ssid);
    strlcpy((char *)wc.sta.password, password, sizeof wc.sta.password);
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    esp_wifi_connect();
    /* ...wait for IP_EVENT_STA_GOT_IP... */
    return true;     // -> <<PROV:OK>>; return false for <<PROV:ERR ...>>
}

void app_main(void) {
    provisioner_uart_config_t cfg = PROVISIONER_UART_CONFIG_DEFAULT();
    cfg.on_credentials = on_creds;
    cfg.device_name    = "Kitchen Caller ID";  // shown in the web page
    ESP_ERROR_CHECK(provisioner_start_uart(&cfg, NULL));
}
```

When `device_name` is set, the web page displays
"Connected to *Kitchen Caller ID*." right under the status line so the
user can confirm which board they are talking to.

A complete project is in
[`provisioner/examples/basic/`](provisioner/examples/basic/),
and a second one demonstrating
[`share_with_console`](provisioner/examples/shared_console/) on the
same UART as the IDF console:

```sh
cd provisioner/examples/basic
idf.py set-target esp32
idf.py build flash monitor
```

Defaults (UART port, baud, task stack/priority) are set through
`menuconfig` under **Provisioner**.

The component only reacts to lines that begin with `<<` and look like
its own framed messages, so it co-exists peacefully with `ESP_LOGx`
output from the rest of your project on the same UART.

> **Note on UART sharing.** On most ESP32 boards UART0 is wired to the
> on-board USB-serial bridge — that is what the web page connects to.
> The default IDF console also uses UART0. There are two ways to handle
> this:
>
> - **Dedicated UART or no console.** Set `CONFIG_ESP_CONSOLE_NONE=y` /
>   `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y` so the IDF console does not
>   claim UART0, or pick a separate UART (e.g. `UART_NUM_1` with explicit
>   pins) for the provisioner.
> - **Share the UART with the IDF console.** Set
>   `cfg.share_with_console = true`. The provisioner will install the
>   UART driver itself, sniff `<<PROV…>>` frames out of the byte stream,
>   and forward everything else to a redirected `stdin` so the IDF
>   console (or any code reading `stdin`) keeps working on the same
>   wire. Standard output is unchanged. Call `provisioner_start_uart()`
>   *before* starting any console REPL or reading from `stdin`. This
>   mode is incompatible with REPLs that re-install the UART driver
>   themselves (e.g. `esp_console_new_repl_uart()`); for those, prefer a
>   dedicated UART.

## Wire protocol

All messages are ASCII, terminated by a single `\n`. Frame markers
`<<...>>` make them easy to recognise inside an otherwise noisy serial
stream.

| Direction    | Message                                                  | Meaning                            |
|--------------|----------------------------------------------------------|------------------------------------|
| Web → ESP32  | `<<PROV?>>`                                              | Attention probe                    |
| ESP32 → Web  | `<<PROV!>>`                                              | Ready to receive credentials       |
| ESP32 → Web  | `<<PROV:ID <name_b64>>>`                                 | Optional human-readable device name|
| Web → ESP32  | `<<PROV:SET <ssid_b64> <pass_b64> <crc16_hex>>>`         | Set credentials                    |
| ESP32 → Web  | `<<PROV:OK>>`                                            | Credentials accepted               |
| ESP32 → Web  | `<<PROV:ERR <reason>>>`                                  | Failure (`reason` is a short token)|

- `ssid_b64` and `pass_b64` are standard Base64 of the UTF-8 bytes of
  the SSID and password. The decoded SSID must be 1..32 bytes, the
  decoded password must be 0..63 bytes, and embedded NUL bytes are
  rejected. `pass_b64` may be empty for an open network.
- `crc16_hex` is four uppercase hex digits of CRC-16/CCITT-FALSE
  (polynomial `0x1021`, initial value `0xFFFF`, no reflection, no
  xorout) computed over the literal ASCII string
  `"<ssid_b64> <pass_b64>"` (the two Base64 strings joined by exactly
  one space).
- After `<<PROV!>>` the ESP32 may emit a single
  `<<PROV:ID <name_b64>>>` line whose payload is the Base64-encoded
  human-readable device name set by the firmware (`cfg.device_name`).
  The web page decodes it and shows "Connected to *name*." so the user
  can confirm which device they are provisioning. Older firmware that
  doesn't emit this line still works.
- Base64 and CRC framing are for transport robustness, not secrecy or
  authentication. Treat provisioning as a local serial-access operation.

The web page sends `<<PROV?>>` repeatedly until it sees `<<PROV!>>`
(timeout: 8 s). After sending `<<PROV:SET ...>>` it waits up to 30 s
for `<<PROV:OK>>` or `<<PROV:ERR ...>>`.

## Accessibility notes

- Every input has a real, visible `<label>` and an associated
  `aria-describedby` hint.
- Form controls are grouped in a `<fieldset>` with a `<legend>`.
- The page has a single `<h1>` and stepwise `<h2>` headings, so screen
  reader users can navigate by heading.
- Status updates go to a `role="status"` `aria-live="polite"` region;
  errors go to a separate `role="alert"` `aria-live="assertive"` region
  and receive focus on failure so the message is not missed.
- Focus styles are explicit and high-contrast.
- Colour is never the only signal — every state change is also
  announced as text.
- The page works with the keyboard alone.

## Repository layout

```
index.html                                 Provisioning web page
provisioner/                               ESP-IDF v6 component
  CMakeLists.txt                           idf_component_register
  Kconfig                                  menuconfig defaults
  idf_component.yml                        Component manifest
  include/provisioner.h                    Public C API
  src/provisioner.c                        ESP-IDF / UART glue
  src/provisioner_proto.[ch]               Transport-agnostic protocol parser
  examples/basic/                          Standalone example project
  examples/shared_console/                 Provisioner sharing UART0 with
                                           the IDF console
  test/host/                               Host-side unit tests for the
                                           protocol parser (no IDF
                                           required; run with `cmake -S
                                           provisioner/test/host -B
                                           build && cmake --build build &&
                                           ctest --test-dir build`)
```
