# prov_cop

A tiny, accessible Wi-Fi provisioning system for ESP32 boards.

It has two parts:

1. **`index.html`** — a single self-contained web page that uses the
   [Web Serial API](https://developer.mozilla.org/docs/Web/API/Web_Serial_API)
   to send a Wi-Fi SSID and password to an ESP32 over its USB serial
   adapter. Designed for novices and fully usable with the JAWS screen
   reader (and other AT) using semantic HTML, real `<label>`s,
   `aria-live` regions, and visible focus styles.

2. **`esp32/Provisioner/`** — a drop-in Arduino library for ESP32 that
   sits in the background watching for the provisioning protocol on a
   `Stream` (typically `Serial`). When valid credentials arrive, it
   hands them to a callback in the main project and reports
   success/failure back to the web page.

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

Copy the `esp32/Provisioner` folder into your Arduino `libraries/`
directory (or your PlatformIO project's `lib/` folder) and add to your
sketch:

```cpp
#include <Provisioner.h>

Provisioner provisioner;

bool onCreds(const String& ssid, const String& password) {
  WiFi.begin(ssid.c_str(), password.c_str());
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(250);
  return WiFi.status() == WL_CONNECTED;
}

void setup() {
  Serial.begin(115200);
  provisioner.begin(Serial, onCreds);
}

void loop() {
  provisioner.poll();   // non-blocking
  // ... your app ...
}
```

A complete sketch is in
[`esp32/Provisioner/examples/Basic/Basic.ino`](esp32/Provisioner/examples/Basic/Basic.ino).

The component only reacts to lines that begin with `<<` and look like
its own framed messages, so it co-exists peacefully with `Serial.print`
debug output from the rest of your project.

## Wire protocol

All messages are ASCII, terminated by a single `\n`. Frame markers
`<<...>>` make them easy to recognise inside an otherwise noisy serial
stream.

| Direction    | Message                                                  | Meaning                            |
|--------------|----------------------------------------------------------|------------------------------------|
| Web → ESP32  | `<<PROV?>>`                                              | Attention probe                    |
| ESP32 → Web  | `<<PROV!>>`                                              | Ready to receive credentials       |
| Web → ESP32  | `<<PROV:SET <ssid_b64> <pass_b64> <crc16_hex>>>`         | Set credentials                    |
| ESP32 → Web  | `<<PROV:OK>>`                                            | Credentials accepted               |
| ESP32 → Web  | `<<PROV:ERR <reason>>>`                                  | Failure (`reason` is a short token)|

- `ssid_b64` and `pass_b64` are standard Base64 of the UTF-8 bytes of
  the SSID and password. `pass_b64` may be empty for an open network.
- `crc16_hex` is four uppercase hex digits of CRC-16/CCITT-FALSE
  (polynomial `0x1021`, initial value `0xFFFF`, no reflection, no
  xorout) computed over the literal ASCII string
  `"<ssid_b64> <pass_b64>"` (the two Base64 strings joined by exactly
  one space).

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
index.html                       Provisioning web page
esp32/Provisioner/
  library.properties             Arduino library manifest
  keywords.txt                   Arduino IDE syntax colouring
  src/Provisioner.h              Public API
  src/Provisioner.cpp            Implementation
  examples/Basic/Basic.ino       Minimal demo sketch
```
