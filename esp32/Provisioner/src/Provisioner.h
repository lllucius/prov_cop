// Provisioner.h - drop-in Wi-Fi provisioning component for ESP32.
//
// Listens on a Serial stream for a small framed protocol spoken by the
// companion web page (Web Serial). When valid SSID/password values arrive,
// they are passed to a user-supplied callback. The callback returns true on
// success (e.g. Wi-Fi connected) or false on failure; the result is reported
// back to the web page.
//
// Wire protocol (ASCII, line-terminated with '\n'):
//
//   Web -> ESP   <<PROV?>>
//   ESP -> Web   <<PROV!>>
//   Web -> ESP   <<PROV:SET <ssid_b64> <pass_b64> <crc16_hex>>>
//   ESP -> Web   <<PROV:OK>>
//   ESP -> Web   <<PROV:ERR <reason>>>
//
// The CRC is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection,
// no xorout) computed over the ASCII string "<ssid_b64> <pass_b64>" (the two
// base64 strings joined by exactly one space).
//
// Usage:
//
//   #include <Provisioner.h>
//
//   Provisioner provisioner;
//
//   bool onCreds(const String& ssid, const String& password) {
//     WiFi.begin(ssid.c_str(), password.c_str());
//     // ...wait for connect...
//     return WiFi.status() == WL_CONNECTED;
//   }
//
//   void setup() {
//     Serial.begin(115200);
//     provisioner.begin(Serial, onCreds);
//   }
//
//   void loop() {
//     provisioner.poll();
//     // ...your code...
//   }

#ifndef PROV_COP_PROVISIONER_H
#define PROV_COP_PROVISIONER_H

#include <Arduino.h>

class Provisioner {
public:
  // Callback signature. Return true on success, false on failure.
  // The reason string (max ~32 chars, no spaces, no '>') is reported back
  // to the web page on failure; it may be left empty.
  typedef bool (*CredentialsCallback)(const String& ssid,
                                      const String& password);

  Provisioner();

  // Bind to a stream (typically Serial) and a callback.
  // Safe to call again to rebind.
  void begin(Stream& io, CredentialsCallback cb);

  // Must be called frequently from loop(). Non-blocking.
  void poll();

  // If true, the component will not echo or interfere with bytes that are
  // not part of its protocol. (Default true.)
  void setQuiet(bool quiet) { _quiet = quiet; }

  // Override the default failure reason returned when the callback returns
  // false without setting one explicitly. Default: "callback".
  void setDefaultFailureReason(const String& r) { _defaultFail = r; }

private:
  // Maximum size of one inbound line. SET line with two base64-encoded
  // strings (max ~44 + ~88 chars) plus framing easily fits in 256 bytes.
  static const size_t kLineMax = 320;

  // Wi-Fi 802.11 limits: SSID is up to 32 octets; WPA-PSK passphrase is
  // 8..63 ASCII characters. We accept 0..63 here so an empty password is
  // also valid (open network) and let the caller reject too-short PSKs.
  static const size_t kMaxSsidLen = 32;
  static const size_t kMaxPassLen = 63;

  Stream*              _io;
  CredentialsCallback  _cb;
  char                 _line[kLineMax];
  size_t               _len;
  bool                 _overflow;
  bool                 _quiet;
  String               _defaultFail;

  void handleLine(const char* line);
  void handleSet(const char* args);
  void sendLine(const char* s);

  static uint16_t crc16ccitt(const char* data, size_t len);
  // Base64 decode using mbedtls (bundled with Arduino-ESP32). Returns true on
  // success and writes decoded bytes to `out` (which is resized accordingly).
  static bool base64Decode(const char* in, size_t inLen, String& out);
};

#endif // PROV_COP_PROVISIONER_H
