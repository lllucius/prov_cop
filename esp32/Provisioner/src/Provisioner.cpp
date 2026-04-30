// Provisioner.cpp - see Provisioner.h for documentation.

#include "Provisioner.h"

#include <string.h>
#include <mbedtls/base64.h>

namespace {
  // Frame markers and tokens.
  const char kProbe[]   = "<<PROV?>>";
  const char kReady[]   = "<<PROV!>>";
  const char kSetPfx[]  = "<<PROV:SET ";
  const char kEndMark[] = ">>";
  const char kAckOk[]   = "<<PROV:OK>>";
  const char kAckErrP[] = "<<PROV:ERR ";
}

Provisioner::Provisioner()
  : _io(nullptr),
    _cb(nullptr),
    _len(0),
    _overflow(false),
    _quiet(true),
    _defaultFail("callback") {}

void Provisioner::begin(Stream& io, CredentialsCallback cb) {
  _io  = &io;
  _cb  = cb;
  _len = 0;
  _overflow = false;
}

void Provisioner::poll() {
  if (_io == nullptr) return;

  while (_io->available() > 0) {
    int c = _io->read();
    if (c < 0) break;

    if (c == '\r') continue;
    if (c == '\n') {
      if (_overflow) {
        // Line was too long; drop it silently.
        _len = 0;
        _overflow = false;
        continue;
      }
      _line[_len] = '\0';
      // Only act on lines that look like our protocol; everything else is
      // ignored so that this component can co-exist with other Serial output.
      if (_len >= 4 && _line[0] == '<' && _line[1] == '<') {
        handleLine(_line);
      }
      _len = 0;
      continue;
    }

    if (_len + 1 >= kLineMax) {
      _overflow = true;
      continue;
    }
    _line[_len++] = (char)c;
  }
}

void Provisioner::handleLine(const char* line) {
  if (strcmp(line, kProbe) == 0) {
    sendLine(kReady);
    return;
  }
  if (strncmp(line, kSetPfx, sizeof(kSetPfx) - 1) == 0) {
    // Extract the body between "<<PROV:SET " and ">>".
    const char* body = line + (sizeof(kSetPfx) - 1);
    size_t bodyLen = strlen(body);
    if (bodyLen < 2 || body[bodyLen - 1] != '>' || body[bodyLen - 2] != '>') {
      sendLine("<<PROV:ERR malformed>>");
      return;
    }
    // Make a mutable copy without the trailing ">>".
    char args[kLineMax];
    size_t argsLen = bodyLen - 2;
    if (argsLen >= sizeof(args)) {
      sendLine("<<PROV:ERR toolong>>");
      return;
    }
    memcpy(args, body, argsLen);
    args[argsLen] = '\0';
    handleSet(args);
    return;
  }
  // Other framed lines are ignored.
}

void Provisioner::handleSet(const char* args) {
  // args is "ssid_b64 pass_b64 crc16hex" (pass_b64 may be empty for open Wi-Fi).
  // We split on the LAST two spaces so a base64 string (which never contains
  // spaces) is unambiguously parsed.
  const char* s1 = strchr(args, ' ');
  if (!s1) { sendLine("<<PROV:ERR fields>>"); return; }
  const char* s2 = strchr(s1 + 1, ' ');
  if (!s2) { sendLine("<<PROV:ERR fields>>"); return; }
  // Make sure there are no further spaces (the format is fixed-arity).
  if (strchr(s2 + 1, ' ') != nullptr) {
    sendLine("<<PROV:ERR fields>>");
    return;
  }

  size_t ssidLen = (size_t)(s1 - args);
  size_t passLen = (size_t)(s2 - (s1 + 1));
  const char* crcStr = s2 + 1;

  // CRC is computed over "ssid_b64 pass_b64".
  size_t crcInputLen = (size_t)(s2 - args);
  uint16_t expected = crc16ccitt(args, crcInputLen);

  // Parse 4-hex-digit CRC.
  if (strlen(crcStr) != 4) { sendLine("<<PROV:ERR crc>>"); return; }
  uint16_t got = 0;
  for (int i = 0; i < 4; i++) {
    char ch = crcStr[i];
    uint8_t v;
    if      (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'A' && ch <= 'F') v = 10 + (ch - 'A');
    else if (ch >= 'a' && ch <= 'f') v = 10 + (ch - 'a');
    else { sendLine("<<PROV:ERR crc>>"); return; }
    got = (got << 4) | v;
  }
  if (got != expected) {
    sendLine("<<PROV:ERR crc>>");
    return;
  }

  String ssid;
  String pass;
  if (!base64Decode(args, ssidLen, ssid)) {
    sendLine("<<PROV:ERR b64ssid>>");
    return;
  }
  if (passLen == 0) {
    pass = "";
  } else if (!base64Decode(s1 + 1, passLen, pass)) {
    sendLine("<<PROV:ERR b64pass>>");
    return;
  }

  if (ssid.length() == 0 || ssid.length() > kMaxSsidLen ||
      pass.length() > kMaxPassLen) {
    sendLine("<<PROV:ERR length>>");
    return;
  }

  if (_cb == nullptr) {
    sendLine("<<PROV:ERR nocallback>>");
    return;
  }

  bool ok = _cb(ssid, pass);
  if (ok) {
    sendLine(kAckOk);
  } else {
    String reason = _defaultFail;
    // Sanitise: tokens must not contain spaces or '>'.
    for (size_t i = 0; i < reason.length(); i++) {
      char c = reason[i];
      if (c == ' ' || c == '>' || c == '\n' || c == '\r') reason[i] = '_';
    }
    if (reason.length() == 0) reason = "fail";
    String msg = String(kAckErrP) + reason + ">>";
    sendLine(msg.c_str());
  }
}

void Provisioner::sendLine(const char* s) {
  if (!_io) return;
  _io->print(s);
  _io->print('\n');
  _io->flush();
}

uint16_t Provisioner::crc16ccitt(const char* data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= ((uint16_t)(uint8_t)data[i]) << 8;
    for (int b = 0; b < 8; b++) {
      if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
      else              crc = (crc << 1);
    }
  }
  return crc;
}

bool Provisioner::base64Decode(const char* in, size_t inLen, String& out) {
  // First call with a NULL output to get the required size.
  size_t needed = 0;
  int rc = mbedtls_base64_decode(nullptr, 0, &needed,
                                 (const unsigned char*)in, inLen);
  // rc is MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL when needed > 0; treat that
  // as success for sizing. Any other non-zero is a real error.
  if (rc != 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    return false;
  }
  if (needed == 0) {
    // Empty input decodes to empty output.
    out = "";
    return true;
  }
  // Decode into a temporary buffer, then copy into the String as a NUL-
  // terminated C string. (Wi-Fi SSIDs/passwords are byte strings; we do not
  // expect embedded NULs and the ESP32 Wi-Fi APIs take C strings anyway.)
  unsigned char* buf = (unsigned char*)malloc(needed + 1);
  if (!buf) return false;
  size_t written = 0;
  rc = mbedtls_base64_decode(buf, needed, &written,
                             (const unsigned char*)in, inLen);
  if (rc != 0) {
    free(buf);
    return false;
  }
  buf[written] = '\0';
  out = String((const char*)buf);
  free(buf);
  return true;
}
