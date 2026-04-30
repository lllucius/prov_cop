// Basic example: receive Wi-Fi credentials over USB serial from the
// companion provisioning web page and connect to the network.
//
// 1. Flash this sketch to your ESP32.
// 2. Open the index.html provisioning page in Chrome or Edge over https://
//    or http://localhost.
// 3. Click "Send to ESP32", pick this board's serial port, and enter your
//    Wi-Fi details.

#include <Arduino.h>
#include <WiFi.h>
#include <Provisioner.h>

Provisioner provisioner;

static bool onCredentials(const String& ssid, const String& password) {
  // Print to Serial AFTER the ack travels back to the browser. To keep the
  // browser session quiet, we only log once provisioning is complete, but
  // for a basic demo we just log here too -- the web page ignores anything
  // that is not a framed <<PROV:...>> line.
  Serial.print("[prov] connecting to SSID: ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), password.c_str());

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) {
    delay(250);
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("[prov] connected, IP: ");
    Serial.println(WiFi.localIP());
    return true;
  }

  Serial.println("[prov] failed to connect");
  // Reported back to the browser as "<<PROV:ERR no_connect>>".
  provisioner.setDefaultFailureReason("no_connect");
  return false;
}

void setup() {
  Serial.begin(115200);
  // Give the host a moment to open the port.
  delay(200);

  provisioner.begin(Serial, onCredentials);
  Serial.println("[prov] ready, waiting for provisioning...");
}

void loop() {
  provisioner.poll();
  // ... your application code here ...
}
