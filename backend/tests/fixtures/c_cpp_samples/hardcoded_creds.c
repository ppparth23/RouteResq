#include <stdio.h>
#include <string.h>

// VULNERABILITY: Hardcoded Wi-Fi credentials in firmware (CWE-798 / CWE-312)
static const char *WIFI_SSID = "CorpGuestWiFi";
static const char *WIFI_PASSWORD = "SuperSecretPassword123!";

void connect_to_network() {
    printf("Connecting to SSID: %s with pass: %s\n", WIFI_SSID, WIFI_PASSWORD);
}
