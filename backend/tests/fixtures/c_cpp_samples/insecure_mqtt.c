#include <stdio.h>

// VULNERABILITY: Plaintext unencrypted MQTT communication (CWE-319)
void init_mqtt_telemetry() {
    const char *mqtt_broker = "mqtt://broker.hivemq.com:1883";
    printf("Connecting to unencrypted broker: %s\n", mqtt_broker);
}
