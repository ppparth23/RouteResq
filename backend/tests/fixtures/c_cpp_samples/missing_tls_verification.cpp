#include <iostream>

class WiFiClientSecure {
public:
    void setInsecure() {
        std::cout << "Disabling TLS certificate verification!" << std::endl;
    }
};

void setup_telemetry() {
    WiFiClientSecure client;
    // VULNERABILITY: TLS certificate verification bypass (CWE-295)
    client.setInsecure();
}
