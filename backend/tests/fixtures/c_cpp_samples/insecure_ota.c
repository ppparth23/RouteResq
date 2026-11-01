#include <stdio.h>

typedef struct {
    int handle;
} esp_ota_handle_t;

// VULNERABILITY: Unsigned OTA firmware update (CWE-494)
void flash_firmware_update(const void *partition_desc) {
    esp_ota_handle_t update_handle;
    esp_ota_begin(partition_desc, 0, &update_handle);
    printf("Flashing unverified firmware stream...\n");
}
