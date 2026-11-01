#include <stdio.h>
#include <string.h>

void process_client_data(const char *user_input) {
    char stack_buffer[64];
    // VULNERABILITY: Stack buffer overflow (CWE-120 / CWE-121)
    strcpy(stack_buffer, user_input);
    printf("Processed input: %s\n", stack_buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_client_data(argv[1]);
    }
    return 0;
}
