#include <iostream>
#include <cstdlib>

struct DeviceSession {
    int session_id;
    char token[32];
};

void terminate_session(DeviceSession *session) {
    // Free the allocated memory
    free(session);
    // VULNERABILITY: Use After Free (CWE-416)
    // Accessing member after deallocation
    session->session_id = 0;
    std::cout << "Terminated session: " << session->session_id << std::endl;
}

int main() {
    DeviceSession *s = (DeviceSession *)malloc(sizeof(DeviceSession));
    if (s) {
        s->session_id = 42;
        terminate_session(s);
    }
    return 0;
}
