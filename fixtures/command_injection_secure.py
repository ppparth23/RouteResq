"""Test fixture demonstrating secure command execution without shell."""

import shlex
import subprocess

def run_network_check(target_host):
    # Secure subprocess invocation with argument array and shell=False
    cmd = ["ping", "-c", "1", target_host]
    return subprocess.run(cmd, shell=False, check=True, capture_output=True)
