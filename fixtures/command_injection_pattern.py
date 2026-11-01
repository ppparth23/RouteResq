"""Test fixture demonstrating Command Injection patterns without executing."""

import os
import subprocess

def run_network_check(target_host):
    # Command injection via os.system and shell=True
    os.system(f"ping -c 1 {target_host}")
    subprocess.Popen(f"traceroute {target_host}", shell=True)
