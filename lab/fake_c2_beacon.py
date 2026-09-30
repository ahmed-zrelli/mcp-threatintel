"""Scenario A: hold a TCP connection open to the "C2" IP listed in local_iocs.

    python lab/fake_c2_beacon.py [ip] [port]

Default 9.9.9.9:443. It only opens a connection and waits; it sends nothing.
"""

import os
import socket
import sys
import time

ip = sys.argv[1] if len(sys.argv) > 1 else "9.9.9.9"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

s = socket.create_connection((ip, port), timeout=10)
print(f"beacon PID {os.getpid()} connected to {ip}:{port}; waiting (Ctrl+C to stop)")
try:
    while True:
        time.sleep(30)
except KeyboardInterrupt:
    pass
