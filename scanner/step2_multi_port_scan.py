# step2_multi_port_scan.py
# Scan many ports on localhost and report which are open

import socket

HOST = "127.0.0.1"
PORTS = [21, 22, 80, 443, 8000]  # a few common ones + our test port

def is_port_open(host, port, timeout=1.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except:
        return False
    finally:
        s.close()

if __name__ == "__main__":
    print(f"Scanning {HOST}...\n")
    for port in PORTS:
        if is_port_open(HOST, port):
            print(f"✅ OPEN: {port}")
        else:
            print(f"❌ CLOSED: {port}")
