# step1_port_check.py
# Checks if port 8000 is open on your own computer

import socket

HOST = "127.0.0.1"   # "me" (your computer)
PORT = 8000          # the door we opened with http.server

def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

if __name__ == "__main__":
    if is_port_open(HOST, PORT):
        print(f"✅ OPEN: {HOST}:{PORT}")
    else:
        print(f"❌ CLOSED: {HOST}:{PORT}")
