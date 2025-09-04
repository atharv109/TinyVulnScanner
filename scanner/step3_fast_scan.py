# step3_fast_scan.py
# Fast port scanner using threads (beginner-friendly concurrency)

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "127.0.0.1"
# Try a wider set so you see speed-up. You can change to range(1, 1025) later.
PORTS = list(range(1, 1025))  # scans ports 1..1024

MAX_WORKERS = 200   # how many ports to test at the same time (tweak this)
TIMEOUT = 0.8       # seconds per connection attempt

def is_port_open(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

def scan_ports(host: str, ports: list[int]) -> list[int]:
    open_ports = []
    # Thread pool = send many workers to test ports in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = {executor.submit(is_port_open, host, p): p for p in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                # Ignore rare socket errors; treat as closed
                pass
    return sorted(open_ports)

if __name__ == "__main__":
    print(f"Scanning {HOST} with up to {MAX_WORKERS} parallel checks...")
    open_ports = scan_ports(HOST, PORTS)
    if open_ports:
        print("✅ Open ports:", ", ".join(map(str, open_ports)))
    else:
        print("❌ No open ports found in your list.")

