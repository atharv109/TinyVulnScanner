# step4_banner_grab.py
# Identify what's running on each open port by grabbing a short banner

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "127.0.0.1"
PORTS = [22, 80, 443, 8000, 8080,5055]  # you can change to range(1, 1025) later

MAX_WORKERS = 200
CONNECT_TIMEOUT = 1.0
READ_TIMEOUT = 1.0
READ_BYTES = 512  # small, polite

def is_port_open(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

def read_some(sock: socket.socket, nbytes: int = READ_BYTES) -> bytes:
    sock.settimeout(READ_TIMEOUT)
    try:
        data = sock.recv(nbytes)
        return data or b""
    except Exception:
        return b""

def banner_http(host: str, port: int) -> str:
    """Send a tiny HTTP request and read response headers/body start."""
    s = socket.socket()
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
        s.sendall(req)
        data = read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except:
            pass

def banner_ssh(host: str, port: int) -> str:
    """Most SSH servers send a banner first, just read it."""
    s = socket.socket()
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        data = read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except:
            pass

def banner_generic(host: str, port: int) -> str:
    """Fallback: connect, then read whatever comes back (if anything)."""
    s = socket.socket()
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        # Some services talk first; others need a probe. We just listen briefly.
        data = read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except:
            pass

def grab_banner(host: str, port: int) -> tuple[int, str]:
    # Choose a probe based on the port (very simple heuristics)
    if port in (80, 8080, 8000, 8888, 8443):
        b = banner_http(host, port)
    elif port == 22:
        b = banner_ssh(host, port)
    else:
        b = banner_generic(host, port)

    return port, b

def open_ports(host: str, ports: list[int]) -> list[int]:
    # Quick parallel open-check like Step 3
    result = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut = {ex.submit(is_port_open, host, p): p for p in ports}
        for f in as_completed(fut):
            p = fut[f]
            try:
                if f.result():
                    result.append(p)
            except:
                pass
    return sorted(result)

if __name__ == "__main__":
    print(f"Scanning {HOST} for open ports...")
    opens = open_ports(HOST, PORTS)
    if not opens:
        print("No open ports from your list.")
        exit(0)

    print("Open ports:", ", ".join(map(str, opens)))
    print("\nGrabbing banners...")
    with ThreadPoolExecutor(max_workers=min(len(opens), MAX_WORKERS)) as ex:
        fut = {ex.submit(grab_banner, HOST, p): p for p in opens}
        for f in as_completed(fut):
            port, banner = f.result()
            print(f"\n--- {HOST}:{port} ---")
            if banner:
                # Show only first few lines to keep it tidy
                lines = banner.splitlines()
                preview = "\n".join(lines[:6])
                print(preview)
                if len(lines) > 6:
                    print("... (truncated)")
            else:
                print("(no banner or not readable with our simple probe)")
