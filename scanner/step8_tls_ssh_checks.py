# step8_tls_ssh_checks.py
# Quick HTTPS/TLS & SSH checks (version, cipher bits, simple cert sanity, SSH banner)

import socket, ssl, datetime, re

# ---- Choose targets (edit these) ----
TLS_TARGETS = [("example.com", 443)]          # add ("127.0.0.1", 8443) if you run a local HTTPS service
SSH_TARGETS = []             # change/remove if you don't run local SSH

TIMEOUT = 3.0

def check_tls(host: str, port: int) -> dict:
    """
    Try verified TLS first (so we can read expiry, issuer, etc.).
    If that fails, fall back to unverified and at least confirm a cert was sent.
    """
    result = {"host": host, "port": port, "ok": False, "notes": [], "findings": []}

    def _summarize(version, cipher_tuple):
        if version:
            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                result["findings"].append(("HIGH", f"Weak TLS version negotiated: {version} (use TLS 1.2+)."))
            elif version == "TLSv1.2":
                result["notes"].append("Negotiated TLS 1.2 (acceptable, 1.3 preferred).")
            elif version == "TLSv1.3":
                result["notes"].append("Negotiated TLS 1.3 (good).")
            else:
                result["notes"].append(f"Negotiated {version}.")
        if cipher_tuple:
            name, _, bits = cipher_tuple
            result.update({"cipher": name, "cipher_bits": bits})
            if bits is None or bits < 128:
                result["findings"].append(("MEDIUM", f"Weak cipher strength: {name} ({bits} bits)."))

    # --- Attempt 1: VERIFIED (preferred)
    try:
        ctx1 = ssl.create_default_context()              # CERT_REQUIRED by default
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with ctx1.wrap_socket(raw, server_hostname=host) as tls:
                result["ok"] = True
                result["tls_version"] = tls.version()
                _summarize(result["tls_version"], tls.cipher())
                cert_dict = tls.getpeercert()            # full dict in verified mode
                if cert_dict:
                    not_after = cert_dict.get("notAfter")
                    if not_after:
                        try:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.datetime.utcnow()).days
                            if days < 0:
                                result["findings"].append(("HIGH", "Certificate is EXPIRED."))
                            elif days <= 30:
                                result["findings"].append(("MEDIUM", f"Certificate expires soon (~{days} days)."))
                            else:
                                result["notes"].append(f"Certificate valid; ~{days} days left.")
                        except Exception:
                            result["notes"].append("Could not parse certificate expiry.")
                else:
                    result["notes"].append("Verified handshake but no cert details returned (unusual).")
                return result
    except Exception as e_verified:
        result["notes"].append(f"Verified handshake failed: {e_verified}")

    # --- Attempt 2: UNVERIFIED (fallback, still capture binary cert)
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with ctx2.wrap_socket(raw, server_hostname=host) as tls:
                result["ok"] = True
                result["tls_version"] = tls.version()
                _summarize(result["tls_version"], tls.cipher())
                der = tls.getpeercert(binary_form=True)  # returns bytes even when unverified
                if der and isinstance(der, (bytes, bytearray)):
                    result["notes"].append("Peer certificate was presented (unverified).")
                else:
                    result["findings"].append(("MEDIUM", "No peer certificate returned."))
                return result
    except Exception as e_unverified:
        result["error"] = f"Unverified handshake failed: {e_unverified}"

    return result


def check_ssh(host: str, port: int) -> dict:
    """Grab SSH banner and flag obviously old OpenSSH versions."""
    result = {"host": host, "port": port, "ok": False, "banner": "", "findings": [], "notes": []}
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            banner = s.recv(256).decode("latin-1", "ignore").strip()
        result.update({"ok": True, "banner": banner})

        # Typical banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
        m = re.search(r"OpenSSH[_-]([\d.]+)", banner)
        if m:
            ver_text = m.group(1)
            # Compare to 7.4 (very rough)
            def vtuple(v): return tuple(int(x) for x in v.split(".") if x.isdigit())
            if vtuple(ver_text) < vtuple("7.4"):
                result["findings"].append(("MEDIUM",
                                           f"Old OpenSSH version detected ({ver_text}). Consider upgrading (>=7.4)."))
            else:
                result["notes"].append(f"OpenSSH {ver_text} detected.")
        else:
            if banner:
                result["notes"].append("SSH banner detected (non-OpenSSH or unparsed).")
            else:
                result["findings"].append(("INFO", "No SSH banner received; server may be silent until we speak first."))

    except Exception as e:
        result["error"] = str(e)

    return result


def print_tls_result(r: dict):
    target = f"{r['host']}:{r['port']}"
    if not r.get("ok"):
        print(f"TLS  ✖  {target}  error: {r.get('error')}")
        return
    print(f"TLS  ✔  {target}  version={r.get('tls_version')}  cipher={r.get('cipher')} ({r.get('cipher_bits')} bits)")
    for sev, msg in r.get("findings", []):
        print(f"   [{sev}] {msg}")
    for note in r.get("notes", []):
        print(f"   [note] {note}")


def print_ssh_result(r: dict):
    target = f"{r['host']}:{r['port']}"
    if not r.get("ok"):
        print(f"SSH  ✖  {target}  error: {r.get('error')}")
        return
    print(f"SSH  ✔  {target}  banner={r.get('banner')}")
    for sev, msg in r.get("findings", []):
        print(f"   [{sev}] {msg}")
    for note in r.get("notes", []):
        print(f"   [note] {note}")


if __name__ == "__main__":
    print("=== TLS checks ===")
    for h, p in TLS_TARGETS:
        print_tls_result(check_tls(h, p))

    print("\n=== SSH checks ===")
    for h, p in SSH_TARGETS:
        print_ssh_result(check_ssh(h, p))
