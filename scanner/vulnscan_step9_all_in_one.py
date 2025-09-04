# vulnscan_step9_all_in_one.py
# All-in-one beginner-friendly scanner:
# - Port scan (fast, threaded)
# - Banner grab (HTTP/SSH/generic)
# - Web checks (security headers + simple boolean SQLi)
# - TLS check (version/cipher/cert sanity)
# - SSH check (banner + very rough version flag)
#
# NOTE: Scan only systems you own or have explicit permission to test.

import asyncio, json, datetime, re, socket, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode

import aiohttp

# -------------------- CONFIG: edit to your lab --------------------
HOST_TO_SCAN = "127.0.0.1"
PORTS_TO_SCAN = list(range(1, 1025))            # try 1..1024 (fast with threads)
COMMON_PORTS = [22, 80, 443, 8000, 8080, 8443]  # optional: scan these first

WEB_HOME = "http://127.0.0.1:5055/"
WEB_PRODUCT = "http://127.0.0.1:5055/product"   # expects ?id=

TLS_TARGETS = [("example.com", 443)]            # add your own HTTPS endpoints here
SSH_TARGETS = []                                # e.g., [("127.0.0.1", 22)] if you run ssh

MAX_WORKERS = 200
CONNECT_TIMEOUT = 1.0
READ_TIMEOUT = 1.0
READ_BYTES = 512

# -------------------- PORT SCAN (threads) --------------------
def is_port_open(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

def scan_ports(host: str, ports: list[int]) -> list[int]:
    # Scan "interesting" ones first to feel snappy
    ordered = sorted(set(COMMON_PORTS + ports))
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut = {ex.submit(is_port_open, host, p): p for p in ordered}
        for f in as_completed(fut):
            p = fut[f]
            try:
                if f.result(): open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)

# -------------------- BANNER GRAB --------------------
def _read_some(sock: socket.socket, nbytes: int = READ_BYTES) -> bytes:
    sock.settimeout(READ_TIMEOUT)
    try: return sock.recv(nbytes) or b""
    except Exception: return b""

def banner_http(host: str, port: int) -> str:
    s = socket.socket(); s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
        s.sendall(req)
        data = _read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try: s.close()
        except: pass

def banner_ssh(host: str, port: int) -> str:
    s = socket.socket(); s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        data = _read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try: s.close()
        except: pass

def banner_generic(host: str, port: int) -> str:
    s = socket.socket(); s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        data = _read_some(s)
        return data.decode("latin-1", "ignore").strip()
    except Exception:
        return ""
    finally:
        try: s.close()
        except: pass

def grab_banner(host: str, port: int) -> str:
    if port in (80, 8080, 8000, 8888, 8443):
        return banner_http(host, port)
    elif port == 22:
        return banner_ssh(host, port)
    elif port == 443:
        return "(HTTPS detected: use TLS check for details)"
    else:
        return banner_generic(host, port)

# -------------------- WEB CHECKS --------------------
RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

async def check_security_headers(url: str) -> dict:
    out = {"url": url, "missing": [], "notes": []}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=4, allow_redirects=True) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                for h in RECOMMENDED_HEADERS:
                    if h.lower() not in headers:
                        out["missing"].append(h)
                if urlparse(str(r.url)).scheme == "https":
                    if "strict-transport-security" not in headers:
                        out["missing"].append("Strict-Transport-Security")
                else:
                    out["notes"].append("HSTS (Strict-Transport-Security) only relevant on HTTPS.")
                return out
    except Exception as e:
        return {"url": url, "error": str(e)}

POS_PAYLOAD = "' OR '1'='1"
NEG_PAYLOAD = "' AND '1'='2"

def add_or_replace_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q_pairs = [kv for kv in p.query.split("&") if kv]
    q = {}
    for kv in q_pairs:
        if "=" in kv:
            k, v = kv.split("=", 1)
        else:
            k, v = kv, ""
        q[k] = v
    q[key] = value
    new_q = urlencode(q)
    return p._replace(query=new_q).geturl()

async def _fetch_text(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=5, allow_redirects=True) as r:
            t = await r.text()
            return r.status, t, len(t)
    except Exception:
        return None, None, None

async def test_boolean_sqli(base_url: str, param: str = "id") -> dict:
    u_base = add_or_replace_param(base_url, param, "1")
    u_pos  = add_or_replace_param(base_url, param, "1" + POS_PAYLOAD)
    u_neg  = add_or_replace_param(base_url, param, "1" + NEG_PAYLOAD)
    out = {"tested": {"base": u_base, "pos": u_pos, "neg": u_neg}}

    async with aiohttp.ClientSession() as s:
        s_base, t_base, L_base = await _fetch_text(s, u_base)
        s_pos,  t_pos,  L_pos  = await _fetch_text(s, u_pos)
        s_neg,  t_neg,  L_neg  = await _fetch_text(s, u_neg)

    out["statuses"] = {"base": s_base, "pos": s_pos, "neg": s_neg}
    out["lengths"]  = {"base": L_base, "pos": L_pos, "neg": L_neg}

    length_signal = (
        all(v is not None for v in (L_base, L_pos, L_neg)) and
        (L_pos > L_base) and (L_neg <= L_base)
    )
    content_signal = ("Item A" in (t_pos or "")) and ("No results" in (t_neg or ""))

    out["signals"] = {"length": bool(length_signal), "content": bool(content_signal)}
    out["suspected"] = bool(length_signal or content_signal)
    return out

# -------------------- TLS CHECK --------------------
def check_tls(host: str, port: int) -> dict:
    """
    Try verified TLS first. If that fails, fall back to unverified and confirm a cert was presented.
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

    # Attempt 1: VERIFIED
    try:
        ctx1 = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with ctx1.wrap_socket(raw, server_hostname=host) as tls:
                result["ok"] = True
                result["tls_version"] = tls.version()
                _summarize(result["tls_version"], tls.cipher())
                cert_dict = tls.getpeercert()
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

    # Attempt 2: UNVERIFIED (binary cert)
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with ctx2.wrap_socket(raw, server_hostname=host) as tls:
                result["ok"] = True
                result["tls_version"] = tls.version()
                _summarize(result["tls_version"], tls.cipher())
                der = tls.getpeercert(binary_form=True)
                if der and isinstance(der, (bytes, bytearray)):
                    result["notes"].append("Peer certificate was presented (unverified).")
                else:
                    result["findings"].append(("MEDIUM", "No peer certificate returned."))
                return result
    except Exception as e_unverified:
        result["error"] = f"Unverified handshake failed: {e_unverified}"

    return result

# -------------------- SSH CHECK --------------------
def check_ssh(host: str, port: int) -> dict:
    result = {"host": host, "port": port, "ok": False, "banner": "", "findings": [], "notes": []}
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            banner = s.recv(256).decode("latin-1", "ignore").strip()
        result.update({"ok": True, "banner": banner})

        m = re.search(r"OpenSSH[_-]([\d.]+)", banner)
        if m:
            ver_text = m.group(1)
            def vtuple(v): return tuple(int(x) for x in v.split(".") if x.isdigit())
            if vtuple(ver_text) < vtuple("7.4"):
                result["findings"].append(("MEDIUM", f"Old OpenSSH version detected ({ver_text}). Consider upgrading (>=7.4)."))
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

# -------------------- REPORT ASSEMBLY --------------------
def remediation_for_header(h: str) -> str:
    tips = {
        "Content-Security-Policy": "Add a CSP, e.g. \"default-src 'self'; script-src 'self'\"; avoid 'unsafe-inline'.",
        "X-Content-Type-Options": "Set header: X-Content-Type-Options: nosniff.",
        "X-Frame-Options": "Set header: X-Frame-Options: DENY (or SAMEORIGIN).",
        "Referrer-Policy": "Set header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
        "Strict-Transport-Security": "Serve over HTTPS, then set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
    }
    return tips.get(h, "Add the recommended header with a secure value.")

def sev_rank(s): return {"INFO":0, "LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4}.get(s, 0)

def build_findings(open_ports, banners, headers_res, sqli_res, tls_res_list, ssh_res_list):
    findings = []

    # Open ports + banners
    for p in open_ports:
        b = banners.get(p, "")
        title = f"Open port: {p}"
        ev = b[:300] + ("..." if b and len(b) > 300 else "")
        findings.append({
            "id": f"PORT-{p}",
            "title": title,
            "severity": "INFO",
            "target": f"{HOST_TO_SCAN}:{p}",
            "evidence": ev or "(no banner)",
            "remediation": "Close unused ports or restrict access with a firewall."
        })

    # Missing headers
    if "error" in headers_res:
        findings.append({
            "id": "HDR-ERROR",
            "title": "Could not check security headers",
            "severity": "INFO",
            "target": headers_res.get("url"),
            "evidence": headers_res["error"],
            "remediation": "Verify the URL is reachable."
        })
    else:
        for h in headers_res.get("missing", []):
            findings.append({
                "id": f"HDR-{h}",
                "title": f"Missing security header: {h}",
                "severity": "MEDIUM",
                "target": headers_res.get("url"),
                "evidence": f"{h} not present in HTTP response headers.",
                "remediation": remediation_for_header(h)
            })

    # Boolean SQLi
    if sqli_res:
        statuses = sqli_res.get("statuses", {})
        if any(v == 404 for v in statuses.values()):
            findings.append({
                "id": "SQLI-NOENDPOINT",
                "title": "Product endpoint not found (404)",
                "severity": "INFO",
                "target": sqli_res["tested"]["base"],
                "evidence": f"Statuses: {statuses}",
                "remediation": "Ensure the test endpoint exists. For the demo, run app.py on 127.0.0.1:5055."
            })
        elif sqli_res.get("suspected"):
            findings.append({
                "id": "SQLI-BOOLEAN",
                "title": "Possible boolean-based SQL injection",
                "severity": "HIGH",
                "target": sqli_res["tested"]["base"],
                "evidence": {
                    "tested_urls": sqli_res["tested"],
                    "lengths": sqli_res["lengths"],
                    "signals": sqli_res["signals"]
                },
                "remediation": "Use parameterized queries/prepared statements; validate input; avoid string concatenation; consider ORM/WAF."
            })
        else:
            findings.append({
                "id": "SQLI-NONE",
                "title": "No boolean SQLi behavior detected",
                "severity": "INFO",
                "target": sqli_res["tested"]["base"],
                "evidence": {
                    "tested_urls": sqli_res["tested"],
                    "lengths": sqli_res["lengths"],
                    "signals": sqli_res["signals"]
                },
                "remediation": "Keep using parameterized queries and input validation."
            })

    # TLS results
    for r in tls_res_list:
        target = f"{r['host']}:{r['port']}"
        if not r.get("ok"):
            findings.append({
                "id": f"TLS-{target}-ERR",
                "title": "TLS check failed",
                "severity": "INFO",
                "target": target,
                "evidence": r.get("error") or "; ".join(r.get("notes", [])),
                "remediation": "Confirm the host/port and that it speaks TLS."
            })
        else:
            # notes
            for note in r.get("notes", []):
                findings.append({
                    "id": f"TLS-{target}-NOTE",
                    "title": "TLS observation",
                    "severity": "INFO",
                    "target": target,
                    "evidence": note,
                    "remediation": "Review TLS configuration for modern best practices."
                })
            # findings (with severities)
            for sev, msg in r.get("findings", []):
                findings.append({
                    "id": f"TLS-{target}-ISSUE",
                    "title": "TLS configuration issue",
                    "severity": sev,
                    "target": target,
                    "evidence": msg,
                    "remediation": "Disable legacy protocols/ciphers; use TLS 1.2/1.3; maintain valid certificates."
                })

    # SSH results
    for r in ssh_res_list:
        target = f"{r['host']}:{r['port']}"
        if not r.get("ok"):
            findings.append({
                "id": f"SSH-{target}-ERR",
                "title": "SSH check failed",
                "severity": "INFO",
                "target": target,
                "evidence": r.get("error"),
                "remediation": "Ensure SSH is listening and reachable."
            })
        else:
            findings.append({
                "id": f"SSH-{target}-BANNER",
                "title": "SSH banner",
                "severity": "INFO",
                "target": target,
                "evidence": r.get("banner"),
                "remediation": "Hide detailed banners in production; keep OpenSSH up-to-date."
            })
            for sev, msg in r.get("findings", []):
                findings.append({
                    "id": f"SSH-{target}-ISSUE",
                    "title": "SSH version/config issue",
                    "severity": sev,
                    "target": target,
                    "evidence": msg,
                    "remediation": "Upgrade OpenSSH and follow hardening guides."
                })

    # Sort by severity descending
    findings.sort(key=lambda f: (-sev_rank(f["severity"]), f["id"]))
    return findings

def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def write_html(path: str, data: dict):
    sev_color = {"INFO":"#6b7280","LOW":"#10b981","MEDIUM":"#f59e0b","HIGH":"#ef4444","CRITICAL":"#7f1d1d"}
    def chip(sev):
        c = sev_color.get(sev, "#6b7280")
        return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:12px;font-size:12px;">{sev}</span>'
    rows = []
    for f in data["findings"]:
        ev = f["evidence"]
        if isinstance(ev, dict):
            ev_pre = "<pre>"+json.dumps(ev, indent=2).replace("<","&lt;")+"</pre>"
        else:
            ev_pre = "<pre>"+str(ev).replace("<","&lt;")+"</pre>"
        rows.append(f"""
        <tr>
          <td>{f['id']}</td>
          <td><strong>{f['title']}</strong><div style="margin-top:6px">{chip(f['severity'])}</div></td>
          <td>{f['target']}</td>
          <td>{ev_pre}</td>
          <td>{f['remediation']}</td>
        </tr>
        """)

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Vuln Scan Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b1220;color:#e5e7eb;}}
.container{{max-width:1000px;margin:40px auto;padding:0 16px;}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:14px;box-shadow:0 6px 24px rgba(0,0,0,.25);}}
.hdr{{padding:18px 20px;border-bottom:1px solid #1f2937;}}
.hdr h1{{margin:0;font-size:22px;}}
.meta{{font-size:13px;color:#9ca3af;margin-top:6px}}
.table{{width:100%;border-collapse:collapse}}
th, td{{padding:12px 10px;vertical-align:top;border-top:1px solid #1f2937}}
th{{text-align:left;color:#9ca3af;font-weight:600;}}
.summary{{padding:14px 20px}}
</style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="hdr">
        <h1>Vulnerability Scan Report</h1>
        <div class="meta">
          Generated: {data['generated_at']} &middot; Host scan: {data['target']['host']} &middot; Web: {data['target']['home']} /product
        </div>
      </div>
      <div class="summary">
        Findings: <strong>{len(data['findings'])}</strong>
      </div>
      <div style="padding:0 20px 20px">
        <table class="table">
          <thead>
            <tr><th>ID</th><th>Issue</th><th>Target</th><th>Evidence</th><th>Remediation</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# -------------------- MAIN --------------------
async def run_web_checks():
    headers_res = await check_security_headers(WEB_HOME)
    sqli_res = await test_boolean_sqli(WEB_PRODUCT, param="id")
    return headers_res, sqli_res

def main():
    # 1) Port scan
    print(f"[*] Scanning ports on {HOST_TO_SCAN} ...")
    open_ports = scan_ports(HOST_TO_SCAN, PORTS_TO_SCAN)
    print(f"[+] Open ports: {open_ports if open_ports else 'none from selection'}")

    # 2) Banners for open ports
    print("[*] Grabbing banners for open ports ...")
    banners = {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(open_ports)))) as ex:
        fut = {ex.submit(grab_banner, HOST_TO_SCAN, p): p for p in open_ports}
        for f in as_completed(fut):
            p = fut[f]
            try: banners[p] = f.result()
            except Exception: banners[p] = ""

    # 3) Web checks (async)
    print("[*] Running web checks (headers + boolean SQLi) ...")
    headers_res, sqli_res = asyncio.run(run_web_checks())

    # 4) TLS checks
    print("[*] TLS checks ...")
    tls_res_list = [check_tls(h, p) for (h, p) in TLS_TARGETS]

    # 5) SSH checks
    print("[*] SSH checks ...")
    ssh_res_list = [check_ssh(h, p) for (h, p) in SSH_TARGETS]

    # 6) Build report & write files
    findings = build_findings(open_ports, banners, headers_res, sqli_res, tls_res_list, ssh_res_list)
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": {"host": HOST_TO_SCAN, "home": WEB_HOME, "product": WEB_PRODUCT},
        "findings": findings
    }
    write_json("report.json", report)
    write_html("report.html", report)
    print("✅ Wrote report.json and report.html")

if __name__ == "__main__":
    main()
