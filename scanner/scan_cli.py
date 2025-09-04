# scan_cli.py
# Beginner-friendly CLI + tiny plugin system
#   Usage (examples):
#     python scan_cli.py --host 127.0.0.1 --ports 1-1024 \
#       --web-home http://127.0.0.1:5055/ --web-product http://127.0.0.1:5055/product \
#       --tls example.com:443 --out-html report.html --out-json report.json

import argparse, asyncio, datetime, json, re, socket, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode
import aiohttp

# ------------------ Core helpers (ports + banners) ------------------
CONNECT_TIMEOUT = 1.0
READ_TIMEOUT = 1.0
READ_BYTES = 512
MAX_WORKERS_DEFAULT = 200

def is_port_open(host, port, timeout=CONNECT_TIMEOUT) -> bool:
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host, port)); return True
    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

def scan_ports(host, ports, max_workers) -> list[int]:
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(is_port_open, host, p): p for p in ports}
        open_ports = []
        for f in as_completed(fut):
            p = fut[f]
            try:
                if f.result(): open_ports.append(p)
            except: pass
    return sorted(open_ports)

def _read_some(sock, nbytes=READ_BYTES) -> bytes:
    sock.settimeout(READ_TIMEOUT)
    try: return sock.recv(nbytes) or b""
    except Exception: return b""

def banner_http(host, port) -> str:
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

def banner_ssh(host, port) -> str:
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

def banner_generic(host, port) -> str:
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

def grab_banner(host, port) -> str:
    if port in (80, 8080, 8000, 8888, 8443): return banner_http(host, port)
    if port == 22: return banner_ssh(host, port)
    if port == 443: return "(HTTPS detected: use TLS check for details)"
    return banner_generic(host, port)

# ------------------ Tiny plugin registry ------------------
REGISTRY = []
def register(cls): REGISTRY.append(cls()); return cls

class Check:
    name = "base"
    async def run(self, ctx) -> list[dict]: return []

# ------------------ Plugins: Web headers ------------------
RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

@register
class WebHeadersCheck(Check):
    name = "web_headers"
    async def run(self, ctx):
        url = ctx.get("web_home")
        if not url: return []
        out = []
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=ctx["http_timeout"], allow_redirects=True) as r:
                    hdrs = {k.lower(): v for k, v in r.headers.items()}
                    missing = []
                    for h in RECOMMENDED_HEADERS:
                        if h.lower() not in hdrs: missing.append(h)
                    if urlparse(str(r.url)).scheme == "https":
                        if "strict-transport-security" not in hdrs:
                            missing.append("Strict-Transport-Security")
                    else:
                        note = "HSTS (Strict-Transport-Security) only relevant on HTTPS."

                    for h in missing:
                        out.append({
                            "id": f"HDR-{h}",
                            "title": f"Missing security header: {h}",
                            "severity": "MEDIUM",
                            "target": str(r.url),
                            "evidence": f"{h} not present in HTTP response headers.",
                            "remediation": self._remediation(h)
                        })
                    if not missing:
                        out.append({
                            "id": "HDR-OK",
                            "title": "All recommended headers present",
                            "severity": "INFO",
                            "target": str(r.url),
                            "evidence": "CSP, X-CTO, X-FO, Referrer-Policy present.",
                            "remediation": "Keep headers maintained across all endpoints."
                        })
                    if urlparse(str(r.url)).scheme != "https":
                        out.append({
                            "id": "HDR-HSTS-NOTE",
                            "title": "HSTS note",
                            "severity": "INFO",
                            "target": str(r.url),
                            "evidence": note,
                            "remediation": "Use HTTPS to enable HSTS."
                        })
        except Exception as e:
            out.append({
                "id": "HDR-ERROR",
                "title": "Could not check security headers",
                "severity": "INFO",
                "target": url,
                "evidence": str(e),
                "remediation": "Verify the URL is reachable."
            })
        return out

    def _remediation(self, h):
        tips = {
            "Content-Security-Policy": "Add CSP, e.g. \"default-src 'self'; script-src 'self'\"; avoid 'unsafe-inline'.",
            "X-Content-Type-Options": "Set: X-Content-Type-Options: nosniff.",
            "X-Frame-Options": "Set: X-Frame-Options: DENY (or SAMEORIGIN).",
            "Referrer-Policy": "Set: Referrer-Policy: strict-origin-when-cross-origin.",
            "Strict-Transport-Security": "Serve over HTTPS, then set HSTS with long max-age.",
        }
        return tips.get(h, "Add the header with a secure value.")

# ------------------ Plugins: Boolean SQLi (with guards) ------------------
@register
class WebBooleanSQLiCheck(Check):
    name = "web_boolean_sqli"
    POS = "' OR '1'='1"
    NEG = "' AND '1'='2"

    def _url_set(self, base, param):
        def add_or_replace_param(url: str, key: str, value: str) -> str:
            p = urlparse(url)
            q_pairs = [kv for kv in p.query.split("&") if kv]
            q = {}
            for kv in q_pairs:
                if "=" in kv: k, v = kv.split("=", 1)
                else: k, v = kv, ""
                q[k] = v
            q[key] = value
            return p._replace(query=urlencode(q)).geturl()
        u_base = add_or_replace_param(base, param, "1")
        u_pos  = add_or_replace_param(base, param, "1"+self.POS)
        u_neg  = add_or_replace_param(base, param, "1"+self.NEG)
        return u_base, u_pos, u_neg

    async def run(self, ctx):
        base_url = ctx.get("web_product")
        if not base_url: return []
        param = ctx.get("sqli_param", "id")
        safe_mode = ctx.get("safe_mode", True)
        threshold = ctx.get("sqli_len_threshold", 30)  # bytes
        out = []

        u_base, u_pos, u_neg = self._url_set(base_url, param)

        async def fetch(session, url):
            try:
                async with session.get(url, timeout=ctx["http_timeout"], allow_redirects=True) as r:
                    txt = await r.text()
                    return r.status, txt, len(txt)
            except Exception:
                return None, None, None

        async with aiohttp.ClientSession() as s:
            s_base, t_base, L_base = await fetch(s, u_base)
            s_pos,  t_pos,  L_pos  = await fetch(s, u_pos)
            s_neg,  t_neg,  L_neg  = await fetch(s, u_neg)

        # False-positive guards
        statuses_ok = all(x == 200 for x in (s_base, s_pos, s_neg))
        length_signal = (
            None not in (L_base, L_pos, L_neg) and
            (L_pos - L_base) >= threshold and
            (L_neg <= L_base)
        )
        content_signal = ("Item A" in (t_pos or "")) and ("No results" in (t_neg or ""))

        suspected = (length_signal or content_signal)
        if safe_mode:
            # Safer: require statuses OK and at least one strong signal
            suspected = statuses_ok and (length_signal or content_signal)

        evidence = {
            "tested_urls": {"base": u_base, "pos": u_pos, "neg": u_neg},
            "statuses": {"base": s_base, "pos": s_pos, "neg": s_neg},
            "lengths": {"base": L_base, "pos": L_pos, "neg": L_neg},
            "signals": {"length": bool(length_signal), "content": bool(content_signal)},
            "safe_mode": safe_mode, "threshold": threshold
        }

        if suspected:
            out.append({
                "id": "SQLI-BOOLEAN",
                "title": "Possible boolean-based SQL injection",
                "severity": "HIGH",
                "target": base_url,
                "evidence": evidence,
                "remediation": "Use parameterized queries; validate input; avoid string concatenation; consider WAF."
            })
        else:
            out.append({
                "id": "SQLI-NONE",
                "title": "No boolean SQLi behavior detected",
                "severity": "INFO",
                "target": base_url,
                "evidence": evidence,
                "remediation": "Keep using parameterized queries and input validation."
            })
        return out

# ------------------ Plugins: TLS quick check ------------------
@register
class TLSCheck(Check):
    name = "tls_basic"
    def _summarize(self, result, version, cipher_tuple):
        if version in ("SSLv2","SSLv3","TLSv1","TLSv1.1"):
            result["findings"].append(("HIGH", f"Weak TLS version: {version}"))
        elif version == "TLSv1.2":
            result["notes"].append("TLS 1.2 negotiated (OK; 1.3 preferred).")
        elif version == "TLSv1.3":
            result["notes"].append("TLS 1.3 negotiated (good).")
        if cipher_tuple:
            name, _, bits = cipher_tuple
            if bits is None or bits < 128:
                result["findings"].append(("MEDIUM", f"Weak cipher: {name} ({bits} bits)."))

    def _check_one(self, host, port):
        result = {"host": host, "port": port, "ok": False, "notes": [], "findings": []}
        # verified first
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=3.0) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    result["ok"] = True
                    result["version"] = tls.version()
                    self._summarize(result, result["version"], tls.cipher())
                    cert = tls.getpeercert()
                    if cert and cert.get("notAfter"):
                        import datetime as dt
                        exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days = (exp - dt.datetime.utcnow()).days
                        if days < 0: result["findings"].append(("HIGH","Certificate expired"))
                        elif days <= 30: result["findings"].append(("MEDIUM", f"Cert expires soon (~{days}d)"))
                        else: result["notes"].append(f"Certificate valid (~{days}d left).")
            return result
        except Exception as e:
            result["notes"].append(f"Verified failed: {e}")

        # unverified fallback
        try:
            ctx2 = ssl.create_default_context(); ctx2.check_hostname=False; ctx2.verify_mode=ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3.0) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as tls:
                    result["ok"] = True
                    result["version"] = tls.version()
                    self._summarize(result, result["version"], tls.cipher())
                    der = tls.getpeercert(binary_form=True)
                    if der: result["notes"].append("Peer certificate presented (unverified).")
                    else: result["findings"].append(("MEDIUM", "No peer certificate returned."))
            return result
        except Exception as e2:
            result["error"] = f"TLS failed: {e2}"
            return result

    async def run(self, ctx):
        targets = ctx.get("tls_targets", [])
        out = []
        for host, port in targets:
            r = self._check_one(host, port)
            target = f"{host}:{port}"
            if not r.get("ok"):
                out.append({
                    "id": f"TLS-{target}-ERR", "title": "TLS check failed",
                    "severity": "INFO", "target": target,
                    "evidence": r.get("error") or "; ".join(r.get("notes", [])),
                    "remediation": "Confirm the host/port and that it speaks TLS."
                })
            else:
                for sev, msg in r.get("findings", []):
                    out.append({
                        "id": f"TLS-{target}-ISSUE", "title": "TLS configuration issue",
                        "severity": sev, "target": target, "evidence": msg,
                        "remediation": "Disable legacy protocols/ciphers; use TLS 1.2/1.3; maintain valid certs."
                    })
                for note in r.get("notes", []):
                    out.append({
                        "id": f"TLS-{target}-NOTE", "title": "TLS observation",
                        "severity": "INFO", "target": target, "evidence": note,
                        "remediation": "Review TLS configuration for best practices."
                    })
        return out

# ------------------ Plugins: SSH banner (optional) ------------------
@register
class SSHBannerCheck(Check):
    name = "ssh_banner"
    async def run(self, ctx):
        targets = ctx.get("ssh_targets", [])
        out = []
        for host, port in targets:
            try:
                with socket.create_connection((host, port), timeout=3.0) as s:
                    s.settimeout(3.0)
                    banner = s.recv(256).decode("latin-1","ignore").strip()
                out.append({
                    "id": f"SSH-{host}:{port}-BANNER",
                    "title": "SSH banner",
                    "severity": "INFO",
                    "target": f"{host}:{port}",
                    "evidence": banner or "(no banner)",
                    "remediation": "Hide detailed banners in production; keep OpenSSH updated."
                })
                m = re.search(r"OpenSSH[_-]([\d.]+)", banner)
                if m:
                    vt = tuple(int(x) for x in m.group(1).split(".") if x.isdigit())
                    if vt < (7,4):
                        out.append({
                            "id": f"SSH-{host}:{port}-ISSUE",
                            "title": "SSH version issue",
                            "severity": "MEDIUM",
                            "target": f"{host}:{port}",
                            "evidence": f"Old OpenSSH {m.group(1)} detected (<7.4).",
                            "remediation": "Upgrade OpenSSH and apply hardening."
                        })
            except Exception as e:
                out.append({
                    "id": f"SSH-{host}:{port}-ERR",
                    "title": "SSH check failed",
                    "severity": "INFO",
                    "target": f"{host}:{port}",
                    "evidence": str(e),
                    "remediation": "Ensure SSH is listening and reachable."
                })
        return out

# ------------------ Reporting ------------------
def sev_rank(s): return {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(s,0)

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)

def write_html(path, data):
    sev_color = {"INFO":"#6b7280","LOW":"#10b981","MEDIUM":"#f59e0b","HIGH":"#ef4444","CRITICAL":"#7f1d1d"}
    def chip(sev): c = sev_color.get(sev,"#6b7280"); return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:12px;font-size:12px;">{sev}</span>'
    rows=[]
    for f in data["findings"]:
        ev = f["evidence"]; ev_pre = "<pre>"+(json.dumps(ev, indent=2) if isinstance(ev,dict) else str(ev)).replace("<","&lt;")+"</pre>"
        rows.append(f"""<tr>
          <td>{f['id']}</td><td><strong>{f['title']}</strong><div>{chip(f['severity'])}</div></td>
          <td>{f['target']}</td><td>{ev_pre}</td><td>{f['remediation']}</td></tr>""")
    html=f"""<!doctype html><html><head><meta charset="utf-8"><title>Vuln Scan Report</title>
<style>body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5e7eb}}
.container{{max-width:1000px;margin:40px auto;padding:0 16px}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:14px}}
.hdr{{padding:18px 20px;border-bottom:1px solid #1f2937}} .meta{{color:#9ca3af;font-size:13px}}
.table{{width:100%;border-collapse:collapse}} th,td{{padding:12px 10px;border-top:1px solid #1f2937;vertical-align:top}}
th{{text-align:left;color:#9ca3af}}</style></head>
<body><div class="container"><div class="card">
<div class="hdr"><h1>Vulnerability Scan Report</h1>
<div class="meta">Generated: {data['generated_at']} · Host: {data['target'].get('host','-')} · Web: {data['target'].get('web_home','-')}</div></div>
<div style="padding:0 20px 20px"><table class="table"><thead>
<tr><th>ID</th><th>Issue</th><th>Target</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table></div></div></div></body></html>"""
    with open(path, "w", encoding="utf-8") as f: f.write(html)

# ------------------ CLI + Orchestration ------------------
def parse_ports(s: str) -> list[int]:
    # e.g., "1-1024,8080,8443"
    out=set()
    for part in s.split(","):
        part=part.strip()
        if "-" in part:
            a,b=part.split("-",1)
            out.update(range(int(a), int(b)+1))
        elif part:
            out.add(int(part))
    return sorted(out)

def parse_hostports(s: str) -> list[tuple[str,int]]:
    # e.g., "example.com:443,127.0.0.1:8443"
    out=[]
    for part in s.split(","):
        part=part.strip()
        if not part: continue
        host, port = part.rsplit(":",1)
        out.append((host.strip(), int(port)))
    return out

async def run_plugins(ctx):
    findings=[]
    for plugin in REGISTRY:
        # skip plugins if no targets relevant
        if plugin.name == "web_headers" and not ctx.get("web_home"): continue
        if plugin.name == "web_boolean_sqli" and not ctx.get("web_product"): continue
        if plugin.name == "tls_basic" and not ctx.get("tls_targets"): continue
        if plugin.name == "ssh_banner" and not ctx.get("ssh_targets"): continue
        res = await plugin.run(ctx)
        findings.extend(res)
    return findings

def main():
    ap = argparse.ArgumentParser(description="Beginner-friendly vulnerability scanner")
    ap.add_argument("--host", required=True, help="Host/IP to port-scan (e.g., 127.0.0.1)")
    ap.add_argument("--ports", default="1-1024", help="Ports to scan, e.g., 1-1024,8080,8443")
    ap.add_argument("--max-workers", type=int, default=MAX_WORKERS_DEFAULT, help="Concurrency for port scan")
    ap.add_argument("--web-home", help="Base URL for header checks, e.g., http://127.0.0.1:5055/")
    ap.add_argument("--web-product", help="Product URL base for SQLi test, e.g., http://127.0.0.1:5055/product")
    ap.add_argument("--sqli-param", default="id", help="Query parameter name for SQLi probe (default: id)")
    ap.add_argument("--tls", help="Comma list of host:port for TLS checks")
    ap.add_argument("--ssh", help="Comma list of host:port for SSH checks (only your own!)")
    ap.add_argument("--http-timeout", type=float, default=4.0)
    ap.add_argument("--safe", action="store_true", help="Safer heuristics (default)")
    ap.add_argument("--aggressive", action="store_true", help="Looser heuristics")
    ap.add_argument("--out-json", default="report.json")
    ap.add_argument("--out-html", default="report.html")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    tls_targets = parse_hostports(args.tls) if args.tls else []
    ssh_targets = parse_hostports(args.ssh) if args.ssh else []

    # 1) port scan
    print(f"[*] Scanning {args.host} ports {args.ports} ...")
    open_ports = scan_ports(args.host, ports, args.max_workers)
    print(f"[+] Open ports: {open_ports if open_ports else 'none in selection'}")

    # 2) banners
    print("[*] Grabbing banners ...")
    banners={}
    with ThreadPoolExecutor(max_workers=max(1, min(args.max_workers, len(open_ports) or 1))) as ex:
        fut = {ex.submit(grab_banner, args.host, p): p for p in open_ports}
        for f in as_completed(fut):
            p = fut[f]
            try: banners[p] = f.result()
            except: banners[p] = ""

    # 3) plugin checks
    ctx = {
        "host": args.host,
        "web_home": args.web_home,
        "web_product": args.web_product,
        "sqli_param": args.sqli_param,
        "tls_targets": tls_targets,
        "ssh_targets": ssh_targets,
        "http_timeout": args.http_timeout,
        "safe_mode": False if args.aggressive else True,
        "open_ports": open_ports,
        "banners": banners
    }
    findings_port = [{
        "id": f"PORT-{p}",
        "title": f"Open port: {p}",
        "severity": "INFO",
        "target": f"{args.host}:{p}",
        "evidence": (banners.get(p, "")[:300] + ("..." if banners.get(p,"") and len(banners[p])>300 else "")) or "(no banner)",
        "remediation": "Close unused ports or restrict access with a firewall."
    } for p in open_ports]

    findings_plugins = asyncio.run(run_plugins(ctx))
    findings = findings_port + findings_plugins
    findings.sort(key=lambda f: (-{"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(f["severity"],0), f["id"]))

    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": {"host": args.host, "web_home": args.web_home, "web_product": args.web_product},
        "findings": findings
    }
    write_json(args.out_json, report)
    write_html(args.out_html, report)
    print(f"✅ Wrote {args.out_json} and {args.out_html}")

if __name__ == "__main__":
    main()
