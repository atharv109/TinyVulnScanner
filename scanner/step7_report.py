# step7_report.py
# Runs two checks (security headers + boolean SQLi) and writes JSON + HTML report.

import asyncio, json, datetime
import aiohttp
from urllib.parse import urlparse, urlencode

HOME = "http://127.0.0.1:5055/"
PRODUCT = "http://127.0.0.1:5055/product"

# -------------------- CHECK 1: Security headers --------------------
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

# -------------------- CHECK 2: Boolean SQLi --------------------
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

async def fetch_text(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=5, allow_redirects=True) as r:
            t = await r.text()
            return r.status, t, len(t)
    except Exception as e:
        return None, None, None

async def test_boolean_sqli(base_url: str, param: str = "id") -> dict:
    u_base = add_or_replace_param(base_url, param, "1")
    u_pos  = add_or_replace_param(base_url, param, "1" + POS_PAYLOAD)
    u_neg  = add_or_replace_param(base_url, param, "1" + NEG_PAYLOAD)

    out = {"tested": {"base": u_base, "pos": u_pos, "neg": u_neg}}

    async with aiohttp.ClientSession() as s:
        s_base, t_base, L_base = await fetch_text(s, u_base)
        s_pos,  t_pos,  L_pos  = await fetch_text(s, u_pos)
        s_neg,  t_neg,  L_neg  = await fetch_text(s, u_neg)

    out["statuses"] = {"base": s_base, "pos": s_pos, "neg": s_neg}
    out["lengths"]  = {"base": L_base, "pos": L_pos, "neg": L_neg}

    length_signal = (
        all(v is not None for v in (L_base, L_pos, L_neg)) and
        (L_pos is not None and L_base is not None and L_pos > L_base) and
        (L_neg is not None and L_base is not None and L_neg <= L_base)
    )
    content_signal = ("Item A" in (t_pos or "")) and ("No results" in (t_neg or ""))

    out["signals"] = {"length": bool(length_signal), "content": bool(content_signal)}
    out["suspected"] = bool(length_signal or content_signal)
    return out

# -------------------- Report assembly --------------------
def remediation_for_header(h: str) -> str:
    tips = {
        "Content-Security-Policy": "Add a CSP, e.g. \"default-src 'self'; script-src 'self'\"; avoid 'unsafe-inline'.",
        "X-Content-Type-Options": "Set header: X-Content-Type-Options: nosniff.",
        "X-Frame-Options": "Set header: X-Frame-Options: DENY (or SAMEORIGIN).",
        "Referrer-Policy": "Set header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
        "Strict-Transport-Security": "Serve over HTTPS, then set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
    }
    return tips.get(h, "Add the recommended header with a secure value.")

def build_findings(headers_res: dict, sqli_res: dict) -> list[dict]:
    findings = []

    # Security header findings
    if "error" in headers_res:
        findings.append({
            "id": "HDR-ERROR",
            "title": "Could not check security headers",
            "severity": "INFO",
            "target": headers_res.get("url"),
            "evidence": headers_res["error"],
            "remediation": "Verify the URL is reachable and not blocked by a proxy/firewall."
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

    # Boolean SQLi finding
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
                "remediation": "Use parameterized queries/prepared statements; do not concatenate user input into SQL. Validate and sanitize inputs. Consider ORM and WAF rules."
            })
        else:
            # No issue detected — include as INFO so it shows in the report
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

    return findings

def overall_severity(findings: list[dict]) -> str:
    rank = {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    rev  = {v:k for k,v in rank.items()}
    level = max((rank.get(f["severity"],0) for f in findings), default=0)
    return rev[level]

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
            ev_pre = f"<pre>{str(ev).replace('<','&lt;')}</pre>"
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
.badge{{display:inline-block;margin-right:8px}}
.summary{{padding:14px 20px}}
</style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="hdr">
        <h1>Vulnerability Scan Report</h1>
        <div class="meta">
          Target: {data['target']['home']} &middot; Generated: {data['generated_at']}
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
async def run():
    headers_res = await check_security_headers(HOME)
    sqli_res    = await test_boolean_sqli(PRODUCT, param="id")

    findings = build_findings(headers_res, sqli_res)
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": {"home": HOME, "product": PRODUCT},
        "findings": findings
    }
    write_json("report.json", report)
    write_html("report.html", report)
    print("✅ Wrote report.json and report.html")

if __name__ == "__main__":
    asyncio.run(run())
