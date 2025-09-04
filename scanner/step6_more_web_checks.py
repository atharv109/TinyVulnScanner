# step6_more_web_checks.py
# Robust checks: (1) Security headers (2) Boolean SQLi with content + length signals
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode

# ---------- (1) SECURITY HEADERS ----------
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

# ---------- (2) BOOLEAN SQLi (length + content heuristics) ----------
POS_PAYLOAD = "' OR '1'='1"
NEG_PAYLOAD = "' AND '1'='2"

def add_or_replace_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q_pairs = [kv for kv in p.query.split("&") if kv]  # keep existing
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

async def fetch_text(session: aiohttp.ClientSession, url: str) -> tuple[int | None, str | None, int | None]:
    """Return (status, text, len(text)) or (None, None, None) on error."""
    try:
        async with session.get(url, timeout=5, allow_redirects=True) as r:
            t = await r.text()
            return r.status, t, len(t)
    except Exception:
        return None, None, None

async def test_boolean_sqli(base_url: str, param: str = "id") -> dict:
    # Prepare three URLs
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

    # Heuristic 1: length pattern (pos > base, neg <= base)
    length_signal = (
        all(v is not None for v in (L_base, L_pos, L_neg)) and
        (L_pos > L_base) and (L_neg <= L_base)
    )

    # Heuristic 2: content markers (works with our demo Flask app)
    pos_marker = (t_pos or "")
    neg_marker = (t_neg or "")
    content_signal = ("Item A" in pos_marker) and ("No results" in neg_marker)

    out["signals"] = {"length": bool(length_signal), "content": bool(content_signal)}
    out["suspected"] = bool(length_signal or content_signal)

    # Include short previews for debugging
    def preview(txt):
        if not txt:
            return ""
        lines = txt.splitlines()
        return "\n".join(lines[:6]) + ("\n... (truncated)" if len(lines) > 6 else "")

    out["previews"] = {
        "base": preview(t_base),
        "pos":  preview(t_pos),
        "neg":  preview(t_neg),
    }
    return out

# ---------- RUN ----------
async def main():
    # 1) Headers check
    home = "http://127.0.0.1:5055/"
    hdr = await check_security_headers(home)
    if "error" in hdr:
        print(f"⚠️  Error checking headers: {hdr['error']}")
    else:
        if hdr["missing"]:
            print(f"❌ Missing security headers at {hdr['url']}: {', '.join(hdr['missing'])}")
        else:
            print(f"✅ All recommended headers present at {hdr['url']}")
        for note in hdr.get("notes", []):
            print(f"ℹ️  {note}")

    # 2) Boolean SQLi check
    prod = "http://127.0.0.1:5055/product"
    res = await test_boolean_sqli(prod, param="id")

    print("\n--- Boolean SQLi debug ---")
    print("Tested URLs:")
    print("  base:", res["tested"]["base"])
    print("  pos :", res["tested"]["pos"])
    print("  neg :", res["tested"]["neg"])

    print("HTTP statuses:", res["statuses"])
    print("Lengths:", res["lengths"])
    print("Signals:", res["signals"])

    if res["suspected"]:
        print("\n❌ Possible boolean SQL injection behavior detected.")
    else:
        print("\n✅ No boolean SQLi behavior detected by our simple heuristics.")

    # Optional: uncomment to see short previews
    # print("\nPreview (pos):\n", res["previews"]["pos"])
    # print("\nPreview (neg):\n", res["previews"]["neg"])

if __name__ == "__main__":
    asyncio.run(main())
