# step5_web_checks.py
# Simple reflected XSS checker (server-side reflection)
# Use only on systems you own or have permission to test.

import asyncio
import aiohttp

TOKEN = "XSSPROBE123"

async def test_reflected_xss(url: str) -> dict:
    """
    Appends ?q=TOKEN (or &q=TOKEN) and checks if the token
    is reflected in the HTML response.
    """
    test_url = f"{url}{'&' if '?' in url else '?'}q={TOKEN}"
    out = {"url": test_url, "xss": False}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(test_url, timeout=4, allow_redirects=True) as resp:
                body = await resp.text()
                out["status"] = resp.status
                out["length"] = len(body)
                if TOKEN in body:
                    out["xss"] = True
    except Exception as e:
        out["error"] = str(e)

    return out

async def main():
    # Point at your demo Flask app home page (server-side reflection of ?q=)
    target = "http://127.0.0.1:5055/reflect"
    result = await test_reflected_xss(target)

    print(f"Tested: {result.get('url')}")
    if "error" in result:
        print(f"⚠️  Error: {result['error']}")
        return

    print(f"HTTP {result.get('status')} · bytes={result.get('length')}")
    if result.get("xss"):
        print("❌ Potential reflected XSS: token echoed in response HTML.")
        print("   Remediation: HTML-escape user input before rendering, avoid innerHTML, set a Content-Security-Policy.")
    else:
        print("✅ No reflected XSS found with this simple token check.")

if __name__ == "__main__":
    asyncio.run(main())
