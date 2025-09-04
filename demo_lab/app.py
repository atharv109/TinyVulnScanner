# app.py  (INTENTIONALLY INSECURE FOR LEARNING)
from flask import Flask, request

app = Flask(__name__)

@app.get("/")
def home():
    return """<!doctype html><html><body>
    <h1>Home</h1>
    <p>Try /product?id=1</p>
    </body></html>"""

@app.get("/product")
def product():
    """Simulate boolean SQLi signals via content differences."""
    pid = request.args.get("id", "1")

    base = "<h1>Product</h1><p>Basic product information.</p>"

    # If the string contains the classic OR-true pattern, make page longer
    if "' OR '1'='1" in pid:
        extra = "<ul><li>Item A</li><li>Item B</li><li>Item C</li></ul>"
        html = base + extra
    # If it contains the AND-false pattern, return 'No results'
    elif "' AND '1'='2" in pid:
        html = "<h1>Product</h1><p>No results.</p>"
    else:
        html = base

    return f"<!doctype html><html><body>{html}</body></html>"

@app.get("/reflect")
def reflect():
    q = request.args.get("q", "")
    # INTENTIONALLY INSECURE: echoes user input directly
    return f"""<!doctype html><html><body>
      <h1>Reflect Demo</h1>
      <p>You searched for: <span id="result">{q}</span></p>
    </body></html>"""


if __name__ == "__main__":
    # Print routes so you can see them in the console
    print("ROUTES:", app.url_map)
    # Use a clean port to avoid conflicts with anything else
    app.run(host="127.0.0.1", port=5055, debug=False)
