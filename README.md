
## Quick start
pip install -r requirements.txt
cd demo_lab && python app.py  # runs on 127.0.0.1:5055
cd ../scanner
python scan_cli.py --host 127.0.0.1 --ports 1-1024 \
  --web-home http://127.0.0.1:5055/ \
  --web-product http://127.0.0.1:5055/product \
  --tls example.com:443 \
  --out-html ../samples/sample_report.html --out-json ../samples/sample_report.json --safe