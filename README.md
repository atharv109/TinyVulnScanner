# TinyVulnScanner

[![CI](https://github.com/atharv109/TinyVulnScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/atharv109/TinyVulnScanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Beginner-friendly Python vulnerability scanner with a demo lab, modular checks, and pretty HTML/JSON reports.

## ✨ What it does
- Fast **port scan** (threads) + **banner grab**
- Web checks: **missing security headers**, **reflected XSS**, **boolean-based SQLi**
- **TLS** quick look (version, cipher, cert sanity) + **SSH** banner/version hints
- Clean **HTML/JSON** report; “safe mode” heuristics to reduce false positives

> **For educational use. Scan only systems you own or have explicit written permission to test.**

---

## ⚡ Quick start

```bash
git clone https://github.com/atharv109/TinyVulnScanner.git
cd TinyVulnScanner
pip install -r requirements.txt
