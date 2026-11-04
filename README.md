# 🦓 ZebraStrike

**ZebraStrike** is a fast, asynchronous web application pentesting tool written in Python. It is designed for WAF bypass testing, vulnerability discovery (XSS, SQLi), and sensitive file fuzzing.

## 🚀 Features

- **Asynchronous Engine:** Built on `httpx` with HTTP/2 support for high-speed scanning.
- **WAF Detection & Bypass:** Detects Cloudflare, Sucuri, Wordfence, and attempts to bypass them using header injection (`X-Forwarded-For`, `CF-Connecting-IP`).
- **Sensitive File Fuzzing:** Smart detection of exposed `.env`, `.git`, backups, and configs (ignores generic 404 HTML pages).
- **WordPress Recon:** Identifies WP core version and enumerates installed plugins from HTML source.
- **XSS & SQLi Testing:** Automated payload injection into URL parameters.
- **JSON Reporting:** Saves all findings into a structured `report.json`.

## 🛠️ Installation

```bash
git clone https://github.com/smsl1/ZebraStrike
cd ZebraStrike
pip install -r requirements.txt