# scanner.py
import requests
from bs4 import BeautifulSoup
import re

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.vulnerabilities = []

    def crawl(self, url):
        if url in self.visited_urls or not url.startswith(self.target_url):
            return []
        try:
            resp = requests.get(url, timeout=5)
            self.visited_urls.add(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            links = [requests.compat.urljoin(url, l) for l in links if l]
            for link in links:
                self.crawl(link)
            self.check_sql_injection(url)
            self.check_xss(url)
        except Exception as e:
            pass

    def check_sql_injection(self, url):
        sqli_payload = "' OR '1'='1"
        params = {"test": sqli_payload}
        try:
            resp = requests.get(url, params=params, timeout=5)
            if re.search(r"sql|syntax|PDO|mysql|odbc_safe", resp.text, re.I):
                self.report_vulnerability({
                    "type": "SQL Injection",
                    "url": url,
                    "evidence": "SQL error detected in response",
                    "severity": "High"
                })
        except Exception:
            pass

    def check_xss(self, url):
        xss_payload = "<script>alert('xss')</script>"
        params = {"test": xss_payload}
        try:
            resp = requests.get(url, params=params, timeout=5)
            if xss_payload in resp.text:
                self.report_vulnerability({
                    "type": "XSS",
                    "url": url,
                    "evidence": "Payload reflected in response",
                    "severity": "High"
                })
        except Exception:
            pass

    def report_vulnerability(self, vuln):
        self.vulnerabilities.append(vuln)
        with open("reports/scan_log.txt", "a") as f:
            f.write(str(vuln) + "\n")

    def scan(self):
        self.crawl(self.target_url)
        return self.vulnerabilities

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    scanner = WebSecurityScanner(sys.argv[1])
    vulns = scanner.scan()
    print("Scan complete!")
    for v in vulns:
        print(v)
