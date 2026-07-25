"""
Sentinel Guard — URL/Phishing Scanner
Scans URLs against multiple threat intelligence APIs
"""
import os
import re
import json
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)

SUSPICIOUS_TLDS = {'.zip', '.review', '.country', '.kim', '.cricket', '.science',
                   '.work', '.party', '.gq', '.cf', '.tk', '.ml', '.ga', '.click',
                   '.top', '.loan', '.men', '.pw', '.download', '.stream', '.bid',
                   '.date', '.trade', '.racing', '.win', '.tech', '.accountant'}

URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
                  'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorte.st', 'tiny.cc',
                  'soo.gd', 's2r.co', 'v.gd', 'qr.ae', 'x.co', 'shorturl.at'}

SUSPICIOUS_PATTERNS = [
    (r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'ip_as_hostname', 15),
    (r'@', 'url_with_at_symbol', 10),
    (r'//\S+//', 'double_slash_redirect', 10),
    (r'\.exe$|\.scr$|\.bat$|\.cmd$', 'executable_download', 20),
    (r'(\d+)\.(\d+)\.(\d+)\.(\d+).*\.(?:exe|scr|bat|zip)', 'ip_host_exec_download', 25),
    (r'(.)\1{4,}', 'excessive_char_repeat', 8),
    (r'[^\x00-\x7F]', 'non_ascii_chars', 10),
    (r'xn--', 'punycode_idn', 12),
]


@dataclass
class URLScanResult:
    url: str
    is_malicious: bool = False
    threat_name: str = ""
    source: str = ""
    details: str = ""
    response_time: float = 0.0
    heuristic_flags: List[str] = field(default_factory=list)
    risk_score: int = 0


class URLScanner:
    """Scans URLs against multiple threat intelligence APIs."""

    def __init__(self, google_safebrowsing_key: str = None, urlhaus_enabled: bool = True,
                 phishtank_enabled: bool = True):
        self.google_key = google_safebrowsing_key or os.environ.get("GOOGLE_SAFEBROWSING_API_KEY")
        self.urlhaus_enabled = urlhaus_enabled
        self.phishtank_enabled = phishtank_enabled

    def scan_url(self, url: str) -> URLScanResult:
        result = URLScanResult(url=url)
        flags, score = self._check_url_patterns(url)
        result.heuristic_flags = flags
        result.risk_score = score

        tasks = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            if self.urlhaus_enabled:
                tasks.append(pool.submit(self._query_urlhaus, url))
            if self.phishtank_enabled:
                tasks.append(pool.submit(self._query_phishtank, url))
            if self.google_key:
                tasks.append(pool.submit(self._query_google_safebrowsing, url))
            for future in as_completed(tasks):
                api_result = future.result()
                if api_result and api_result.is_malicious:
                    result.is_malicious = True
                    result.threat_name = api_result.threat_name
                    result.source = api_result.source
                    result.details = api_result.details
                    result.risk_score = max(result.risk_score, 80)
        return result

    def _check_url_patterns(self, url: str) -> tuple:
        flags = []
        score = 0
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            for tld in SUSPICIOUS_TLDS:
                if host.endswith(tld):
                    flags.append(f"suspicious_tld:{tld}")
                    score += 15
                    break
            if host in URL_SHORTENERS:
                flags.append(f"url_shortener:{host}")
                score += 8
            if host.count('.') > 4:
                flags.append(f"excessive_subdomains")
                score += 10
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                flags.append("ip_as_hostname")
                score += 15
        except Exception:
            pass
        for pattern, name, weight in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url):
                flags.append(name)
                score += weight
        return flags, min(score, 100)

    def _query_urlhaus(self, url: str) -> Optional[URLScanResult]:
        result = URLScanResult(url=url, source="URLhaus")
        start = time.time()
        try:
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=data)
            req.add_header("User-Agent", "SentinelGuard/2.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())
            result.response_time = time.time() - start
            if response.get("query_status") == "ok":
                result.is_malicious = True
                result.threat_name = response.get("threat", "Malware URL")
                result.details = f"First seen: {response.get('firstseen', 'N/A')}"
        except Exception as e:
            result.response_time = time.time() - start
        return result

    def _query_phishtank(self, url: str) -> Optional[URLScanResult]:
        result = URLScanResult(url=url, source="PhishTank")
        start = time.time()
        try:
            data = urllib.parse.urlencode({"url": url, "format": "json"}).encode()
            req = urllib.request.Request("https://checkurl.phishtank.com/checkurl/", data=data)
            req.add_header("User-Agent", "SentinelGuard/2.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())
            result.response_time = time.time() - start
            if response.get("results", {}).get("in_database"):
                result.is_malicious = True
                result.threat_name = "Phishing URL (PhishTank)"
        except Exception:
            result.response_time = time.time() - start
        return result

    def _query_google_safebrowsing(self, url: str) -> Optional[URLScanResult]:
        result = URLScanResult(url=url, source="GoogleSafeBrowsing")
        start = time.time()
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
            payload = json.dumps({
                "client": {"clientId": "sentinel-guard", "clientVersion": "2.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }).encode()
            req = urllib.request.Request(api_url, data=payload,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())
            result.response_time = time.time() - start
            if response.get("matches"):
                match = response["matches"][0]
                result.is_malicious = True
                result.threat_name = match.get("threatType", "Unknown")
                result.details = f"Platform: {match.get('platformType', 'N/A')}"
        except Exception:
            result.response_time = time.time() - start
        return result

    def scan_file_for_urls(self, file_path: str) -> List[URLScanResult]:
        results = []
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            urls = re.findall(r'https?://[^\s<>"\']+', content)
            for url in set(urls[:50]):
                results.append(self.scan_url(url))
        except Exception:
            pass
        return results
