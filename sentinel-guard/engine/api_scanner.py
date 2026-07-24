"""
Sentinel Guard — Multi-API Parallel Scanner
Queries multiple threat intelligence APIs simultaneously for hash-based detection
"""
import json
import time
import hashlib
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class APIResult:
    api_name: str
    detected: bool = False
    threat_name: str = ""
    threat_score: int = 0  # 0-100 confidence
    details: str = ""
    response_time: float = 0.0
    error: str = ""
    quota_remaining: str = ""


@dataclass
class MultiAPIResult:
    sha256: str
    md5: str
    results: List[APIResult] = field(default_factory=list)
    consensus_score: int = 0  # 0-100 based on how many APIs flagged it
    total_detected: int = 0
    total_queried: int = 0

    @property
    def is_threat(self) -> bool:
        return self.total_detected > 0


class APIScanner:
    """Multi-API parallel hash lookup scanner."""

    def __init__(self, virustotal_key: str = None, hybrid_analysis_key: str = None,
                 abuseipdb_key: str = None):
        self.virustotal_key = virustotal_key or self._read_key("VIRUSTOTAL_API_KEY")
        self.hybrid_analysis_key = hybrid_analysis_key or self._read_key("HYBRID_ANALYSIS_API_KEY")
        self.abuseipdb_key = abuseipdb_key or self._read_key("ABUSEIPDB_API_KEY")
        self._vt_rate_timer = 0
        self._vt_rate_count = 0

    @staticmethod
    def _read_key(env_name: str) -> Optional[str]:
        import os
        return os.environ.get(env_name)

    def scan_hash_parallel(self, sha256: str, md5: str = None) -> MultiAPIResult:
        """Query all available APIs in parallel for a single hash."""
        result = MultiAPIResult(sha256=sha256, md5=md5 or "")
        tasks = []

        with ThreadPoolExecutor(max_workers=5) as pool:
            # MalwareBazaar (free, no key needed)
            tasks.append(pool.submit(self._query_malwarebazaar, sha256))

            # VirusTotal (needs key)
            if self.virustotal_key:
                tasks.append(pool.submit(self._query_virustotal, sha256))

            # Hybrid Analysis (needs key)
            if self.hybrid_analysis_key:
                tasks.append(pool.submit(self._query_hybrid_analysis, sha256))

            # URLhaus (free, check if hash is associated with malware URLs)
            tasks.append(pool.submit(self._query_urlhaus_hash, sha256))

            for future in as_completed(tasks):
                api_result = future.result()
                if api_result:
                    result.results.append(api_result)
                    result.total_queried += 1
                    if api_result.detected:
                        result.total_detected += 1

        # Consensus score — more APIs that flag it = higher confidence
        if result.total_queried > 0:
            base = (result.total_detected / result.total_queried) * 100
            result.consensus_score = int(base)
        return result

    def _query_malwarebazaar(self, sha256: str) -> APIResult:
        """Query MalwareBazaar API (free, no key needed)."""
        result = APIResult(api_name="MalwareBazaar")
        start = time.time()
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = urllib.parse.urlencode({
                "query": "get_info",
                "hash": sha256
            }).encode()
            req = urllib.request.Request(url, data=data)
            req.add_header("User-Agent", "SentinelGuard/2.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())
            result.response_time = time.time() - start
            if response.get("query_status") == "ok" and response.get("data"):
                info = response["data"][0]
                result.detected = True
                result.threat_name = info.get("signature_name") or info.get("file_type", "Unknown")
                result.threat_score = 80
                result.details = f"Family: {info.get('signature_name', 'N/A')}, Type: {info.get('file_type', 'N/A')}"
            else:
                result.details = "Not in database"
        except Exception as e:
            result.error = str(e)
            result.response_time = time.time() - start
        return result

    def _query_virustotal(self, sha256: str) -> APIResult:
        """Query VirusTotal API v3 (free tier: 4 req/min, 500/day)."""
        result = APIResult(api_name="VirusTotal")
        start = time.time()
        try:
            # Rate limiting: 4 requests per minute
            now = time.time()
            if now - self._vt_rate_timer < 60:
                self._vt_rate_count += 1
                if self._vt_rate_count > 4:
                    result.error = "Rate limited (4/min)"
                    result.response_time = time.time() - start
                    return result
            else:
                self._vt_rate_timer = now
                self._vt_rate_count = 1

            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.virustotal_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())

            result.response_time = time.time() - start
            stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = stats.get("harmless", 0) + malicious + suspicious + stats.get("undetected", 0)

            if malicious > 0:
                result.detected = True
                result.threat_score = min(100, int((malicious / max(total, 1)) * 100))
                result.threat_name = response.get("data", {}).get("attributes", {}).get("popular_threat_name", "Malware")
                result.details = f"{malicious}/{total} engines detected"
                result.quota_remaining = response.get("data", {}).get("attributes", {}).get("reputation", "")
            else:
                result.details = f"0/{total} engines detected"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result.details = "Not in database"
            elif e.code == 429:
                result.error = "Rate limited"
            else:
                result.error = f"HTTP {e.code}"
            result.response_time = time.time() - start
        except Exception as e:
            result.error = str(e)
            result.response_time = time.time() - start
        return result

    def _query_hybrid_analysis(self, sha256: str) -> APIResult:
        """Query Hybrid Analysis (Falcon Sandbox) API."""
        result = APIResult(api_name="HybridAnalysis")
        start = time.time()
        try:
            url = "https://www.hybrid-analysis.com/api/v2/search/hash"
            data = urllib.parse.urlencode({"hash": sha256}).encode()
            req = urllib.request.Request(url, data=data)
            req.add_header("api-key", self.hybrid_analysis_key)
            req.add_header("User-Agent", "Falcon Sandbox")
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())

            result.response_time = time.time() - start
            if isinstance(response, list) and len(response) > 0:
                item = response[0]
                threat_score = item.get("threat_score", 0)
                verdict = item.get("verdict", "")
                if verdict == "malicious" or threat_score > 50:
                    result.detected = True
                    result.threat_score = min(100, threat_score)
                    result.threat_name = item.get("threat_name", "Malware")
                    result.details = f"Verdict: {verdict}, Score: {threat_score}"
                else:
                    result.details = f"Verdict: {verdict}, Score: {threat_score}"
            else:
                result.details = "Not in database"
        except Exception as e:
            result.error = str(e)
            result.response_time = time.time() - start
        return result

    def _query_urlhaus_hash(self, sha256: str) -> APIResult:
        """Query URLhaus for malware-associated URLs by hash."""
        result = APIResult(api_name="URLhaus")
        start = time.time()
        try:
            url = "https://urlhaus-api.abuse.ch/v1/payload/"
            data = urllib.parse.urlencode({"sha256_hash": sha256}).encode()
            req = urllib.request.Request(url, data=data)
            req.add_header("User-Agent", "SentinelGuard/2.0")

            with urllib.request.urlopen(req, timeout=15) as resp:
                response = json.loads(resp.read().decode())

            result.response_time = time.time() - start
            if response.get("query_status") == "ok":
                result.detected = True
                result.threat_name = response.get("signature", "Payload malware")
                result.threat_score = 75
                result.details = f"First seen: {response.get('firstseen', 'N/A')}"
            else:
                result.details = "Not in database"
        except Exception as e:
            result.error = str(e)
            result.response_time = time.time() - start
        return result

    def get_available_apis(self) -> List[Dict]:
        """Return list of available APIs and their status."""
        return [
            {"name": "MalwareBazaar", "status": "active", "needs_key": False},
            {"name": "VirusTotal", "status": "active" if self.virustotal_key else "no_key", "needs_key": True},
            {"name": "HybridAnalysis", "status": "active" if self.hybrid_analysis_key else "no_key", "needs_key": True},
            {"name": "URLhaus", "status": "active", "needs_key": False},
        ]
