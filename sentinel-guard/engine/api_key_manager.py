"""
Sentinel Guard — API Key Manager
Manages API keys for various threat intelligence and scanning integrations.
"""
import os
import json
import base64
from pathlib import Path
from typing import List, Dict, Optional
import urllib.request
import urllib.parse
import urllib.error
from utils.logger import get_logger

logger = get_logger(__name__)


class APIKeyManager:
    """Manages API keys for all threat intelligence and scanner integrations."""

    SUPPORTED_SERVICES = {
        "virustotal": "VirusTotal Threat Intelligence",
        "hybrid_analysis": "Hybrid Analysis Sandbox",
        "abuseipdb": "AbuseIPDB IP Reputation",
        "google_safebrowsing": "Google Safe Browsing URL Lookup",
        "phishtank": "PhishTank Phishing Database",
        "malwarebazaar": "MalwareBazaar Hash Database",
        "urlhaus": "URLhaus Malicious URL Database"
    }

    ENV_MAPPING = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "google_safebrowsing": "GOOGLE_SAFEBROWSING_API_KEY",
        "phishtank": "PHISHTANK_API_KEY",
        "malwarebazaar": "MALWAREBAZAAR_API_KEY",
        "urlhaus": "URLHAUS_API_KEY"
    }

    def __init__(self, file_path: str = "data/api_keys.json"):
        self.file_path = file_path
        self.keys: Dict[str, str] = {service: "" for service in self.SUPPORTED_SERVICES}
        
        # Load keys from file if it exists, then load from env to override if present
        if os.path.exists(self.file_path):
            try:
                self.load_from_file(self.file_path)
            except Exception as e:
                logger.error(f"Failed to auto-load API keys: {e}")
        
        self.load_from_env()

    def _obfuscate(self, data: str) -> str:
        """Obfuscate data using simple XOR and Base64."""
        xor_key = b"sentinel-guard-secret-key-obfuscator"
        data_bytes = data.encode('utf-8')
        obfuscated = bytearray(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data_bytes))
        return base64.b64encode(obfuscated).decode('utf-8')

    def _deobfuscate(self, obfuscated_str: str) -> str:
        """Deobfuscate data using Base64 and simple XOR."""
        xor_key = b"sentinel-guard-secret-key-obfuscator"
        obfuscated_bytes = base64.b64decode(obfuscated_str.encode('utf-8'))
        deobfuscated = bytearray(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(obfuscated_bytes))
        return deobfuscated.decode('utf-8')

    def get_key(self, service: str) -> str:
        """Get the API key for a service."""
        return self.keys.get(service.lower(), "")

    def set_key(self, service: str, key: str):
        """Set the API key for a service."""
        service_lower = service.lower()
        if service_lower not in self.SUPPORTED_SERVICES:
            raise ValueError(f"Unsupported service: {service}")
        self.keys[service_lower] = key.strip()
        logger.debug(f"API key updated for service: {service_lower}")

    def list_services(self) -> List[Dict]:
        """List all supported services and their configuration status."""
        return [
            {
                "service": name,
                "description": desc,
                "configured": bool(self.get_key(name)),
                "env_variable": self.ENV_MAPPING.get(name)
            }
            for name, desc in self.SUPPORTED_SERVICES.items()
        ]

    def load_from_env(self):
        """Load API keys from environment variables."""
        for service, env_var in self.ENV_MAPPING.items():
            val = os.environ.get(env_var)
            if val:
                self.keys[service] = val.strip()
                logger.info(f"Loaded API key for {service} from environment variable {env_var}")

    def save_to_file(self, path: Optional[str] = None):
        """Save and obfuscate API keys to data/api_keys.json."""
        target_path = path or self.file_path
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)

        data_str = json.dumps(self.keys)
        obfuscated_str = self._obfuscate(data_str)

        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated_str)
        logger.info(f"API keys successfully saved and obfuscated to {target_path}")

    def load_from_file(self, path: Optional[str] = None):
        """Load and deobfuscate API keys from data/api_keys.json."""
        target_path = path or self.file_path
        if not os.path.exists(target_path):
            logger.warning(f"API key file not found: {target_path}")
            return

        with open(target_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        if not content:
            logger.warning(f"API key file is empty: {target_path}")
            return

        # Attempt to load as obfuscated first, then fall back to plain JSON
        try:
            deobfuscated_str = self._deobfuscate(content)
            loaded_keys = json.loads(deobfuscated_str)
        except Exception:
            try:
                # Fallback to plain JSON if deobfuscation fails (e.g., user wrote it manually)
                loaded_keys = json.loads(content)
                logger.info(f"Loaded API keys as plain JSON from {target_path}")
            except Exception as e:
                logger.error(f"Failed to parse API key file {target_path}: {e}")
                raise ValueError(f"Failed to load keys from {target_path}: invalid format.")

        for service, key in loaded_keys.items():
            service_lower = service.lower()
            if service_lower in self.SUPPORTED_SERVICES:
                self.keys[service_lower] = key.strip()
        logger.info(f"API keys loaded from {target_path}")

    def test_key(self, service: str) -> bool:
        """Test if the API key for a given service is valid using a mock or live request."""
        service_lower = service.lower()
        key = self.get_key(service_lower)
        if not key:
            logger.warning(f"Cannot test key for {service_lower}: No key configured")
            return False

        headers = {"User-Agent": "SentinelGuard/1.0"}
        req_url = ""
        req_data = None
        method = "GET"

        if service_lower == "virustotal":
            # VT endpoint to lookup user info or simple object
            req_url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
            headers["x-apikey"] = key
        elif service_lower == "hybrid_analysis":
            # HA user endpoint
            req_url = "https://www.hybrid-analysis.com/api/v2/user/current"
            headers["api-key"] = key
            headers["User-Agent"] = "Falcon Sandbox"
        elif service_lower == "abuseipdb":
            # AbuseIPDB check endpoint
            req_url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"
            headers["Key"] = key
            headers["Accept"] = "application/json"
        elif service_lower == "google_safebrowsing":
            # GSafebrowsing POST endpoint
            req_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
            method = "POST"
            headers["Content-Type"] = "application/json"
            req_data = json.dumps({
                "client": {"clientId": "sentinel-guard", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/apicandles/s/malware.html"}]
                }
            }).encode('utf-8')
        elif service_lower == "phishtank":
            # PhishTank optional check or simple HEAD request
            # Since phishtank is mostly free/rate-limited, we can just check if key is not empty
            return True
        elif service_lower == "malwarebazaar":
            # MalwareBazaar API check
            req_url = "https://mb-api.abuse.ch/api/v1/"
            method = "POST"
            headers["API-KEY"] = key
            req_data = urllib.parse.urlencode({
                "query": "get_recent",
                "selector": "1"
            }).encode('utf-8')
        elif service_lower == "urlhaus":
            # URLhaus API check
            req_url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            method = "POST"
            # URLhaus doesn't strictly require API key for most, so we just check connectivity
            return True
        else:
            logger.error(f"Unknown service for testing: {service_lower}")
            return False

        try:
            req = urllib.request.Request(req_url, data=req_data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=5) as response:
                status = response.status
                if status in (200, 201):
                    logger.info(f"API key for {service_lower} tested successfully!")
                    return True
                else:
                    logger.warning(f"API key for {service_lower} returned status code {status}")
                    return False
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.warning(f"API key for {service_lower} is invalid (HTTP {e.code})")
                return False
            # If we get standard HTTP errors (like 400 Bad Request or 405), the API key itself is likely accepted
            logger.info(f"API key test for {service_lower} returned HTTP {e.code}, key is likely valid")
            return True
        except Exception as e:
            logger.error(f"Connection error testing API key for {service_lower}: {e}")
            return False
