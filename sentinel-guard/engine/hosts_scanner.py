"""
Sentinel Guard — Hosts File Scanner
Scans system hosts file for DNS hijacking, excessive entries, and redirection of sensitive domains.
"""

import os
import platform
from dataclasses import dataclass
from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)

# Sensitive domains typically targeted for DNS hijacking or blocking
SENSITIVE_DOMAINS = {
    # Search and Social
    "google.com", "google.co.uk", "google.ca", "google.de", "google.fr",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "youtube.com",
    "linkedin.com", "yahoo.com", "bing.com", "duckduckgo.com",
    
    # Financial and Payment
    "paypal.com", "stripe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "hsbc.com", "barclays.co.uk", "capitalone.com", "americanexpress.com",
    
    # Security Vendors & Update Services
    "microsoft.com", "windowsupdate.com", "update.microsoft.com",
    "virustotal.com", "malwarebytes.com", "kaspersky.com", "symantec.com",
    "mcafee.com", "avast.com", "avg.com", "bitdefender.com", "eset.com",
    "sophos.com", "trendmicro.com", "f-secure.com", "clamav.net"
}

# Known malicious/adware/suspicious IPs
SUSPICIOUS_IPS = {
    "185.190.140.1", "104.244.42.1", "198.101.242.72", "23.21.193.169"
}

# Safe suffixes commonly used in local development
SAFE_LOCAL_SUFFIXES = {
    ".local", ".localhost", ".test", ".example", ".invalid", ".dev", ".lan"
}


@dataclass
class HostsEntry:
    ip: str
    hostname: str
    is_suspicious: bool
    reason: str


class HostsScanner:
    """Scans system hosts file for DNS hijacking and malicious entries."""

    def __init__(self, hosts_path: str = None):
        if hosts_path:
            self.hosts_path = hosts_path
        else:
            if platform.system() == "Windows":
                self.hosts_path = os.path.join(
                    os.environ.get("SystemRoot", "C:\\Windows"),
                    "System32", "drivers", "etc", "hosts"
                )
            else:
                self.hosts_path = "/etc/hosts"

    def scan(self) -> List[HostsEntry]:
        """Scans the hosts file and returns a list of parsed entries, marking suspicious ones."""
        logger.info(f"Scanning hosts file: {self.hosts_path}")
        entries: List[HostsEntry] = []

        if not os.path.exists(self.hosts_path):
            logger.warning(f"Hosts file not found: {self.hosts_path}")
            return entries

        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed to read hosts file: {e}")
            return entries

        raw_entries = []
        for line in lines:
            # Strip comments
            cleaned_line = line.split("#", 1)[0].strip()
            if not cleaned_line:
                continue

            parts = cleaned_line.split()
            if len(parts) < 2:
                continue

            ip = parts[0]
            hostnames = parts[1:]
            for hostname in hostnames:
                hostname_norm = hostname.lower().strip()
                raw_entries.append((ip, hostname_norm))

        # Check for excessive entries
        if len(raw_entries) > 500:
            logger.warning(
                f"Hosts file has an excessive number of entries ({len(raw_entries)}). "
                "This could be a custom ad-blocker list or indicator of adware/spyware activity."
            )

        for ip, hostname in raw_entries:
            entry = HostsEntry(
                ip=ip,
                hostname=hostname,
                is_suspicious=False,
                reason=""
            )
            # Call check_suspicious to evaluate the entry
            if self._check_suspicious(entry):
                pass
            entries.append(entry)

        return entries

    def _check_suspicious(self, entry: HostsEntry) -> bool:
        """Determines if a hosts entry is suspicious and populates the reason if so."""
        ip = entry.ip
        hostname = entry.hostname.lower()

        # Check for loopback or local IPs
        is_loopback = ip in ("127.0.0.1", "::1", "0.0.0.0") or ip.startswith("127.")

        # 1. Check for known malicious / suspicious IPs
        if ip in SUSPICIOUS_IPS:
            entry.is_suspicious = True
            entry.reason = f"IP {ip} matches a known malicious or suspicious server address."
            return True

        # 2. Check for hijacking of common/sensitive domains
        is_sensitive = False
        for domain in SENSITIVE_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                is_sensitive = True
                break

        if is_sensitive:
            if is_loopback:
                # Security update domains redirected to localhost is highly suspicious (malware blocking updates)
                if any(vendor in hostname for vendor in ("update", "microsoft", "malwarebytes", "virustotal", "kaspersky", "symantec", "mcafee", "avast", "bitdefender", "eset")):
                    entry.is_suspicious = True
                    entry.reason = f"Security/Update domain {hostname} redirected to local loopback IP ({ip}). Possible update block/hijack."
                    return True
                else:
                    entry.is_suspicious = True
                    entry.reason = f"Sensitive domain {hostname} redirected to local loopback IP ({ip}). Possible blocking or hijacking."
                    return True
            else:
                # Sensitive domain mapped to external IP is high risk of active DNS hijacking/phishing
                entry.is_suspicious = True
                entry.reason = f"Sensitive domain {hostname} mapped to external IP {ip} in hosts file. High risk of DNS hijacking/phishing."
                return True

        # 3. Redirect to localhost for non-localhost services
        if is_loopback:
            has_safe_suffix = any(hostname.endswith(suffix) for suffix in SAFE_LOCAL_SUFFIXES)
            is_generic_local_name = hostname in ("localhost", "localhost.localdomain", "broadcasthost")

            if "." in hostname and not has_safe_suffix and not is_generic_local_name:
                entry.is_suspicious = True
                entry.reason = f"Non-local domain {hostname} redirected to local loopback IP ({ip}). Possible hosts-based blocking."
                return True

        return False
