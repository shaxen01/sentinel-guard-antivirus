"""
Sentinel Guard — String Extractor
Extracts and analyzes ASCII and Unicode strings from binary files for threat intelligence.
"""
import re
from dataclasses import dataclass, field
from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class StringAnalysisResult:
    """Dataclass holding results of string analysis."""
    total_strings: int
    total_chars: int
    avg_length: float
    contains_urls: List[str] = field(default_factory=list)
    contains_ips: List[str] = field(default_factory=list)
    contains_paths: List[str] = field(default_factory=list)
    contains_registry_keys: List[str] = field(default_factory=list)
    contains_email: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)


class StringExtractor:
    """Extracts printable strings (ASCII & UTF-16LE) from raw binary content and analyzes them."""

    def extract_ascii(self, content: bytes, min_len: int = 4) -> List[str]:
        """Extract consecutive printable ASCII strings from raw bytes."""
        # Range of printable ASCII: 0x20 (space) to 0x7E (tilde)
        pattern = re.compile(br'[\x20-\x7E]{' + str(min_len).encode() + b',}')
        matches = pattern.findall(content)
        return [m.decode('ascii', errors='ignore') for m in matches]

    def extract_unicode(self, content: bytes, min_len: int = 4) -> List[str]:
        """Extract consecutive UTF-16LE printable characters (common in Windows binaries) from raw bytes."""
        # A printable UTF-16LE character is a printable ASCII byte followed by a null byte 0x00
        pattern = re.compile(br'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',}')
        matches = pattern.findall(content)
        return [m.decode('utf-16le', errors='ignore') for m in matches]

    def extract(self, content: bytes, min_len: int = 4, max_len: int = 1024) -> List[str]:
        """Extract both ASCII and Unicode strings, filter by length, and remove duplicates."""
        if not isinstance(content, bytes):
            logger.warning("Content provided for string extraction must be bytes")
            return []

        ascii_strings = self.extract_ascii(content, min_len)
        unicode_strings = self.extract_unicode(content, min_len)
        
        all_strings = ascii_strings + unicode_strings
        
        # Filter strings by length constraints and de-duplicate
        filtered = []
        seen = set()
        for s in all_strings:
            s_clean = s.strip()
            if min_len <= len(s_clean) <= max_len:
                if s_clean not in seen:
                    seen.add(s_clean)
                    filtered.append(s_clean)
                    
        logger.info(f"Extracted {len(filtered)} unique strings (ASCII & Unicode) from binary content")
        return filtered

    def analyze_strings(self, strings: List[str]) -> StringAnalysisResult:
        """Scan a list of extracted strings for indicators of compromise (IOCs) and suspicious patterns."""
        total_strings = len(strings)
        total_chars = sum(len(s) for s in strings)
        avg_length = total_chars / total_strings if total_strings > 0 else 0.0

        contains_urls = []
        contains_ips = []
        contains_paths = []
        contains_registry_keys = []
        contains_email = []
        suspicious_strings = []

        # High quality regular expression patterns
        url_pat = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+', re.IGNORECASE)
        
        # Matches valid IPv4 addresses
        ip_pat = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        
        # Matches Unix-like systems paths and Windows paths
        path_pat = re.compile(
            r'\b(?:[a-zA-Z]:\\[a-zA-Z0-9_\-\\.\s]+|/(?:bin|etc|var|usr|tmp|opt|lib|sbin|sys|proc|home|root)/[a-zA-Z0-9_\-./]+)', 
            re.IGNORECASE
        )
        
        # Matches standard Windows Registry Hives and Subkeys
        reg_pat = re.compile(
            r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)\\[a-zA-Z0-9_\-\\.]+', 
            re.IGNORECASE
        )
        
        # Matches valid email structures
        email_pat = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        
        # Matches suspicious APIs, files, CLI tools, and offensive keywords
        susp_pat = re.compile(
            r'\b(?:virtualalloc|virtualprotect|writeprocessmemory|createremotethread|'
            r'getprocaddress|loadlibrary|shellexecute|winexec|cmd\.exe|powershell|'
            r'mimikatz|shellcode|keylogger|backdoor|payload|downloadstring|uploadstring|'
            r'iex|invoke-expression|bypass|ntdll|kernel32)\b', 
            re.IGNORECASE
        )

        for s in strings:
            # URLs
            urls = url_pat.findall(s)
            if urls:
                contains_urls.extend(urls)
            
            # IPs
            ips = ip_pat.findall(s)
            if ips:
                contains_ips.extend(ips)
                
            # Paths
            paths = path_pat.findall(s)
            if paths:
                contains_paths.extend(paths)
                
            # Registry Keys
            regs = reg_pat.findall(s)
            if regs:
                contains_registry_keys.extend(regs)
                
            # Emails
            emails = email_pat.findall(s)
            if emails:
                contains_email.extend(emails)
                
            # Suspicious Keywords
            if susp_pat.search(s):
                suspicious_strings.append(s)

        # De-duplicate and sort results
        contains_urls = sorted(list(set(contains_urls)))
        contains_ips = sorted(list(set(contains_ips)))
        contains_paths = sorted(list(set(contains_paths)))
        contains_registry_keys = sorted(list(set(contains_registry_keys)))
        contains_email = sorted(list(set(contains_email)))
        suspicious_strings = sorted(list(set(suspicious_strings)))

        return StringAnalysisResult(
            total_strings=total_strings,
            total_chars=total_chars,
            avg_length=avg_length,
            contains_urls=contains_urls,
            contains_ips=contains_ips,
            contains_paths=contains_paths,
            contains_registry_keys=contains_registry_keys,
            contains_email=contains_email,
            suspicious_strings=suspicious_strings
        )
