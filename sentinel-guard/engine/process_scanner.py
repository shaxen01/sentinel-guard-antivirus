"""
Sentinel Guard — Process Scanner
Analyzes running processes for suspicious behavior
"""
import os
import time
from typing import List, Dict
from dataclasses import dataclass
from utils.logger import get_logger
from utils.hasher import compute_sha256

logger = get_logger(__name__)


@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str
    command: str
    is_suspicious: bool = False
    reason: str = ""
    sha256: str = ""
    memory_mb: float = 0.0
    cpu_percent: float = 0.0


class ProcessScanner:
    """Scans running processes for suspicious activity."""

    SUSPICIOUS_PROCESS_NAMES = {
        'mimikatz', 'procdump', 'hashcat', 'john', 'hydra',
        'nmap', 'metasploit', 'msfconsole', 'armitage',
        'cobaltstrike', 'beacon', 'powershell99', 'cmd99',
        'nc.exe', 'ncat', 'netcat', 'wireshark', 'tcpdump',
        'processhacker', 'x64dbg', 'x32dbg', 'ollydbg',
        'regshot', 'autoruns', 'procmon',
    }

    SUSPICIOUS_PATH_PATTERNS = [
        '/tmp/', '/var/tmp/', '/dev/shm/',
        'C:\\Temp\\', 'C:\\Users\\Public\\',
        'AppData\\Local\\Temp\\',
    ]

    def __init__(self, sig_db=None):
        self.sig_db = sig_db

    def scan_processes(self) -> List[ProcessInfo]:
        """Scan all running processes."""
        results = []
        try:
            if os.name == 'nt':
                results = self._scan_windows()
            else:
                results = self._scan_linux()
        except Exception as e:
            logger.error(f"Process scan error: {e}")
        return results

    def _scan_linux(self) -> List[ProcessInfo]:
        """Scan processes on Linux/macOS."""
        results = []
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            try:
                # Read process info
                with open(f'/proc/{pid}/cmdline', 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()

                with open(f'/proc/{pid}/comm', 'r') as f:
                    name = f.read().strip()

                # Get executable path
                try:
                    exe_path = os.readlink(f'/proc/{pid}/exe')
                except:
                    exe_path = cmdline.split()[0] if cmdline else name

                # Get memory info
                mem_kb = 0
                try:
                    with open(f'/proc/{pid}/status', 'r') as f:
                        for line in f:
                            if line.startswith('VmRSS:'):
                                mem_kb = int(line.split()[1])
                except:
                    pass

                info = ProcessInfo(
                    pid=pid,
                    name=name,
                    path=exe_path,
                    command=cmdline[:200],
                    memory_mb=mem_kb / 1024,
                )

                self._check_suspicious(info)
                results.append(info)

            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
        return results

    def _scan_windows(self) -> List[ProcessInfo]:
        """Scan processes on Windows."""
        results = []
        try:
            import ctypes
            import subprocess
            output = subprocess.check_output(
                ['tasklist', '/FO', 'CSV', '/NH'],
                stderr=subprocess.DEVNULL,
                text=True
            )
            for line in output.strip().split('\n'):
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    name = parts[0]
                    pid = int(parts[1])
                    info = ProcessInfo(pid=pid, name=name, path=name, command=name)
                    self._check_suspicious(info)
                    results.append(info)
        except Exception as e:
            logger.debug(f"Windows process scan error: {e}")
        return results

    def _check_suspicious(self, info: ProcessInfo):
        """Check if a process is suspicious."""
        name_lower = info.name.lower()

        # Check against suspicious names
        for sus_name in self.SUSPICIOUS_PROCESS_NAMES:
            if sus_name in name_lower:
                info.is_suspicious = True
                info.reason = f"Known hacking tool: {sus_name}"
                return

        # Check path patterns
        for pattern in self.SUSPICIOUS_PATH_PATTERNS:
            if pattern.lower() in info.path.lower():
                info.is_suspicious = True
                info.reason = f"Running from suspicious path: {pattern}"
                return

        # Check against signature database
        if self.sig_db and info.path and os.path.exists(info.path):
            sha = compute_sha256(info.path)
            if sha:
                info.sha256 = sha
                match = self.sig_db.check_hash(sha)
                if match:
                    info.is_suspicious = True
                    info.reason = f"Signature match: {match.get('name', 'Unknown')}"

    def get_suspicious(self) -> List[ProcessInfo]:
        """Return only suspicious processes."""
        return [p for p in self.scan_processes() if p.is_suspicious]
