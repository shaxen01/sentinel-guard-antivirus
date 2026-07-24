"""
Sentinel Guard — Network Scanner
Analyzes network connections for suspicious activity
"""
import os
import re
import subprocess
from typing import List, Dict
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NetworkConnection:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int = 0
    process_name: str = ""
    is_suspicious: bool = False
    reason: str = ""


# Known malicious IPs (sample — extend with real feeds)
KNOWN_MALICIOUS_IPS = {
    # These are example ranges that are commonly associated with malicious activity
    # In production, fetch from AbuseIPDB, ThreatFox, etc.
}

# Suspicious ports to flag
SUSPICIOUS_PORTS = {
    4444,  # Metasploit default
    1337,  # Common C2
    31337, # Back Orifice
    6666,  # Various
    9999,  # Various
    12345, # NetBus
    54321, # Various backdoors
}


class NetworkScanner:
    """Scans network connections for suspicious activity."""

    def __init__(self, abuseipdb_key: str = None):
        self.abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")

    def scan_connections(self) -> List[NetworkConnection]:
        """Scan all network connections."""
        connections = []

        try:
            if os.name == 'nt':
                connections = self._scan_windows()
            else:
                connections = self._scan_linux()
        except Exception as e:
            logger.error(f"Network scan error: {e}")

        # Check for suspicious connections
        for conn in connections:
            self._check_suspicious(conn)

        return connections

    def _scan_linux(self) -> List[NetworkConnection]:
        """Get network connections on Linux using ss/netstat."""
        connections = []
        try:
            # Try 'ss' first (modern), fall back to 'netstat'
            try:
                output = subprocess.check_output(
                    ['ss', '-tunp'],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=10
                )
                connections = self._parse_ss_output(output)
            except FileNotFoundError:
                output = subprocess.check_output(
                    ['netstat', '-tunp'],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=10
                )
                connections = self._parse_netstat_output(output)
        except Exception as e:
            logger.debug(f"Linux network scan error: {e}")

        return connections

    def _scan_windows(self) -> List[NetworkConnection]:
        """Get network connections on Windows."""
        connections = []
        try:
            output = subprocess.check_output(
                ['netstat', '-ano'],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10
            )
            connections = self._parse_netstat_output(output)
        except Exception as e:
            logger.debug(f"Windows network scan error: {e}")
        return connections

    def _parse_ss_output(self, output: str) -> List[NetworkConnection]:
        """Parse 'ss -tunp' output."""
        connections = []
        lines = output.strip().split('\n')[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            remote = parts[5] if len(parts) > 5 else "*:*"
            state = parts[1] if len(parts) > 1 else ""

            local_addr, local_port = self._parse_addr(local)
            remote_addr, remote_port = self._parse_addr(remote)

            conn = NetworkConnection(
                protocol=proto,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
            )

            # Try to get PID from the process info column
            if len(parts) > 6:
                pid_match = re.search(r'pid=(\d+)', parts[-1])
                if pid_match:
                    conn.pid = int(pid_match.group(1))

            connections.append(conn)
        return connections

    def _parse_netstat_output(self, output: str) -> List[NetworkConnection]:
        """Parse 'netstat' output."""
        connections = []
        lines = output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('Active') or line.startswith('Proto'):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue

            proto = parts[0]
            local = parts[1]
            remote = parts[2]
            state = parts[3] if len(parts) > 3 else ""

            local_addr, local_port = self._parse_addr(local)
            remote_addr, remote_port = self._parse_addr(remote)

            conn = NetworkConnection(
                protocol=proto,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
            )

            # PID (usually last column on Windows)
            if len(parts) > 4:
                try:
                    conn.pid = int(parts[-1])
                except ValueError:
                    pass

            connections.append(conn)
        return connections

    @staticmethod
    def _parse_addr(addr: str) -> tuple:
        """Parse address:port string."""
        if ':' in addr:
            host, port = addr.rsplit(':', 1)
            try:
                port = int(port)
            except ValueError:
                port = 0
            return host, port
        return addr, 0

    def _check_suspicious(self, conn: NetworkConnection):
        """Check if a connection is suspicious."""
        # Check remote port
        if conn.remote_port in SUSPICIOUS_PORTS:
            conn.is_suspicious = True
            conn.reason = f"Known backdoor port: {conn.remote_port}"

        # Check against known malicious IPs
        if conn.remote_addr in KNOWN_MALICIOUS_IPS:
            conn.is_suspicious = True
            conn.reason = f"Known malicious IP: {conn.remote_addr}"

        # Flag connections to unusual ports from external IPs
        if conn.remote_addr and conn.remote_addr not in ('0.0.0.0', '*', '::', '127.0.0.1', '::1'):
            if conn.remote_port not in (80, 443, 53, 25, 587, 993, 995, 8080, 8443):
                if conn.state.upper() in ('ESTABLISHED', 'LISTEN'):
                    if not conn.is_suspicious:
                        conn.is_suspicious = True
                        conn.reason = f"Unusual connection: {conn.remote_addr}:{conn.remote_port} ({conn.state})"

    def get_suspicious(self) -> List[NetworkConnection]:
        """Return only suspicious connections."""
        return [c for c in self.scan_connections() if c.is_suspicious]
