"""
Sentinel Guard — Rootkit Indicator Scanner
Checks for hidden processes, suspicious kernel modules, un-signed drivers, hidden ports, and filesystem anomalies.
"""

import os
import re
import platform
import subprocess
from dataclasses import dataclass
from typing import List, Set
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RootkitScanResult:
    checks_passed: int
    checks_failed: int
    indicators: List[str]
    risk_score: int


class RootkitScanner:
    """Scans the operating system for rootkit-related indicators and modifications."""

    def scan(self) -> RootkitScanResult:
        """Executes a suite of OS-specific rootkit checks and compiles a scan result."""
        logger.info("Starting rootkit scan...")
        
        indicators: List[str] = []
        checks_passed = 0
        checks_failed = 0
        
        # System-specific scans
        if platform.system() == "Linux":
            # 1. Hidden Processes
            logger.info("Checking for hidden processes (/proc vs ps)...")
            res = self._check_hidden_processes()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 2. Hidden Files in /tmp
            logger.info("Checking for hidden files in temporary directories...")
            res = self._check_hidden_tmp_files()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 3. Suspicious Kernel Modules
            logger.info("Checking for suspicious kernel modules...")
            res = self._check_kernel_modules()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 4. Shared Library Preload (/etc/ld.so.preload)
            logger.info("Checking for dynamic linker preloads...")
            res = self._check_ld_preload()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 5. Suspicious SUID Binaries
            logger.info("Checking for suspicious SUID binaries in writable directories...")
            res = self._check_suid_binaries()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 6. Hidden Network Ports
            logger.info("Checking for hidden networking ports...")
            res = self._check_hidden_ports()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 7. Known Rootkit Files
            logger.info("Checking for known rootkit files/directories...")
            res = self._check_known_rootkit_paths()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
        elif platform.system() == "Windows":
            # 1. Check for Unsigned Drivers
            logger.info("Checking for unsigned system drivers...")
            res = self._check_windows_unsigned_drivers()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
            # 2. Check Registry Driver Service Names and Paths
            logger.info("Checking for suspicious driver services in registry...")
            res = self._check_windows_suspicious_driver_services()
            if res:
                indicators.extend(res)
                checks_failed += 1
            else:
                checks_passed += 1
                
        else:
            logger.warning(f"Rootkit scanning is not supported on platform: {platform.system()}")
            
        # Calculate Risk Score (capped at 100)
        risk_score = self._calculate_risk_score(indicators)
        
        logger.info(
            f"Rootkit scan complete. Passed: {checks_passed}, Failed: {checks_failed}, "
            f"Risk Score: {risk_score}/100, Indicators Found: {len(indicators)}"
        )
        
        return RootkitScanResult(
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            indicators=indicators,
            risk_score=risk_score
        )

    # ================= Linux Specific Checks =================

    def _check_hidden_processes(self) -> List[str]:
        """Compares process IDs in /proc filesystem to those visible to 'ps'."""
        indicators = []
        if not os.path.exists("/proc"):
            return indicators

        try:
            proc_pids = {int(name) for name in os.listdir("/proc") if name.isdigit()}
        except Exception as e:
            logger.debug(f"Error reading /proc: {e}")
            return indicators

        if not proc_pids:
            return indicators

        try:
            res = subprocess.run(["ps", "-e", "-o", "pid"], capture_output=True, text=True, timeout=5)
            ps_pids = set()
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    ps_pids.add(int(line))
        except Exception as e:
            logger.debug(f"Could not execute or parse ps command: {e}")
            return indicators

        hidden_pids = proc_pids - ps_pids
        actual_hidden = []
        
        # Verify with brief sleep to filter out short-lived transient processes
        if hidden_pids:
            import time
            time.sleep(0.1)
            for pid in hidden_pids:
                if os.path.exists(f"/proc/{pid}"):
                    actual_hidden.append(pid)

        for pid in actual_hidden:
            p_name = "Unknown"
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    p_name = f.read().strip()
            except Exception:
                pass
            indicators.append(f"Hidden process detected: PID {pid} ({p_name}) exists in /proc but is not reported by 'ps'.")

        return indicators

    def _check_hidden_tmp_files(self) -> List[str]:
        """Looks for highly suspicious hidden files or folders inside public writeable tmp folders."""
        indicators = []
        search_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        
        # Normal standard hidden folders in Linux tmp
        standard_hidden = {
            ".X11-unix", ".ICE-unix", ".Test-unix", ".font-unix", ".XIM-unix", 
            ".xfsm-IM-unix", ".pwd", ".drive", ".oracle", ".wine", ".vbox-qemu-u"
        }
        
        for s_dir in search_dirs:
            if not os.path.exists(s_dir):
                continue
            try:
                for entry in os.listdir(s_dir):
                    if entry.startswith(".") and entry not in (".", "..") and entry not in standard_hidden:
                        full_path = os.path.join(s_dir, entry)
                        indicators.append(f"Suspicious hidden file/folder in temporary directory: {full_path}")
            except Exception:
                pass
        return indicators

    def _check_kernel_modules(self) -> List[str]:
        """Checks loaded kernel modules against known rootkit LKM names."""
        indicators = []
        modules_file = "/proc/modules"
        if not os.path.exists(modules_file):
            return indicators

        # Known Linux rootkit LKM (Loadable Kernel Module) identifiers
        malicious_lkms = {"reptile", "diamorphine", "vlany", "adore_lkm", "suckit", "kis", "hp_feedback"}

        try:
            with open(modules_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        mod_name = parts[0].lower()
                        if mod_name in malicious_lkms:
                            indicators.append(f"Malicious kernel module loaded: {parts[0]}")
        except Exception as e:
            logger.debug(f"Error reading kernel modules: {e}")
            
        return indicators

    def _check_ld_preload(self) -> List[str]:
        """Flags the presence of /etc/ld.so.preload, commonly used to intercept syscalls in userland."""
        indicators = []
        preload_path = "/etc/ld.so.preload"
        
        if os.path.exists(preload_path):
            try:
                if os.path.getsize(preload_path) > 0:
                    with open(preload_path, "r", encoding="utf-8", errors="ignore") as f:
                        preload_libs = f.read().strip()
                    if preload_libs:
                        indicators.append(f"Linker hijack detected: {preload_path} is configured to preload libraries: {preload_libs}")
            except Exception as e:
                logger.debug(f"Error reading {preload_path}: {e}")
                
        return indicators

    def _check_suid_binaries(self) -> List[str]:
        """Scans temporary writeable directories for binaries with SetUID/SetGID flags."""
        indicators = []
        import stat
        search_paths = ["/tmp", "/var/tmp", "/dev/shm", "/dev"]
        
        for base_path in search_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for root, _, files in os.walk(base_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            st = os.stat(fp)
                            if st.st_mode & stat.S_ISUID:
                                indicators.append(f"Suspicious SUID backdoor: File '{fp}' is executable with ROOT privileges (SUID set).")
                        except Exception:
                            pass
            except Exception:
                pass
        return indicators

    def _parse_proc_net_ports(self, proto: str) -> Set[int]:
        """Helper to parse raw active ports from /proc/net/ tcp/udp files."""
        ports = set()
        path = f"/proc/net/{proto}"
        if not os.path.exists(path):
            return ports
        try:
            with open(path, "r") as f:
                lines = f.readlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) >= 2:
                    local_addr = parts[1]
                    if ":" in local_addr:
                        port_hex = local_addr.split(":")[1]
                        ports.add(int(port_hex, 16))
        except Exception:
            pass
        return ports

    def _check_hidden_ports(self) -> List[str]:
        """Compares socket listings from /proc/net/ with visible outputs of ss or netstat."""
        indicators = []
        
        # 1. Get raw ports from system /proc
        proc_ports = set()
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            proc_ports.update(self._parse_proc_net_ports(proto))
            
        if not proc_ports:
            return indicators

        # 2. Get reported ports from standard userland tooling
        cmd_ports = set()
        try:
            res = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                matches = re.findall(r":(\d+)\b", line)
                for m in matches:
                    cmd_ports.add(int(m))
        except Exception:
            try:
                res = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    matches = re.findall(r":(\d+)\b", line)
                    for m in matches:
                        cmd_ports.add(int(m))
            except Exception:
                return indicators  # Neither ss nor netstat is available, skip

        # 3. Detect ports in proc that are completely invisible to standard userland tools
        hidden_ports = proc_ports - cmd_ports
        for port in hidden_ports:
            if port > 0:
                indicators.append(f"Hidden network port: Port {port} is active in system sockets but hidden from ss/netstat listing.")
                
        return indicators

    def _check_known_rootkit_paths(self) -> List[str]:
        """Performs chkrootkit-style checks for files or folders typical to common Linux backdoors."""
        indicators = []
        known_bad_paths = {
            "/dev/.tmp": "Common hidden directory for rootkit files",
            "/dev/.adm": "Adore rootkit folder",
            "/dev/.lib": "Common rootkit library backup folder",
            "/dev/shm/.tmp": "Temporary hidden backdoor folder in shared memory",
            "/usr/lib/libproc.a": "Suspicious backup of proc library",
            "/usr/include/rpcsvc/key.h": "Often manipulated key file",
            "/dev/shm/.keys": "Reptile rootkit keys",
            "/dev/shm/yk": "Reptile rootkit executor",
            "/etc/rc.d/rc.sysinit": "Sometimes hijacked during system boot",
            "/lib/security/pam_userdb.so": "Backdoored PAM module location",
        }
        
        for path, reason in known_bad_paths.items():
            if os.path.exists(path):
                indicators.append(f"Known rootkit signature path found: {path} ({reason})")
                
        return indicators

    # ================= Windows Specific Checks =================

    def _check_windows_unsigned_drivers(self) -> List[str]:
        """Uses system 'driverquery' command to verify if any running system drivers are unsigned."""
        indicators = []
        import csv
        import io
        
        try:
            cmd = ["driverquery", "/si", "/fo", "csv"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            reader = csv.reader(io.StringIO(res.stdout))
            header = next(reader, None)
            if not header:
                return indicators
                
            is_signed_col = -1
            device_name_col = 0
            
            for idx, col in enumerate(header):
                col_normalized = col.lower().replace(" ", "")
                if "signed" in col_normalized:
                    is_signed_col = idx
                elif "devicename" in col_normalized:
                    device_name_col = idx
                    
            if is_signed_col != -1:
                for row in reader:
                    if len(row) > is_signed_col:
                        is_signed = row[is_signed_col].lower().strip()
                        dev_name = row[device_name_col] if len(row) > device_name_col else "Unknown"
                        if is_signed in ("false", "no"):
                            indicators.append(f"Unsigned kernel driver loaded: '{dev_name}' is active but unsigned.")
        except Exception as e:
            logger.debug(f"Error querying Windows driver signatures: {e}")
            
        return indicators

    def _check_windows_suspicious_driver_services(self) -> List[str]:
        """Scans Windows Registry for active kernel driver services mapped to user-writable paths or random names."""
        indicators = []
        if platform.system() != "Windows":
            return indicators
            
        try:
            import winreg
        except ImportError:
            return indicators
            
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            i = 0
            while True:
                try:
                    srv_name = winreg.EnumKey(key, i)
                    i += 1
                    
                    is_suspicious_name = False
                    if len(srv_name) >= 12 and re.match(r"^[0-9a-fA-F]+$", srv_name):
                        is_suspicious_name = True
                        
                    try:
                        sub_key = winreg.OpenKey(key, srv_name)
                        try:
                            srv_type, _ = winreg.QueryValueEx(sub_key, "Type")
                            image_path, _ = winreg.QueryValueEx(sub_key, "ImagePath")
                        except FileNotFoundError:
                            continue
                        finally:
                            sub_key.Close()
                            
                        # Type 1 = Kernel Driver, Type 2 = File System Driver
                        if srv_type in (1, 2) and isinstance(image_path, str):
                            img_path_lower = image_path.lower()
                            
                            # Drivers should normally run from System32/drivers.
                            # Flag any kernel drivers loaded from AppData, Temp, ProgramData, Users etc.
                            writable_locations = ["\\temp", "\\users\\", "\\appdata\\", "\\programdata\\", "localsemp"]
                            is_writable_path = any(loc in img_path_lower for loc in writable_locations)
                            
                            if is_writable_path:
                                indicators.append(
                                    f"Suspicious driver service path: Service '{srv_name}' loads driver from a user-writable location: '{image_path}'."
                                )
                            elif is_suspicious_name:
                                indicators.append(
                                    f"Suspicious service name: Service '{srv_name}' has a random-looking identifier and loads driver '{image_path}'."
                                )
                    except OSError:
                        pass
                except OSError:
                    break
            key.Close()
        except Exception as e:
            logger.debug(f"Error scanning Windows registry services: {e}")
            
        return indicators

    # ================= Risk Score Model =================

    def _calculate_risk_score(self, indicators: List[str]) -> int:
        """Calculates a normalized risk score (0-100) based on severity of findings."""
        score = 0
        for ind in indicators:
            ind_lower = ind.lower()
            if "malicious kernel module" in ind_lower:
                score += 45
            elif "hidden process" in ind_lower:
                score += 40
            elif "linker hijack" in ind_lower:
                score += 40
            elif "suid backdoor" in ind_lower:
                score += 35
            elif "hidden network port" in ind_lower:
                score += 30
            elif "suspicious driver service path" in ind_lower:
                score += 30
            elif "rootkit signature path found" in ind_lower:
                score += 25
            elif "unsigned kernel driver" in ind_lower:
                score += 15
            elif "suspicious service name" in ind_lower:
                score += 15
            else:
                score += 10
                
        return min(score, 100)
