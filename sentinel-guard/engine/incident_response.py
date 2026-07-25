"""
Sentinel Guard — Incident Response
Automated response actions and mitigation when threats are detected
"""
import os
import sys
import time
import signal
import subprocess
from enum import Enum
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Union, Any

from engine.quarantine import QuarantineManager
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ResponseAction:
    action_type: str
    target: str
    success: bool
    message: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")


class IncidentResponse:
    """Handles automated mitigation and response actions for detected threats."""

    def __init__(self, notifier=None):
        self.notifier = notifier

    def kill_process(self, pid: int) -> bool:
        """Terminate a suspicious process by PID."""
        logger.info(f"🛡️ Action triggered: Kill process PID {pid}")
        try:
            if sys.platform == "win32":
                # Windows process termination
                res = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                if res.returncode == 0:
                    logger.info(f"✅ Successfully killed process PID {pid} on Windows.")
                    return True
                else:
                    logger.warning(f"Failed to kill process PID {pid} via taskkill: {res.stderr.strip()}")
                    # Fallback to os.kill
                    os.kill(pid, 9)
                    logger.info(f"✅ Fallback termination succeeded for PID {pid}.")
                    return True
            else:
                # Unix process termination
                os.kill(pid, signal.SIGKILL)
                logger.info(f"✅ Successfully sent SIGKILL to process PID {pid}.")
                return True
        except ProcessLookupError:
            logger.warning(f"Process PID {pid} already terminated or does not exist.")
            return True
        except PermissionError as e:
            logger.error(f"❌ Permission denied when trying to terminate process PID {pid}: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Error terminating process PID {pid}: {e}")
            return False

    def block_ip(self, ip: str) -> bool:
        """Add IP to blocklist (iptables on Linux, Windows Firewall on Windows)."""
        logger.info(f"🛡️ Action triggered: Block IP {ip}")
        try:
            if sys.platform == "win32":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Sentinel_Block_IP_{ip}",
                    "dir=in", "action=block", f"remoteip={ip}"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                if res.returncode == 0:
                    logger.info(f"✅ Successfully blocked inbound IP {ip} via Windows Firewall.")
                    return True
                else:
                    logger.error(f"❌ Failed to block IP {ip} via netsh: {res.stderr.strip()}")
                    return False
            else:
                cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                if res.returncode == 0:
                    logger.info(f"✅ Successfully blocked IP {ip} via iptables.")
                    return True
                else:
                    logger.error(f"❌ Failed to block IP {ip} via iptables: {res.stderr.strip()}")
                    return False
        except PermissionError:
            logger.error(f"❌ Permission denied: Administrator/Root privileges required to block IP {ip}.")
            return False
        except Exception as e:
            logger.error(f"❌ Error blocking IP {ip}: {e}")
            return False

    def isolate_file(self, file_path: str) -> bool:
        """Move file to quarantine and remove from all common locations."""
        logger.info(f"🛡️ Action triggered: Isolate file {file_path}")
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File {file_path} not found. It may have already been removed.")
            return True

        try:
            # Try computing sha256 to pass to QuarantineManager
            sha256 = ""
            try:
                from utils.hasher import compute_sha256
                sha256 = compute_sha256(str(path))
            except Exception as e:
                logger.warning(f"Could not compute SHA-256 for {file_path}: {e}")

            # Quarantine original file using QuarantineManager
            qm = QuarantineManager()
            qid = qm.quarantine_file(
                file_path=str(path.resolve()),
                sha256=sha256,
                threat_name="IncidentResponse.AutoIsolate"
            )

            if qid:
                logger.info(f"🔒 Original file quarantined. Quarantine ID: {qid}")

                # Ensure removal from common locations if duplicates exist with the same filename
                filename = path.name
                common_dirs = []
                if sys.platform == "win32":
                    user_profile = os.environ.get("USERPROFILE", "")
                    common_dirs = [
                        os.path.join(user_profile, "Downloads"),
                        os.path.join(user_profile, "Desktop"),
                        os.path.join(user_profile, "Documents"),
                        os.environ.get("TEMP", ""),
                    ]
                else:
                    home = os.path.expanduser("~")
                    common_dirs = [
                        os.path.join(home, "Downloads"),
                        os.path.join(home, "Desktop"),
                        "/tmp",
                        "/var/tmp"
                    ]

                for dir_path in common_dirs:
                    if dir_path and os.path.isdir(dir_path):
                        duplicate = Path(dir_path) / filename
                        # Do not delete the quarantine dir path itself or the newly quarantined file
                        if duplicate.exists() and duplicate.resolve() != path.resolve():
                            try:
                                dup_sha256 = ""
                                try:
                                    dup_sha256 = compute_sha256(str(duplicate))
                                except:
                                    pass
                                qm.quarantine_file(
                                    file_path=str(duplicate.resolve()),
                                    sha256=dup_sha256,
                                    threat_name="IncidentResponse.DuplicateAutoIsolate"
                                )
                                logger.info(f"🗑️ Removed duplicate threat from common location: {duplicate}")
                            except Exception as ex:
                                logger.warning(f"Could not remove duplicate threat from {duplicate}: {ex}")
                return True
            else:
                logger.error(f"❌ QuarantineManager failed to isolate {file_path}")
                return False
        except Exception as e:
            logger.error(f"❌ Error isolating file {file_path}: {e}")
            return False

    def disable_startup_entry(self, name: str) -> bool:
        """Disable a suspicious startup entry."""
        logger.info(f"🛡️ Action triggered: Disable startup entry {name}")
        success = False

        if sys.platform == "win32":
            # 1. Try Windows Registry Run Keys
            try:
                import winreg
                reg_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]
                for hive, path in reg_paths:
                    try:
                        key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
                        try:
                            winreg.DeleteValue(key, name)
                            logger.info(f"✅ Successfully deleted registry startup value: '{name}' in '{path}'")
                            success = True
                        except FileNotFoundError:
                            pass
                        finally:
                            winreg.CloseKey(key)
                    except PermissionError:
                        logger.warning(f"Permission denied modifying registry path: {path}")
                    except Exception:
                        pass
            except ImportError:
                pass

            # 2. Try Startup Folder
            startup_folders = [
                os.path.expanduser(r'~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
                r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
            ]
            for folder in startup_folders:
                if os.path.isdir(folder):
                    for f in os.listdir(folder):
                        if name.lower() in f.lower():
                            target = Path(folder) / f
                            try:
                                target.rename(target.with_suffix(target.suffix + ".disabled"))
                                logger.info(f"✅ Disabled startup shortcut: {target}")
                                success = True
                            except Exception as e:
                                logger.error(f"Error disabling startup folder file {target}: {e}")
        else:
            # Linux Startup Mechanisms
            # 1. Systemd Service
            service_name = name if name.endswith(".service") else f"{name}.service"
            try:
                subprocess.run(["systemctl", "stop", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                res = subprocess.run(["systemctl", "disable", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if res.returncode == 0:
                    logger.info(f"✅ Successfully disabled systemd service: {service_name}")
                    success = True
            except Exception:
                pass

            # Rename systemd file if exists
            systemd_paths = ['/etc/systemd/system/', '/lib/systemd/system/', os.path.expanduser('~/.config/systemd/user/')]
            for path in systemd_paths:
                if os.path.isdir(path):
                    target_file = Path(path) / service_name
                    if target_file.exists():
                        try:
                            target_file.rename(target_file.with_suffix(".service.disabled"))
                            logger.info(f"✅ Renamed systemd service file to .disabled: {target_file}")
                            success = True
                        except Exception:
                            pass

            # 2. Desktop Autostart Files
            autostart_paths = [
                '/etc/xdg/autostart/',
                os.path.expanduser('~/.config/autostart/'),
            ]
            for path in autostart_paths:
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        if name.lower() in f.lower() and f.endswith(".desktop"):
                            target = Path(path) / f
                            try:
                                target.rename(target.with_suffix(".desktop.disabled"))
                                logger.info(f"✅ Renamed autostart .desktop file to .disabled: {target}")
                                success = True
                            except Exception:
                                pass

            # 3. Cron jobs
            cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/', '/etc/cron.weekly/', '/etc/cron.monthly/']
            for path in cron_dirs:
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        if name.lower() in f.lower():
                            target = Path(path) / f
                            try:
                                target.rename(target.with_suffix(target.suffix + ".disabled"))
                                logger.info(f"✅ Renamed cron job file to .disabled: {target}")
                                success = True
                            except Exception:
                                pass

        if success:
            logger.info(f"✅ Startup entry '{name}' disabled successfully.")
        else:
            logger.warning(f"Could not find or disable startup entry: '{name}'.")
        return success

    def block_domain(self, domain: str) -> bool:
        """Add domain to hosts file as 0.0.0.0."""
        logger.info(f"🛡️ Action triggered: Block domain {domain}")
        if sys.platform == "win32":
            hosts_path = os.path.join(
                os.environ.get('SystemRoot', 'C:\\Windows'),
                'System32', 'drivers', 'etc', 'hosts'
            )
        else:
            hosts_path = '/etc/hosts'

        if not os.path.exists(hosts_path):
            logger.error(f"Hosts file not found at {hosts_path}")
            return False

        domain = domain.strip().lower()
        if not domain:
            return False

        try:
            with open(hosts_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Simple duplication check
            already_blocked = False
            for line in content.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith('#'):
                    continue
                parts = line_stripped.split()
                if len(parts) >= 2 and parts[1].lower() == domain:
                    already_blocked = True
                    break

            if already_blocked:
                logger.info(f"Domain {domain} is already listed in the hosts file.")
                return True

            # Append block entry
            entry = f"\n0.0.0.0 {domain} # Sentinel Guard Blocked Domain\n"
            with open(hosts_path, 'a', encoding='utf-8') as f:
                f.write(entry)

            logger.info(f"✅ Successfully blocked domain {domain} in {hosts_path}")
            return True
        except PermissionError:
            logger.error(f"❌ Permission denied: Administrator/Root privileges required to edit {hosts_path}")
            return False
        except Exception as e:
            logger.error(f"❌ Error blocking domain {domain}: {e}")
            return False

    def create_incident_report(self, threats) -> dict:
        """Create structured incident report."""
        import socket
        import getpass
        import uuid

        if not isinstance(threats, list):
            threats = [threats]

        logger.info(f"Generating structured incident report for {len(threats)} threat(s)...")

        severity = "CLEAN"
        severity_map = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        threat_details = []
        for threat in threats:
            details = {}
            if hasattr(threat, "file_path"):  # ScanResult
                details["type"] = "file"
                details["path"] = getattr(threat, "file_path", "")
                details["name"] = getattr(threat, "threat_name", "Unknown Threat")
                details["sha256"] = getattr(threat, "sha256", "")
                
                level_attr = getattr(threat, "threat_level", "CLEAN")
                level_str = level_attr.name if isinstance(level_attr, Enum) else str(level_attr)
                details["threat_level"] = level_str.upper()

            elif hasattr(threat, "pid"):  # ProcessInfo
                details["type"] = "process"
                details["pid"] = getattr(threat, "pid", 0)
                details["name"] = getattr(threat, "name", "Unknown Process")
                details["path"] = getattr(threat, "path", "")
                details["reason"] = getattr(threat, "reason", "")
                details["threat_level"] = "HIGH"

            elif hasattr(threat, "type") and hasattr(threat, "name") and hasattr(threat, "path") and not hasattr(threat, "threat_level"):  # StartupEntry
                details["type"] = "startup_entry"
                details["name"] = getattr(threat, "name", "")
                details["path"] = getattr(threat, "path", "")
                details["entry_type"] = getattr(threat, "type", "")
                details["reason"] = getattr(threat, "reason", "")
                details["threat_level"] = "HIGH"

            elif isinstance(threat, dict):
                details = threat.copy()
                if "threat_level" not in details:
                    details["threat_level"] = "HIGH"
            else:
                details["type"] = "unknown"
                details["raw"] = str(threat)
                details["threat_level"] = "MEDIUM"

            level = details.get("threat_level", "MEDIUM").upper()
            if severity_map.get(level, 0) > severity_map.get(severity, 0):
                severity = level

            threat_details.append(details)

        ip_addr = "unknown"
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

        report = {
            "incident_id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "system_info": {
                "hostname": socket.gethostname(),
                "os": sys.platform,
                "current_user": getpass.getuser(),
                "ip_address": ip_addr
            },
            "threats_count": len(threats),
            "threat_details": threat_details,
            "status": "responded" if severity in ("HIGH", "CRITICAL") else "logged_only"
        }

        return report

    def escalate_to_admin(self, report: dict) -> bool:
        """Send alert (via notifier)."""
        logger.info(f"Escalating incident {report.get('incident_id', 'unknown')} to administrator...")
        try:
            from engine.notifier import Notifier
            notifier = self.notifier
            if not notifier:
                notifier = Notifier()

            title = f"🚨 Sentinel Guard Incident: [{report.get('severity', 'HIGH')}]"

            msg_parts = [
                f"Incident ID: {report.get('incident_id')}",
                f"Severity: {report.get('severity')}",
                f"Time: {report.get('timestamp')}",
                f"Host: {report.get('system_info', {}).get('hostname')} ({report.get('system_info', {}).get('os')})",
                f"User: {report.get('system_info', {}).get('current_user')}",
                f"Threats Detected: {report.get('threats_count')}",
                "\nThreat Details:"
            ]

            for i, td in enumerate(report.get("threat_details", []), 1):
                t_type = td.get("type", "unknown").upper()
                t_name = td.get("name", "Unknown Threat")
                t_path = td.get("path", td.get("file_path", ""))
                msg_parts.append(f"  {i}. [{t_type}] {t_name} at {t_path}")

            message = "\n".join(msg_parts)

            success = notifier.send_alert(
                title=title,
                message=message,
                severity=report.get('severity', 'HIGH')
            )
            if success:
                logger.info(f"✅ Escalation successfully sent via notifier.")
            else:
                logger.error(f"❌ Notifier failed to send escalation.")
            return success
        except Exception as e:
            logger.error(f"❌ Error escalating incident to admin: {e}")
            return False

    def respond(self, scan_result) -> ResponseAction:
        """Decide and execute automated response based on threat level."""
        # Determine threat level
        threat_level_val = "CLEAN"
        if hasattr(scan_result, "threat_level"):
            val = scan_result.threat_level
            if isinstance(val, Enum):
                threat_level_val = val.name
            elif isinstance(val, str):
                threat_level_val = val.upper()
        elif isinstance(scan_result, dict):
            val = scan_result.get("threat_level")
            if isinstance(val, Enum):
                threat_level_val = val.name
            elif isinstance(val, str):
                threat_level_val = val.upper()

        is_suspicious_process = getattr(scan_result, "is_suspicious", False)
        if is_suspicious_process:
            threat_level_val = "HIGH"

        logger.info(f"Evaluating automated response. Threat severity: {threat_level_val}")

        # Be conservative: only auto-respond to HIGH/CRITICAL threats
        if threat_level_val not in ("HIGH", "CRITICAL"):
            msg = f"Threat severity ({threat_level_val}) is below auto-response threshold (HIGH/CRITICAL). No automated response executed."
            logger.info(msg)
            return ResponseAction(
                action_type="NONE",
                target=str(getattr(scan_result, "file_path", getattr(scan_result, "name", "unknown"))),
                success=True,
                message=msg
            )

        action_type = "NONE"
        target = ""
        success = False
        message = ""

        # Process termination
        if hasattr(scan_result, "pid") and getattr(scan_result, "pid", 0) > 0:
            pid = getattr(scan_result, "pid")
            name = getattr(scan_result, "name", "unknown")
            action_type = "KILL_PROCESS"
            target = f"PID {pid} ({name})"
            success = self.kill_process(pid)
            message = f"Process {target} termination completed. Status: {success}"

        # Startup entry disabling
        elif hasattr(scan_result, "type") and hasattr(scan_result, "name") and hasattr(scan_result, "path") and not hasattr(scan_result, "threat_level"):
            name = getattr(scan_result, "name")
            action_type = "DISABLE_STARTUP"
            target = name
            success = self.disable_startup_entry(name)
            message = f"Startup entry '{name}' disable completed. Status: {success}"

        # File isolation (Quarantine)
        elif hasattr(scan_result, "file_path") and getattr(scan_result, "file_path", ""):
            file_path = getattr(scan_result, "file_path")
            action_type = "ISOLATE_FILE"
            target = file_path
            success = self.isolate_file(file_path)
            message = f"File isolation for {file_path} completed. Status: {success}"

        # Dict structure checking
        elif isinstance(scan_result, dict):
            if "pid" in scan_result:
                pid = scan_result["pid"]
                action_type = "KILL_PROCESS"
                target = f"PID {pid}"
                success = self.kill_process(pid)
                message = f"Process termination for PID {pid} completed. Status: {success}"
            elif "ip" in scan_result:
                ip = scan_result["ip"]
                action_type = "BLOCK_IP"
                target = ip
                success = self.block_ip(ip)
                message = f"IP blocking for {ip} completed. Status: {success}"
            elif "domain" in scan_result:
                domain = scan_result["domain"]
                action_type = "BLOCK_DOMAIN"
                target = domain
                success = self.block_domain(domain)
                message = f"Domain blocking for {domain} completed. Status: {success}"
            elif "file_path" in scan_result:
                file_path = scan_result["file_path"]
                action_type = "ISOLATE_FILE"
                target = file_path
                success = self.isolate_file(file_path)
                message = f"File isolation for {file_path} completed. Status: {success}"
            elif "startup_name" in scan_result:
                startup_name = scan_result["startup_name"]
                action_type = "DISABLE_STARTUP"
                target = startup_name
                success = self.disable_startup_entry(startup_name)
                message = f"Startup entry '{startup_name}' disable completed. Status: {success}"
            else:
                message = "Unsupported threat payload dictionary. Skipping automated response."
                logger.warning(message)
        else:
            message = "Unsupported threat object type. Skipping automated response."
            logger.warning(message)

        logger.info(f"Response actions executed: Action={action_type}, Target={target}, Success={success}, Message={message}")

        return ResponseAction(
            action_type=action_type,
            target=target,
            success=success,
            message=message
        )
