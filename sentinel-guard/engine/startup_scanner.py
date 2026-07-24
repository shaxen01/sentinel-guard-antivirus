"""
Sentinel Guard — Startup Scanner
Detects autostart entries that could be persistence mechanisms
"""
import os
import glob
from typing import List, Dict
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class StartupEntry:
    name: str
    path: str
    type: str  # "registry", "cron", "systemd", "rc", "autostart"
    enabled: bool = True
    is_suspicious: bool = False
    reason: str = ""


class StartupScanner:
    """Scans for autostart/persistence entries."""

    SUSPICIOUS_KEYWORDS = [
        'powershell', 'cmd.exe', 'wscript', 'cscript',
        'rundll32', 'regsvr32', 'mshta', 'certutil',
        'bitsadmin', 'msiexec', 'installutil',
    ]

    SUSPICIOUS_PATHS = [
        '/tmp/', '/var/tmp/', '/dev/shm/',
        'C:\\Temp\\', 'AppData\\Local\\Temp\\',
    ]

    def scan_all(self) -> List[StartupEntry]:
        """Scan all startup locations."""
        entries = []
        if os.name == 'nt':
            entries = self._scan_windows()
        else:
            entries = self._scan_linux()
        return entries

    def _scan_linux(self) -> List[StartupEntry]:
        """Scan Linux startup locations."""
        entries = []

        # Systemd services
        entries.extend(self._scan_systemd())

        # Cron jobs
        entries.extend(self._scan_cron())

        # RC scripts
        entries.extend(self._scan_rc())

        # Autostart (.desktop files)
        entries.extend(self._scan_autostart())

        # Check each entry
        for entry in entries:
            self._check_suspicious(entry)

        return entries

    def _scan_systemd(self) -> List[StartupEntry]:
        """Scan systemd service files."""
        entries = []
        systemd_paths = [
            '/etc/systemd/system/',
            '/lib/systemd/system/',
            os.path.expanduser('~/.config/systemd/user/'),
        ]
        for path in systemd_paths:
            for service_file in glob.glob(os.path.join(path, '*.service')):
                try:
                    with open(service_file, 'r') as f:
                        content = f.read()
                    name = os.path.basename(service_file)
                    # Extract ExecStart
                    exec_start = ""
                    for line in content.split('\n'):
                        if line.startswith('ExecStart='):
                            exec_start = line.split('=', 1)[1].strip()
                            break
                    entries.append(StartupEntry(
                        name=name,
                        path=exec_start or service_file,
                        type="systemd",
                    ))
                except (PermissionError, FileNotFoundError):
                    continue
        return entries

    def _scan_cron(self) -> List[StartupEntry]:
        """Scan cron jobs."""
        entries = []
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/',
        ]

        # User crontabs
        if os.path.exists('/var/spool/cron/crontabs'):
            for f in os.listdir('/var/spool/cron/crontabs'):
                entries.append(StartupEntry(
                    name=f"user_cron_{f}",
                    path=f"/var/spool/cron/crontabs/{f}",
                    type="cron",
                ))

        for cron_path in cron_paths:
            if os.path.isfile(cron_path):
                entries.append(StartupEntry(
                    name=os.path.basename(cron_path),
                    path=cron_path,
                    type="cron",
                ))
            elif os.path.isdir(cron_path):
                for f in os.listdir(cron_path):
                    entries.append(StartupEntry(
                        name=f,
                        path=os.path.join(cron_path, f),
                        type="cron",
                    ))
        return entries

    def _scan_rc(self) -> List[StartupEntry]:
        """Scan rc.local and init.d scripts."""
        entries = []
        rc_paths = ['/etc/rc.local', '/etc/init.d/']
        for path in rc_paths:
            if os.path.isfile(path):
                entries.append(StartupEntry(name=os.path.basename(path), path=path, type="rc"))
            elif os.path.isdir(path):
                for f in os.listdir(path):
                    if f.startswith('S') or f.startswith('K'):
                        entries.append(StartupEntry(name=f, path=os.path.join(path, f), type="rc"))
        return entries

    def _scan_autostart(self) -> List[StartupEntry]:
        """Scan .desktop autostart files."""
        entries = []
        autostart_paths = [
            '/etc/xdg/autostart/',
            os.path.expanduser('~/.config/autostart/'),
        ]
        for path in autostart_paths:
            if os.path.isdir(path):
                for f in os.listdir(path):
                    if f.endswith('.desktop'):
                        full = os.path.join(path, f)
                        try:
                            with open(full, 'r') as df:
                                content = df.read()
                            exec_line = ""
                            for line in content.split('\n'):
                                if line.startswith('Exec='):
                                    exec_line = line.split('=', 1)[1].strip()
                                    break
                            entries.append(StartupEntry(
                                name=f,
                                path=exec_line or full,
                                type="autostart",
                            ))
                        except (PermissionError, FileNotFoundError):
                            continue
        return entries

    def _scan_windows(self) -> List[StartupEntry]:
        """Scan Windows startup locations."""
        entries = []

        # Registry Run keys
        try:
            import winreg
            reg_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            for hive, path in reg_paths:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries.append(StartupEntry(
                                name=name, path=str(value), type="registry"
                            ))
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except ImportError:
            pass

        # Startup folder
        startup_folders = [
            os.path.expanduser(r'~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        ]
        for folder in startup_folders:
            if os.path.isdir(folder):
                for f in os.listdir(folder):
                    entries.append(StartupEntry(
                        name=f, path=os.path.join(folder, f), type="startup_folder"
                    ))

        for entry in entries:
            self._check_suspicious(entry)
        return entries

    def _check_suspicious(self, entry: StartupEntry):
        """Check if a startup entry is suspicious."""
        path_lower = entry.path.lower()

        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in path_lower:
                entry.is_suspicious = True
                entry.reason = f"Suspicious command: {keyword}"
                return

        for sus_path in self.SUSPICIOUS_PATHS:
            if sus_path.lower() in path_lower:
                entry.is_suspicious = True
                entry.reason = f"Running from suspicious path: {sus_path}"
                return

    def get_suspicious(self) -> List[StartupEntry]:
        return [e for e in self.scan_all() if e.is_suspicious]
