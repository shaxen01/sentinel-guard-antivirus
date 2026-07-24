"""
Sentinel Guard — Real-time File Monitor
Watches file system for new/modified files and scans them automatically
"""
import os
import time
from pathlib import Path
from typing import Optional, Callable
from threading import Thread
from utils.logger import get_logger

logger = get_logger(__name__)


class FileMonitor:
    """Real-time file system monitor using polling (no external deps required)."""

    # Extensions to monitor
    WATCHABLE_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
        '.vbs', '.js', '.jar', '.apk', '.sh', '.py', '.elf', '.so',
        '.lnk', '.hta', '.vbe', '.jse', '.wsf', '.doc', '.docx', '.xls',
        '.xlsx', '.pdf', '.htm', '.html', '.zip', '.rar', '.7z',
    }

    # Directories to skip
    SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
                 'site-packages', 'dist-packages', '/proc', '/sys', '/dev'}

    def __init__(self, scanner, watch_paths: list = None, poll_interval: float = 2.0):
        self.scanner = scanner
        self.watch_paths = watch_paths or [os.path.expanduser("~")]
        self.poll_interval = poll_interval
        self._running = False
        self._thread = None
        self._known_files = {}
        self._on_threat: Optional[Callable] = None

    def on_threat_detected(self, callback: Callable):
        """Register a callback for when a threat is detected."""
        self._on_threat = callback

    def start(self):
        """Start monitoring in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"👁️ Real-time monitor started — watching: {', '.join(self.watch_paths)}")

    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("👁️ Real-time monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        # Initial scan to build baseline
        logger.info("Building file baseline (first pass)...")
        for watch_path in self.watch_paths:
            self._scan_baseline(watch_path)
        logger.info(f"Baseline established: {len(self._known_files)} files tracked")

        while self._running:
            time.sleep(self.poll_interval)
            for watch_path in self.watch_paths:
                self._check_changes(watch_path)

    def _scan_baseline(self, root: str):
        """Build initial file baseline."""
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip system/hidden directories
                dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]

                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        stat = os.stat(fpath)
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in self.WATCHABLE_EXTENSIONS:
                            self._known_files[fpath] = {
                                'mtime': stat.st_mtime,
                                'size': stat.st_size
                            }
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            logger.debug(f"Baseline scan error on {root}: {e}")

    def _check_changes(self, root: str):
        """Check for new or modified files."""
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]

                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    ext = os.path.splitext(fname)[1].lower()

                    if ext not in self.WATCHABLE_EXTENSIONS:
                        continue

                    try:
                        stat = os.stat(fpath)
                        known = self._known_files.get(fpath)

                        if known is None:
                            # New file detected
                            logger.info(f"📁 New file detected: {fpath}")
                            self._known_files[fpath] = {'mtime': stat.st_mtime, 'size': stat.st_size}
                            self._scan_file_realtime(fpath)

                        elif stat.st_mtime != known['mtime'] or stat.st_size != known['size']:
                            # Modified file
                            logger.info(f"📝 Modified file: {fpath}")
                            self._known_files[fpath] = {'mtime': stat.st_mtime, 'size': stat.st_size}
                            self._scan_file_realtime(fpath)

                    except (OSError, PermissionError):
                        pass

            # Check for deleted files
            deleted = [fp for fp in self._known_files if not os.path.exists(fp)]
            for fp in deleted:
                del self._known_files[fp]

        except Exception as e:
            logger.debug(f"Monitor check error on {root}: {e}")

    def _scan_file_realtime(self, file_path: str):
        """Scan a file detected by the monitor."""
        try:
            result = self.scanner.scan_file(file_path)
            if result.is_threat:
                logger.warning(f"🚨 Real-time threat: {result.threat_name} → {file_path}")

                # Auto-quarantine high/critical threats
                if result.threat_level.value in ('high', 'critical'):
                    self.scanner.quarantine.quarantine_file(
                        file_path, result.sha256, result.threat_name
                    )
                    logger.info(f"🔒 Auto-quarantined: {file_path}")

                if self._on_threat:
                    self._on_threat(result)

        except Exception as e:
            logger.debug(f"Real-time scan error on {file_path}: {e}")
