"""
Sentinel Guard — Scan Scheduler
Handles scheduled/periodic scans
"""
import time
import json
import threading
from typing import Callable, Optional
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


class ScanScheduler:
    """Schedules and runs periodic scans."""

    def __init__(self, config_path: str = "data/schedules.json"):
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._schedules = {}
        self._thread = None
        self._running = False
        self._callback = None
        self._load()

    def _load(self):
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self._schedules = json.load(f)
        else:
            self._schedules = {"schedules": []}
            self._save()

    def _save(self):
        with open(self.config_path, 'w') as f:
            json.dump(self._schedules, f, indent=2)

    def add_schedule(self, name: str, path: str, interval_minutes: int,
                     auto_quarantine: bool = False):
        """Add a scheduled scan."""
        schedule = {
            "name": name,
            "path": path,
            "interval_minutes": interval_minutes,
            "auto_quarantine": auto_quarantine,
            "last_run": "",
            "next_run": time.strftime("%Y-%m-%d %H:%M:%S"),
            "enabled": True,
        }
        self._schedules["schedules"].append(schedule)
        self._save()
        logger.info(f"📅 Schedule added: {name} — every {interval_minutes} min")

    def remove_schedule(self, name: str) -> bool:
        """Remove a scheduled scan."""
        before = len(self._schedules["schedules"])
        self._schedules["schedules"] = [
            s for s in self._schedules["schedules"] if s["name"] != name
        ]
        if len(self._schedules["schedules"]) < before:
            self._save()
            return True
        return False

    def set_callback(self, callback: Callable):
        """Set callback for when a scheduled scan runs."""
        self._callback = callback

    def start(self):
        """Start the scheduler daemon."""
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("📅 Scan scheduler started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._running:
            time.sleep(60)  # Check every minute
            now = time.time()
            for schedule in self._schedules["schedules"]:
                if not schedule.get("enabled", True):
                    continue
                last_run = schedule.get("last_run_timestamp", 0)
                interval_sec = schedule["interval_minutes"] * 60
                if now - last_run >= interval_sec:
                    logger.info(f"📅 Running scheduled scan: {schedule['name']}")
                    schedule["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    schedule["last_run_timestamp"] = now
                    self._save()
                    if self._callback:
                        try:
                            self._callback(schedule)
                        except Exception as e:
                            logger.error(f"Scheduled scan error: {e}")

    def list_schedules(self):
        return self._schedules["schedules"]

    def toggle_schedule(self, name: str) -> bool:
        for s in self._schedules["schedules"]:
            if s["name"] == name:
                s["enabled"] = not s.get("enabled", True)
                self._save()
                return s["enabled"]
        return None
