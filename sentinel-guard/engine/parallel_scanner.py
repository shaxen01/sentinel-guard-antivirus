"""
Sentinel Guard — Parallel Scanner
Multi-threaded file scanning with ThreadPoolExecutor
"""
import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional
from dataclasses import dataclass
from engine.scanner import Scanner, ScanResult, ScanReport, ThreatLevel
from engine.api_scanner import APIScanner, MultiAPIResult
from engine.whitelist import Whitelist
from utils.logger import get_logger

logger = get_logger(__name__)


class ParallelScanner(Scanner):
    """Multi-threaded scanner with API integration and whitelist support."""

    def __init__(self, db_path: str = "data/signatures.db",
                 quarantine_dir: str = "data/quarantine",
                 max_workers: int = 8,
                 enable_api_scan: bool = False,
                 api_scanner: Optional[APIScanner] = None,
                 whitelist: Optional[Whitelist] = None):
        super().__init__(db_path, quarantine_dir)
        self.max_workers = max_workers
        self.enable_api_scan = enable_api_scan
        self.api_scanner = api_scanner or APIScanner()
        self.whitelist = whitelist or Whitelist()
        self._api_results: List[MultiAPIResult] = []

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file with whitelist + local + API checks."""
        result = super().scan_file(file_path)

        # Skip whitelist check for threats (they shouldn't be whitelisted)
        if not result.is_threat and result.sha256:
            if self.whitelist.is_whitelisted(result.sha256):
                result.threat_level = ThreatLevel.CLEAN
                result.heuristic_score = 0
                result.heuristic_flags = ["whitelisted"]
                return result

        # API scan for files that passed local checks (suspicious or unknown)
        if self.enable_api_scan and result.sha256 and not result.is_threat:
            if result.heuristic_score >= 20 or self.enable_api_scan:
                api_result = self.api_scanner.scan_hash_parallel(result.sha256)
                self._api_results.append(api_result)
                if api_result.is_threat:
                    result.threat_level = ThreatLevel.HIGH
                    result.threat_name = f"API.MultiEngine ({api_result.total_detected}/{api_result.total_queried} engines)"
                    result.threat_type = "api_cloud"
                    result.heuristic_flags.append(f"api_detection ({api_result.consensus_score}% consensus)")
                    logger.warning(f"☁️ API DETECTED: {result.threat_name} → {result.file_name}")

        return result

    def scan_directory_parallel(self, directory: str, recursive: bool = True,
                                 auto_quarantine: bool = False,
                                 progress_callback: Callable = None) -> ScanReport:
        """Scan directory with multiple threads in parallel."""
        self._stop_requested = False
        self._api_results = []
        start_time = time.time()
        report = ScanReport(
            scan_id=f"scan_{int(start_time)}",
            started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            root_path=str(Path(directory).resolve()),
        )

        logger.info(f"🔍 Parallel scan started: {directory} ({self.max_workers} threads)")
        if self.enable_api_scan:
            apis = self.api_scanner.get_available_apis()
            active = [a["name"] for a in apis if a["status"] == "active"]
            logger.info(f"   Cloud APIs: {', '.join(active) if active else 'disabled'}")

        # Collect files
        file_list = []
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    if self._stop_requested:
                        break
                    for f in files:
                        file_list.append(os.path.join(root, f))
            else:
                for f in os.listdir(directory):
                    fp = os.path.join(directory, f)
                    if os.path.isfile(fp):
                        file_list.append(fp)
        except Exception as e:
            report.errors.append(f"Directory walk error: {e}")

        report.total_files = len(file_list)
        logger.info(f"   Files to scan: {report.total_files}")

        # Scan in parallel
        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.scan_file, fp): fp for fp in file_list}

            for future in as_completed(futures):
                if self._stop_requested:
                    break

                result = future.result()
                completed += 1
                report.scanned_files += 1

                if result.is_threat:
                    report.threats_found += 1
                    report.results.append(result)

                    if auto_quarantine and result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                        self.quarantine.quarantine_file(
                            futures[future], result.sha256, result.threat_name
                        )
                        report.files_quarantined += 1

                if progress_callback:
                    progress_callback(completed, report.total_files, result)

        report.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        report.scan_duration = time.time() - start_time

        logger.info(f"✅ Scan complete: {report.scanned_files} files, "
                     f"{report.threats_found} threats, "
                     f"{report.files_quarantined} quarantined, "
                     f"{report.scan_duration:.1f}s "
                     f"({report.scanned_files/max(report.scan_duration, 0.1):.0f} files/s)")

        return report

    def get_api_results(self) -> List[MultiAPIResult]:
        """Get results from API scans."""
        return self._api_results
