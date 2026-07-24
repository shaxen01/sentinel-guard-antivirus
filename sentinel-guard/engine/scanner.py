"""
Sentinel Guard — Real Antivirus Engine
Core scanner module
"""
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from engine.signatures import SignatureDatabase
from engine.heuristics import HeuristicAnalyzer
from engine.quarantine import QuarantineManager
from utils.hasher import compute_sha256, compute_md5
from utils.logger import get_logger

logger = get_logger(__name__)


class ThreatLevel(Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    threat_name: str = ""
    threat_type: str = ""  # "signature" or "heuristic"
    heuristic_score: int = 0
    heuristic_flags: List[str] = field(default_factory=list)
    scanned_at: str = ""

    @property
    def is_threat(self) -> bool:
        return self.threat_level != ThreatLevel.CLEAN


@dataclass
class ScanReport:
    scan_id: str
    started_at: str
    finished_at: str = ""
    root_path: str = ""
    total_files: int = 0
    scanned_files: int = 0
    threats_found: int = 0
    files_quarantined: int = 0
    scan_duration: float = 0.0
    results: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def clean_files(self) -> int:
        return self.scanned_files - self.threats_found


class Scanner:
    """Core antivirus scanning engine."""

    # Max file size to scan (skip very large files by default)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

    # File extensions to scan
    SCANABLE_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
        '.vbs', '.js', '.jar', '.apk', '.deb', '.rpm', '.dmg', '.pkg',
        '.msi', '.sh', '.py', '.rb', '.pl', '.php', '.elf', '.so',
        '.dylib', '.bin', '.dat', '.tmp', '.zip', '.rar', '.7z', '.tar',
        '.gz', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.htm', '.html',
        '.hta', '.lnk', '.inf', '.reg', '.vbe', '.jse', '.wsf', '.wsh',
    }

    def __init__(self, db_path: str = "data/signatures.db",
                 quarantine_dir: str = "data/quarantine"):
        self.sig_db = SignatureDatabase(db_path)
        self.heuristics = HeuristicAnalyzer()
        self.quarantine = QuarantineManager(quarantine_dir)
        self._stop_requested = False

    def stop(self):
        """Request scan to stop gracefully."""
        self._stop_requested = True
        logger.info("Stop requested — finishing current file...")

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file for threats."""
        path = Path(file_path)
        result = ScanResult(
            file_path=str(path.resolve()),
            file_name=path.name,
            file_size=0,
            sha256="",
            scanned_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        try:
            if not path.exists():
                result.threat_level = ThreatLevel.CLEAN
                return result

            if path.is_dir():
                return result

            result.file_size = path.stat().st_size

            if result.file_size > self.MAX_FILE_SIZE:
                logger.debug(f"Skipping large file: {path.name} ({result.file_size} bytes)")
                return result

            # --- 1. Signature-based detection ---
            sha256 = compute_sha256(str(path))
            result.sha256 = sha256

            sig_match = self.sig_db.check_hash(sha256)
            if sig_match:
                result.threat_level = ThreatLevel[sig_match.get("severity", "HIGH").upper()]
                result.threat_name = sig_match.get("name", "Unknown")
                result.threat_type = "signature"
                logger.warning(f"⚠ THREAT DETECTED (signature): {sig_match['name']} → {path.name}")
                return result

            # --- 2. Heuristic analysis ---
            score, flags = self.heuristics.analyze(str(path))
            result.heuristic_score = score
            result.heuristic_flags = flags

            if score >= 70:
                result.threat_level = ThreatLevel.HIGH
                result.threat_name = "Heuristic.HighRisk"
                result.threat_type = "heuristic"
                logger.warning(f"⚠ THREAT DETECTED (heuristic, score={score}): {path.name} — {flags}")
            elif score >= 40:
                result.threat_level = ThreatLevel.MEDIUM
                result.threat_name = "Heuristic.Suspicious"
                result.threat_type = "heuristic"
                logger.info(f"⚡ Suspicious file (score={score}): {path.name} — {flags}")
            elif score >= 20:
                result.threat_level = ThreatLevel.LOW
                result.threat_name = "Heuristic.Note"
                result.threat_type = "heuristic"

        except PermissionError:
            logger.debug(f"Permission denied: {file_path}")
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")

        return result

    def scan_directory(self, directory: str, recursive: bool = True,
                       auto_quarantine: bool = False,
                       progress_callback=None) -> ScanReport:
        """Scan an entire directory tree."""
        self._stop_requested = False
        start_time = time.time()
        report = ScanReport(
            scan_id=f"scan_{int(start_time)}",
            started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            root_path=str(Path(directory).resolve()),
        )

        logger.info(f"🔍 Scan started: {directory}")
        logger.info(f"   Mode: {'recursive' if recursive else 'shallow'}")

        # Count files first for progress
        file_list = []
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    if self._stop_requested:
                        break
                    for f in files:
                        file_path = os.path.join(root, f)
                        ext = os.path.splitext(f)[1].lower()
                        # Scan all files, but track extension-based ones
                        file_list.append(file_path)
            else:
                for f in os.listdir(directory):
                    fp = os.path.join(directory, f)
                    if os.path.isfile(fp):
                        file_list.append(fp)
        except Exception as e:
            report.errors.append(f"Directory walk error: {e}")
            logger.error(f"Directory walk error: {e}")

        report.total_files = len(file_list)
        logger.info(f"   Files to scan: {report.total_files}")

        # Scan each file
        for i, file_path in enumerate(file_list):
            if self._stop_requested:
                logger.info("Scan stopped by user.")
                break

            result = self.scan_file(file_path)
            report.scanned_files += 1

            if result.is_threat:
                report.threats_found += 1
                report.results.append(result)

                if auto_quarantine and result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                    self.quarantine.quarantine_file(file_path, result.sha256, result.threat_name)
                    report.files_quarantined += 1
                    logger.info(f"🔒 Auto-quarantined: {result.file_name}")

            if progress_callback:
                progress_callback(i + 1, report.total_files, result)

        report.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        report.scan_duration = time.time() - start_time

        logger.info(f"✅ Scan complete: {report.scanned_files} files, "
                     f"{report.threats_found} threats, "
                     f"{report.files_quarantined} quarantined, "
                     f"{report.scan_duration:.1f}s")

        return report

    def generate_report_txt(self, report: ScanReport) -> str:
        """Generate a text report from a scan report."""
        lines = []
        lines.append("=" * 60)
        lines.append("       SENTINEL GUARD — TARAMA RAPORU")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Tarama ID     : {report.scan_id}")
        lines.append(f"Başlangıç    : {report.started_at}")
        lines.append(f"Bitiş        : {report.finished_at}")
        lines.append(f"Taranan Dizin: {report.root_path}")
        lines.append(f"Süre         : {report.scan_duration:.1f} saniye")
        lines.append(f"Toplam Dosya : {report.total_files}")
        lines.append(f"Taranan      : {report.scanned_files}")
        lines.append(f"Temiz        : {report.clean_files}")
        lines.append(f"Tehdit       : {report.threats_found}")
        lines.append(f"Karantina    : {report.files_quarantined}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("TEHDİT DETAYLARI")
        lines.append("-" * 60)
        lines.append("")

        if not report.results:
            lines.append("  Tehdit tespit edilmedi. Sistem güvenli.")
        else:
            for i, r in enumerate(report.results, 1):
                lines.append(f"  [{i}] {r.threat_name}")
                lines.append(f"      Tür          : {r.threat_type}")
                lines.append(f"      Risk Seviyesi: {r.threat_level.value.upper()}")
                lines.append(f"      Dosya        : {r.file_name}")
                lines.append(f"      Yol          : {r.file_path}")
                lines.append(f"      SHA256       : {r.sha256}")
                if r.heuristic_flags:
                    lines.append(f"      Heuristic    : score={r.heuristic_score}, flags={', '.join(r.heuristic_flags)}")
                lines.append("")

        if report.errors:
            lines.append("-" * 60)
            lines.append("HATALAR")
            lines.append("-" * 60)
            for e in report.errors:
                lines.append(f"  ! {e}")
            lines.append("")

        lines.append("-" * 60)
        if report.threats_found == 0:
            lines.append("DURUM: SİSTEM GÜVENLİ ✓")
        else:
            lines.append(f"DURUM: {report.threats_found} TEHDİT TESPİT EDİLDİ ⚠")
        lines.append("-" * 60)
        lines.append("")
        lines.append("Engine: SENTINEL-CORE™ v1.0.0")
        lines.append("Sentinel Guard — Real Antivirus Engine")
        lines.append("=" * 60)

        return "\n".join(lines)
