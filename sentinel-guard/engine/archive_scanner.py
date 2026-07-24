"""
Sentinel Guard — Archive Scanner
Extracts and scans files within archives (zip, tar, gzip)
"""
import os
import tempfile
import shutil
from pathlib import Path
from typing import List, Tuple
from engine.scanner import Scanner, ScanResult, ThreatLevel
from utils.logger import get_logger

logger = get_logger(__name__)


class ArchiveScanner:
    """Scans files inside archives by extracting them temporarily."""

    SUPPORTED_FORMATS = {'.zip', '.tar', '.gz', '.tgz', '.bz2', '.rar', '.7z'}

    MAX_ARCHIVE_SIZE = 500 * 1024 * 1024  # 500MB
    MAX_EXTRACTED_SIZE = 1000 * 1024 * 1024  # 1GB
    MAX_FILES_IN_ARCHIVE = 10000

    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def is_archive(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self.SUPPORTED_FORMATS

    def scan_archive(self, archive_path: str, auto_quarantine: bool = False) -> List[ScanResult]:
        """Extract and scan all files within an archive."""
        results = []

        if not self.is_archive(archive_path):
            return results

        file_size = os.path.getsize(archive_path)
        if file_size > self.MAX_ARCHIVE_SIZE:
            logger.warning(f"Archive too large, skipping: {archive_path}")
            return results

        temp_dir = tempfile.mkdtemp(prefix="sentinel_archive_")

        try:
            extracted = self._extract(archive_path, temp_dir)
            if extracted:
                logger.info(f"📦 Archive extracted: {Path(archive_path).name} → {len(extracted)} files")

                for extracted_file in extracted[:self.MAX_FILES_IN_ARCHIVE]:
                    result = self.scanner.scan_file(extracted_file)
                    if result.is_threat:
                        result.file_path = f"{archive_path} → {result.file_name}"
                        results.append(result)

                        if auto_quarantine and result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                            self.scanner.quarantine.quarantine_file(
                                extracted_file, result.sha256, result.threat_name
                            )
        except Exception as e:
            logger.error(f"Archive extraction failed: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return results

    def _extract(self, archive_path: str, dest_dir: str) -> List[str]:
        """Extract archive and return list of extracted file paths."""
        ext = Path(archive_path).suffix.lower()
        extracted = []

        try:
            if ext == '.zip':
                extracted = self._extract_zip(archive_path, dest_dir)
            elif ext in ('.tar', '.gz', '.tgz'):
                extracted = self._extract_tar(archive_path, dest_dir)
            elif ext == '.bz2':
                extracted = self._extract_tar(archive_path, dest_dir)
            else:
                logger.debug(f"Unsupported archive format: {ext}")
        except Exception as e:
            logger.error(f"Extraction error: {e}")

        return extracted

    def _extract_zip(self, archive_path: str, dest_dir: str) -> List[str]:
        import zipfile
        extracted = []
        with zipfile.ZipFile(archive_path, 'r') as zf:
            total_size = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # Prevent path traversal
                safe_path = os.path.join(dest_dir, os.path.basename(info.filename))
                if not safe_path.startswith(dest_dir):
                    continue
                zf.extract(info, dest_dir)
                total_size += info.file_size
                if total_size > self.MAX_EXTRACTED_SIZE:
                    logger.warning("Archive too large after extraction, stopping")
                    break
                extracted.append(os.path.join(dest_dir, info.filename))
        return extracted

    def _extract_tar(self, archive_path: str, dest_dir: str) -> List[str]:
        import tarfile
        extracted = []
        with tarfile.open(archive_path, 'r:*') as tf:
            total_size = 0
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                safe_name = os.path.basename(member.name)
                if not safe_name or safe_name.startswith('.'):
                    continue
                tf.extract(member, dest_dir)
                total_size += member.size
                if total_size > self.MAX_EXTRACTED_SIZE:
                    logger.warning("Archive too large after extraction, stopping")
                    break
                extracted.append(os.path.join(dest_dir, member.name))
        return extracted
