"""
Sentinel Guard — Quarantine Manager
Isolates infected files safely
"""
import os
import shutil
import json
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class QuarantineManager:
    """Manages quarantined files."""

    def __init__(self, quarantine_dir: str = "data/quarantine"):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.quarantine_dir / "quarantine.json"
        self._load_metadata()

    def _load_metadata(self):
        """Load quarantine metadata from JSON file."""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {"items": []}

    def _save_metadata(self):
        """Save quarantine metadata to JSON file."""
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)

    def quarantine_file(self, file_path: str, sha256: str, threat_name: str) -> str:
        """
        Move an infected file to quarantine.
        Returns the quarantine ID.
        """
        src = Path(file_path)
        if not src.exists():
            logger.warning(f"File not found for quarantine: {file_path}")
            return ""

        # Get file stats BEFORE moving/deleting
        file_size = src.stat().st_size

        # Generate quarantine ID
        qid = hashlib.md5(f"{file_path}{time.time()}".encode()).hexdigest()[:12]

        # Create quarantined file with .quarantined extension
        dest = self.quarantine_dir / f"{qid}.quarantined"

        # Copy file to quarantine
        shutil.copy2(str(src), str(dest))

        # Delete original
        try:
            os.remove(str(src))
        except Exception as e:
            logger.warning(f"Could not delete original file: {e}")

        # Record metadata
        item = {
            "id": qid,
            "original_path": str(src.resolve()),
            "original_name": src.name,
            "quarantined_path": str(dest),
            "sha256": sha256,
            "threat_name": threat_name,
            "file_size": file_size,
            "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        self.metadata["items"].append(item)
        self._save_metadata()

        logger.info(f"🔒 File quarantined: {src.name} → {dest.name}")
        return qid

    def list_quarantined(self) -> List[Dict]:
        """List all quarantined files."""
        return self.metadata["items"]

    def restore_file(self, qid: str) -> bool:
        """Restore a quarantined file to its original location."""
        for i, item in enumerate(self.metadata["items"]):
            if item["id"] == qid:
                src = Path(item["quarantined_path"])
                dest = Path(item["original_path"])

                if not src.exists():
                    logger.error(f"Quarantine file not found: {src}")
                    return False

                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dest))
                os.remove(str(src))

                self.metadata["items"].pop(i)
                self._save_metadata()
                logger.info(f"✅ File restored: {item['original_name']} → {dest}")
                return True

        logger.warning(f"Quarantine ID not found: {qid}")
        return False

    def delete_file(self, qid: str) -> bool:
        """Permanently delete a quarantined file."""
        for i, item in enumerate(self.metadata["items"]):
            if item["id"] == qid:
                src = Path(item["quarantined_path"])
                if src.exists():
                    os.remove(str(src))
                self.metadata["items"].pop(i)
                self._save_metadata()
                logger.info(f"🗑️ Permanently deleted: {item['original_name']}")
                return True
        return False

    def clear_all(self) -> int:
        """Delete all quarantined files. Returns count deleted."""
        count = len(self.metadata["items"])
        for item in self.metadata["items"]:
            p = Path(item["quarantined_path"])
            if p.exists():
                os.remove(str(p))
        self.metadata["items"] = []
        self._save_metadata()
        logger.info(f"🗑️ Cleared {count} quarantined files")
        return count

    def get_stats(self) -> Dict:
        """Get quarantine statistics."""
        items = self.metadata["items"]
        total_size = sum(item.get("file_size", 0) for item in items)
        return {
            "total_files": len(items),
            "total_size": total_size,
            "total_size_human": self._human_size(total_size),
        }

    @staticmethod
    def _human_size(size: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
