"""
Sentinel Guard — Whitelist Manager
Trusted file hashes to skip during scanning
"""
import json
import time
from pathlib import Path
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class Whitelist:
    """Manages a whitelist of trusted file hashes."""

    def __init__(self, whitelist_path: str = "data/whitelist.json"):
        self.path = Path(whitelist_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._hashes = set()
        self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path, 'r') as f:
                data = json.load(f)
                self._hashes = set(data.get("sha256", []))
        else:
            # Seed with some known-safe system file hashes (example)
            self._hashes = set()
            self._save()

    def _save(self):
        with open(self.path, 'w') as f:
            json.dump({"sha256": list(self._hashes)}, f, indent=2)

    def add(self, sha256: str):
        """Add a hash to the whitelist."""
        self._hashes.add(sha256)
        self._save()

    def add_file(self, file_path: str):
        """Add a file to the whitelist by computing its hash."""
        from utils.hasher import compute_sha256
        h = compute_sha256(file_path)
        if h:
            self.add(h)
            logger.info(f"Added to whitelist: {Path(file_path).name} ({h[:16]}...)")

    def remove(self, sha256: str):
        """Remove a hash from the whitelist."""
        self._hashes.discard(sha256)
        self._save()

    def is_whitelisted(self, sha256: str) -> bool:
        """Check if a hash is whitelisted."""
        return sha256 in self._hashes

    def list_all(self) -> List[str]:
        """List all whitelisted hashes."""
        return sorted(self._hashes)

    def clear(self):
        """Clear the whitelist."""
        self._hashes.clear()
        self._save()

    def count(self) -> int:
        return len(self._hashes)
