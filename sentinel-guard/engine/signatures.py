"""
Sentinel Guard — Signature Database Manager
SQLite-based malware signature database
"""
import sqlite3
import json
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class SignatureDatabase:
    """Manages the malware signature database (SQLite)."""

    def __init__(self, db_path: str = "data/signatures.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_known_signatures()

    def _init_db(self):
        """Initialize the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT UNIQUE NOT NULL,
                md5 TEXT,
                name TEXT NOT NULL,
                severity TEXT DEFAULT 'HIGH',
                family TEXT,
                source TEXT DEFAULT 'local',
                added_at TEXT,
                updated_at TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON signatures(sha256)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_md5 ON signatures(md5)")

        conn.commit()
        conn.close()
        logger.debug(f"Signature database initialized: {self.db_path}")

    def _seed_known_signatures(self):
        """Seed the database with known test signatures."""
        # EICAR test file — standard antivirus test file
        # Content: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"

        existing = self.check_hash(eicar_sha256)
        if not existing:
            self.add_signature(
                sha256=eicar_sha256,
                md5=eicar_md5,
                name="EICAR-Test-File",
                severity="CRITICAL",
                family="Test",
                source="builtin"
            )
            logger.info("Seeded EICAR test signature")

    def check_hash(self, sha256: str) -> Optional[Dict]:
        """Check if a SHA256 hash matches any known signature."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM signatures WHERE sha256 = ?", (sha256,))
        row = c.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def check_md5(self, md5: str) -> Optional[Dict]:
        """Check if an MD5 hash matches any known signature."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM signatures WHERE md5 = ?", (md5,))
        row = c.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def add_signature(self, sha256: str, name: str, severity: str = "HIGH",
                      family: str = None, md5: str = None, source: str = "local"):
        """Add a single signature to the database."""
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("""
                INSERT OR REPLACE INTO signatures (sha256, md5, name, severity, family, source, added_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (sha256, md5, name, severity, family, source, now, now))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()

    def bulk_add_signatures(self, signatures: List[Dict]):
        """Bulk add multiple signatures."""
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        added = 0
        for sig in signatures:
            try:
                c.execute("""
                    INSERT OR IGNORE INTO signatures (sha256, md5, name, severity, family, source, added_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sig.get("sha256"),
                    sig.get("md5"),
                    sig.get("name", "Unknown"),
                    sig.get("severity", "HIGH"),
                    sig.get("family"),
                    sig.get("source", "import"),
                    now, now
                ))
                if c.rowcount > 0:
                    added += 1
            except sqlite3.IntegrityError:
                pass
        conn.commit()
        conn.close()
        logger.info(f"Imported {added} new signatures (out of {len(signatures)})")
        return added

    def import_from_csv(self, csv_path: str) -> int:
        """Import signatures from a CSV file (sha256,name,severity,family)."""
        import csv
        signatures = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                signatures.append({
                    "sha256": row.get("sha256", ""),
                    "md5": row.get("md5"),
                    "name": row.get("name", "Unknown"),
                    "severity": row.get("severity", "HIGH"),
                    "family": row.get("family"),
                    "source": "csv_import"
                })
        return self.bulk_add_signatures(signatures)

    def import_from_json(self, json_path: str) -> int:
        """Import signatures from a JSON file."""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return self.bulk_add_signatures(data)
        elif isinstance(data, dict) and "signatures" in data:
            return self.bulk_add_signatures(data["signatures"])
        return 0

    def update_from_malwarebazaar(self, limit: int = 1000) -> int:
        """Update signatures from MalwareBazaar API (public, free)."""
        try:
            import urllib.request
            import urllib.parse

            url = "https://mb-api.abuse.ch/api/v1/"
            data = urllib.parse.urlencode({
                "query": "get_recent",
                "selector": "100"
            }).encode()

            req = urllib.request.Request(url, data=data)
            req.add_header("User-Agent", "SentinelGuard/1.0")

            logger.info("Fetching recent signatures from MalwareBazaar...")
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode())

            if result.get("query_status") != "ok":
                logger.warning(f"MalwareBazaar API error: {result.get('query_status')}")
                return 0

            signatures = []
            for item in result.get("data", [])[:limit]:
                sha256 = item.get("sha256_hash")
                if sha256:
                    signatures.append({
                        "sha256": sha256,
                        "name": item.get("signature_name") or item.get("file_type", "Unknown"),
                        "severity": "HIGH",
                        "family": item.get("signature_name"),
                        "source": "malwarebazaar"
                    })

            return self.bulk_add_signatures(signatures)

        except Exception as e:
            logger.error(f"MalwareBazaar update failed: {e}")
            return 0

    def get_stats(self) -> Dict:
        """Get database statistics."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM signatures")
        total = c.fetchone()[0]
        c.execute("SELECT severity, COUNT(*) FROM signatures GROUP BY severity")
        by_severity = {row[0]: row[1] for row in c.fetchall()}
        c.execute("SELECT source, COUNT(*) FROM signatures GROUP BY source")
        by_source = {row[0]: row[1] for row in c.fetchall()}
        conn.close()
        return {
            "total_signatures": total,
            "by_severity": by_severity,
            "by_source": by_source
        }

    def remove_signature(self, sha256: str) -> bool:
        """Remove a signature from the database."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM signatures WHERE sha256 = ?", (sha256,))
        deleted = c.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
