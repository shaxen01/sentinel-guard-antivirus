"""
Sentinel Guard — Database Maintenance Tools
Provides backup, restore, optimization, deduplication, and export/import utilities for the signature DB.
"""
import os
import json
import csv
import sqlite3
import shutil
import time
from pathlib import Path
from typing import Dict, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class DBTools:
    """Database maintenance utilities for the Sentinel Guard signatures database."""

    @staticmethod
    def backup(db_path: str, backup_path: str) -> bool:
        """Create a safe backup of the SQLite database using SQLite's backup API."""
        try:
            if not os.path.exists(db_path):
                logger.error(f"Source database not found for backup: {db_path}")
                return False

            Path(backup_path).parent.mkdir(parents=True, exist_ok=True)
            
            src = sqlite3.connect(db_path)
            dst = sqlite3.connect(backup_path)
            
            with dst:
                src.backup(dst)
                
            dst.close()
            src.close()
            
            logger.info(f"Database successfully backed up from '{db_path}' to '{backup_path}'")
            return True
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            # Fallback to file copy in case of locks/failures
            try:
                shutil.copy2(db_path, backup_path)
                logger.info(f"Backup fallback successful using file copy to '{backup_path}'")
                return True
            except Exception as copy_err:
                logger.error(f"Backup copy fallback failed: {copy_err}")
                return False

    @staticmethod
    def restore(backup_path: str, db_path: str) -> bool:
        """Restore the SQLite database from a backup file."""
        try:
            if not os.path.exists(backup_path):
                logger.error(f"Backup file not found for restore: {backup_path}")
                return False

            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            src = sqlite3.connect(backup_path)
            dst = sqlite3.connect(db_path)
            
            with dst:
                src.backup(dst)
                
            dst.close()
            src.close()
            
            logger.info(f"Database successfully restored from '{backup_path}' to '{db_path}'")
            return True
        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            # Fallback to file copy in case of locks/failures
            try:
                shutil.copy2(backup_path, db_path)
                logger.info(f"Restore fallback successful using file copy to '{db_path}'")
                return True
            except Exception as copy_err:
                logger.error(f"Restore copy fallback failed: {copy_err}")
                return False

    @staticmethod
    def optimize(db_path: str) -> Dict:
        """Optimize SQLite database size and index efficiency using VACUUM and REINDEX."""
        if not os.path.exists(db_path):
            return {"status": "error", "message": "Database file does not exist"}

        try:
            size_before = os.path.getsize(db_path)
            
            conn = sqlite3.connect(db_path)
            # VACUUM cannot be run inside a transaction
            conn.isolation_level = None
            c = conn.cursor()
            
            logger.info("Optimizing database: running VACUUM...")
            c.execute("VACUUM")
            
            logger.info("Optimizing database: running REINDEX...")
            c.execute("REINDEX")
            
            conn.close()
            
            size_after = os.path.getsize(db_path)
            space_saved = size_before - size_after
            
            result = {
                "status": "success",
                "size_before_bytes": size_before,
                "size_after_bytes": size_after,
                "space_saved_bytes": max(0, space_saved),
                "optimization_time": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            logger.info(f"Database optimization successful. Space saved: {result['space_saved_bytes']} bytes")
            return result
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def deduplicate(db_path: str) -> int:
        """Remove duplicate hashes in the signatures table, keeping the oldest record."""
        if not os.path.exists(db_path):
            logger.error(f"Database not found for deduplication: {db_path}")
            return 0

        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            
            # Count records before deduplication
            c.execute("SELECT COUNT(*) FROM signatures")
            count_before = c.fetchone()[0]
            
            # Delete duplicate rows, keeping the smallest row ID (oldest)
            c.execute("""
                DELETE FROM signatures
                WHERE id NOT IN (
                    SELECT MIN(id)
                    FROM signatures
                    GROUP BY sha256
                )
            """)
            conn.commit()
            
            # Count records after deduplication
            c.execute("SELECT COUNT(*) FROM signatures")
            count_after = c.fetchone()[0]
            
            deleted_count = count_before - count_after
            conn.close()
            
            logger.info(f"Deduplication completed. Removed {deleted_count} duplicate signatures.")
            return deleted_count
        except Exception as e:
            logger.error(f"Failed to deduplicate database: {e}")
            return 0

    @staticmethod
    def export_signatures(db_path: str, output_path: str, format: str = 'csv') -> bool:
        """Export all signatures in the database to a CSV or JSON file."""
        if not os.path.exists(db_path):
            logger.error(f"Database not found for export: {db_path}")
            return False

        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT sha256, md5, name, severity, family, source, added_at, updated_at 
                FROM signatures
            """)
            rows = [dict(r) for r in c.fetchall()]
            conn.close()

            if not rows:
                logger.warning("No signatures found in database to export")
                # Write empty file with headers or empty list
                if format.lower() == 'csv':
                    with open(output_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["sha256", "md5", "name", "severity", "family", "source", "added_at", "updated_at"])
                else:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump([], f)
                return True

            if format.lower() == 'csv':
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
            elif format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(rows, f, indent=4)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False

            logger.info(f"Successfully exported {len(rows)} signatures to '{output_path}'")
            return True
        except Exception as e:
            logger.error(f"Failed to export signatures: {e}")
            return False

    @staticmethod
    def import_signatures(db_path: str, input_path: str) -> int:
        """Import signatures from a CSV or JSON file into the database."""
        if not os.path.exists(input_path):
            logger.error(f"Import file not found: {input_path}")
            return 0

        try:
            from engine.signatures import SignatureDatabase
            db = SignatureDatabase(db_path)
            
            if input_path.lower().endswith('.csv'):
                count = db.import_from_csv(input_path)
            elif input_path.lower().endswith('.json'):
                count = db.import_from_json(input_path)
            else:
                # Try JSON first, fallback to CSV
                try:
                    count = db.import_from_json(input_path)
                except Exception:
                    try:
                        count = db.import_from_csv(input_path)
                    except Exception as e:
                        logger.error(f"Failed parsing file '{input_path}' as CSV or JSON: {e}")
                        return 0
                        
            logger.info(f"Imported {count} signatures from '{input_path}' into '{db_path}'")
            return count
        except Exception as e:
            logger.error(f"Failed to import signatures: {e}")
            return 0

    @staticmethod
    def get_stats(db_path: str) -> Dict:
        """Get comprehensive statistics for the signature database."""
        try:
            from engine.signatures import SignatureDatabase
            db = SignatureDatabase(db_path)
            stats = db.get_stats()
            
            # Supplement with file system stats
            if os.path.exists(db_path):
                stats["file_size_bytes"] = os.path.getsize(db_path)
                stats["last_modified"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", 
                    time.localtime(os.path.getmtime(db_path))
                )
            else:
                stats["file_size_bytes"] = 0
                stats["last_modified"] = "N/A"
                
            stats["db_path"] = db_path
            return stats
        except Exception as e:
            logger.error(f"Failed to retrieve database stats: {e}")
            return {"status": "error", "message": str(e)}
