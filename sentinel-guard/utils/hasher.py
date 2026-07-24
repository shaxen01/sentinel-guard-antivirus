"""
Sentinel Guard — File Hashing Utilities
"""
import hashlib
from pathlib import Path
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# Buffer size for file reading (64KB chunks)
CHUNK_SIZE = 65536


def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.debug(f"SHA256 error on {file_path}: {e}")
        return ""


def compute_md5(file_path: str) -> str:
    """Compute MD5 hash of a file."""
    h = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.debug(f"MD5 error on {file_path}: {e}")
        return ""


def compute_sha1(file_path: str) -> str:
    """Compute SHA1 hash of a file."""
    h = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.debug(f"SHA1 error on {file_path}: {e}")
        return ""


def compute_all_hashes(file_path: str) -> dict:
    """Compute all common hashes for a file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest()
        }
    except Exception as e:
        logger.debug(f"Hash error on {file_path}: {e}")
        return {"sha256": "", "md5": "", "sha1": ""}
