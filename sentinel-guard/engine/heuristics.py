"""
Sentinel Guard — Heuristic Analysis Engine
Detects suspicious files based on behavior patterns, entropy, and file structure
"""
import os
import math
import re
import struct
from pathlib import Path
from typing import Tuple, List, Dict
from utils.logger import get_logger

logger = get_logger(__name__)


class HeuristicAnalyzer:
    """Heuristic analysis for detecting unknown/suspicious files."""

    SUSPICIOUS_STRINGS = [
        (b"powershell -enc", 15),
        (b"powershell -e ", 12),
        (b"Invoke-Expression", 10),
        (b"DownloadString", 10),
        (b"DownloadFile", 10),
        (b"System.Net.WebClient", 8),
        (b"IEX(", 12),
        (b"FromBase64String", 8),
        (b"/bin/sh", 5),
        (b"cmd.exe /c", 10),
        (b"cmd /c", 8),
        (b"WScript.Shell", 10),
        (b"Shell.Application", 10),
        (b"HKEY_LOCAL_MACHINE", 8),
        (b"reg add", 8),
        (b"reg delete", 8),
        (b"CurrentVersion\\Run", 12),
        (b"schtasks /create", 15),
        (b"crontab -e", 5),
        (b"~/.bashrc", 5),
        (b"~/.profile", 5),
        (b"BaseAddress=http", 10),
        (b"checkip.amazonaws.com", 8),
        (b"pastebin.com/raw", 10),
        (b"ngrok.io", 8),
        (b"Meterpreter", 20),
        (b"reverse_tcp", 18),
        (b"msfvenom", 18),
        (b"Metasploit", 15),
        (b"ransom", 10),
        (b"bitcoin", 5),
        (b"AES_decrypt", 8),
        (b"your files have been encrypted", 25),
        (b"UPX", 3),
        (b"MPRESS", 5),
        (b"Themida", 8),
        (b"VMProtect", 8),
        (b"ASPack", 5),
        (b"os.system('cp ", 10),
        (b"shutil.copy2", 5),
        (b"socket.connect", 8),
        (b"GetAsyncKeyState", 15),
        (b"keylog", 12),
        (b"SetWindowsHookEx", 12),
    ]

    SUSPICIOUS_DOUBLE_EXTENSIONS = [
        ".pdf.exe", ".jpg.exe", ".doc.exe", ".xls.exe", ".txt.exe",
        ".mp4.exe", ".mp3.exe", ".png.exe", ".zip.exe", ".docx.exe",
        ".xlsx.exe", ".ppt.exe", ".pptx.exe", ".avi.exe", ".mov.exe",
        ".pdf.scr", ".jpg.scr", ".doc.scr", ".pdf.com", ".jpg.com",
        ".txt.vbs", ".pdf.vbs", ".jpg.vbs", ".doc.js", ".pdf.js",
        ".doc.lnk", ".pdf.lnk", ".jpg.lnk",
    ]

    SUSPICIOUS_PE_SECTIONS = [b".vmp0", b".vmp1", b".themida", b".aspack", b".upx0", b".upx1"]

    def __init__(self):
        self.max_string_scan_size = 2 * 1024 * 1024  # 2MB

    def analyze(self, file_path: str) -> Tuple[int, List[str]]:
        """Analyze a file heuristically. Returns (threat_score 0-100, list of flags)."""
        score = 0
        flags = []
        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                return 0, []
            file_size = path.stat().st_size
            if file_size == 0:
                return 0, []
            with open(file_path, 'rb') as f:
                content = f.read(self.max_string_scan_size)
            s, f1 = self._check_entropy(content); score += s; flags += f1
            s, f2 = self._check_strings(content); score += s; flags += f2
            s, f3 = self._check_extension(path, content); score += s; flags += f3
            s, f4 = self._check_double_extension(path); score += s; flags += f4
            s, f5 = self._check_pe_file(content); score += s; flags += f5
            s, f6 = self._check_size_anomaly(file_size, path); score += s; flags += f6
            score = min(score, 100)
        except PermissionError:
            pass
        except Exception as e:
            logger.debug(f"Heuristic error on {file_path}: {e}")
        return score, flags

    def _check_entropy(self, content: bytes) -> Tuple[int, List[str]]:
        if len(content) < 256:
            return 0, []
        entropy = self._shannon_entropy(content)
        if entropy > 7.5:
            return 25, [f"high_entropy ({entropy:.2f})"]
        elif entropy > 7.0:
            return 10, [f"elevated_entropy ({entropy:.2f})"]
        return 0, []

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _check_strings(self, content: bytes) -> Tuple[int, List[str]]:
        score = 0
        flags = []
        found = set()
        for pattern, weight in self.SUSPICIOUS_STRINGS:
            if pattern in content and pattern not in found:
                score += weight
                found.add(pattern)
                flags.append(f"suspicious_string:{pattern.decode('utf-8', errors='replace')}")
        return score, flags

    def _check_extension(self, path: Path, content: bytes) -> Tuple[int, List[str]]:
        ext = path.suffix.lower()
        is_pe = content[:2] == b"MZ"
        is_elf = content[:4] == b"\x7fELF"
        is_macho = content[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
        is_exec = is_pe or is_elf or is_macho
        non_exec = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".mp3", ".mp4", ".avi", ".mov", ".zip", ".rar"}
        if is_exec and ext in non_exec:
            return 20, [f"extension_mismatch ({ext} but executable content)"]
        image_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp"}
        if ext in image_exts and not self._is_valid_image(content, ext):
            return 10, [f"fake_image (extension {ext} but not valid image)"]
        return 0, []

    @staticmethod
    def _is_valid_image(content: bytes, ext: str) -> bool:
        if ext in (".jpg", ".jpeg"):
            return content[:2] == b"\xff\xd8"
        elif ext == ".png":
            return content[:8] == b"\x89PNG\r\n\x1a\n"
        elif ext == ".gif":
            return content[:6] in (b"GIF87a", b"GIF89a")
        elif ext == ".bmp":
            return content[:2] == b"BM"
        return True

    def _check_double_extension(self, path: Path) -> Tuple[int, List[str]]:
        name = path.name.lower()
        for de in self.SUSPICIOUS_DOUBLE_EXTENSIONS:
            if name.endswith(de):
                return 15, [f"double_extension ({de})"]
        return 0, []

    def _check_pe_file(self, content: bytes) -> Tuple[int, List[str]]:
        score = 0
        flags = []
        if len(content) < 64 or content[:2] != b"MZ":
            return 0, []
        try:
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            if pe_offset + 24 > len(content):
                return 5, ["pe_truncated_header"]
            if content[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return 5, ["pe_invalid_signature"]
            num_sections = struct.unpack_from("<H", content, pe_offset + 6)[0]
            if num_sections > 96:
                score += 15; flags.append(f"pe_too_many_sections ({num_sections})")
            elif num_sections == 0:
                score += 10; flags.append("pe_zero_sections")
            opt_hdr_size = struct.unpack_from("<H", content, pe_offset + 20)[0]
            sec_offset = pe_offset + 24 + opt_hdr_size
            for i in range(min(num_sections, 96)):
                so = sec_offset + i * 40
                if so + 40 > len(content):
                    break
                sn = content[so:so + 8].rstrip(b'\x00')
                if sn in self.SUSPICIOUS_PE_SECTIONS:
                    score += 10; flags.append(f"pe_suspicious_section ({sn.decode('utf-8', errors='replace')})")
            entry_point = struct.unpack_from("<I", content, pe_offset + 24 + 16)[0]
            if entry_point == 0:
                score += 5; flags.append("pe_zero_entry_point")
        except (struct.error, IndexError):
            score += 5; flags.append("pe_parse_error")
        return score, flags

    def _check_size_anomaly(self, file_size: int, path: Path) -> Tuple[int, List[str]]:
        ext = path.suffix.lower()
        exec_exts = {".exe", ".dll", ".sys", ".scr", ".com"}
        if ext in exec_exts and file_size < 1024:
            return 10, [f"tiny_executable ({file_size} bytes)"]
        script_exts = {".vbs", ".js", ".ps1", ".bat", ".cmd"}
        if ext in script_exts and file_size > 1024 * 1024:
            return 5, [f"oversized_script ({file_size} bytes)"]
        return 0, []
