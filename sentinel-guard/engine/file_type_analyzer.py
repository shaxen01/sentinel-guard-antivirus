"""
Sentinel Guard — File Type Analyzer
Deep file type detection using magic bytes, structure analysis, and entropy.
"""

import os
import math
import struct
import io
import zipfile
from dataclasses import dataclass, field
from typing import List, Dict

from utils.logger import get_logger

logger = get_logger(__name__)

# MIME Types Map
MIME_TYPES = {
    "PE": "application/x-dosexec",
    "ELF": "application/x-elf",
    "Mach-O": "application/x-mach-binary",
    "ZIP": "application/zip",
    "JAR": "application/java-archive",
    "APK": "application/vnd.android.package-archive",
    "RAR": "application/x-rar-compressed",
    "7z": "application/x-7z-compressed",
    "GZIP": "application/gzip",
    "BZIP2": "application/x-bzip2",
    "PDF": "application/pdf",
    "PNG": "image/png",
    "JPG": "image/jpeg",
    "GIF": "image/gif",
    "BMP": "image/bmp",
    "ICO": "image/x-icon",
    "MP3": "audio/mpeg",
    "MP4": "video/mp4",
    "AVI": "video/x-msvideo",
    "WAV": "audio/wav",
    "OLE2": "application/x-ole-storage",
    "RTF": "application/rtf",
    "XML": "application/xml",
    "HTML": "text/html",
    "PHP": "application/x-httpd-php",
    "DEX": "application/vnd.android.dex",
    "WASM": "application/wasm",
    "TXT": "text/plain",
    "UNKNOWN": "application/octet-stream"
}


@dataclass
class FileTypeResult:
    file_path: str
    extension: str
    detected_type: str
    mime_type: str
    encoding: str
    entropy: float
    is_packed: bool
    packer_name: str
    is_polyglot: bool
    polyglot_types: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)


class FileTypeAnalyzer:
    """Performs deep file type detection using magic bytes, structure, and entropy."""

    def __init__(self):
        # Cache for mime types
        self.mime_types = MIME_TYPES

    def analyze(self, file_path: str) -> FileTypeResult:
        """Analyze a file and perform deep type/integrity verification."""
        from pathlib import Path
        path = Path(file_path)
        ext = path.suffix.lower()
        
        content = b""
        try:
            if path.exists() and path.is_file():
                file_size = path.stat().st_size
                # Limit memory consumption for extremely large files
                if file_size > 50 * 1024 * 1024:
                    logger.warning(
                        f"File {file_path} is very large ({file_size} bytes). "
                        "Reading first 50MB for analysis."
                    )
                    with open(file_path, 'rb') as f:
                        content = f.read(50 * 1024 * 1024)
                else:
                    with open(file_path, 'rb') as f:
                        content = f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return FileTypeResult(
                file_path=str(path.resolve()),
                extension=ext,
                detected_type="UNKNOWN",
                mime_type="application/octet-stream",
                encoding="None",
                entropy=0.0,
                is_packed=False,
                packer_name="",
                is_polyglot=False,
                polyglot_types=[],
                is_suspicious=True,
                suspicion_reasons=[f"Read error: {str(e)}"]
            )

        detected_type = self._detect_magic(content)
        mime_type = self.mime_types.get(detected_type, "application/octet-stream")
        encoding = self._detect_text_encoding(content)
        entropy = self._compute_entropy(content)
        
        packer_name = self._detect_packing(content)
        is_packed = bool(packer_name)
        
        polyglot_desc = self._is_polyglot(content)
        is_polyglot = bool(polyglot_desc)
        polyglot_types = polyglot_desc.split("+") if polyglot_desc else []
        
        is_double_ext = self._detect_double_extension(file_path)
        
        # Heuristics & integrity checks
        suspicion_reasons = []
        
        if is_double_ext:
            suspicion_reasons.append(f"Double extension detected: {path.name}")
            
        if is_polyglot:
            suspicion_reasons.append(f"Polyglot structure detected: {polyglot_desc}")
            
        if is_packed:
            suspicion_reasons.append(f"File is packed with {packer_name}")
            
        # Extension mismatch check
        is_mismatch = False
        TYPE_EXTENSIONS = {
            "PE": [".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx"],
            "ELF": [".elf", ".so", ".bin", ""],
            "Mach-O": [".dylib", ".bin", ""],
            "ZIP": [".zip", ".zipx"],
            "JAR": [".jar"],
            "APK": [".apk"],
            "RAR": [".rar"],
            "7z": [".7z"],
            "GZIP": [".gz", ".gzip"],
            "BZIP2": [".bz2", ".bzip2"],
            "PDF": [".pdf"],
            "PNG": [".png"],
            "JPG": [".jpg", ".jpeg", ".jpe"],
            "GIF": [".gif"],
            "BMP": [".bmp"],
            "ICO": [".ico"],
            "MP3": [".mp3"],
            "MP4": [".mp4", ".m4v"],
            "AVI": [".avi"],
            "WAV": [".wav"],
            "OLE2": [".doc", ".xls", ".ppt", ".msi"],
            "RTF": [".rtf"],
            "XML": [".xml"],
            "HTML": [".html", ".htm", ".xhtml"],
            "PHP": [".php", ".php3", ".php4", ".phtml"],
            "DEX": [".dex"],
            "WASM": [".wasm"],
            "TXT": [
                ".txt", ".log", ".ini", ".conf", ".cfg", ".sh", ".py", ".bat", ".cmd", 
                ".ps1", ".vbs", ".js", ".json", ".md", ".markdown", ".yaml", ".yml", 
                ".csv", ".tsv", ".css", ".sql", ".properties", ".toml", ".gitconfig",
                ".gitignore", ".gitattributes", ".dockerignore", ".env"
            ]
        }
        
        if detected_type != "UNKNOWN" and detected_type in TYPE_EXTENSIONS:
            expected = TYPE_EXTENSIONS[detected_type]
            if ext not in expected:
                if ext == "" and detected_type in ("ELF", "Mach-O"):
                    pass
                else:
                    is_mismatch = True
                    suspicion_reasons.append(
                        f"Extension mismatch: file suffix is '{ext}' but detected type is '{detected_type}'"
                    )
                    
        # High entropy on non-compressed / text files
        LOW_ENTROPY_FORMATS = ("TXT", "XML", "HTML", "PHP", "RTF")
        if detected_type in LOW_ENTROPY_FORMATS and entropy > 6.8:
            suspicion_reasons.append(
                f"Abnormally high entropy ({entropy:.2f}) for text-based file type '{detected_type}'"
            )
        elif detected_type == "PE" and entropy > 7.4 and not is_packed:
            suspicion_reasons.append(
                f"High entropy ({entropy:.2f}) on unpacked executable (possible obfuscation/encryption)"
            )
            
        is_suspicious = len(suspicion_reasons) > 0
        
        return FileTypeResult(
            file_path=str(path.resolve()),
            extension=ext,
            detected_type=detected_type,
            mime_type=mime_type,
            encoding=encoding,
            entropy=round(entropy, 4),
            is_packed=is_packed,
            packer_name=packer_name,
            is_polyglot=is_polyglot,
            polyglot_types=polyglot_types,
            is_suspicious=is_suspicious,
            suspicion_reasons=suspicion_reasons
        )

    def _detect_magic(self, content: bytes) -> str:
        """Detect file type from magic bytes."""
        if not content:
            return "UNKNOWN"
            
        # 1. Check Binary Signatures
        if content.startswith(b"MZ"):
            return "PE"
        if content.startswith(b"\x7fELF"):
            return "ELF"
        if content[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            return "Mach-O"
        if content.startswith(b"PK\x03\x04"):
            # Deep ZIP analysis for JAR / APK
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as z:
                    namelist = z.namelist()
                    if "AndroidManifest.xml" in namelist:
                        return "APK"
                    if "META-INF/MANIFEST.MF" in namelist:
                        return "JAR"
            except Exception:
                pass
            return "ZIP"
        if content.startswith(b"Rar!\x1a\x07"):
            return "RAR"
        if content.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7z"
        if content.startswith(b"\x1f\x8b"):
            return "GZIP"
        if content.startswith(b"BZh"):
            return "BZIP2"
        if content.startswith(b"%PDF"):
            return "PDF"
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG"
        if content.startswith(b"\xff\xd8\xff"):
            return "JPG"
        if content[:6] in (b"GIF87a", b"GIF89a"):
            return "GIF"
        if content.startswith(b"BM"):
            return "BMP"
        if content.startswith(b"\x00\x00\x01\x00"):
            return "ICO"
        if content.startswith(b"ID3") or content.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xfa")):
            return "MP3"
        if len(content) >= 12 and content[4:8] == b"ftyp":
            return "MP4"
        if content.startswith(b"RIFF") and len(content) >= 12:
            if content[8:12] == b"AVI ":
                return "AVI"
            if content[8:12] == b"WAVE":
                return "WAV"
        if content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE2"
        if content.startswith(b"{\\rtf"):
            return "RTF"
        if content.startswith(b"dex\n"):
            return "DEX"
        if content.startswith(b"\x00asm"):
            return "WASM"
            
        # 2. Text / Script / markup analysis
        if b"<?php" in content:
            return "PHP"
            
        encoding = self._detect_text_encoding(content)
        if encoding != "None":
            stripped = content.lstrip()
            if stripped.startswith(b"<?xml") or b"<?xml" in content[:1024]:
                return "XML"
            
            lower_sample = stripped[:1024].lower()
            if lower_sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in lower_sample:
                return "HTML"
                
            return "TXT"
            
        return "UNKNOWN"

    def _detect_text_encoding(self, content: bytes) -> str:
        """Detect UTF-8, UTF-16, ASCII, etc. from content."""
        if not content:
            return "ASCII"
            
        # Byte Order Marks (BOM)
        if content.startswith(b"\xef\xbb\xbf"):
            return "UTF-8-BOM"
        if content.startswith(b"\xff\xfe\x00\x00"):
            return "UTF-32LE"
        if content.startswith(b"\x00\x00\xfe\xff"):
            return "UTF-32BE"
        if content.startswith(b"\xff\xfe"):
            return "UTF-16LE"
        if content.startswith(b"\xfe\xff"):
            return "UTF-16BE"
            
        # Check standard decoding using a sample
        sample = content[:65536]
        
        try:
            decoded = sample.decode('utf-8')
            if '\x00' in decoded:
                return "None"
            if all(ord(c) < 128 for c in decoded):
                return "ASCII"
            return "UTF-8"
        except UnicodeDecodeError:
            pass
            
        try:
            decoded = sample.decode('utf-16-le')
            if '\x00' not in decoded and all(ord(c) < 65536 for c in decoded):
                printable = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t')
                if len(decoded) > 0 and (printable / len(decoded)) > 0.8:
                    return "UTF-16LE"
        except UnicodeDecodeError:
            pass

        try:
            decoded = sample.decode('utf-16-be')
            if '\x00' not in decoded and all(ord(c) < 65536 for c in decoded):
                printable = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t')
                if len(decoded) > 0 and (printable / len(decoded)) > 0.8:
                    return "UTF-16BE"
        except UnicodeDecodeError:
            pass
            
        try:
            decoded = sample.decode('latin-1')
            if '\x00' not in decoded:
                printable = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t')
                if len(decoded) > 0 and (printable / len(decoded)) > 0.9:
                    return "ISO-8859-1"
        except Exception:
            pass
            
        return "None"

    def _compute_entropy(self, content: bytes) -> float:
        """Compute Shannon entropy of the content."""
        if not content:
            return 0.0
            
        length = len(content)
        # Use fast native C-level count in loop for efficiency
        counts = [content.count(bytes([i])) for i in range(256)]
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
                
        return entropy

    def _detect_packing(self, content: bytes) -> str:
        """Detect packers like UPX, MPRESS, Themida from sections and markers."""
        if len(content) < 64:
            return ""
            
        # Parse PE Sections if Executable
        if content.startswith(b"MZ"):
            try:
                pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
                if pe_offset + 24 <= len(content) and content[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    num_sections = struct.unpack_from("<H", content, pe_offset + 6)[0]
                    opt_hdr_size = struct.unpack_from("<H", content, pe_offset + 20)[0]
                    sec_offset = pe_offset + 24 + opt_hdr_size
                    
                    for i in range(min(num_sections, 96)):
                        so = sec_offset + i * 40
                        if so + 8 > len(content):
                            break
                        sec_bytes = content[so:so + 8].rstrip(b'\x00')
                        sec_name = sec_bytes.decode('utf-8', errors='ignore').upper()
                        
                        if "UPX" in sec_name:
                            return "UPX"
                        if "MPRESS" in sec_name:
                            return "MPRESS"
                        if "THEMIDA" in sec_name or ".THEM" in sec_name:
                            return "Themida"
                        if "VMP" in sec_name:
                            return "VMProtect"
                        if "ASPACK" in sec_name:
                            return "ASPack"
                        if "PELOCK" in sec_name:
                            return "PELock"
                        if "ENIGMA" in sec_name:
                            return "Enigma"
                        if "PESPIN" in sec_name:
                            return "PESpin"
            except Exception as e:
                logger.debug(f"PE packing parsing error: {e}")
                
        # Fallback to signature/marker byte scan
        if b"UPX!" in content:
            return "UPX"
        if b"MPRESS" in content:
            return "MPRESS"
        if b"Themida" in content:
            return "Themida"
        if b"VMProtect" in content:
            return "VMProtect"
        if b"ASPack" in content:
            return "ASPack"
            
        return ""

    def _detect_double_extension(self, file_path: str) -> bool:
        """Detect double extensions (e.g. invoice.pdf.exe) ignoring safe combinations."""
        name = os.path.basename(file_path)
        if name.startswith('.'):
            name = name[1:]
            
        parts = name.split('.')
        if len(parts) < 3:
            return False
            
        safe_combinations = {
            ("tar", "gz"), ("tar", "bz2"), ("tar", "xz"), ("tar", "z"),
            ("js", "map"), ("d", "ts")
        }
        
        ext2 = parts[-1].lower()
        ext1 = parts[-2].lower()
        
        if (ext1, ext2) in safe_combinations:
            return False
            
        if ext1.isalnum() and 1 <= len(ext1) <= 5 and ext2.isalnum() and 1 <= len(ext2) <= 5:
            return True
            
        return False

    def _is_polyglot(self, content: bytes) -> str:
        """Detect files containing valid multi-format signatures."""
        formats = []
        
        # PE check
        has_pe = False
        if content.startswith(b"MZ"):
            try:
                pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
                if pe_offset + 4 <= len(content) and content[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    has_pe = True
            except Exception:
                pass
                
        has_elf = content.startswith(b"\x7fELF")
        has_pdf = b"%PDF" in content[:1024]
        has_zip = b"PK\x03\x04" in content
        
        lower_sample = content[:100000].lower()
        has_html = b"<html" in lower_sample or b"<!doctype html" in lower_sample or b"<body" in lower_sample
        
        has_gif = content.startswith(b"GIF87a") or content.startswith(b"GIF89a")
        has_png = content.startswith(b"\x89PNG\r\n\x1a\n")
        has_class = content.startswith(b"\xca\xfe\xba\xbe")
        
        if has_pe:
            formats.append("PE")
        if has_elf:
            formats.append("ELF")
        if has_pdf:
            formats.append("PDF")
        if has_zip:
            if b"AndroidManifest.xml" in content:
                formats.append("APK")
            elif b"META-INF/MANIFEST.MF" in content:
                formats.append("JAR")
            else:
                formats.append("ZIP")
        if has_html:
            formats.append("HTML")
        if has_gif:
            formats.append("GIF")
        if has_png:
            formats.append("PNG")
        if has_class:
            formats.append("CLASS")
            
        # De-duplicate nested/sub-formats
        distinct_formats = []
        for f in formats:
            if f in ("APK", "JAR") and "ZIP" in distinct_formats:
                distinct_formats.remove("ZIP")
            if f == "ZIP" and any(x in distinct_formats for x in ("APK", "JAR")):
                continue
            if f not in distinct_formats:
                distinct_formats.append(f)
                
        if len(distinct_formats) >= 2:
            return "+".join(distinct_formats)
            
        return ""
