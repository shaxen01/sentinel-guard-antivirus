"""
Sentinel Guard — Document Scanner Module
Scans document files (PDF, Office) for malicious content like macros, scripts, DDE, links, and embedded objects.
"""

import os
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DocumentScanResult:
    file_path: str
    file_type: str                  # 'PDF', 'Office', or 'Unknown'
    has_macros: bool = False
    has_javascript: bool = False
    has_embedded_files: bool = False
    has_suspicious_actions: bool = False
    risk_score: int = 0             # 0 to 100
    threats: List[str] = field(default_factory=list)


class DocumentScanner:
    """Scans PDF and Office documents for malicious elements (scripts, embedded files, macros)."""

    def __init__(self):
        pass

    @staticmethod
    def scan_text_for_macros(content: bytes) -> List[str]:
        """Scan binary or text content for VBA macro-like patterns and suspicious commands."""
        detected = []
        content_lower = content.lower()

        patterns = {
            b"autoopen": "VBA Auto-execution entrypoint: AutoOpen",
            b"auto_open": "VBA Auto-execution entrypoint: Auto_Open",
            b"document_open": "VBA Auto-execution entrypoint: Document_Open",
            b"documentopen": "VBA Auto-execution entrypoint: DocumentOpen",
            b"workbook_open": "VBA Auto-execution entrypoint: Workbook_Open",
            b"workbookopen": "VBA Auto-execution entrypoint: WorkbookOpen",
            b"autoclose": "VBA Auto-execution entrypoint: AutoClose",
            b"autonew": "VBA Auto-execution entrypoint: AutoNew",
            
            b"shell": "VBA Command Execution keyword: Shell",
            b"createobject": "VBA COM Object Creation: CreateObject",
            b"getobject": "VBA COM Object retrieval: GetObject",
            b"wscript.shell": "VBA Script Host execution: WScript.Shell",
            b"shell.application": "VBA Shell Application: Shell.Application",
            
            b"virtualalloc": "VBA Memory Allocation API: VirtualAlloc (Suspicious)",
            b"rtlmovememory": "VBA Memory Copy API: RtlMoveMemory (Suspicious)",
            b"callwindowproc": "VBA Window Procedure call: CallWindowProc (Suspicious)",
            
            b"adodb.stream": "VBA File writing object: ADODB.Stream",
            b"microsoft.xmlhttp": "VBA HTTP client object: Microsoft.XMLHTTP",
            b"winhttprequest": "VBA HTTP request object: WinHttpRequest",
            
            b"cmd.exe": "Command Prompt reference: cmd.exe",
            b"powershell": "PowerShell execution reference",
            b"mshta.exe": "HTML Application launcher reference: mshta.exe",
            b"regsvr32.exe": "Register server DLL execution reference: regsvr32.exe",
            b"certutil.exe": "Certutil download/decode reference: certutil.exe",
            b"rundll32.exe": "RunDLL32 execution reference: rundll32.exe",
        }

        for pattern, description in patterns.items():
            if pattern in content_lower:
                detected.append(description)

        return detected

    def _normalize_pdf_names(self, content: bytes) -> bytes:
        """Resolve any hex-encoded character sequences like #XX in PDF names."""
        def replace_hex(match):
            hex_val = match.group(1)
            try:
                return bytes([int(hex_val, 16)])
            except Exception:
                return match.group(0)

        return re.sub(rb'#([0-9a-fA-F]{2})', replace_hex, content)

    def _extract_pdf_streams(self, content: bytes) -> List[bytes]:
        """Extract all stream objects from raw PDF bytes."""
        streams = []
        idx = 0
        max_streams = 500
        while len(streams) < max_streams:
            start_idx = content.find(b'stream', idx)
            if start_idx == -1:
                break

            end_idx = content.find(b'endstream', start_idx)
            if end_idx == -1:
                break

            # Stream data begins after 'stream' keyword and its trailing newline
            stream_data_start = start_idx + 6
            if content[stream_data_start:stream_data_start+2] == b'\r\n':
                stream_data_start += 2
            elif content[stream_data_start:stream_data_start+1] == b'\n':
                stream_data_start += 1

            stream_data = content[stream_data_start:end_idx]

            # Clean trailing newline from stream data
            if stream_data.endswith(b'\r\n'):
                stream_data = stream_data[:-2]
            elif stream_data.endswith(b'\n'):
                stream_data = stream_data[:-1]

            streams.append(stream_data)
            idx = end_idx + 9

        return streams

    def _decompress_stream(self, data: bytes) -> Optional[bytes]:
        """Decompress compressed PDF streams (FlateDecode)."""
        if not data or len(data) > 15 * 1024 * 1024:  # 15MB limit
            return None
        try:
            return zlib.decompress(data)
        except Exception:
            try:
                # Try raw deflate without header
                return zlib.decompress(data, -15)
            except Exception:
                return None

    def _scan_pdf_bytes(self, content: bytes) -> List[str]:
        """Scan a block of bytes for PDF-specific features."""
        threats = []
        
        # De-obfuscate PDF names first
        normalized = self._normalize_pdf_names(content)
        content_lower = normalized.lower()

        # PDF feature and action signatures
        if b'/javascript' in content_lower or b'/js' in content_lower:
            threats.append("Suspicious JavaScript found in PDF")
        if b'/openaction' in content_lower:
            threats.append("Automatic action on document open (OpenAction) detected")
        if b'/launch' in content_lower:
            threats.append("External process execution command (Launch) detected")
        if b'/embeddedfiles' in content_lower or b'/ef' in content_lower or b'/filespec' in content_lower:
            threats.append("Embedded files (payload carrier) detected within PDF")
        if b'/uri' in content_lower:
            threats.append("External link/URI action detected (potential phishing)")
        if b'/encrypt' in content_lower:
            threats.append("Encrypted PDF content detected (obscures scanning)")
        if b'/aa' in content_lower:
            threats.append("Event-triggered script execution (Additional Actions) detected")
        if b'/xfa' in content_lower:
            threats.append("XML Forms Architecture (XFA) stream detected")
        if b'/richmedia' in content_lower:
            threats.append("Deprecated RichMedia/Flash object detected")

        return threats

    def _calculate_pdf_risk_score(self, result: DocumentScanResult) -> int:
        """Calculate a risk score from 0 to 100 based on PDF threats."""
        score = 0
        for threat in result.threats:
            if "Launch" in threat:
                score += 40
            elif "JavaScript" in threat:
                score += 30
            elif "OpenAction" in threat:
                score += 25
            elif "Embedded files" in threat:
                score += 30
            elif "Event-triggered" in threat:
                score += 20
            elif "RichMedia" in threat:
                score += 20
            elif "XFA" in threat:
                score += 15
            elif "Encrypted" in threat:
                score += 15
            elif "URI" in threat:
                score += 10

        return min(100, score)

    def scan_pdf(self, file_path: str) -> DocumentScanResult:
        """Scan PDF for malicious content (JavaScript, embedded files, suspicious actions)."""
        logger.info(f"Scanning PDF: {file_path}")
        result = DocumentScanResult(
            file_path=file_path,
            file_type='PDF',
            threats=[]
        )

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(file_path, 'rb') as f:
                content = f.read()

            # 1. Scan raw file content
            raw_threats = self._scan_pdf_bytes(content)

            # 2. Extract and decompress streams to find obfuscated/hidden content
            streams = self._extract_pdf_streams(content)
            decompressed_threats = []
            for stream in streams:
                decomp_bytes = self._decompress_stream(stream)
                if decomp_bytes:
                    decompressed_threats.extend(self._scan_pdf_bytes(decomp_bytes))

            # Combine and deduplicate threats
            all_threats = list(set(raw_threats + decompressed_threats))

            for threat in all_threats:
                if "JavaScript" in threat:
                    result.has_javascript = True
                if "Embedded files" in threat:
                    result.has_embedded_files = True
                if any(x in threat for x in ("OpenAction", "Launch", "Event-triggered")):
                    result.has_suspicious_actions = True
                result.threats.append(threat)

            # 3. Compute Risk Score
            result.risk_score = self._calculate_pdf_risk_score(result)

        except Exception as e:
            logger.error(f"Error scanning PDF {file_path}: {e}")
            result.threats.append(f"Scan error: {str(e)}")
            result.risk_score = 0

        return result

    def _scan_rels_content(self, rels_content: bytes, result: DocumentScanResult):
        """Parse XML relationships to detect external web templates or malicious links."""
        # Find all relationship fields with target and external status
        relationships = re.findall(rb'<Relationship\s+([^>]+)>', rels_content)
        for rel in relationships:
            target_match = re.search(rb'Target="([^"]+)"', rel)
            target_mode_match = re.search(rb'TargetMode="External"', rel)

            if target_match:
                target = target_match.group(1).decode('utf-8', errors='ignore')
                if target_mode_match:
                    # External resource target
                    if target.startswith(('http://', 'https://', 'ftp://')):
                        ext = os.path.splitext(target.split('?')[0])[1].lower()
                        if ext in ('.dot', '.dotm', '.dotx', '.docm', '.exe', '.scr', '.vbs', '.js', '.bin'):
                            result.has_suspicious_actions = True
                            result.threats.append(f"High-risk remote template injection attempt: {target}")
                        else:
                            result.threats.append(f"Suspicious external relationship/link: {target}")

    def _scan_ooxml(self, file_path: str, result: DocumentScanResult):
        """Scan modern Office XML formats (.docx, .xlsx, .pptx) zipped structure."""
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                namelist = z.namelist()

                # 1. Search for VBA macros (vbaProject.bin)
                for name in namelist:
                    if 'vbaProject.bin' in name:
                        result.has_macros = True
                        result.threats.append("VBA Macros detected in Office document (vbaProject.bin)")

                        # Scan macro streams for patterns
                        try:
                            vba_data = z.read(name)
                            macro_threats = self.scan_text_for_macros(vba_data)
                            for t in macro_threats:
                                result.threats.append(f"Macro signature: {t}")
                        except Exception as e:
                            logger.debug(f"Could not read VBA project stream: {e}")
                        break

                # 2. Check for Embedded files or OLE Objects
                for name in namelist:
                    if 'embeddings/' in name or (name.endswith('.bin') and 'ole' in name.lower()):
                        result.has_embedded_files = True
                        result.threats.append(f"Embedded OLE object detected in OOXML: {name}")

                        try:
                            ole_data = z.read(name)
                            if ole_data.startswith(b'MZ'):
                                result.threats.append(f"Executable file (MZ header) embedded in OLE object: {name}")
                            
                            # Scan embedded binaries for macros too
                            macro_threats = self.scan_text_for_macros(ole_data)
                            for t in macro_threats:
                                result.threats.append(f"Macro signature in embedded OLE object: {t}")
                        except Exception as e:
                            logger.debug(f"Could not read embedded OLE object {name}: {e}")

                # 3. Check for external relationship links
                for name in namelist:
                    if name.endswith('.rels'):
                        try:
                            rels_content = z.read(name)
                            self._scan_rels_content(rels_content, result)
                        except Exception as e:
                            logger.debug(f"Error reading relationship file {name}: {e}")

                # 4. Check for DDE injections in document text
                for name in namelist:
                    if name.endswith('.xml') and ('document' in name or 'sheet' in name or 'slides' in name):
                        try:
                            xml_content = z.read(name)
                            if any(k in xml_content.lower() for k in (b'dde', b'ddeauto')):
                                if re.search(rb'\b(DDE|DDEAUTO)\b', xml_content, re.IGNORECASE):
                                    result.has_suspicious_actions = True
                                    result.threats.append(f"DDE (Dynamic Data Exchange) injection command found in XML: {name}")
                        except Exception as e:
                            logger.debug(f"Error reading XML file {name}: {e}")

        except Exception as e:
            logger.error(f"Failed to scan OOXML zip structure: {e}")
            result.threats.append(f"OOXML parsing error: {str(e)}")

    def _scan_ole2(self, file_path: str, result: DocumentScanResult):
        """Scan legacy binary Office formats (.doc, .xls, .ppt)."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # 1. Look for macro streams in structured storage
            if b'_VBA_PROJECT_CUR' in content or b'PROJECT' in content:
                result.has_macros = True
                result.threats.append("VBA Macros detected in legacy OLE2 document")

            # Scan the content for macro signatures
            macro_threats = self.scan_text_for_macros(content)
            for t in macro_threats:
                result.has_macros = True
                result.threats.append(f"Macro signature in legacy document: {t}")

            # 2. Check for nested OLE files (starts with OLE2 header again)
            idx = 1
            nested_ole_count = 0
            while True:
                idx = content.find(b'\xd0\xcf\x11\xe0', idx)
                if idx == -1:
                    break
                nested_ole_count += 1
                idx += 4

            if nested_ole_count > 0:
                result.has_embedded_files = True
                result.threats.append(f"Nested/Embedded OLE objects detected ({nested_ole_count}) in legacy document")

            # 3. Check for external URLs and links
            urls = re.findall(rb'https?://[a-zA-Z0-9\-\.\/\_\?\&\=\%\#\+]+', content)
            for url_bytes in set(urls):
                url = url_bytes.decode('utf-8', errors='ignore')
                ext = os.path.splitext(url.split('?')[0])[1].lower()
                if ext in ('.dot', '.dotm', '.dotx', '.docm', '.exe', '.scr', '.vbs', '.js', '.bin'):
                    result.has_suspicious_actions = True
                    result.threats.append(f"Suspicious external URL with high-risk extension in binary: {url}")
                elif len(url) < 150:
                    result.threats.append(f"External link detected in binary Office document: {url}")

            # 4. Check for DDE in legacy content
            if any(k in content.lower() for k in (b'dde', b'ddeauto')):
                if re.search(rb'\b(DDE|DDEAUTO)\b', content, re.IGNORECASE):
                    result.has_suspicious_actions = True
                    result.threats.append("DDE execution string detected in binary Office document")

        except Exception as e:
            logger.error(f"Error scanning legacy OLE2: {e}")
            result.threats.append(f"Legacy OLE2 scanning error: {str(e)}")

    def _calculate_office_risk_score(self, result: DocumentScanResult) -> int:
        """Calculate risk score for Office documents based on found threats."""
        score = 0
        if result.has_macros:
            score += 40
        if result.has_embedded_files:
            score += 25
        if result.has_suspicious_actions:
            score += 35

        # Check details for extra weight
        for threat in result.threats:
            if "Executable file (MZ header) embedded" in threat:
                score += 50
            elif "High-risk remote template injection" in threat:
                score += 15
            elif "Macro signature" in threat:
                score += 5
            elif "DDE" in threat:
                score += 15

        return min(100, score)

    def scan_office(self, file_path: str) -> DocumentScanResult:
        """Scan Microsoft Office document for malicious content (macros, OLE, links, DDE)."""
        logger.info(f"Scanning Office document: {file_path}")
        result = DocumentScanResult(
            file_path=file_path,
            file_type='Office',
            threats=[]
        )

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(file_path, 'rb') as f:
                header = f.read(8)

            if header.startswith(b'PK\x03\x04'):
                self._scan_ooxml(file_path, result)
            elif header.startswith(b'\xd0\xcf\x11\xe0'):
                self._scan_ole2(file_path, result)
            else:
                # Extension fallback
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm'):
                    self._scan_ooxml(file_path, result)
                else:
                    self._scan_ole2(file_path, result)

            # Compute risk score
            result.risk_score = self._calculate_office_risk_score(result)

        except Exception as e:
            logger.error(f"Error scanning Office document {file_path}: {e}")
            result.threats.append(f"Scan error: {str(e)}")
            result.risk_score = 0

        return result

    def scan_file(self, file_path: str) -> DocumentScanResult:
        """Auto-detect document type by magic bytes or extension and run scan."""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(file_path, 'rb') as f:
                magic = f.read(8)

            if magic.startswith(b'%PDF'):
                return self.scan_pdf(file_path)
            elif magic.startswith(b'PK\x03\x04') or magic.startswith(b'\xd0\xcf\x11\xe0'):
                return self.scan_office(file_path)
            else:
                # Extension check
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.pdf':
                    return self.scan_pdf(file_path)
                elif ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt'):
                    return self.scan_office(file_path)
                else:
                    return DocumentScanResult(
                        file_path=file_path,
                        file_type='Unknown',
                        threats=["Unknown or unsupported document format"],
                        risk_score=0
                    )
        except Exception as e:
            logger.error(f"Error in scan_file for {file_path}: {e}")
            return DocumentScanResult(
                file_path=file_path,
                file_type='Unknown',
                threats=[f"Scan error: {str(e)}"],
                risk_score=0
            )
