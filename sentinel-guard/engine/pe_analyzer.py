"""
Sentinel Guard — Portable Executable (PE) File Analyzer
Provides deep static analysis of Windows PE files (EXE, DLL, SYS, etc.)
"""

import math
import struct
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from utils.logger import get_logger

logger = get_logger(__name__)

# MSVC Product IDs from Rich Header (decrypted compid higher 16-bits)
PRODID_MAP = {
    0: "Unknown",
    1: "Import0",
    2: "Linker510",
    3: "Cvtomf510",
    4: "Linker600",
    5: "Cvtomf600",
    6: "Cvtres500",
    7: "Utc11_Basic",
    8: "Utc11_C",
    9: "Utc12_Basic",
    10: "Utc12_C",
    11: "Utc12_CPP",
    12: "AliasObj60",
    13: "VisualBasic60",
    14: "Masm613",
    15: "Masm710",
    16: "Linker511",
    17: "Cvtomf511",
    18: "Masm614",
    19: "Linker512",
    20: "Cvtomf512",
    21: "Utc12_C_Std",
    22: "Utc12_CPP_Std",
    23: "Utc12_C_Book",
    24: "Utc12_CPP_Book",
    25: "Implib700",
    26: "Cvtomf700",
    27: "Utc13_Basic",
    28: "Utc13_C",
    29: "Utc13_CPP",
    30: "Linker610",
    31: "Cvtomf610",
    32: "Linker601",
    33: "Cvtomf601",
    34: "Utc12_1_Basic",
    35: "Utc12_1_C",
    36: "Utc12_1_CPP",
    37: "Linker620",
    38: "Cvtomf620",
    39: "AliasObj70",
    40: "Linker621",
    41: "Cvtomf621",
    42: "Masm615",
    43: "Utc13_LTCG_C",
    44: "Utc13_LTCG_CPP",
    45: "Masm620",
    46: "ILAsm100",
    47: "Utc12_2_Basic",
    48: "Utc12_2_C",
    49: "Utc12_2_CPP",
    50: "Utc12_2_C_Std",
    51: "Utc12_2_CPP_Std",
    52: "Utc12_2_C_Book",
    53: "Utc12_2_CPP_Book",
    54: "Implib622",
    55: "Cvtomf622",
    56: "Cvtres501",
    57: "Utc13_C_Std",
    58: "Utc13_CPP_Std",
    59: "Cvtpgd1300",
    60: "Linker622",
    61: "Linker700",
    62: "Export622",
    63: "Export700",
    64: "Masm700",
    65: "Utc13_POGO_I_C",
    66: "Utc13_POGO_I_CPP",
    67: "Utc13_POGO_O_C",
    68: "Utc13_POGO_O_CPP",
    69: "Cvtres700",
    70: "Cvtres710p",
    71: "Linker710p",
    72: "Cvtomf710p",
    73: "Export710p",
    74: "Implib710p",
    75: "Masm710p",
    76: "Utc1310p_C",
    77: "Utc1310p_CPP",
    78: "Utc1310p_C_Std",
    79: "Utc1310p_CPP_Std",
    80: "Utc1310p_LTCG_C",
    81: "Utc1310p_LTCG_CPP",
    82: "Utc1310p_POGO_I_C",
    83: "Utc1310p_POGO_I_CPP",
    84: "Utc1310p_POGO_O_C",
    85: "Utc1310p_POGO_O_CPP",
    86: "Linker624",
    87: "Cvtomf624",
    88: "Export624",
    89: "Implib624",
    90: "Linker710",
    91: "Cvtomf710",
    92: "Export710",
    93: "Implib710",
    94: "Cvtres710",
    95: "Utc1310_C",
    96: "Utc1310_CPP",
    97: "Utc1310_C_Std",
    98: "Utc1310_CPP_Std",
    99: "Utc1310_LTCG_C",
    100: "Utc1310_LTCG_CPP",
    101: "Utc1310_POGO_I_C",
    102: "Utc1310_POGO_I_CPP",
    103: "Utc1310_POGO_O_C",
    104: "Utc1310_POGO_O_CPP",
    105: "AliasObj710",
    106: "AliasObj710p",
    107: "Cvtpgd1310",
    108: "Cvtpgd1310p",
    109: "Utc1400_C",
    110: "Utc1400_CPP",
    111: "Utc1400_C_Std",
    112: "Utc1400_CPP_Std",
    113: "Utc1400_LTCG_C",
    114: "Utc1400_LTCG_CPP",
    115: "Utc1400_POGO_I_C",
    116: "Utc1400_POGO_I_CPP",
    117: "Utc1400_POGO_O_C",
    118: "Utc1400_POGO_O_CPP",
    119: "Cvtpgd1400",
    120: "Linker800",
    121: "Cvtomf800",
    122: "Export800",
    123: "Implib800",
    124: "Cvtres800",
    125: "Masm800",
    126: "AliasObj800",
    127: "PhoenixPrerelease",
    128: "Utc1400_CVTCIL_C",
    129: "Utc1400_CVTCIL_CPP",
    130: "Utc1400_LTCG_MSIL",
    131: "Utc1500_C",
    132: "Utc1500_CPP",
    133: "Utc1500_C_Std",
    134: "Utc1500_CPP_Std",
    135: "Utc1500_CVTCIL_C",
    136: "Utc1500_CVTCIL_CPP",
    137: "Utc1500_LTCG_C",
    138: "Utc1500_LTCG_CPP",
    139: "Utc1500_LTCG_MSIL",
    140: "Utc1500_POGO_I_C",
    141: "Utc1500_POGO_I_CPP",
    142: "Utc1500_POGO_O_C",
    143: "Utc1500_POGO_O_CPP",
    144: "Cvtpgd1500",
    145: "Linker900",
    146: "Export900",
    147: "Implib900",
    148: "Cvtres900",
    149: "Masm900",
    150: "AliasObj900",
    151: "Resource900",
    152: "AliasObj1000",
    154: "Cvtres1000",
    155: "Export1000",
    156: "Implib1000",
    157: "Linker1000",
    158: "Masm1000",
    170: "Utc1600_C",
    171: "Utc1600_CPP",
    172: "Utc1600_CVTCIL_C",
    173: "Utc1600_CVTCIL_CPP",
    174: "Utc1600_LTCG_C ",
    175: "Utc1600_LTCG_CPP",
    176: "Utc1600_LTCG_MSIL",
    177: "Utc1600_POGO_I_C",
    178: "Utc1600_POGO_I_CPP",
    179: "Utc1600_POGO_O_C",
    180: "Utc1600_POGO_O_CPP",
    183: "Linker1010",
    184: "Export1010",
    185: "Implib1010",
    186: "Cvtres1010",
    187: "Masm1010",
    188: "AliasObj1010",
    199: "AliasObj1100",
    201: "Cvtres1100",
    202: "Export1100",
    203: "Implib1100",
    204: "Linker1100",
    205: "Masm1100",
    206: "Utc1700_C",
    207: "Utc1700_CPP",
    208: "Utc1700_CVTCIL_C",
    209: "Utc1700_CVTCIL_CPP",
    210: "Utc1700_LTCG_C ",
    211: "Utc1700_LTCG_CPP",
    212: "Utc1700_LTCG_MSIL",
    213: "Utc1700_POGO_I_C",
    214: "Utc1700_POGO_I_CPP",
    215: "Utc1700_POGO_O_C",
    216: "Utc1700_POGO_O_CPP",
}

# Machine type mappings
MACHINE_MAP = {
    0x014c: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0xaa64: "ARM64",
    0x0200: "Intel IA64",
    0x01c0: "ARM",
    0x01c4: "ARMNT"
}

# Suspicious APIs commonly used by malware
SUSPICIOUS_FUNCTIONS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "ntwritevirtualmemory", "createremotethread", "rtlcreateuserthread",
    "setwindowshookexa", "setwindowshookexw", "ldrloaddll", "ntunmapviewofsection",
    "ntmapviewofsection", "ntcreatesection", "queueuserapc", "setthreadcontext",
    "getthreadcontext", "openprocess", "rtlcreateuserthread", "ntallocatevirtualmemory",
    "isdebuggerpresent", "checkremotedebuggerpresent", "winexec", "shellexecutea",
    "shellexecutew", "createprocessa", "createprocessw", "getprocaddress",
    "loadlibrarya", "loadlibraryw", "ldrgetprocedureaddress", "resumethread"
}


@dataclass
class ImportEntry:
    dll: str
    functions: List[str]


@dataclass
class SectionHash:
    name: str
    sha256: str
    entropy: float
    virtual_size: int
    raw_size: int


@dataclass
class PEAnalysisResult:
    file_path: str
    is_pe: bool
    is_dll: bool
    is_64bit: bool
    machine: str
    timestamp: int
    entry_point: int
    num_sections: int
    imports: List[ImportEntry]
    exports: List[str]
    imphash: str
    rich_header: dict
    section_hashes: List[SectionHash]
    anomalies: List[str]
    risk_score: int


class PEAnalyzer:
    """Deep static analysis of Windows Portable Executable (PE) files."""

    def analyze(self, file_path: str) -> PEAnalysisResult:
        """Analyze a file and return its PE analysis result."""
        # Initialize default empty result in case parsing fails or file is not a PE
        default_result = PEAnalysisResult(
            file_path=file_path,
            is_pe=False,
            is_dll=False,
            is_64bit=False,
            machine="Unknown",
            timestamp=0,
            entry_point=0,
            num_sections=0,
            imports=[],
            exports=[],
            imphash="",
            rich_header={},
            section_hashes=[],
            anomalies=[],
            risk_score=0
        )

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return default_result
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return default_result

        # 1. Parse DOS Header
        dos_info = self._parse_dos_header(content)
        if not dos_info.get('is_mz'):
            logger.debug(f"File {file_path} does not start with MZ signature.")
            return default_result

        e_lfanew = dos_info['e_lfanew']

        # 2. Parse PE Header
        pe_info = self._parse_pe_header(content, e_lfanew)
        if not pe_info.get('is_pe'):
            logger.debug(f"File {file_path} is missing PE signature at offset {e_lfanew}.")
            return default_result

        # Store attributes to help internal functions
        self.is_64bit = pe_info['is_64bit']
        self.image_base = pe_info['image_base']

        sections = pe_info['sections']

        # 3. Parse Import Table
        imports = self._parse_import_table(content, pe_info['import_dir_rva'], sections)

        # 4. Parse Export Table
        exports = self._parse_export_table(content, pe_info['export_dir_rva'], sections)

        # 5. Parse Rich Header
        rich_header = self._parse_rich_header(content)

        # 6. Compute Imphash
        imphash = self._compute_imphash(imports)

        # 7. Compute Section Hashes & Entropies
        section_hashes = self._hash_sections(content, sections)

        # Construct intermediate object for anomaly checking
        # Note: we need some internal fields in analysis to check things like content and raw directories
        analysis_dict = {
            'imports': imports,
            'exports': exports,
            'section_hashes': section_hashes,
            '_sections': sections,
            'is_64bit': pe_info['is_64bit'],
            'image_base': pe_info['image_base'],
            'tls_dir_rva': pe_info['tls_dir_rva'],
            'resource_dir_size': pe_info['resource_dir_size'],
            '_content': content
        }

        # 8. Check Anomalies
        anomalies = self._check_anomalies(analysis_dict)

        # 9. Compute Risk Score
        risk_score = self._calculate_risk_score(anomalies, imports, section_hashes)

        return PEAnalysisResult(
            file_path=file_path,
            is_pe=True,
            is_dll=pe_info['is_dll'],
            is_64bit=pe_info['is_64bit'],
            machine=pe_info['machine'],
            timestamp=pe_info['timestamp'],
            entry_point=pe_info['entry_point'],
            num_sections=len(sections),
            imports=imports,
            exports=exports,
            imphash=imphash,
            rich_header=rich_header,
            section_hashes=section_hashes,
            anomalies=anomalies,
            risk_score=risk_score
        )

    def _parse_dos_header(self, content: bytes) -> dict:
        """Parse the DOS Header to verify MZ signature and extract e_lfanew."""
        if len(content) < 64:
            return {'is_mz': False, 'e_lfanew': 0}
        
        # Verify MZ signature
        if content[0:2] != b'MZ':
            return {'is_mz': False, 'e_lfanew': 0}
            
        try:
            # Offset 0x3C (60) contains the 4-byte offset to the PE Header
            e_lfanew = struct.unpack('<I', content[0x3C:0x40])[0]
            return {'is_mz': True, 'e_lfanew': e_lfanew}
        except Exception:
            return {'is_mz': False, 'e_lfanew': 0}

    def _parse_pe_header(self, content: bytes, offset: int) -> dict:
        """Parse PE COFF and Optional Header to extract key metadata and section headers."""
        result = {'is_pe': False, 'sections': []}
        
        # Check basic boundaries
        if offset <= 0 or offset + 24 > len(content):
            return result
            
        # PE Signature: b'PE\x00\x00'
        if content[offset:offset+4] != b'PE\x00\x00':
            return result
            
        try:
            # COFF File Header (20 bytes starting at offset + 4)
            machine, num_sections, timestamp, _, _, size_of_opt_header, characteristics = struct.unpack(
                '<HHIIIHH', content[offset+4:offset+24]
            )
            
            is_dll = (characteristics & 0x2000) != 0
            machine_str = MACHINE_MAP.get(machine, f"Unknown ({hex(machine)})")
            
            # Optional Header starts at offset + 24
            opt_offset = offset + 24
            if opt_offset + size_of_opt_header > len(content) or size_of_opt_header < 2:
                return result
                
            magic = struct.unpack('<H', content[opt_offset:opt_offset+2])[0]
            is_64bit = (magic == 0x20b)
            
            # Parse Optional Header Standard Fields
            # Magic up to AddressOfEntryPoint is identical layout for 32-bit and 64-bit
            entry_point = 0
            if size_of_opt_header >= 20:
                entry_point = struct.unpack('<I', content[opt_offset+16:opt_offset+20])[0]
                
            # Windows-specific fields layouts are different
            image_base = 0
            num_rva_sizes = 0
            dirs_start = 0
            
            if is_64bit:
                if size_of_opt_header >= 112:
                    image_base = struct.unpack('<Q', content[opt_offset+24:opt_offset+32])[0]
                    num_rva_sizes = struct.unpack('<I', content[opt_offset+108:opt_offset+112])[0]
                    dirs_start = opt_offset + 112
            else:
                if size_of_opt_header >= 96:
                    image_base = struct.unpack('<I', content[opt_offset+28:opt_offset+32])[0]
                    num_rva_sizes = struct.unpack('<I', content[opt_offset+92:opt_offset+96])[0]
                    dirs_start = opt_offset + 96
                    
            # Extract data directories
            export_dir_rva = 0
            import_dir_rva = 0
            resource_dir_size = 0
            tls_dir_rva = 0
            
            # Read directories (limit to 16)
            num_dirs = min(num_rva_sizes, 16)
            for i in range(num_dirs):
                dir_offset = dirs_start + i * 8
                if dir_offset + 8 > len(content):
                    break
                rva, size = struct.unpack('<II', content[dir_offset:dir_offset+8])
                if i == 0:   # Export Directory
                    export_dir_rva = rva
                elif i == 1: # Import Directory
                    import_dir_rva = rva
                elif i == 2: # Resource Directory
                    resource_dir_size = size
                elif i == 9: # TLS Directory
                    tls_dir_rva = rva
                    
            # Parse Section Headers (located immediately after Optional Header)
            sections_start = opt_offset + size_of_opt_header
            sections = []
            
            for i in range(num_sections):
                sec_offset = sections_start + i * 40
                if sec_offset + 40 > len(content):
                    break
                    
                name_bytes = content[sec_offset:sec_offset+8]
                name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
                
                vsize, vaddr, raw_size, ptr_raw, ptr_reloc, ptr_line, num_reloc, num_line, characteristics = struct.unpack(
                    '<IIIIIIHHI', content[sec_offset+8:sec_offset+40]
                )
                
                sections.append({
                    'name': name,
                    'virtual_size': vsize,
                    'virtual_address': vaddr,
                    'raw_size': raw_size,
                    'pointer_to_raw_data': ptr_raw,
                    'characteristics': characteristics
                })
                
            return {
                'is_pe': True,
                'is_dll': is_dll,
                'is_64bit': is_64bit,
                'machine': machine_str,
                'timestamp': timestamp,
                'entry_point': entry_point,
                'image_base': image_base,
                'export_dir_rva': export_dir_rva,
                'import_dir_rva': import_dir_rva,
                'resource_dir_size': resource_dir_size,
                'tls_dir_rva': tls_dir_rva,
                'sections': sections
            }
        except Exception as e:
            logger.error(f"Error parsing PE Header: {e}")
            return result

    def _parse_import_table(self, content: bytes, rva: int, sections: List[dict]) -> List[ImportEntry]:
        """Parse Import Table (IDT) to extract imported DLLs and functions."""
        imports = []
        if rva == 0:
            return imports
            
        descriptor_offset = self._rva_to_offset(rva, sections)
        if descriptor_offset is None or descriptor_offset >= len(content):
            return imports
            
        # Determine 64-bit flag
        is_64bit = getattr(self, 'is_64bit', True)
        
        # Loop over import descriptors (each is 20 bytes)
        for desc_idx in range(4096): # Safety limit
            off = descriptor_offset + desc_idx * 20
            if off + 20 > len(content):
                break
                
            orig_first_thunk, timestamp, forwarder, name_rva, first_thunk = struct.unpack('<IIIII', content[off:off+20])
            if orig_first_thunk == 0 and timestamp == 0 and forwarder == 0 and name_rva == 0 and first_thunk == 0:
                break
                
            # Resolve DLL name
            dll_offset = self._rva_to_offset(name_rva, sections)
            if dll_offset is None:
                continue
            dll_name = self._read_null_terminated_string(content, dll_offset)
            if not dll_name:
                continue
                
            # ILT (OriginalFirstThunk) is preferred, but fall back to IAT (FirstThunk) if ILT is 0
            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_offset = self._rva_to_offset(thunk_rva, sections)
            if thunk_offset is None or thunk_offset >= len(content):
                continue
                
            functions = []
            step = 8 if is_64bit else 4
            
            # Loop over thunks
            for thunk_idx in range(8192): # Safety limit
                t_off = thunk_offset + thunk_idx * step
                if t_off + step > len(content):
                    break
                    
                if is_64bit:
                    thunk_val = struct.unpack('<Q', content[t_off:t_off+8])[0]
                else:
                    thunk_val = struct.unpack('<I', content[t_off:t_off+4])[0]
                    
                if thunk_val == 0:
                    break
                    
                # Check Ordinal flag
                is_ordinal = (thunk_val & 0x8000000000000000) != 0 if is_64bit else (thunk_val & 0x80000000) != 0
                if is_ordinal:
                    ordinal_num = thunk_val & 0xFFFF
                    functions.append(f"ordinal_{ordinal_num}")
                else:
                    func_name_offset = self._rva_to_offset(thunk_val, sections)
                    if func_name_offset is not None and func_name_offset + 2 < len(content):
                        # Skip 2-byte Hint and read the ASCII name
                        func_name = self._read_null_terminated_string(content, func_name_offset + 2)
                        if func_name:
                            functions.append(func_name)
                            
            if functions:
                imports.append(ImportEntry(dll=dll_name, functions=functions))
                
        return imports

    def _parse_export_table(self, content: bytes, rva: int, sections: List[dict]) -> List[str]:
        """Parse Export Table (EDT) to extract exported function names."""
        exports = []
        if rva == 0:
            return exports
            
        export_offset = self._rva_to_offset(rva, sections)
        if export_offset is None or export_offset + 40 > len(content):
            return exports
            
        try:
            _, _, _, _, _, _, _, num_names, _, addr_names, _ = struct.unpack(
                '<IIHHIIIIIII', content[export_offset:export_offset+40]
            )
            
            names_offset = self._rva_to_offset(addr_names, sections)
            if names_offset is None:
                return exports
                
            limit = min(num_names, 8192) # Safety limit
            for i in range(limit):
                off = names_offset + i * 4
                if off + 4 > len(content):
                    break
                name_rva = struct.unpack('<I', content[off:off+4])[0]
                func_name_offset = self._rva_to_offset(name_rva, sections)
                if func_name_offset is not None:
                    name_str = self._read_null_terminated_string(content, func_name_offset)
                    if name_str:
                        exports.append(name_str)
        except Exception as e:
            logger.error(f"Error parsing export table: {e}")
            
        return exports

    def _parse_rich_header(self, content: bytes) -> dict:
        """Parse the Microsoft Visual C++ Rich Header to detect tools and compiler info."""
        result = {'compiler': 'Unknown', 'builds': [], 'raw_entries': []}
        try:
            if len(content) < 0x40:
                return result
            e_lfanew = struct.unpack('<I', content[0x3C:0x40])[0]
            
            # Rich Header resides in DOS Stub (offset 0x40 to e_lfanew)
            search_area = content[0x40:e_lfanew]
            rich_index_in_stub = search_area.find(b'Rich')
            if rich_index_in_stub == -1:
                return result
                
            rich_offset = 0x40 + rich_index_in_stub
            xor_key_bytes = content[rich_offset+4:rich_offset+8]
            if len(xor_key_bytes) < 4:
                return result
            xor_key = struct.unpack('<I', xor_key_bytes)[0]
            
            # Read 8-byte entries backwards from 'Rich'
            entries = []
            curr_offset = rich_offset - 8
            dans_found = False
            
            for _ in range(100): # Safety limit
                if curr_offset < 0x40:
                    break
                chunk = content[curr_offset:curr_offset+8]
                if len(chunk) < 8:
                    break
                    
                comp_id_enc, count_enc = struct.unpack('<II', chunk)
                comp_id = comp_id_enc ^ xor_key
                count = count_enc ^ xor_key
                
                if comp_id == 0x536e6144: # 'DanS' in little-endian (SnaD)
                    dans_found = True
                    break
                    
                entries.append((comp_id, count))
                curr_offset -= 8
                
            # Sort chronologically (reversing since we went backwards)
            entries.reverse()
            
            builds = []
            compilers_detected = []
            
            for comp_id, count in entries:
                prod_id = comp_id >> 16
                build_num = comp_id & 0xFFFF
                prod_name = PRODID_MAP.get(prod_id, f"Unknown")
                
                # Determine tool category
                tool_type = "Utility"
                if prod_id in [7, 8, 9, 10, 11, 21, 22, 23, 24, 27, 28, 29, 34, 35, 36, 47, 48, 49, 50, 51, 52, 53, 57, 58, 76, 77, 78, 79, 80, 81, 95, 96, 97, 98, 99, 100, 109, 110, 111, 112, 113, 114, 128, 129, 131, 132, 133, 134, 135, 136, 137, 138, 170, 171, 174, 175, 206, 207, 210, 211]:
                    tool_type = "MSVC Compiler"
                elif prod_id in [2, 4, 16, 19, 30, 32, 37, 40, 60, 61, 71, 86, 90, 120, 145, 157, 183, 204]:
                    tool_type = "MSVC Linker"
                elif prod_id in [14, 15, 18, 42, 45, 64, 75, 125, 149, 158, 187, 205]:
                    tool_type = "Masm Assembler"
                elif prod_id == 13:
                    tool_type = "Visual Basic 6.0"
                    
                build_entry = {
                    'product_id': prod_id,
                    'product_name': prod_name,
                    'build_number': build_num,
                    'count': count,
                    'tool_type': tool_type
                }
                builds.append(build_entry)
                
                if tool_type in ["MSVC Compiler", "Masm Assembler", "Visual Basic 6.0"]:
                    compilers_detected.append(f"{tool_type} (Build {build_num})")
                    
            if compilers_detected:
                result['compiler'] = ", ".join(sorted(list(set(compilers_detected))))
            else:
                product_names = [b['product_name'] for b in builds if b['product_name'] != "Unknown"]
                if product_names:
                    result['compiler'] = ", ".join(sorted(list(set(product_names))))
                    
            result['builds'] = builds
            result['raw_entries'] = [{'comp_id': cid, 'count': cnt} for cid, cnt in entries]
            result['xor_key'] = hex(xor_key)
            result['valid'] = dans_found
            
        except Exception as e:
            logger.debug(f"Rich header parsing skipped or failed: {e}")
            
        return result

    def _compute_imphash(self, import_entries: List[ImportEntry]) -> str:
        """Compute the imphash (MD5 hash of sorted lowercased imported DLL+function names)."""
        imphash_list = []
        for entry in import_entries:
            dll = entry.dll.lower()
            if dll.endswith(('.dll', '.sys', '.ocx')):
                dll = dll.rsplit('.', 1)[0]
                
            for func in entry.functions:
                func_name = func.lower()
                imphash_list.append(f"{dll}.{func_name}")
                
        # Sort as requested
        imphash_list.sort()
        
        imphash_str = ",".join(imphash_list)
        return hashlib.md5(imphash_str.encode('utf-8')).hexdigest()

    def _hash_sections(self, content: bytes, sections: List[dict]) -> List[SectionHash]:
        """Compute SHA256 and Shannon entropy for each section."""
        section_hashes = []
        for sec in sections:
            name = sec['name']
            ptr_raw = sec['pointer_to_raw_data']
            raw_size = sec['raw_size']
            vsize = sec['virtual_size']
            
            if ptr_raw > 0 and raw_size > 0:
                raw_data = content[ptr_raw:min(ptr_raw + raw_size, len(content))]
            else:
                raw_data = b''
                
            sha256_hash = hashlib.sha256(raw_data).hexdigest()
            entropy = self._compute_entropy(raw_data)
            
            section_hashes.append(SectionHash(
                name=name,
                sha256=sha256_hash,
                entropy=entropy,
                virtual_size=vsize,
                raw_size=raw_size
            ))
        return section_hashes

    def _check_anomalies(self, analysis) -> List[str]:
        """Check for structural and import anomalies (overlapping sections, zero-size sections, etc.)."""
        anomalies = []
        
        is_dict = isinstance(analysis, dict)
        imports = analysis.get('imports', []) if is_dict else getattr(analysis, 'imports', [])
        section_hashes = analysis.get('section_hashes', []) if is_dict else getattr(analysis, 'section_hashes', [])
        sections = analysis.get('_sections', []) if is_dict else getattr(analysis, '_sections', [])
        is_64bit = analysis.get('is_64bit', True) if is_dict else getattr(analysis, 'is_64bit', True)
        image_base = analysis.get('image_base', 0) if is_dict else getattr(analysis, 'image_base', 0)
        tls_dir_rva = analysis.get('tls_dir_rva', 0) if is_dict else getattr(analysis, 'tls_dir_rva', 0)
        resource_dir_size = analysis.get('resource_dir_size', 0) if is_dict else getattr(analysis, 'resource_dir_size', 0)
        content = analysis.get('_content', b'') if is_dict else getattr(analysis, '_content', b'')

        # 1. Overlapping sections check
        for i in range(len(sections)):
            sec_a = sections[i]
            va_a = sec_a.get('virtual_address', 0)
            vsize_a = sec_a.get('virtual_size', 0)
            size_a = vsize_a if vsize_a > 0 else sec_a.get('raw_size', 0)
            if size_a == 0:
                continue
                
            for j in range(i + 1, len(sections)):
                sec_b = sections[j]
                va_b = sec_b.get('virtual_address', 0)
                vsize_b = sec_b.get('virtual_size', 0)
                size_b = vsize_b if vsize_b > 0 else sec_b.get('raw_size', 0)
                if size_b == 0:
                    continue
                    
                if va_a < va_b + size_b and va_b < va_a + size_a:
                    anomalies.append(f"Overlapping sections: Section '{sec_a['name']}' overlaps with '{sec_b['name']}' in virtual memory")
                    break

        # 2. Zero-size sections check
        for hash_entry in section_hashes:
            if hash_entry.virtual_size == 0:
                anomalies.append(f"Zero virtual-size section: '{hash_entry.name}' has VirtualSize = 0")
            elif hash_entry.raw_size == 0 and hash_entry.name not in ['.bss', 'BSS', '']:
                anomalies.append(f"Zero raw-size section: '{hash_entry.name}' has RawSize = 0")

        # 3. Suspicious import combos
        all_funcs = set()
        for entry in imports:
            for func in entry.functions:
                all_funcs.add(func.lower())
                
        # Combo A: Process Injection
        has_alloc = any(f in all_funcs for f in ["virtualalloc", "virtualallocex", "ntallocatevirtualmemory"])
        has_write = any(f in all_funcs for f in ["writeprocessmemory", "ntwritevirtualmemory"])
        has_thread = any(f in all_funcs for f in ["createremotethread", "rtlcreateuserthread", "queueuserapc"])
        if has_alloc and has_write and has_thread:
            anomalies.append("Suspicious API combo (Process Injection): Alloc + Write + Execution APIs are imported")
            
        # Combo B: Process Hollowing
        has_unmap = "ntunmapviewofsection" in all_funcs
        has_create_proc = any(f in all_funcs for f in ["createprocessa", "createprocessw"])
        if has_unmap and has_write and (has_create_proc or "resumethread" in all_funcs):
            anomalies.append("Suspicious API combo (Process Hollowing): Unmap + Write + Process Creation APIs are imported")
            
        # Individual alarming APIs
        if any(f in all_funcs for f in ["setwindowshookexa", "setwindowshookexw"]):
            anomalies.append("Suspicious API: SetWindowsHookEx (potential keyboard hook/keylogging)")
        if "createremotethread" in all_funcs:
            anomalies.append("Suspicious API: CreateRemoteThread (potential cross-process code execution)")
        if "writeprocessmemory" in all_funcs:
            anomalies.append("Suspicious API: WriteProcessMemory (potential cross-process memory manipulation)")
        if "ldrloaddll" in all_funcs:
            anomalies.append("Suspicious API: LdrLoadDll (potential dynamic / evasive module loading)")
        if "ntunmapviewofsection" in all_funcs:
            anomalies.append("Suspicious API: NtUnmapViewOfSection (potential process hollowing)")

        # 4. TLS Callbacks check
        if tls_dir_rva > 0:
            tls_offset = self._rva_to_offset(tls_dir_rva, sections)
            if tls_offset is not None:
                addr_of_callbacks = 0
                if is_64bit:
                    if tls_offset + 32 <= len(content):
                        addr_of_callbacks = struct.unpack('<Q', content[tls_offset+24:tls_offset+32])[0]
                else:
                    if tls_offset + 16 <= len(content):
                        addr_of_callbacks = struct.unpack('<I', content[tls_offset+12:tls_offset+16])[0]
                        
                if addr_of_callbacks > 0:
                    callbacks_rva = addr_of_callbacks - image_base
                    callbacks_offset = self._rva_to_offset(callbacks_rva, sections)
                    if callbacks_offset is not None:
                        callback_pointers = []
                        step = 8 if is_64bit else 4
                        for idx in range(100):
                            cb_off = callbacks_offset + idx * step
                            if cb_off + step > len(content):
                                break
                            cb_va = struct.unpack('<Q' if is_64bit else '<I', content[cb_off:cb_off+step])[0]
                            if cb_va == 0:
                                break
                            callback_pointers.append(cb_va)
                            
                        if callback_pointers:
                            anomalies.append(f"TLS Callbacks detected: {len(callback_pointers)} callback(s) defined at {hex(addr_of_callbacks)}")
                        else:
                            anomalies.append("TLS Directory present but empty callbacks array")
                    else:
                        anomalies.append("TLS Directory present with unresolvable callbacks array address")

        # 5. Resources size & entropy check
        if resource_dir_size > 0 and len(content) > 0:
            resource_ratio = resource_dir_size / len(content)
            if resource_ratio > 0.5:
                anomalies.append(f"Unusually large resource directory: {resource_ratio:.1%} of total file size")
                
        for hash_entry in section_hashes:
            if hash_entry.name == '.rsrc' and hash_entry.entropy > 7.2:
                anomalies.append(f"High entropy in resource section (.rsrc): {hash_entry.entropy:.2f} (potential encrypted payload)")
            elif hash_entry.entropy > 7.5 and hash_entry.raw_size > 1024:
                anomalies.append(f"High entropy section '{hash_entry.name}': {hash_entry.entropy:.2f} (likely packed or encrypted)")
                
            # Packer section names check
            SUSPICIOUS_SEC_NAMES = {
                'UPX0', 'UPX1', 'UPX2', '.UPX0', '.UPX1', 'aspack', 'ASPack', '.aspack',
                'pesta', 'PECompact', 'protect', 'petite', 'themida', '.themida',
                'vmp', '.vmp0', '.vmp1', '.vmp2', 'enigma', '.enigma'
            }
            if hash_entry.name in SUSPICIOUS_SEC_NAMES:
                anomalies.append(f"Suspicious section name: '{hash_entry.name}' (associated with packers/protectors)")
                
        return anomalies

    def _compute_entropy(self, data: bytes) -> float:
        """Compute Shannon Entropy of a given byte block."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _rva_to_offset(self, rva: int, sections: List[dict]) -> Optional[int]:
        """Convert a Relative Virtual Address (RVA) to file offset using section headers."""
        if rva == 0:
            return None
        for sec in sections:
            va = sec['virtual_address']
            vsize = sec['virtual_size']
            raw_size = sec['raw_size']
            ptr_raw = sec['pointer_to_raw_data']
            
            eff_size = vsize if vsize > 0 else raw_size
            if va <= rva < va + eff_size:
                offset_diff = rva - va
                return ptr_raw + offset_diff
        return None

    def _read_null_terminated_string(self, content: bytes, offset: int, max_length: int = 256) -> str:
        """Read a null-terminated ASCII string from the file content safely."""
        if offset is None or offset >= len(content):
            return ""
        end = offset
        while end < len(content) and content[end] != 0 and (end - offset) < max_length:
            end += 1
        return content[offset:end].decode('utf-8', errors='ignore')

    def _calculate_risk_score(self, anomalies: List[str], imports: List[ImportEntry], section_hashes: List[SectionHash]) -> int:
        """Calculate dynamic risk score (0-100) based on detected anomalies and imports."""
        score = 0
        for anomaly in anomalies:
            if "Process Injection" in anomaly:
                score += 35
            elif "Process Hollowing" in anomaly:
                score += 35
            elif "SetWindowsHookEx" in anomaly:
                score += 20
            elif "TLS Callbacks" in anomaly:
                score += 15
            elif "Overlapping sections" in anomaly:
                score += 25
            elif "Zero virtual-size" in anomaly:
                score += 20
            elif "High entropy section" in anomaly:
                score += 20
            elif "Suspicious section name" in anomaly:
                score += 25
            elif "resource directory" in anomaly:
                score += 15
            elif "resource section" in anomaly:
                score += 15
                
        # Check suspicious imports
        all_funcs = {f.lower() for entry in imports for f in entry.functions}
        suspicious_count = sum(1 for f in all_funcs if f in SUSPICIOUS_FUNCTIONS)
        score += suspicious_count * 4
        
        return min(max(score, 0), 100)
