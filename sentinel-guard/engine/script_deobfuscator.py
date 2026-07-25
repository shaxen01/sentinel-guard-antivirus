"""
Sentinel Guard — Script Deobfuscator and Analyzer
Deobfuscates and analyzes scripts for malicious patterns.
"""
import re
import base64
import binascii
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ObfuscationResult:
    is_obfuscated: bool
    techniques: List[str]
    deobfuscated_content: str
    iocs: List[str]
    risk_score: int


class ScriptDeobfuscator:
    """Deobfuscator and analyzer for PowerShell, JavaScript, VBScript, and HTML scripts."""

    REVERSED_KEYWORDS = {
        'llehsrewop': 'powershell',
        'atad': 'data',
        'ptth': 'http',
        'sptth': 'https',
        'xei': 'iex',
        'gnirtSdaolnwoD': 'DownloadString',
        'eliFdaolnwoD': 'DownloadFile',
        'tneilCbeW': 'WebClient',
        'tnetnoc': 'content',
        'etaerC': 'Create',
        'llehS.tpircSW': 'WScript.Shell',
        'noitpecxE-ekovnI': 'Invoke-Expression',
        'ssapyb': 'bypass',
        'noisreVtnerruC': 'CurrentVersion',
        'enil_dnoc': 'cond_line',
        'lave': 'eval',
    }

    def _normalize_script_type(self, script_type: str) -> str:
        """Normalize the script type input into a standard canonical form."""
        if not script_type:
            return 'unknown'
        st = script_type.lower().strip()
        if st in ('powershell', 'ps1', 'ps', 'powershell/script'):
            return 'powershell'
        if st in ('javascript', 'js', 'ecmascript', 'jscript'):
            return 'javascript'
        if st in ('vbscript', 'vbs', 'visualbasic'):
            return 'vbscript'
        if st in ('html', 'htm', 'hta', 'xhtml'):
            return 'html'
        return 'unknown'

    def deobfuscate(self, content: str, script_type: str) -> str:
        """Deobfuscate PowerShell, JavaScript, VBScript, and HTML scripts."""
        if not content:
            return ""

        script_type_norm = self._normalize_script_type(script_type)
        logger.debug(f"Deobfuscating script (type: {script_type}, normalized: {script_type_norm})")

        current_content = content
        max_iterations = 5

        for i in range(max_iterations):
            previous_content = current_content

            # 1. Decode HTML Entities (common in HTML or embedded scripts)
            current_content = self._decode_html_entities(current_content)

            # 2. Decode Unicode Escapes (\uXXXX)
            current_content = self._decode_unicode_escape(current_content)

            # 3. Decode Hex Escapes (\xXX)
            current_content = self._decode_hex(current_content)

            # 4. Decode Base64 Encodings
            current_content = self._decode_base64(current_content)

            # 5. Language-Specific Deobfuscations
            if script_type_norm == 'powershell':
                current_content = self._deobfuscate_reversed_keywords(current_content)
                current_content = self._unescape_powershell(current_content)
                current_content = self._resolve_concatenation(current_content, 'powershell')
            elif script_type_norm == 'javascript':
                current_content = self._deobfuscate_reversed_keywords(current_content)
                current_content = self._resolve_js_char_encoding(current_content)
                current_content = self._resolve_js_string_reversal(current_content)
                current_content = self._resolve_concatenation(current_content, 'javascript')
            elif script_type_norm == 'vbscript':
                current_content = self._deobfuscate_reversed_keywords(current_content)
                current_content = self._resolve_vbs_chr(current_content)
                current_content = self._resolve_concatenation(current_content, 'vbscript')
            elif script_type_norm == 'html':
                current_content = self._deobfuscate_html_scripts(current_content)
            else:
                # Fallback generic deobfuscation
                current_content = self._deobfuscate_reversed_keywords(current_content)
                current_content = self._resolve_js_char_encoding(current_content)
                current_content = self._resolve_vbs_chr(current_content)
                current_content = self._resolve_concatenation(current_content, 'generic')

            # If no change was made, we have reached a stable point
            if current_content == previous_content:
                logger.debug(f"Deobfuscation loop stabilized after {i + 1} iterations.")
                break

        return current_content

    def detect_obfuscation(self, content: str, script_type: str) -> ObfuscationResult:
        """Detect obfuscation techniques used and estimate risk score and IOCs."""
        if not content:
            return ObfuscationResult(
                is_obfuscated=False,
                techniques=[],
                deobfuscated_content="",
                iocs=[],
                risk_score=0
            )

        script_type_norm = self._normalize_script_type(script_type)
        deobfuscated_content = self.deobfuscate(content, script_type_norm)

        techniques = []
        score = 0

        # 1. Base64 Check
        has_base64_sig = bool(re.search(r'(?i)FromBase64|atob|-(?:encodedcommand|encoded|enc|en|e)\b\s+["\']?[A-Za-z0-9+/=]{12,}', content))
        has_base64_change = self._decode_base64(content) != content
        if has_base64_sig or has_base64_change:
            techniques.append("base64_encoding")
            score += 25

        # 2. Hex Check
        has_hex_sig = bool(re.search(r'\\x[0-9a-fA-F]{2}', content))
        has_hex_change = self._decode_hex(content) != content
        if has_hex_sig or has_hex_change:
            techniques.append("hex_encoding")
            score += 15

        # 3. Unicode Escapes Check
        has_unicode_sig = bool(re.search(r'\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}', content))
        has_unicode_change = self._decode_unicode_escape(content) != content
        if has_unicode_sig or has_unicode_change:
            techniques.append("unicode_escapes")
            score += 10

        # 4. Char Encoding Check
        has_char_sig = bool(re.search(r'(?i)String\s*\.\s*fromCharCode|ChrW?\s*\(|\[char\]\s*[\doxX]', content))
        has_char_change = (
            self._resolve_js_char_encoding(content) != content or
            self._resolve_vbs_chr(content) != content or
            (script_type_norm == 'powershell' and self._unescape_powershell(content) != content and '[char]' in content)
        )
        if has_char_sig or has_char_change:
            techniques.append("char_encoding")
            score += 15

        # 5. Concatenation Abuse Check
        # Significant concatenation (3+ concatenations) or noticeable change
        concat_count = len(re.findall(r'["\']\s*[\+&]\s*["\']', content))
        has_concat_change = self._resolve_concatenation(content, script_type_norm) != content
        if concat_count >= 3 or has_concat_change:
            techniques.append("concatenation_abuse")
            score += 20

        # 6. String Reversal Check
        has_reversal_sig = bool(re.search(r'(?i)\.reverse\s*\(|split\s*\(\s*["\']\s*["\']\s*\)\s*\.\s*reverse', content))
        has_reversal_change = self._deobfuscate_reversed_keywords(content) != content
        if has_reversal_sig or has_reversal_change:
            techniques.append("string_reversal")
            score += 20

        # 7. Eval/Exec Execution Check (presence is highly risky)
        has_eval = bool(re.search(
            r'(?i)\beval\s*\(|\bexec\s*\(|\bIEX\b|\bInvoke-Expression\b|\bFunction\s*\(|\bWScript\.Shell\.Run\b|\bShell\.Application\.Execute\b',
            content
        ))
        if has_eval:
            techniques.append("eval_execution")
            score += 30

        # Cap the risk score at 100
        risk_score = min(score, 100)
        is_obfuscated = len(techniques) > 0 or (deobfuscated_content != content)

        # Extract IOCs from both original and deobfuscated content (maximizing visibility)
        iocs_original = self._extract_iocs(content)
        iocs_deobf = self._extract_iocs(deobfuscated_content)
        all_iocs = sorted(list(set(iocs_original + iocs_deobf)))

        return ObfuscationResult(
            is_obfuscated=is_obfuscated,
            techniques=techniques,
            deobfuscated_content=deobfuscated_content,
            iocs=all_iocs,
            risk_score=risk_score
        )

    def _try_decode_bytes(self, data: bytes) -> Optional[str]:
        """Try to decode bytes into a printable string using UTF-16LE, UTF-8, or Latin-1."""
        if not data:
            return None

        # Try UTF-16LE first (PowerShell default)
        try:
            decoded = data.decode('utf-16-le')
            if len(decoded) > 0:
                printable_chars = sum(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded)
                if (printable_chars / len(decoded)) > 0.85:
                    return decoded
        except Exception:
            pass

        # Try UTF-8
        try:
            decoded = data.decode('utf-8')
            if len(decoded) > 0:
                printable_chars = sum(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded)
                if (printable_chars / len(decoded)) > 0.85:
                    return decoded
        except Exception:
            pass

        # Try Latin-1 fallback (stricter printable threshold)
        try:
            decoded = data.decode('latin-1')
            if len(decoded) > 0:
                printable_chars = sum(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded)
                if (printable_chars / len(decoded)) > 0.95:
                    return decoded
        except Exception:
            pass

        return None

    def _decode_base64(self, content: str) -> str:
        """Locate and decode Base64 encoded strings within the content."""
        # 1. Search for explicit base64 patterns in calls like FromBase64String("...") or atob("...")
        patterns = [
            r'(?i)FromBase64String\s*\(\s*[\'"]([A-Za-z0-9+/=\s\r\n]+)[\'"]\s*\)',
            r'(?i)atob\s*\(\s*[\'"]([A-Za-z0-9+/=\s\r\n]+)[\'"]\s*\)',
        ]
        for pattern in patterns:
            def repl(match):
                b64_str = re.sub(r'\s+', '', match.group(1))
                try:
                    missing_padding = len(b64_str) % 4
                    if missing_padding:
                        b64_str += '=' * (4 - missing_padding)
                    decoded_bytes = base64.b64decode(b64_str)
                    decoded_str = self._try_decode_bytes(decoded_bytes)
                    if decoded_str is not None:
                        escaped = decoded_str.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                        return f'"{escaped}"'
                except Exception:
                    pass
                return match.group(0)
            content = re.sub(pattern, repl, content)

        # 2. Search for generic quoted base64 strings
        quoted_pattern = r'([\'"])([A-Za-z0-9+/=\s\r\n]{12,})\1'
        def repl_quoted(match):
            b64_str = re.sub(r'\s+', '', match.group(2))
            # Pad if required
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str_padded = b64_str + '=' * (4 - missing_padding)
            else:
                b64_str_padded = b64_str

            try:
                decoded_bytes = base64.b64decode(b64_str_padded)
                decoded_str = self._try_decode_bytes(decoded_bytes)
                if decoded_str is not None:
                    escaped = decoded_str.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                    return f'"{escaped}"'
            except Exception:
                pass
            return match.group(0)

        content = re.sub(quoted_pattern, repl_quoted, content)
        return content

    def _decode_hex(self, content: str) -> str:
        """Locate and decode Hex escaped sequences like \\xXX."""
        pattern = r'\\x([0-9a-fA-F]{2})'
        def repl_hex(match):
            hex_val = match.group(1)
            try:
                char = chr(int(hex_val, 16))
                if 32 <= ord(char) < 127 or char in '\r\n\t':
                    return char
            except Exception:
                pass
            return match.group(0)

        return re.sub(pattern, repl_hex, content)

    def _decode_unicode_escape(self, content: str) -> str:
        """Locate and decode Unicode escaped sequences like \\uXXXX or \\u{XXXX}."""
        # 1. Standard Unicode sequences like \u0041
        pattern_std = r'\\u([0-9a-fA-F]{4})'
        def repl_std(match):
            hex_val = match.group(1)
            try:
                char = chr(int(hex_val, 16))
                if 32 <= ord(char) < 127 or char in '\r\n\t' or ord(char) > 127:
                    return char
            except Exception:
                pass
            return match.group(0)
        content = re.sub(pattern_std, repl_std, content)

        # 2. ES6 Unicode sequences like \u{0041} or \u{41}
        pattern_es6 = r'\\u\{([0-9a-fA-F]{1,6})\}'
        def repl_es6(match):
            hex_val = match.group(1)
            try:
                char = chr(int(hex_val, 16))
                if 32 <= ord(char) < 127 or char in '\r\n\t' or ord(char) > 127:
                    return char
            except Exception:
                pass
            return match.group(0)
        content = re.sub(pattern_es6, repl_es6, content)

        return content

    def _decode_html_entities(self, content: str) -> str:
        """Locate and decode HTML entities (decimal, hex, and named)."""
        # 1. Decimal entities like &#41;
        content = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), content)

        # 2. Hex entities like &#x29; or &#X29;
        content = re.sub(r'&#[xX]([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), content)

        # 3. Named entities
        named_entities = {
            'quot': '"',
            'amp': '&',
            'lt': '<',
            'gt': '>',
            'apos': "'",
            'nbsp': ' ',
            'iexcl': '¡',
            'cent': '¢',
            'pound': '£',
            'curren': '¤',
            'yen': '¥',
            'brvbar': '¦',
            'sect': '§',
            'uml': '¨',
            'copy': '©',
            'ordf': 'ª',
            'laquo': '«',
            'not': '¬',
            'reg': '®',
            'macr': '¯',
            'deg': '°',
            'plusmn': '±',
            'sup2': '²',
            'sup3': '³',
            'acute': '´',
            'micro': 'µ',
            'para': '¶',
            'middot': '·',
            'cedil': '¸',
            'sup1': '¹',
            'ordm': 'º',
            'raquo': '»',
            'frac14': '¼',
            'frac12': '½',
            'frac34': '¾',
            'iquest': '¿',
        }
        def repl_named(match):
            name = match.group(1)
            return named_entities.get(name, match.group(0))

        return re.sub(r'&([a-zA-Z0-9]+);', repl_named, content)

    def _unescape_powershell(self, content: str) -> str:
        """Deobfuscate PowerShell specific obfuscations (backticks, -enc command line, -f formatting, [char])."""
        # 1. Resolve backtick line continuations: backtick at the end of a line
        content = re.sub(r'`\r?\n', '', content)

        # 2. Resolve general backtick character escapes
        backtick_pattern = r'`([nrtb0]|.)'
        def repl_backtick(match):
            char = match.group(1)
            mapping = {
                'n': '\n',
                'r': '\r',
                't': '\t',
                'b': '\b',
                '0': '\x00'
            }
            return mapping.get(char, char)
        content = re.sub(backtick_pattern, repl_backtick, content)

        # 3. Resolve PowerShell base64 encoded command arguments
        enc_pattern = r'(?i)-(?:encodedcommand|encoded|enc|en|e)\s+["\']?([A-Za-z0-9+/=]{12,})["\']?'
        def repl_enc(match):
            b64_str = match.group(1)
            try:
                missing_padding = len(b64_str) % 4
                if missing_padding:
                    b64_str += '=' * (4 - missing_padding)
                decoded_bytes = base64.b64decode(b64_str)
                decoded_str = decoded_bytes.decode('utf-16-le', errors='ignore')
                printable_chars = sum(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded_str)
                if len(decoded_str) > 0 and (printable_chars / len(decoded_str)) > 0.8:
                    return f'-Command "{decoded_str}"'
            except Exception:
                pass
            return match.group(0)
        content = re.sub(enc_pattern, repl_enc, content)

        # 4. Resolve format operator: "{1}{0}" -f "world", "hello"
        format_pattern = r'(?i)(["\'](?:\{[0-9]+\})+["\'])\s*-f\s*((?:["\'][^"\']*["\']\s*(?:,\s*)?)+)'
        def repl_format(match):
            fmt_str_quoted = match.group(1)
            args_str = match.group(2)
            fmt_str = fmt_str_quoted[1:-1]
            args = re.findall(r'["\']([^"\']*)["\']', args_str)
            try:
                result = fmt_str
                for idx, arg in enumerate(args):
                    result = result.replace(f"{{{idx}}}", arg)
                return f'"{result}"'
            except Exception:
                pass
            return match.group(0)
        content = re.sub(format_pattern, repl_format, content)

        # 5. Resolve decimal [char] casting: [char]65 -> "A"
        char_pattern_dec = r'(?i)\[char\]\s*(\d+)'
        def repl_char_dec(match):
            try:
                char = chr(int(match.group(1)))
                if 32 <= ord(char) < 127 or char in '\r\n\t':
                    return f'"{char}"'
            except Exception:
                pass
            return match.group(0)
        content = re.sub(char_pattern_dec, repl_char_dec, content)

        # 6. Resolve hexadecimal [char] casting: [char]0x41 -> "A"
        char_pattern_hex = r'(?i)\[char\]\s*(0x[0-9a-fA-F]+)'
        def repl_char_hex(match):
            try:
                char = chr(int(match.group(1), 16))
                if 32 <= ord(char) < 127 or char in '\r\n\t':
                    return f'"{char}"'
            except Exception:
                pass
            return match.group(0)
        content = re.sub(char_pattern_hex, repl_char_hex, content)

        return content

    def _resolve_js_char_encoding(self, content: str) -> str:
        """Resolve JS char encoding like String.fromCharCode(104, 101, 108, 108, 111)."""
        pattern = r'(?i)\bString\s*\.\s*fromCharCode\s*\(\s*([0-9\s,xXa-fA-F]+)\s*\)'
        def repl_js_char(match):
            args_str = match.group(1)
            parts = [p.strip() for p in args_str.split(',') if p.strip()]
            chars = []
            try:
                for part in parts:
                    if part.lower().startswith('0x'):
                        val = int(part, 16)
                    else:
                        val = int(part)
                    chars.append(chr(val))
                joined = "".join(chars)
                escaped = joined.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                return f'"{escaped}"'
            except Exception:
                pass
            return match.group(0)

        return re.sub(pattern, repl_js_char, content)

    def _resolve_js_string_reversal(self, content: str) -> str:
        """Resolve JS string reversal like "dlrow".split("").reverse().join("")."""
        pattern = r'(["\'])([^\n"\\]*(?:\\.[^\n"\\]*)*)\1\s*\.\s*split\s*\(\s*(["\'])\3\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(["\'])\4\s*\)'
        def repl_js_rev(match):
            val = match.group(2)
            reversed_val = val[::-1]
            quote = match.group(1)
            return f"{quote}{reversed_val}{quote}"

        return re.sub(pattern, repl_js_rev, content)

    def _resolve_vbs_chr(self, content: str) -> str:
        """Resolve VBScript Chr/ChrW conversions."""
        vbs_chr_pattern = r'(?i)\bChrW?\s*\(\s*(&[hH][0-9a-fA-F]+|\d+)\s*\)'
        def repl_vbs_chr(match):
            val = match.group(1)
            try:
                if val.lower().startswith('&h'):
                    char_code = int(val[2:], 16)
                else:
                    char_code = int(val)
                char = chr(char_code)
                if 32 <= ord(char) < 127 or char in '\r\n\t':
                    return f'"{char}"'
            except Exception:
                pass
            return match.group(0)

        return re.sub(vbs_chr_pattern, repl_vbs_chr, content)

    def _resolve_concatenation(self, content: str, script_type: str) -> str:
        """Merge adjacent concatenated strings."""
        # Double quotes concatenation
        pattern_double = r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*[\+&]\s*"([^"\\]*(?:\\.[^"\\]*)*)"'

        # Single quotes concatenation
        pattern_single = r"'([^'\\]*(?:\\.[^'\\]*)*)'\s*[\+&]\s*'([^'\\]*(?:\\.[^'\\]*)*)'"

        # Mixed quotes
        pattern_mixed1 = r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*[\+&]\s*\'([^\'\\]*(?:\\.[\'\\]*)*)\''
        pattern_mixed2 = r'\'([^\'\\]*(?:\\.[\'\\]*)*)\'\s*[\+&]\s*"([^"\\]*(?:\\.[^"\\]*)*)"'

        old_content = ""
        iterations = 0
        max_iterations = 10

        while old_content != content and iterations < max_iterations:
            old_content = content
            iterations += 1

            content = re.sub(pattern_double, lambda m: f'"{m.group(1)}{m.group(2)}"', content)
            content = re.sub(pattern_single, lambda m: f"'{m.group(1)}{m.group(2)}'", content)
            content = re.sub(pattern_mixed1, lambda m: f'"{m.group(1)}{m.group(2)}"', content)
            content = re.sub(pattern_mixed2, lambda m: f'"{m.group(1)}{m.group(2)}"', content)

        return content

    def _deobfuscate_reversed_keywords(self, content: str) -> str:
        """Reverse specifically known obfuscated keyword patterns (like 'llehsrewop')."""
        quoted_pattern = r'(["\'])([^\n"\\]*(?:\\.[^\n"\\]*)*)\1'
        def repl_reversed(match):
            quote = match.group(1)
            val = match.group(2)
            for rev_key, orig_key in self.REVERSED_KEYWORDS.items():
                if val.lower() == rev_key.lower():
                    return f"{quote}{orig_key}{quote}"
            return match.group(0)

        return re.sub(quoted_pattern, repl_reversed, content)

    def _deobfuscate_html_scripts(self, content: str) -> str:
        """Find script tags in HTML, deobfuscate them as JS, and replace them."""
        script_pattern = r'(?is)(<script[^>]*>)(.*?)(</script>)'
        def repl_html_script(match):
            start_tag = match.group(1)
            script_code = match.group(2)
            end_tag = match.group(3)
            deobfuscated_code = self.deobfuscate(script_code, 'javascript')
            return f"{start_tag}{deobfuscated_code}{end_tag}"

        return re.sub(script_pattern, repl_html_script, content)

    def _extract_iocs(self, content: str) -> List[str]:
        """Extract IPs, URLs, domains, file paths, and registry keys from content."""
        iocs = set()

        # 1. IP Addresses (IPv4)
        raw_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        for ip in raw_ips:
            octets = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                iocs.add(ip)

        # 2. URLs
        urls = re.findall(r'https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[a-zA-Z0-9.\-_?&=%#~+]*)?', content)
        for url in urls:
            iocs.add(url.strip())

        # 3. Domains from URLs and standalone suspicious domains
        for url in urls:
            match = re.match(r'https?://([a-zA-Z0-9.\-_]+)', url)
            if match:
                domain = match.group(1)
                if ':' in domain:
                    domain = domain.split(':')[0]
                iocs.add(domain)

        # Standalone domains with standard malicious/general TLDs
        tlds = r'com|org|net|edu|gov|mil|biz|info|io|co|ru|cn|tk|xyz|top|pw|cc|icu|gq|cf|ml|ga'
        quoted_domains = re.findall(r'["\']([a-zA-Z0-9.\-_]+\.(?:' + tlds + r'))["\']', content)
        for domain in quoted_domains:
            # Prevent matching classes (e.g. System.Object) by requiring no capitalized parts before TLD
            if not re.search(r'\s', domain) and not any(part[0].isupper() for part in domain.split('.')[:-1] if part):
                iocs.add(domain.strip().lower())

        # 4. Registry Keys
        reg_patterns = [
            r'\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)(?:\\\\?)[a-zA-Z0-9_\-\\]+',
        ]
        for pattern in reg_patterns:
            keys = re.findall(pattern, content)
            for key in keys:
                cleaned_key = key.rstrip('\\').replace('\\\\', '\\')
                iocs.add(cleaned_key)

        # 5. File Paths
        # Drive letter paths: C:\path\file.ext or C:\\path\\file.ext
        win_drive_paths = re.findall(r'\b[a-zA-Z]:(?:\\\\?)[a-zA-Z0-9_\-\\]+\.[a-zA-Z0-9]{2,4}\b', content)
        for path in win_drive_paths:
            cleaned_path = path.replace('\\\\', '\\')
            iocs.add(cleaned_path)

        # Environment variable paths: %TEMP%\file.ext
        win_env_paths = re.findall(r'%[a-zA-Z_]+%(?:\\\\?)[a-zA-Z0-9_\-\\]+\.[a-zA-Z0-9]{2,4}\b', content)
        for path in win_env_paths:
            cleaned_path = path.replace('\\\\', '\\')
            iocs.add(cleaned_path)

        # Unix paths
        unix_paths = re.findall(r'\b/(?:bin|tmp|var|etc|opt|usr|home|lib|dev|run|mnt|sbin)/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z0-9]{2,4})?\b', content)
        for path in unix_paths:
            iocs.add(path.rstrip('/.'))

        return sorted(list(iocs))
