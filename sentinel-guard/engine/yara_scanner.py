"""
Sentinel Guard — YARA Rule Scanner
This module provides YARA-based signature scanning with optional yara-python integration.
If yara-python is not installed, it falls back to a custom regex-based parser and scanner.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Try to import yara gracefully
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.info("yara-python is not installed. YARA scanning will use the built-in fallback parser.")

@dataclass
class YaraMatch:
    rule_name: str
    file_path: str
    matched_strings: List[str]
    meta: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


def extract_rules_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Extract rule blocks from YARA rule text while handling comments 
    and nested braces gracefully.
    """
    # Remove C-style comments (/* ... */) and single-line comments (// ...)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'//.*', '', text)

    rules = []
    pos = 0
    n = len(text)
    while pos < n:
        match = re.search(r'\brule\s+(\w+)', text[pos:])
        if not match:
            break
        
        rule_name = match.group(1)
        rule_start = pos + match.start()
        
        # Find the opening brace of this rule
        brace_start = text.find('{', rule_start)
        if brace_start == -1:
            break
            
        # Parse tags from the header (between rule name and opening brace)
        header = text[rule_start + len("rule") + len(rule_name):brace_start]
        tags = []
        if ':' in header:
            tag_part = header.split(':', 1)[1]
            tags = [t.strip() for t in re.split(r'\s+', tag_part) if t.strip()]
        
        # Find matching closing brace tracking depth to avoid issues with internal nested braces (e.g. { ... } in hex strings)
        depth = 1
        i = brace_start + 1
        while i < n and depth > 0:
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
            i += 1
        
        if depth == 0:
            rule_body = text[brace_start+1 : i-1]
            rules.append({
                "name": rule_name,
                "tags": tags,
                "body": rule_body
            })
            pos = i
        else:
            # Unmatched braces, advance to recover
            pos = brace_start + 1
            
    return rules


def parse_rule_body(body: str) -> Dict[str, Any]:
    """Parse the meta, strings, and condition sections from a rule body."""
    meta = {}
    strings = {}
    condition = ""
    
    # Locate section starts
    meta_match = re.search(r'\bmeta\s*:', body)
    strings_match = re.search(r'\bstrings\s*:', body)
    condition_match = re.search(r'\bcondition\s*:', body)
    
    spans = []
    if meta_match:
        spans.append(("meta", meta_match.start(), meta_match.end()))
    if strings_match:
        spans.append(("strings", strings_match.start(), strings_match.end()))
    if condition_match:
        spans.append(("condition", condition_match.start(), condition_match.end()))
        
    spans.sort(key=lambda x: x[1])
    
    blocks = {}
    for idx, (name, start, end) in enumerate(spans):
        next_start = spans[idx+1][1] if idx + 1 < len(spans) else len(body)
        blocks[name] = body[end:next_start].strip()
        
    # Parse meta block
    if "meta" in blocks:
        for line in blocks["meta"].splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r'^([\w_-]+)\s*=\s*(.*)$', line)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                # Strip quotes if present
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                else:
                    # Convert types
                    if val.lower() == "true":
                        val = True
                    elif val.lower() == "false":
                        val = False
                    else:
                        try:
                            val = int(val)
                        except ValueError:
                            pass
                meta[key] = val
                
    # Parse strings block
    if "strings" in blocks:
        for line in blocks["strings"].splitlines():
            line = line.strip()
            if not line:
                continue
            # Match $name = value and optional modifiers
            m = re.match(r'^(\$[\w_]*)\s*=\s*(.*?)(?:\s+(nocase|ascii|wide|fullword))*$', line)
            if m:
                var_name = m.group(1)
                var_val = m.group(2).strip()
                
                # Extract modifiers
                modifiers = []
                for mod in ["nocase", "ascii", "wide", "fullword"]:
                    if re.search(r'\b' + mod + r'\b', line):
                        modifiers.append(mod)
                        
                if var_val.startswith('{') and var_val.endswith('}'):
                    strings[var_name] = {
                        "type": "hex",
                        "value": var_val[1:-1].strip(),
                        "modifiers": modifiers
                    }
                elif var_val.startswith('/') and var_val.endswith('/'):
                    strings[var_name] = {
                        "type": "regex",
                        "value": var_val[1:-1],
                        "modifiers": modifiers
                    }
                elif var_val.startswith('"') and var_val.endswith('"'):
                    strings[var_name] = {
                        "type": "text",
                        "value": var_val[1:-1],
                        "modifiers": modifiers
                    }
                else:
                    strings[var_name] = {
                        "type": "text",
                        "value": var_val,
                        "modifiers": modifiers
                    }
                    
    # Parse condition block
    if "condition" in blocks:
        condition = blocks["condition"].strip()
        
    return {
        "meta": meta,
        "strings": strings,
        "condition": condition
    }


def compile_hex_pattern(hex_val: str) -> Optional[re.Pattern]:
    """Compile a YARA hex string into a Python bytes-regex pattern."""
    # Clean inner comments & space normalize
    hex_val = re.sub(r'//.*', '', hex_val)
    hex_val = re.sub(r'\s+', ' ', hex_val).strip()
    
    tokens = hex_val.split()
    regex_parts = []
    for token in tokens:
        token = token.upper()
        if token == '??' or token == '?':
            regex_parts.append(b'.')
        elif '?' in token:
            regex_parts.append(b'.')
        elif token.startswith('[') and token.endswith(']'):
            jump_content = token[1:-1]
            if '-' in jump_content:
                low, high = jump_content.split('-', 1)
                regex_parts.append(f'.{{{low},{high}}}'.encode('ascii'))
            else:
                regex_parts.append(f'.{{{jump_content}}}'.encode('ascii'))
        else:
            try:
                val = int(token, 16)
                regex_parts.append(re.escape(bytes([val])))
            except ValueError:
                regex_parts.append(b'.')
                
    try:
        pattern = b"".join(regex_parts)
        return re.compile(pattern, re.DOTALL)
    except Exception:
        return None


def match_pattern(pattern_dict: Dict[str, Any], file_bytes: bytes) -> List[str]:
    """Match a parsed YARA pattern against raw file bytes, returning matched substrings."""
    pat_type = pattern_dict["type"]
    pat_val = pattern_dict["value"]
    modifiers = pattern_dict.get("modifiers", [])
    
    nocase = "nocase" in modifiers
    is_ascii = "ascii" in modifiers
    is_wide = "wide" in modifiers
    
    if not is_ascii and not is_wide:
        is_ascii = True  # YARA default
        
    matched_instances = []
    
    if pat_type == "text":
        byte_variants = []
        if is_ascii:
            byte_variants.append(pat_val.encode('utf-8', errors='ignore'))
        if is_wide:
            # Wide strings have null bytes interleaved
            wide_bytes = "".join(c + '\x00' for c in pat_val).encode('utf-8', errors='ignore')
            byte_variants.append(wide_bytes)
            
        for b_var in byte_variants:
            if nocase:
                try:
                    pat_regex = re.compile(re.escape(b_var), re.IGNORECASE)
                    match = pat_regex.search(file_bytes)
                    if match:
                        matched_instances.append(match.group(0).decode('utf-8', errors='replace'))
                except Exception:
                    if b_var.lower() in file_bytes.lower():
                        matched_instances.append(pat_val)
            else:
                if b_var in file_bytes:
                    matched_instances.append(pat_val)
                    
    elif pat_type == "regex":
        flags = re.DOTALL
        if nocase:
            flags |= re.IGNORECASE
        try:
            pat_bytes = pat_val.encode('utf-8', errors='ignore')
            regex = re.compile(pat_bytes, flags)
            match = regex.search(file_bytes)
            if match:
                matched_instances.append(match.group(0).decode('utf-8', errors='replace'))
        except Exception:
            pass
            
    elif pat_type == "hex":
        regex = compile_hex_pattern(pat_val)
        if regex:
            match = regex.search(file_bytes)
            if match:
                matched_hex = match.group(0).hex().upper()
                spaced_hex = " ".join(matched_hex[i:i+2] for i in range(0, len(matched_hex), 2))
                matched_instances.append(spaced_hex)
                
    return matched_instances


def evaluate_condition(condition: str, matched_vars: Dict[str, bool]) -> bool:
    """Evaluate a YARA condition string using the matched variables' boolean state."""
    cond = condition.strip().lower()
    cond = re.sub(r'//.*', '', cond)
    cond = re.sub(r'/\*.*?\*/', '', cond, flags=re.DOTALL)
    cond = re.sub(r'\s+', ' ', cond)
    
    if cond == "any of them":
        return any(matched_vars.values())
    if cond == "all of them":
        return all(matched_vars.values()) if matched_vars else False
        
    sorted_vars = sorted(matched_vars.keys(), key=len, reverse=True)
    expr = cond
    for var in sorted_vars:
        # Use lowercase string booleans for clean extraction/filtering
        val = str(matched_vars[var]).lower()
        escaped_var = re.escape(var)
        expr = re.sub(escaped_var + r'\b', val, expr)
        
    if "any of them" in expr:
        any_val = str(any(matched_vars.values())).lower()
        expr = expr.replace("any of them", any_val)
    if "all of them" in expr:
        all_val = str(all(matched_vars.values()) if matched_vars else False).lower()
        expr = expr.replace("all of them", all_val)
        
    # Strictly filter characters to prevent arbitrary expression evaluation
    allowed_chars = set("truefalsandornot() ")
    cleaned_expr = "".join(c for c in expr if c in allowed_chars)
    
    try:
        expr_to_eval = cleaned_expr.replace("true", "True").replace("false", "False")
        if expr_to_eval.strip() == "":
            return any(matched_vars.values())
        safe_dict = {"True": True, "False": False}
        return bool(eval(expr_to_eval, {"__builtins__": {}}, safe_dict))
    except Exception as e:
        logger.debug(f"Failed to evaluate rule condition: {e}")
        return any(matched_vars.values())


class YaraScanner:
    """YARA Rule Scanner class supporting native yara-python or robust custom fallback parsing."""

    def __init__(self, rules_dir: Optional[str] = "data/yara_rules"):
        """Initialize the YaraScanner and compile rules from the rules directory if provided."""
        self.rules = None
        self.fallback_rules = []
        if rules_dir:
            self.compile_rules(rules_dir)

    def compile_rules(self, rules_dir: str) -> bool:
        """
        Load and compile YARA rules from the specified directory.
        Works recursively to compile all .yar and .yara files.
        """
        dir_path = Path(rules_dir)
        if not dir_path.exists():
            logger.warning(f"Rules directory does not exist: {rules_dir}")
            return False

        rule_files = list(dir_path.glob("*.yar")) + list(dir_path.glob("*.yara"))
        rule_files += list(dir_path.glob("**/*.yar")) + list(dir_path.glob("**/*.yara"))
        rule_files = sorted(list(set(rule_files)))

        if not rule_files:
            logger.info(f"No YARA rule files found in rules directory: {rules_dir}")
            return False

        logger.info(f"Found {len(rule_files)} YARA rule files to compile.")

        if HAS_YARA:
            # Use yara-python to compile
            filepaths = {f"rule_{i}": str(rf) for i, rf in enumerate(rule_files)}
            try:
                self.rules = yara.compile(filepaths=filepaths)
                logger.info("Successfully compiled YARA rules using yara-python.")
                return True
            except Exception as e:
                logger.error(f"Error compiling YARA rules with yara-python: {e}. Attempting recovery...")
                # Fallback to loading/compiling individual valid files with yara-python
                valid_filepaths = {}
                for i, rf in enumerate(rule_files):
                    try:
                        yara.compile(filepath=str(rf))
                        valid_filepaths[f"rule_{i}"] = str(rf)
                    except Exception as err:
                        logger.error(f"Skipping syntax-invalid YARA rule file {rf.name}: {err}")
                if valid_filepaths:
                    try:
                        self.rules = yara.compile(filepaths=valid_filepaths)
                        logger.info(f"Compiled {len(valid_filepaths)} valid YARA rules with yara-python.")
                        return True
                    except Exception as err_all:
                        logger.error(f"Failed compile after validation: {err_all}")
                logger.warning("yara-python compilation failed completely. Falling back to built-in parser.")

        # Built-in fallback rule parsing & compilation
        self.fallback_rules = []
        for rf in rule_files:
            try:
                with open(rf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                extracted = extract_rules_from_text(content)
                for r in extracted:
                    parsed = parse_rule_body(r["body"])
                    parsed["name"] = r["name"]
                    parsed["tags"] = r["tags"]
                    parsed["file_path"] = str(rf)
                    self.fallback_rules.append(parsed)
            except Exception as e:
                logger.error(f"Error parsing rule file {rf} with built-in compiler: {e}")

        logger.info(f"Compiled {len(self.fallback_rules)} YARA rules using custom fallback matcher.")
        return len(self.fallback_rules) > 0

    def scan_directory(self, rules_dir: str) -> None:
        """
        Alias/method to compile all rules from a given directory as specified 
        by the requirements: `scan_directory(rules_dir) -> compile all rules`.
        """
        self.compile_rules(rules_dir)

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """Scan a file using the compiled YARA rules."""
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            logger.warning(f"File not found or not a valid file: {file_path}")
            return []

        matches = []

        # If yara-python is compiled and working
        if HAS_YARA and self.rules is not None:
            try:
                raw_matches = self.rules.match(str(path))
                for rm in raw_matches:
                    matched_strings = []
                    for offset, string_id, string_data in rm.strings:
                        try:
                            val = string_data.decode('utf-8', errors='replace')
                        except Exception:
                            val = string_data.hex()
                        matched_strings.append(f"{string_id}: {val}")
                        
                    matches.append(YaraMatch(
                        rule_name=rm.rule,
                        file_path=str(path.resolve()),
                        matched_strings=matched_strings,
                        meta=dict(rm.meta),
                        tags=list(rm.tags)
                    ))
                return matches
            except Exception as e:
                logger.error(f"Error scanning with yara-python: {e}. Trying fallback scanner.")

        # Built-in fallback scanning
        if not self.fallback_rules:
            logger.warning("No compiled YARA rules available for scanning.")
            return []

        try:
            with open(path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path} for fallback scanning: {e}")
            return []

        for rule in self.fallback_rules:
            rule_name = rule["name"]
            meta = rule["meta"]
            tags = rule["tags"]
            strings_dict = rule["strings"]
            condition = rule["condition"]

            matched_vars = {}
            matched_strings_details = []
            
            for var_name, pattern_dict in strings_dict.items():
                instances = match_pattern(pattern_dict, file_bytes)
                if instances:
                    matched_vars[var_name] = True
                    for inst in instances[:10]:  # Limit instances logged to prevent extreme sizes
                        matched_strings_details.append(f"{var_name}: {inst}")
                else:
                    matched_vars[var_name] = False

            if evaluate_condition(condition, matched_vars):
                matches.append(YaraMatch(
                    rule_name=rule_name,
                    file_path=str(path.resolve()),
                    matched_strings=matched_strings_details,
                    meta=meta,
                    tags=tags
                ))

        return matches
