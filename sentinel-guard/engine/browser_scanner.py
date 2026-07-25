"""
Sentinel Guard — Browser Extension Scanner
Scans installed extensions for Chrome, Firefox, and Edge to detect malicious and high-risk add-ons.
"""

import os
import json
import zipfile
import platform
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from utils.logger import get_logger

logger = get_logger(__name__)

# Known malicious, adware, or blacklisted extension IDs (Chrome / Edge Web Store)
MALICIOUS_EXTENSION_IDS = {
    "gomejclolomedhhidjnbbgpeagbeicjm",  # Cloud9 Botnet / Adware
    "bgnkhhnnamicdfpeepbndhjneclandgc",  # Fake Flash Player / Adware
    "fgofbclmepmcoofgjcbeolbcoofgjcbe",  # Malware dropper
    "mffccclmepmcoofgjcbeolbcoofgjcbe",  # Malicious adware
    "kclfeidglnononocgjkcbhgecnpndbni",  # Hookads redirector
    "ilgcnbdaffbkebebebebebebebebebeb",  # General malicious injector template
}

# High-risk permissions that should be flagged if misused
HIGH_RISK_PERMISSIONS = {
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*",
    "webRequest", "webRequestBlocking", "debugger", "proxy",
    "cookies", "declarativeNetRequest", "declarativeNetRequestFeedback",
    "browsingData", "management"
}


@dataclass
class ExtensionInfo:
    browser: str
    name: str
    version: str
    path: str
    permissions: List[str]
    is_suspicious: bool
    reason: str


class BrowserScanner:
    """Scans system web browsers for active extensions, plug-ins, and their permissions."""

    def __init__(self):
        self.paths = self._get_browser_paths()

    def _get_browser_paths(self) -> Dict[str, List[Path]]:
        """Determines the standard extension directories for Chrome, Firefox, and Edge across OS platforms."""
        home = Path.home()
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        
        paths = {
            "chrome": [],
            "firefox": [],
            "edge": []
        }
        
        # Chrome Paths
        if platform.system() == "Windows":
            paths["chrome"].append(local_appdata / "Google" / "Chrome" / "User Data")
        elif platform.system() == "Darwin":
            paths["chrome"].append(home / "Library" / "Application Support" / "Google" / "Chrome")
        else:  # Linux
            paths["chrome"].append(home / ".config" / "google-chrome")
            paths["chrome"].append(home / ".config" / "chromium")
            
        # Firefox Paths
        if platform.system() == "Windows":
            paths["firefox"].append(appdata / "Mozilla" / "Firefox")
        elif platform.system() == "Darwin":
            paths["firefox"].append(home / "Library" / "Application Support" / "Firefox")
        else:  # Linux
            paths["firefox"].append(home / ".mozilla" / "firefox")
            paths["firefox"].append(home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox")  # Flatpak
            
        # Edge Paths
        if platform.system() == "Windows":
            paths["edge"].append(local_appdata / "Microsoft" / "Edge" / "User Data")
        elif platform.system() == "Darwin":
            paths["edge"].append(home / "Library" / "Application Support" / "Microsoft Edge")
        else:  # Linux
            paths["edge"].append(home / ".config" / "microsoft-edge")
            paths["edge"].append(home / ".config" / "microsoft-edge-dev")
            paths["edge"].append(home / ".config" / "microsoft-edge-beta")
            
        return paths

    def scan_all(self) -> List[ExtensionInfo]:
        """Runs scan on all supported browsers and aggregates the results."""
        logger.info("Starting browser extension scan...")
        results: List[ExtensionInfo] = []
        
        results.extend(self._scan_chrome())
        results.extend(self._scan_firefox())
        results.extend(self._scan_edge())
        
        logger.info(f"Browser scan complete. Found {len(results)} extensions/plugins.")
        return results

    def _scan_chrome(self) -> List[ExtensionInfo]:
        """Scans Google Chrome (and Chromium) extensions."""
        logger.info("Scanning Google Chrome / Chromium extensions...")
        return self._scan_chromium_browser("Chrome", self.paths["chrome"])

    def _scan_edge(self) -> List[ExtensionInfo]:
        """Scans Microsoft Edge extensions."""
        logger.info("Scanning Microsoft Edge extensions...")
        return self._scan_chromium_browser("Edge", self.paths["edge"])

    def _scan_firefox(self) -> List[ExtensionInfo]:
        """Scans Mozilla Firefox extensions."""
        logger.info("Scanning Mozilla Firefox extensions...")
        extensions_found: List[ExtensionInfo] = []
        base_paths = self.paths["firefox"]
        
        for base_path in base_paths:
            if not base_path.exists():
                continue
            
            # Find extension subdirectories under profiles
            extensions_dirs = list(base_path.glob("Profiles/*/extensions")) + list(base_path.glob("*/extensions"))
            
            for ext_dir in extensions_dirs:
                if not ext_dir.exists():
                    continue
                
                for item in ext_dir.iterdir():
                    ext_id = item.stem  # remove .xpi if present
                    
                    if item.is_dir():
                        # Unpacked directory extension
                        manifest_file = item / "manifest.json"
                        if manifest_file.exists():
                            try:
                                with open(manifest_file, "r", encoding="utf-8", errors="ignore") as f:
                                    manifest = json.load(f)
                                
                                name = manifest.get("name", "Unknown Extension")
                                if isinstance(name, str) and name.startswith("__MSG_") and name.endswith("__"):
                                    localized = self._get_localized_name(item, name)
                                    if localized:
                                        name = localized
                                        
                                permissions = self._extract_permissions(manifest)
                                has_content_scripts = "content_scripts" in manifest
                                
                                ext_info = ExtensionInfo(
                                    browser="Firefox",
                                    name=name,
                                    version=manifest.get("version", "Unknown"),
                                    path=str(item.resolve()),
                                    permissions=permissions,
                                    is_suspicious=False,
                                    reason=""
                                )
                                self._analyze_extension(ext_info, ext_id, has_content_scripts)
                                extensions_found.append(ext_info)
                            except Exception as e:
                                logger.debug(f"Error parsing Firefox directory extension {manifest_file}: {e}")
                                
                    elif item.is_file() and item.suffix.lower() == ".xpi":
                        # Packed XPI (Zip) extension
                        try:
                            with zipfile.ZipFile(item, "r") as zip_ref:
                                if "manifest.json" in zip_ref.namelist():
                                    with zip_ref.open("manifest.json") as f:
                                        manifest = json.loads(f.read().decode("utf-8", errors="ignore"))
                                    
                                    name = manifest.get("name", "Unknown Extension")
                                    if isinstance(name, str) and name.startswith("__MSG_") and name.endswith("__"):
                                        localized = self._get_localized_name_from_zip(zip_ref, name)
                                        if localized:
                                            name = localized
                                            
                                    permissions = self._extract_permissions(manifest)
                                    has_content_scripts = "content_scripts" in manifest
                                    
                                    ext_info = ExtensionInfo(
                                        browser="Firefox",
                                        name=name,
                                        version=manifest.get("version", "Unknown"),
                                        path=str(item.resolve()),
                                        permissions=permissions,
                                        is_suspicious=False,
                                        reason=""
                                    )
                                    self._analyze_extension(ext_info, ext_id, has_content_scripts)
                                    extensions_found.append(ext_info)
                        except Exception as e:
                            logger.debug(f"Error parsing Firefox XPI extension {item}: {e}")
                            
        return extensions_found

    def _scan_chromium_browser(self, browser_name: str, base_paths: List[Path]) -> List[ExtensionInfo]:
        """Shared scanning engine for Chrome and Edge since they use the same storage layout."""
        extensions_found: List[ExtensionInfo] = []
        
        for base_path in base_paths:
            if not base_path.exists():
                continue
            
            # Find manifest.json in matching profile extension folders
            # Format: <Profile_Name>/Extensions/<Extension_ID>/<Version>/manifest.json
            manifest_paths = list(base_path.glob("*/Extensions/*/*/manifest.json"))
            
            for manifest_path in manifest_paths:
                try:
                    parts = manifest_path.parts
                    ext_id = parts[-3]
                    version = parts[-2]
                    
                    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                        manifest = json.load(f)
                        
                    name = manifest.get("name", "Unknown Extension")
                    if isinstance(name, str) and name.startswith("__MSG_") and name.endswith("__"):
                        localized = self._get_localized_name(manifest_path.parent, name)
                        if localized:
                            name = localized
                            
                    permissions = self._extract_permissions(manifest)
                    has_content_scripts = "content_scripts" in manifest
                    
                    ext_info = ExtensionInfo(
                        browser=browser_name,
                        name=name,
                        version=manifest.get("version", version),
                        path=str(manifest_path.parent.resolve()),
                        permissions=permissions,
                        is_suspicious=False,
                        reason=""
                    )
                    
                    self._analyze_extension(ext_info, ext_id, has_content_scripts)
                    extensions_found.append(ext_info)
                except Exception as e:
                    logger.debug(f"Error parsing Chromium manifest {manifest_path}: {e}")
                    
        return extensions_found

    def _extract_permissions(self, manifest: Dict[str, Any]) -> List[str]:
        """Extracts standard, optional, and host permissions from an extension manifest."""
        permissions: List[str] = []
        
        # Standard permissions
        p_list = manifest.get("permissions", [])
        if isinstance(p_list, list):
            permissions.extend([str(p) for p in p_list if p])
            
        # Manifest V3 Host permissions
        hp_list = manifest.get("host_permissions", [])
        if isinstance(hp_list, list):
            permissions.extend([str(p) for p in hp_list if p])
            
        # Optional permissions
        op_list = manifest.get("optional_permissions", [])
        if isinstance(op_list, list):
            permissions.extend([str(p) for p in op_list if p])
            
        return permissions

    def _get_localized_name(self, version_path: Path, msg_key: str) -> Optional[str]:
        """Locates and extracts localized strings (e.g. app name) from an unpacked extension locales folder."""
        key = msg_key[6:-2].lower()
        locales_dir = version_path / "_locales"
        if not locales_dir.exists():
            return None
            
        preferred_langs = ["en_US", "en", "en_GB"]
        all_langs = [d.name for d in locales_dir.iterdir() if d.is_dir()]
        
        for lang in preferred_langs + all_langs:
            msg_file = locales_dir / lang / "messages.json"
            if msg_file.exists():
                try:
                    with open(msg_file, "r", encoding="utf-8", errors="ignore") as f:
                        messages = json.load(f)
                    for k, v in messages.items():
                        if k.lower() == key:
                            return v.get("message")
                except Exception:
                    pass
        return None

    def _get_localized_name_from_zip(self, zip_ref: zipfile.ZipFile, msg_key: str) -> Optional[str]:
        """Locates and extracts localized strings from a zip/XPI file."""
        key = msg_key[6:-2].lower()
        namelist = zip_ref.namelist()
        
        preferred_langs = ["en_US", "en", "en_GB"]
        locales_files = [f for f in namelist if f.startswith("_locales/") and f.endswith("messages.json")]
        
        for lang in preferred_langs:
            for f_path in locales_files:
                parts = f_path.split("/")
                if len(parts) >= 3 and parts[1].lower().startswith(lang.lower()):
                    try:
                        with zip_ref.open(f_path) as f:
                            messages = json.loads(f.read().decode("utf-8", errors="ignore"))
                        for k, v in messages.items():
                            if k.lower() == key:
                                return v.get("message")
                    except Exception:
                        pass
                        
        for f_path in locales_files:
            try:
                with zip_ref.open(f_path) as f:
                    messages = json.loads(f.read().decode("utf-8", errors="ignore"))
                for k, v in messages.items():
                    if k.lower() == key:
                        return v.get("message")
            except Exception:
                pass
                
        return None

    def _analyze_extension(self, ext: ExtensionInfo, ext_id: str, has_content_scripts: bool):
        """Analyzes permission lists and extension IDs to flag high-risk or known malicious additions."""
        norm_id = ext_id.lower().strip()
        
        # 1. Check known malicious databases
        if norm_id in MALICIOUS_EXTENSION_IDS:
            ext.is_suspicious = True
            ext.reason = f"Known malicious extension ID: {ext_id}"
            return
            
        # 2. Check for broad host permissions + content scripts (arbitrary code injection capability)
        broad_permissions = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
        has_broad_host = any(p in broad_permissions for p in ext.permissions)
        
        if has_broad_host and has_content_scripts:
            ext.is_suspicious = True
            ext.reason = "Extension has broad host permissions (<all_urls> or *://*/*) and injected content scripts. It can read/write data on all websites."
            return
            
        # 3. Check for heavy permissions + debugger (very high risk)
        if "debugger" in ext.permissions and has_broad_host:
            ext.is_suspicious = True
            ext.reason = "Extension requests high-privilege 'debugger' control along with broad website access."
            return
            
        # 4. Check for excessive counts of high risk permissions
        high_risk_matches = [p for p in ext.permissions if p in HIGH_RISK_PERMISSIONS]
        if len(high_risk_matches) >= 5:
            ext.is_suspicious = True
            ext.reason = f"Excessive counts of high-risk permissions ({', '.join(high_risk_matches)})."
            return
