"""
Sentinel Guard — Scan Profile Manager
Defines, retrieves, and persists different scan profiles and configurations.
"""
import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Union
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProfileConfig:
    """Scan configuration details for different scan scenarios."""
    name: str
    paths: List[str]
    recursive: bool
    auto_quarantine: bool
    enable_api: bool
    scan_archives: bool
    max_workers: int
    enable_heuristics: bool
    enable_yara: bool
    enable_ml: bool
    enable_document_scan: bool
    enable_process_scan: bool
    enable_network_scan: bool
    enable_startup_scan: bool


class ScanProfile:
    """Manages predefined and custom user-saved antivirus scan profile configurations."""

    @classmethod
    def get_profile(cls, name: str) -> ProfileConfig:
        """
        Get a scan profile config by its name.
        Looks up in predefined profiles first, then falls back to custom saved profiles.
        
        Args:
            name: Case-insensitive name of the profile.
            
        Returns:
            The ProfileConfig object.
            
        Raises:
            ValueError: If the profile name does not exist.
        """
        name_lower = name.strip().lower()
        
        # 1. Check predefined profiles
        predefined = cls._get_predefined_profiles()
        if name_lower in predefined:
            return predefined[name_lower]
            
        # 2. Check saved custom profiles
        saved = cls._load_saved_profiles()
        if name_lower in saved:
            return saved[name_lower]
            
        raise ValueError(f"Scan profile '{name}' is not defined. Available: {', '.join(cls.list_profiles())}")

    @classmethod
    def list_profiles(cls) -> List[str]:
        """
        List the names of all currently available profiles (predefined and custom).
        
        Returns:
            List of profile names.
        """
        predefined_keys = list(cls._get_predefined_profiles().keys())
        saved_keys = list(cls._load_saved_profiles().keys())
        
        # Merge unique profile names preserving order
        seen = set()
        all_profiles = []
        for p in predefined_keys + saved_keys:
            if p not in seen:
                seen.add(p)
                all_profiles.append(p)
        return all_profiles

    @classmethod
    def custom(cls, path: Union[str, List[str]], options: Dict[str, Any]) -> ProfileConfig:
        """
        Generate a dynamic custom ProfileConfig.
        
        Args:
            path: Target scan path or list of paths.
            options: Dictionary of option overrides.
            
        Returns:
            A custom ProfileConfig.
        """
        paths_list = [path] if isinstance(path, str) else list(path)
        
        # Default options base
        config_data = {
            "name": "custom",
            "paths": paths_list,
            "recursive": True,
            "auto_quarantine": False,
            "enable_api": False,
            "scan_archives": False,
            "max_workers": 4,
            "enable_heuristics": True,
            "enable_yara": False,
            "enable_ml": False,
            "enable_document_scan": False,
            "enable_process_scan": False,
            "enable_network_scan": False,
            "enable_startup_scan": False
        }
        
        # Override values with custom user dictionary options
        for key, value in options.items():
            if key in config_data:
                config_data[key] = value
                
        # Enforce path parameter as primary
        config_data["paths"] = paths_list
        
        return ProfileConfig(**config_data)

    @classmethod
    def save_profile(cls, name: str, config: Union[ProfileConfig, Dict[str, Any]]) -> bool:
        """
        Save a custom scan profile config to persistent JSON storage.
        
        Args:
            name: Name of the profile to save.
            config: A ProfileConfig object or dict containing option configurations.
            
        Returns:
            True if successfully saved, False otherwise.
        """
        try:
            name_clean = name.strip()
            if not name_clean:
                logger.error("Profile name cannot be empty.")
                return False
                
            if isinstance(config, ProfileConfig):
                config.name = name_clean
                data_dict = asdict(config)
            elif isinstance(config, dict):
                config_copy = dict(config)
                config_copy["name"] = name_clean
                # Construct standard ProfileConfig to validate and map values
                paths = config_copy.get("paths", ["."])
                profile_obj = cls.custom(paths, config_copy)
                data_dict = asdict(profile_obj)
            else:
                logger.error("Invalid configuration schema format. Must be ProfileConfig or dict.")
                return False
                
            # Load existing saved raw dictionary profiles
            saved_raw = cls._load_saved_profiles_raw()
            saved_raw[name_clean.lower()] = data_dict
            
            # Persist to data/profiles.json file
            data_dir = Path("data")
            data_dir.mkdir(parents=True, exist_ok=True)
            profiles_file = data_dir / "profiles.json"
            
            with open(profiles_file, "w", encoding="utf-8") as f:
                json.dump(saved_raw, f, indent=4)
                
            logger.info(f"Scan profile '{name_clean}' saved successfully to persistent storage.")
            return True
        except Exception as e:
            logger.error(f"Failed to save profile '{name}': {e}")
            return False

    @classmethod
    def _get_predefined_profiles(cls) -> Dict[str, ProfileConfig]:
        """Define and retrieve core hardcoded predefined scan profiles."""
        return {
            "quick": ProfileConfig(
                name="quick",
                paths=["."],
                recursive=False,
                auto_quarantine=False,
                enable_api=False,
                scan_archives=False,
                max_workers=4,
                enable_heuristics=True,
                enable_yara=False,
                enable_ml=False,
                enable_document_scan=False,
                enable_process_scan=False,
                enable_network_scan=False,
                enable_startup_scan=False
            ),
            "full": ProfileConfig(
                name="full",
                paths=["."],
                recursive=True,
                auto_quarantine=True,
                enable_api=True,
                scan_archives=True,
                max_workers=8,
                enable_heuristics=True,
                enable_yara=True,
                enable_ml=True,
                enable_document_scan=True,
                enable_process_scan=True,
                enable_network_scan=True,
                enable_startup_scan=True
            ),
            "deep": ProfileConfig(
                name="deep",
                paths=["."],
                recursive=True,
                auto_quarantine=True,
                enable_api=True,
                scan_archives=True,
                max_workers=12,
                enable_heuristics=True,
                enable_yara=True,
                enable_ml=True,
                enable_document_scan=True,
                enable_process_scan=True,
                enable_network_scan=True,
                enable_startup_scan=True
            ),
            "usb": ProfileConfig(
                name="usb",
                paths=["/media", "/mnt"],
                recursive=True,
                auto_quarantine=True,
                enable_api=True,
                scan_archives=True,
                max_workers=4,
                enable_heuristics=True,
                enable_yara=True,
                enable_ml=True,
                enable_document_scan=True,
                enable_process_scan=False,
                enable_network_scan=False,
                enable_startup_scan=False
            ),
            "memory": ProfileConfig(
                name="memory",
                paths=[],
                recursive=False,
                auto_quarantine=True,
                enable_api=True,
                scan_archives=False,
                max_workers=4,
                enable_heuristics=True,
                enable_yara=True,
                enable_ml=True,
                enable_document_scan=False,
                enable_process_scan=True,
                enable_network_scan=True,
                enable_startup_scan=False
            ),
            "paranoid": ProfileConfig(
                name="paranoid",
                paths=["."],
                recursive=True,
                auto_quarantine=True,
                enable_api=True,
                scan_archives=True,
                max_workers=16,
                enable_heuristics=True,
                enable_yara=True,
                enable_ml=True,
                enable_document_scan=True,
                enable_process_scan=True,
                enable_network_scan=True,
                enable_startup_scan=True
            )
        }

    @classmethod
    def _load_saved_profiles_raw(cls) -> Dict[str, Dict[str, Any]]:
        """Load raw dictionaries from persistent profiles JSON storage."""
        profiles_file = Path("data/profiles.json")
        if not profiles_file.exists():
            return {}
        try:
            with open(profiles_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            logger.error(f"Failed to read custom profiles from file storage: {e}")
        return {}

    @classmethod
    def _load_saved_profiles(cls) -> Dict[str, ProfileConfig]:
        """Load and reconstruct saved profiles into ProfileConfig dataclasses."""
        raw_data = cls._load_saved_profiles_raw()
        profiles = {}
        for name, data in raw_data.items():
            try:
                profiles[name.lower()] = ProfileConfig(
                    name=str(data.get("name", name)),
                    paths=list(data.get("paths", ["."])),
                    recursive=bool(data.get("recursive", True)),
                    auto_quarantine=bool(data.get("auto_quarantine", False)),
                    enable_api=bool(data.get("enable_api", False)),
                    scan_archives=bool(data.get("scan_archives", False)),
                    max_workers=int(data.get("max_workers", 4)),
                    enable_heuristics=bool(data.get("enable_heuristics", True)),
                    enable_yara=bool(data.get("enable_yara", False)),
                    enable_ml=bool(data.get("enable_ml", False)),
                    enable_document_scan=bool(data.get("enable_document_scan", False)),
                    enable_process_scan=bool(data.get("enable_process_scan", False)),
                    enable_network_scan=bool(data.get("enable_network_scan", False)),
                    enable_startup_scan=bool(data.get("enable_startup_scan", False))
                )
            except Exception as e:
                logger.error(f"Error parsing saved profile '{name}': {e}")
        return profiles
