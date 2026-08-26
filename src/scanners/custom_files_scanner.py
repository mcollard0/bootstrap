#!/usr/bin/env python3
"""
Custom & One-Off Files Scanner

Allows users to specify arbitrary one-off files, custom fonts, scripts,
or application configurations via `config/custom_files.json`.

Supported JSON format (list or dict):
[
  {
    "name": "0xProto Fonts",
    "description": "0xProto and 0xProto Nerd Font TTF typography",
    "patterns": [
      "/usr/local/share/fonts/0/0xProto*.ttf"
    ]
  },
  {
    "name": "SQLite Config",
    "description": "User custom SQLite runtime settings",
    "patterns": [
      "~/.sqliterc"
    ]
  }
]
"""

import os
import glob
import json
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class CustomFilesScanner(BaseScanner):
    """Scans and collects arbitrary one-off user and system files."""

    def __init__(self, system_info: Dict[str, Any] = None):
        super().__init__(system_info or {})
        self.project_root = Path(__file__).resolve().parent.parent.parent
        # Search for custom_files.json in config/ or data/
        self.config_paths = [
            self.project_root / 'config/custom_files.json',
            self.project_root / 'data/custom_files.json'
        ]

    def _load_custom_config(self) -> List[Dict[str, Any]]:
        """Load and normalize user configuration for custom files."""
        for cp in self.config_paths:
            if cp.exists():
                try:
                    with open(cp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        return data
                    elif isinstance(data, dict):
                        # Convert dict to list
                        items = []
                        for k, v in data.items():
                            item = {'name': k}
                            if isinstance(v, dict):
                                item.update(v)
                            elif isinstance(v, list):
                                item['patterns'] = v
                            items.append(item)
                        return items
                except Exception as e:
                    print(f"⚠️ Failed to parse custom files config {cp}: {e}")
        return []

    def scan(self) -> Dict[str, Any]:
        """Scan and inventory custom files."""
        configured_items = self._load_custom_config()
        results = []

        for item in configured_items:
            name = item.get('name', 'unnamed')
            desc = item.get('description', '')
            patterns = item.get('patterns', item.get('paths', []))
            if isinstance(patterns, str):
                patterns = [patterns]

            matched_files = []
            for pat in patterns:
                expanded = Path(os.path.expanduser(pat))
                # If wildcard in pattern
                if any(ch in str(pat) for ch in ['*', '?', '[']):
                    for match in glob.glob(os.path.expanduser(pat)):
                        mp = Path(match)
                        if mp.is_file():
                            matched_files.append({
                                'path': str(mp),
                                'size': mp.stat().st_size
                            })
                elif expanded.exists():
                    if expanded.is_file():
                        matched_files.append({
                            'path': str(expanded),
                            'size': expanded.stat().st_size
                        })
                    elif expanded.is_dir():
                        for root, _, files in os.walk(expanded):
                            for f in files:
                                fp = Path(root) / f
                                matched_files.append({
                                    'path': str(fp),
                                    'size': fp.stat().st_size
                                })

            results.append({
                'name': name,
                'description': desc,
                'patterns': patterns,
                'matched_count': len(matched_files),
                'total_size_bytes': sum(f['size'] for f in matched_files),
                'files': [f['path'] for f in matched_files]
            })

        return {
            'custom_entries_count': len(results),
            'items': results
        }

    def get_collectible_files(self) -> Dict[str, Path]:
        """Collect all matching custom files for encrypted vault staging."""
        collectible = {}
        configured_items = self._load_custom_config()

        for item in configured_items:
            patterns = item.get('patterns', item.get('paths', []))
            if isinstance(patterns, str):
                patterns = [patterns]

            for pat in patterns:
                pat_expanded = os.path.expanduser(pat)
                # Expand globs
                found_paths = []
                if any(ch in str(pat) for ch in ['*', '?', '[']):
                    found_paths = [Path(p) for p in glob.glob(pat_expanded)]
                else:
                    p = Path(pat_expanded)
                    if p.exists():
                        if p.is_file():
                            found_paths = [p]
                        elif p.is_dir():
                            found_paths = [Path(r) / f for r, _, fs in os.walk(p) for f in fs]

                for real_file in found_paths:
                    if not real_file.is_file():
                        continue

                    # Map virtual path
                    try:
                        rel_home = real_file.relative_to(self.user_home)
                        virtual_path = f"home/{rel_home}"
                    except ValueError:
                        # Outside home directory (e.g. /usr/local/share/fonts/)
                        virtual_path = f"system{real_file.resolve()}"

                    collectible[virtual_path] = real_file

        return collectible
