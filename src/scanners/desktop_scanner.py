#!/usr/bin/env python3
"""
Desktop Environment Scanner

Scans:
- KDE Plasma configurations (`kglobalshortcutsrc`, `kwinrc`, `kdeglobals`, `khotkeysrc`)
- GNOME dconf / gsettings shortcuts (if running GNOME)
- Terminal configurations (kitty, alacritty, warp, foot, wezterm)
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class DesktopScanner(BaseScanner):
    """Scans desktop shortcuts, window manager rules, and terminal configs."""

    def scan(self) -> Dict[str, Any]:
        de_type = self.system_info.get('desktop', {}).get('name', 'unknown')
        kde_info = self._scan_kde()
        gnome_info = self._scan_gnome() if de_type == 'gnome' else {}
        terminal_info = self._scan_terminals()

        return {
            'detected_de': de_type,
            'kde': kde_info,
            'gnome': gnome_info,
            'terminals': terminal_info
        }

    def _scan_kde(self) -> Dict[str, Any]:
        """Scan KDE Plasma configuration files."""
        kde_files = [
            'kglobalshortcutsrc',
            'kwinrc',
            'kdeglobals',
            'khotkeysrc',
            'plasma-org.kde.plasma.desktop-appletsrc',
            'plasmarc'
        ]
        found = []
        for kf in kde_files:
            p = self.user_home / f'.config/{kf}'
            if p.exists():
                found.append({
                    'file': kf,
                    'size': p.stat().st_size
                })
        return {'found_files': found}

    def _scan_gnome(self) -> Dict[str, Any]:
        """Scan GNOME gsettings shortcuts."""
        shortcuts = []
        if not shutil.which('gsettings'):
            return {'shortcuts': []}

        try:
            res = subprocess.run(
                ['gsettings', 'get', 'org.gnome.settings-daemon.plugins.media-keys', 'custom-keybindings'],
                capture_output=True, text=True
            )
            out = res.stdout.strip()
            if out and out != "@as []":
                shortcuts.append({'raw': out})
        except Exception:
            pass

        return {'shortcuts': shortcuts}

    def _scan_terminals(self) -> List[str]:
        """Detect configured terminal emulators."""
        terminals = []
        terms = [
            ('kitty', '.config/kitty/kitty.conf'),
            ('alacritty', '.config/alacritty/alacritty.toml'),
            ('alacritty_yml', '.config/alacritty/alacritty.yml'),
            ('wezterm', '.config/wezterm/wezterm.lua'),
            ('foot', '.config/foot/foot.ini'),
            ('warp', '.warp')
        ]
        for name, rel_path in terms:
            if (self.user_home / rel_path).exists():
                terminals.append(name)
        return terminals

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return desktop and terminal config files for backup."""
        collectible = {}

        # KDE files
        kde_files = [
            'kglobalshortcutsrc',
            'kwinrc',
            'kdeglobals',
            'khotkeysrc',
            'plasmarc'
        ]
        for kf in kde_files:
            p = self.user_home / f'.config/{kf}'
            if p.exists():
                collectible[f"home/.config/{kf}"] = p

        # Terminals
        for term_dir in ['.config/kitty', '.config/alacritty', '.config/wezterm', '.config/foot']:
            td = self.user_home / term_dir
            if td.exists() and td.is_dir():
                for root, _, files in os.walk(td):
                    for f in files:
                        rp = Path(root) / f
                        collectible[f"home/{term_dir}/{rp.relative_to(td)}"] = rp

        return collectible
