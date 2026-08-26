#!/usr/bin/env python3
"""
Desktop Environment Scanner

Scans:
- KDE Plasma non-default configurations (`kglobalshortcutsrc`, `kwinrc`, `kdeglobals`, `kwinrulesrc`, `kcminputrc`, `plasmashellrc`, `plasma-org.kde.plasma.desktop-appletsrc`)
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
    """Scans desktop shortcuts, window manager rules, and terminal configs, filtering transient state."""

    # Essential user customization files (skipping caches like klipperrc, katemetainfos, kactivitymanagerdrc)
    KDE_USER_CUSTOMIZATIONS = [
        'kglobalshortcutsrc',                      # User keyboard shortcuts
        'kdeglobals',                              # User color scheme, widget theme, fonts
        'kwinrc',                                 # Window manager behavior, effects, titlebars
        'kwinrulesrc',                            # Specific window rules
        'kcminputrc',                             # Mouse, keyboard repeat, touchpad gestures
        'plasmashellrc',                          # Plasma shell layout
        'plasma-org.kde.plasma.desktop-appletsrc',# User desktop applets, widgets, and panels
        'plasmarc'                                # Plasma theme overrides
    ]

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
        """Scan KDE Plasma configuration files that contain non-default user settings."""
        found = []
        for kf in self.KDE_USER_CUSTOMIZATIONS:
            p = self.user_home / f'.config/{kf}'
            if p.exists() and p.is_file() and p.stat().st_size > 0:
                found.append({
                    'file': kf,
                    'size': p.stat().st_size
                })
        return {'custom_configs': found}

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
        """Return non-default desktop and terminal config files for backup."""
        collectible = {}

        # KDE non-default customization files only
        for kf in self.KDE_USER_CUSTOMIZATIONS:
            p = self.user_home / f'.config/{kf}'
            if p.exists() and p.is_file() and p.stat().st_size > 0:
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
