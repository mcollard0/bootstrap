#!/usr/bin/env python3
"""
Desktop Environment, Tooling & Display Layout Scanner

Scans:
- KDE Plasma configurations (`kglobalshortcutsrc`, `kwinrc`, `kdeglobals`, `kwinrulesrc`,
  `kcminputrc`, `plasmashellrc`, `plasma-org.kde.plasma.desktop-appletsrc`, `kwinoutputconfig.json`,
  `dolphinrc`, `spectaclerc`, `konsolesshconfig`, `libinput-gestures.conf`, `mimeapps.list`)
- Multi-monitor EDID display topology (`~/.local/share/kscreen/`)
- User desktop bookmarks & jump databases (`user-places.xbel`, `zoxide/db.zo`)
- GTK theme & font settings (`gtk-3.0`, `gtk-4.0`, `.gtkrc-2.0`, `.fonts.conf`, `.nvidia-settings-rc`)
- Terminal configurations (kitty, alacritty, warp, foot, wezterm)
- Developer editor & utility configs (Neovim, Micro, Btop, OBS Studio, CopyQ)
- Autostart entries (`~/.config/autostart/*.desktop`)
- Custom user scripts (`~/.local/bin/*.sh`, `~/.local/bin/*.py`)
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class DesktopScanner(BaseScanner):
    """Scans desktop shortcuts, window rules, terminal configs, display layouts, and developer tools."""

    # Essential user customization files (skipping caches like katemetainfos, kactivitymanagerdrc)
    KDE_USER_CUSTOMIZATIONS = [
        'kglobalshortcutsrc',                      # User keyboard shortcuts
        'kdeglobals',                              # User color scheme, widget theme, fonts
        'kwinrc',                                 # Window manager behavior, effects, titlebars
        'kwinrulesrc',                            # Specific window rules
        'kcminputrc',                             # Mouse, keyboard repeat, touchpad gestures
        'plasmashellrc',                          # Plasma shell layout
        'plasma-org.kde.plasma.desktop-appletsrc',# User desktop applets, widgets, and panels
        'plasmarc',                               # Plasma theme overrides
        'kwinoutputconfig.json',                  # Multi-monitor display modes, refresh rates, HDR
        'dolphinrc',                              # Dolphin file manager preferences & preview plugins
        'spectaclerc',                            # Spectacle screenshot/recording configs & OCR
        'konsolesshconfig',                       # Konsole saved SSH profiles
        'libinput-gestures.conf',                 # Touchpad gesture definitions
        'mimeapps.list'                           # Default application & protocol associations
    ]

    def scan(self) -> Dict[str, Any]:
        de_type = self.system_info.get('desktop', {}).get('name', 'unknown')
        kde_info = self._scan_kde()
        gnome_info = self._scan_gnome() if de_type == 'gnome' else {}
        terminal_info = self._scan_terminals()
        dev_tools = self._scan_dev_tools()
        desktop_theme = self._scan_desktop_theme()

        return {
            'detected_de': de_type,
            'kde': kde_info,
            'gnome': gnome_info,
            'terminals': terminal_info,
            'developer_tools': dev_tools,
            'theme': desktop_theme
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
            ('warp', '.config/warp-terminal/settings.toml'),
            ('warp_preview', '.config/warp-terminal-preview/settings.toml')
        ]
        for name, rel_path in terms:
            if (self.user_home / rel_path).exists():
                terminals.append(name)
        return terminals

    def _scan_dev_tools(self) -> Dict[str, Any]:
        """Detect presence of developer editor and utility configs."""
        return {
            'neovim': (self.user_home / '.config/nvim/init.lua').exists(),
            'btop': (self.user_home / '.config/btop/btop.conf').exists(),
            'micro': (self.user_home / '.config/micro/settings.json').exists(),
            'obs_studio': (self.user_home / '.config/obs-studio').exists(),
            'copyq': (self.user_home / '.config/copyq/copyq.conf').exists(),
            'zoxide': (self.user_home / '.local/share/zoxide/db.zo').exists()
        }

    def _scan_desktop_theme(self) -> Dict[str, Any]:
        """Detect GTK theme, font, and hardware display overrides."""
        return {
            'gtk3': (self.user_home / '.config/gtk-3.0/settings.ini').exists(),
            'gtk4': (self.user_home / '.config/gtk-4.0/settings.ini').exists(),
            'gtk2_rc': (self.user_home / '.gtkrc-2.0').exists(),
            'fonts_conf': (self.user_home / '.fonts.conf').exists(),
            'nvidia_settings': (self.user_home / '.nvidia-settings-rc').exists()
        }

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return non-default desktop, display, terminal, and tool configs for backup."""
        collectible = {}

        # 1. KDE non-default customization files
        for kf in self.KDE_USER_CUSTOMIZATIONS:
            p = self.user_home / f'.config/{kf}'
            if p.exists() and p.is_file() and p.stat().st_size > 0:
                collectible[f"home/.config/{kf}"] = p

        # 2. GTK theming and font configurations
        for gtk_dir in ['.config/gtk-3.0', '.config/gtk-4.0']:
            gd = self.user_home / gtk_dir
            if gd.exists() and gd.is_dir():
                for f in gd.iterdir():
                    if f.is_file():
                        collectible[f"home/{gtk_dir}/{f.name}"] = f

        for theme_rc in ['.gtkrc-2.0', '.fonts.conf', '.nvidia-settings-rc']:
            tp = self.user_home / theme_rc
            if tp.exists() and tp.is_file():
                collectible[f"home/{theme_rc}"] = tp

        # 3. Terminal configurations
        for term_dir in [
            '.config/kitty',
            '.config/alacritty',
            '.config/wezterm',
            '.config/foot',
            '.config/warp-terminal',
            '.config/warp-terminal-preview'
        ]:
            td = self.user_home / term_dir
            if td.exists() and td.is_dir():
                for root, _, files in os.walk(td):
                    for f in files:
                        rp = Path(root) / f
                        collectible[f"home/{term_dir}/{rp.relative_to(td)}"] = rp

        # 4. Neovim configuration
        nvim_dir = self.user_home / '.config/nvim'
        if nvim_dir.exists() and nvim_dir.is_dir():
            for root, _, files in os.walk(nvim_dir):
                for f in files:
                    rp = Path(root) / f
                    collectible[f"home/.config/nvim/{rp.relative_to(nvim_dir)}"] = rp

        # 5. Micro editor
        micro_dir = self.user_home / '.config/micro'
        if micro_dir.exists() and micro_dir.is_dir():
            for mf in ['settings.json', 'bindings.json']:
                p = micro_dir / mf
                if p.exists() and p.is_file():
                    collectible[f"home/.config/micro/{mf}"] = p

        # 6. Btop monitor
        btop_conf = self.user_home / '.config/btop/btop.conf'
        if btop_conf.exists() and btop_conf.is_file():
            collectible["home/.config/btop/btop.conf"] = btop_conf

        # 7. OBS Studio (Scenes, profiles, and basic settings, skipping logs and profiler)
        obs_dir = self.user_home / '.config/obs-studio'
        if obs_dir.exists() and obs_dir.is_dir():
            global_ini = obs_dir / 'global.ini'
            if global_ini.exists():
                collectible["home/.config/obs-studio/global.ini"] = global_ini

            ws_cfg = obs_dir / 'plugin_config/obs-websocket/config.json'
            if ws_cfg.exists():
                collectible["home/.config/obs-studio/plugin_config/obs-websocket/config.json"] = ws_cfg

            basic_dir = obs_dir / 'basic'
            if basic_dir.exists():
                for root, _, files in os.walk(basic_dir):
                    for f in files:
                        rp = Path(root) / f
                        collectible[f"home/.config/obs-studio/basic/{rp.relative_to(basic_dir)}"] = rp

        # 8. CopyQ (Commands, filter rules, tabs config - skipping binary clipboard data)
        copyq_dir = self.user_home / '.config/copyq'
        if copyq_dir.exists() and copyq_dir.is_dir():
            for cf in ['copyq-commands.ini', 'copyq.conf', 'copyq-filter.ini', 'copyq_tabs.ini']:
                p = copyq_dir / cf
                if p.exists() and p.is_file():
                    collectible[f"home/.config/copyq/{cf}"] = p

        # 9. Autostart desktop entries
        autostart_dir = self.user_home / '.config/autostart'
        if autostart_dir.exists() and autostart_dir.is_dir():
            for f in autostart_dir.iterdir():
                if f.is_file() and f.suffix == '.desktop' and not f.is_symlink():
                    collectible[f"home/.config/autostart/{f.name}"] = f

        # 10. Custom user scripts in ~/.local/bin/
        local_bin = self.user_home / '.local/bin'
        if local_bin.exists() and local_bin.is_dir():
            for f in local_bin.iterdir():
                if f.is_file() and not f.is_symlink() and (f.suffix in ['.sh', '.py'] or f.name.endswith('.sh')):
                    collectible[f"home/.local/bin/{f.name}"] = f

        # 11. Screen layouts, Dolphin places, and Zoxide directory jump database
        kscreen_dir = self.user_home / '.local/share/kscreen'
        if kscreen_dir.exists() and kscreen_dir.is_dir():
            for root, _, files in os.walk(kscreen_dir):
                for f in files:
                    rp = Path(root) / f
                    collectible[f"home/.local/share/kscreen/{rp.relative_to(kscreen_dir)}"] = rp

        places_file = self.user_home / '.local/share/user-places.xbel'
        if places_file.exists() and places_file.is_file():
            collectible["home/.local/share/user-places.xbel"] = places_file

        zoxide_db = self.user_home / '.local/share/zoxide/db.zo'
        if zoxide_db.exists() and zoxide_db.is_file():
            collectible["home/.local/share/zoxide/db.zo"] = zoxide_db

        return collectible
