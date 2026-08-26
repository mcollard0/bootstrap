#!/usr/bin/env python3
"""
Shell & Environment Scanner

Inventories shell configurations for encrypted vault backup:
- Fish shell (`~/.config/fish/config.fish`, `fish_variables`, `conf.d/`, `functions/`, `completions/`)
- System-wide Fish configuration (`/etc/fish/config.fish`, `/etc/fish/conf.d/*.fish`, `/etc/shells`)
- Bash shell (`~/.bashrc`, `~/.bash_profile`, `~/.bash_aliases`, `~/.profile`)
- MOTD & system greetings (`/etc/motd`, `/etc/issue`, `/etc/environment`)
- Prompts & fetch tools (`~/.config/starship.toml`, `~/.config/fastfetch/`)

All configuration files are collected as complete files and sealed directly inside
the encrypted vault (.tar.zst.enc). No file content parsing or regex extraction is performed.
"""

import os
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class ShellScanner(BaseScanner):
    """Inventories shell configuration files for encrypted vault packaging."""

    def scan(self) -> Dict[str, Any]:
        fish_data = self._scan_fish()
        system_fish_data = self._scan_system_fish()
        bash_data = self._scan_bash()
        motd_data = self._scan_motd()
        prompt_data = self._scan_prompts()

        return {
            'fish': fish_data,
            'system_fish': system_fish_data,
            'bash': bash_data,
            'motd': motd_data,
            'prompts': prompt_data
        }

    def _scan_fish(self) -> Dict[str, Any]:
        """Inventory user fish configuration files and variables."""
        fish_dir = self.user_home / '.config/fish'
        info = {
            'exists': fish_dir.exists(),
            'config_path': str(fish_dir / 'config.fish') if (fish_dir / 'config.fish').exists() else None,
            'variables_path': str(fish_dir / 'fish_variables') if (fish_dir / 'fish_variables').exists() else None,
            'conf_d_files': [],
            'functions': [],
            'completions': []
        }

        if not fish_dir.exists():
            return info

        conf_d = fish_dir / 'conf.d'
        if conf_d.exists():
            for f in conf_d.glob('*.fish'):
                info['conf_d_files'].append(f.name)

        funcs_dir = fish_dir / 'functions'
        if funcs_dir.exists():
            for f in funcs_dir.glob('*.fish'):
                info['functions'].append(f.name)

        comp_dir = fish_dir / 'completions'
        if comp_dir.exists():
            for f in comp_dir.glob('*.fish'):
                info['completions'].append(f.name)

        return info

    def _scan_system_fish(self) -> Dict[str, Any]:
        """Inventory system-wide fish configuration in /etc/fish."""
        etc_fish = Path('/etc/fish')
        info = {
            'exists': etc_fish.exists(),
            'has_config': (etc_fish / 'config.fish').exists(),
            'conf_d_files': []
        }
        if etc_fish.exists():
            conf_d = etc_fish / 'conf.d'
            if conf_d.exists():
                for f in conf_d.glob('*.fish'):
                    info['conf_d_files'].append(f.name)
        return info

    def _scan_bash(self) -> Dict[str, Any]:
        """Inventory bash configuration files."""
        bash_files = ['.bashrc', '.bash_profile', '.bash_aliases', '.profile']
        found_files = []
        for bf in bash_files:
            p = self.user_home / bf
            if p.exists():
                found_files.append(bf)
        return {'found_files': found_files}

    def _scan_motd(self) -> Dict[str, Any]:
        """Inventory message of the day, login banners, and shell registry."""
        motd_paths = ['/etc/motd', '/etc/issue', '/etc/issue.net', '/etc/environment', '/etc/shells']
        motd_info = {}
        for mp in motd_paths:
            p = Path(mp)
            if p.exists() and p.is_file():
                motd_info[mp] = {
                    'exists': True,
                    'size': p.stat().st_size
                }
        return motd_info

    def _scan_prompts(self) -> Dict[str, Any]:
        """Inventory Starship or Fastfetch configurations."""
        prompts = {}
        starship = self.user_home / '.config/starship.toml'
        if starship.exists():
            prompts['starship'] = str(starship)

        fastfetch = self.user_home / '.config/fastfetch/config.jsonc'
        if fastfetch.exists():
            prompts['fastfetch'] = str(fastfetch)

        return prompts

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return dict of virtual path -> real path for vault backup."""
        collectible = {}
        fish_dir = self.user_home / '.config/fish'

        # User fish configs
        if fish_dir.exists():
            for root, _, files in os.walk(fish_dir):
                for f in files:
                    real_path = Path(root) / f
                    rel_path = real_path.relative_to(self.user_home)
                    collectible[f"home/{rel_path}"] = real_path

        # System-wide fish configs in /etc/fish
        etc_fish = Path('/etc/fish')
        if etc_fish.exists():
            for root, _, files in os.walk(etc_fish):
                for f in files:
                    real_path = Path(root) / f
                    collectible[f"system{real_path}"] = real_path

        # Bash & Zsh files
        for bf in ['.bashrc', '.bash_profile', '.bash_aliases', '.profile', '.zshrc']:
            p = self.user_home / bf
            if p.exists():
                collectible[f"home/{bf}"] = p

        # System MOTD, environment, shells
        for sys_file in ['/etc/motd', '/etc/issue', '/etc/environment', '/etc/shells']:
            p = Path(sys_file)
            if p.exists():
                collectible[f"system{sys_file}"] = p

        # Starship
        starship = self.user_home / '.config/starship.toml'
        if starship.exists():
            collectible["home/.config/starship.toml"] = starship

        # Fastfetch
        fastfetch = self.user_home / '.config/fastfetch'
        if fastfetch.exists():
            for root, _, files in os.walk(fastfetch):
                for f in files:
                    rp = Path(root) / f
                    collectible[f"home/.config/fastfetch/{rp.relative_to(fastfetch)}"] = rp

        return collectible
