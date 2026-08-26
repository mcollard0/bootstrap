#!/usr/bin/env python3
"""
Shell & Environment Scanner

Scans configuration files and environments for:
- Fish shell (`~/.config/fish/config.fish`, `fish_variables`, `conf.d/`, `functions/`)
- Bash shell (`~/.bashrc`, `~/.bash_profile`, `~/.bash_aliases`, `~/.profile`)
- MOTD & system greetings (`/etc/motd`, `/etc/issue`, `/etc/environment`)
- Prompt configuration (`~/.config/starship.toml`)
- Detects sensitive environment variables (API keys, credentials, URIs)
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from .base_scanner import BaseScanner


class ShellScanner(BaseScanner):
    """Scans multi-shell configurations, functions, aliases, and prompts."""

    SENSITIVE_PATTERNS = [
        (r'(mongodb(\+srv)?://[^@\s]+:[^@\s]+@[^\s]+)', 'MongoDB URI'),
        (r'(sk-[A-Za-z0-9\-_]{20,})', 'API Key (sk- format)'),
        (r'(xai-[A-Za-z0-9\-_]{20,})', 'XAI API Key'),
        (r'(ghp_[A-Za-z0-9]{30,})', 'GitHub Token'),
        (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key'),
        (r'([A-Za-z0-9\-_]{40,})', 'Generic Long Token'),
        (r'(gmail.*password.*=\s*["\']?([^"\'\s]+))', 'Gmail Password'),
        (r'(api.*key.*=\s*["\']?([^"\'\s]+))', 'API Key Assignment')
    ]

    def scan(self) -> Dict[str, Any]:
        fish_data, fish_secrets = self._scan_fish()
        bash_data, bash_secrets = self._scan_bash()
        motd_data = self._scan_motd()
        prompt_data = self._scan_prompts()

        all_secrets = {}
        all_secrets.update(fish_secrets)
        all_secrets.update(bash_secrets)

        return {
            'fish': fish_data,
            'bash': bash_data,
            'motd': motd_data,
            'prompts': prompt_data,
            'detected_secrets': all_secrets
        }

    def _scan_fish(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Scan fish configuration files and variables."""
        fish_dir = self.user_home / '.config/fish'
        info = {
            'exists': fish_dir.exists(),
            'config_path': str(fish_dir / 'config.fish') if (fish_dir / 'config.fish').exists() else None,
            'variables_path': str(fish_dir / 'fish_variables') if (fish_dir / 'fish_variables').exists() else None,
            'conf_d_files': [],
            'functions': [],
            'completions': []
        }
        secrets = {}

        if not fish_dir.exists():
            return info, secrets

        # conf.d files
        conf_d = fish_dir / 'conf.d'
        if conf_d.exists():
            for f in conf_d.glob('*.fish'):
                info['conf_d_files'].append(f.name)
                self._check_file_secrets(f, secrets, prefix='fish_conf_d')

        # functions
        funcs_dir = fish_dir / 'functions'
        if funcs_dir.exists():
            for f in funcs_dir.glob('*.fish'):
                info['functions'].append(f.name)

        # completions
        comp_dir = fish_dir / 'completions'
        if comp_dir.exists():
            for f in comp_dir.glob('*.fish'):
                info['completions'].append(f.name)

        # scan config.fish for secrets
        config_fish = fish_dir / 'config.fish'
        if config_fish.exists():
            self._check_file_secrets(config_fish, secrets, prefix='fish_config')

        return info, secrets

    def _scan_bash(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Scan bash configuration files."""
        bash_files = ['.bashrc', '.bash_profile', '.bash_aliases', '.profile']
        found_files = []
        secrets = {}

        for bf in bash_files:
            p = self.user_home / bf
            if p.exists():
                found_files.append(bf)
                self._check_file_secrets(p, secrets, prefix=f'bash_{bf}')

        return {'found_files': found_files}, secrets

    def _scan_motd(self) -> Dict[str, Any]:
        """Scan message of the day and login banners."""
        motd_paths = ['/etc/motd', '/etc/issue', '/etc/issue.net', '/etc/environment']
        motd_info = {}

        for mp in motd_paths:
            p = Path(mp)
            if p.exists() and p.is_file():
                try:
                    content = p.read_text(encoding='utf-8', errors='ignore').strip()
                    motd_info[mp] = {
                        'exists': True,
                        'size': p.stat().st_size,
                        'preview': content[:200]
                    }
                except Exception:
                    motd_info[mp] = {'exists': True, 'readable': False}

        return motd_info

    def _scan_prompts(self) -> Dict[str, Any]:
        """Scan Starship, Oh-My-Posh or other prompt configurations."""
        prompts = {}
        starship = self.user_home / '.config/starship.toml'
        if starship.exists():
            prompts['starship'] = str(starship)

        fastfetch = self.user_home / '.config/fastfetch/config.jsonc'
        if fastfetch.exists():
            prompts['fastfetch'] = str(fastfetch)

        return prompts

    def _check_file_secrets(self, file_path: Path, secrets_dict: Dict[str, Any], prefix: str = ""):
        """Helper to scan a file for API keys and secrets."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith('#'):
                        continue

                    for pattern, desc in self.SENSITIVE_PATTERNS:
                        match = re.search(pattern, line_clean, re.IGNORECASE)
                        if match:
                            var_key = f"{prefix}_{file_path.stem}_L{line_num}"
                            secrets_dict[var_key] = {
                                'file': str(file_path),
                                'line_num': line_num,
                                'description': desc,
                                'raw_match': match.group(0)
                            }
        except Exception:
            pass

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return dict of virtual path -> real path for vault backup."""
        collectible = {}
        fish_dir = self.user_home / '.config/fish'

        if fish_dir.exists():
            for root, _, files in os.walk(fish_dir):
                for f in files:
                    real_path = Path(root) / f
                    rel_path = real_path.relative_to(self.user_home)
                    collectible[f"home/{rel_path}"] = real_path

        # Bash files
        for bf in ['.bashrc', '.bash_profile', '.bash_aliases', '.profile']:
            p = self.user_home / bf
            if p.exists():
                collectible[f"home/{bf}"] = p

        # System MOTD & environment
        for sys_file in ['/etc/motd', '/etc/issue', '/etc/environment']:
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
