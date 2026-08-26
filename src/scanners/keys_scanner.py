#!/usr/bin/env python3
"""
Keys & Security Scanner

Scans and prepares security credentials:
- SSH keys, public keys, configs, authorized_keys, known_hosts
- GPG configuration and keyrings (`~/.gnupg/`)
- Git user config (`~/.gitconfig`)
- SSL private keys and certificates (`/etc/ssl/private/`)
"""

import os
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class KeysScanner(BaseScanner):
    """Scans and securely catalogues SSH, GPG, and SSL keys."""

    def scan(self) -> Dict[str, Any]:
        ssh_items = self._scan_ssh()
        gpg_items = self._scan_gpg()
        git_items = self._scan_git()
        ssl_items = self._scan_ssl()

        return {
            'ssh_keys': ssh_items,
            'gpg': gpg_items,
            'git': git_items,
            'ssl_private_keys': ssl_items
        }

    def _scan_ssh(self) -> List[Dict[str, Any]]:
        """Scan SSH directory."""
        items = []
        ssh_dir = self.user_home / '.ssh'
        if not ssh_dir.exists():
            return items

        for f in ssh_dir.iterdir():
            if f.is_file():
                is_pub = f.suffix == '.pub' or f.name in ['config', 'known_hosts', 'authorized_keys']
                mode = oct(f.stat().st_mode)[-3:]
                items.append({
                    'name': f.name,
                    'is_public': is_pub,
                    'permissions': mode,
                    'size': f.stat().st_size
                })

        return items

    def _scan_gpg(self) -> Dict[str, Any]:
        """Scan GPG configuration."""
        gpg_dir = self.user_home / '.gnupg'
        if not gpg_dir.exists():
            return {'exists': False, 'files': []}

        files = []
        for f in gpg_dir.iterdir():
            if f.is_file():
                files.append(f.name)

        return {'exists': True, 'files': files}

    def _scan_git(self) -> Dict[str, Any]:
        """Scan git config."""
        gitconfig = self.user_home / '.gitconfig'
        return {
            'has_gitconfig': gitconfig.exists(),
            'path': str(gitconfig) if gitconfig.exists() else None
        }

    def _scan_ssl(self) -> List[Dict[str, str]]:
        """Scan SSL keys in /etc/ssl/private."""
        ssl_dir = Path('/etc/ssl/private')
        keys = []
        if ssl_dir.exists():
            try:
                for f in ssl_dir.glob('*.key'):
                    if 'snakeoil' not in f.name:
                        keys.append({
                            'name': f.name,
                            'path': str(f)
                        })
            except Exception:
                pass
        return keys

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return key files for encrypted bundle."""
        collectible = {}

        # SSH
        ssh_dir = self.user_home / '.ssh'
        if ssh_dir.exists():
            for f in ssh_dir.iterdir():
                if f.is_file() and not f.name.endswith('~'):
                    collectible[f"home/.ssh/{f.name}"] = f

        # GPG config files
        gpg_dir = self.user_home / '.gnupg'
        if gpg_dir.exists():
            for cf in ['gpg.conf', 'gpg-agent.conf', 'pubring.kbx', 'trustdb.gpg']:
                p = gpg_dir / cf
                if p.exists():
                    collectible[f"home/.gnupg/{cf}"] = p

        # Git
        gitconfig = self.user_home / '.gitconfig'
        if gitconfig.exists():
            collectible["home/.gitconfig"] = gitconfig

        # SSL keys if accessible
        ssl_dir = Path('/etc/ssl/private')
        if ssl_dir.exists():
            try:
                for f in ssl_dir.glob('*.key'):
                    if 'snakeoil' not in f.name:
                        collectible[f"system/etc/ssl/private/{f.name}"] = f
            except Exception:
                pass

        return collectible
