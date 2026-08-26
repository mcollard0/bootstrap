#!/usr/bin/env python3
"""
Keys & Security Scanner

Scans and prepares security credentials for encrypted vault packaging:
- SSH keys, public keys, configs, authorized_keys, known_hosts (`~/.ssh/`)
- GPG private and public keys, revocation certs, keyrings (`~/.gnupg/`)
- Password Manager repository (`~/.password-store/`)
- Cloudflare tunnel credentials and certificates (`~/.cloudflared/`)
- GitHub CLI authentication and configs (`~/.config/gh/`)
- Docker authentication and daemon configs (`~/.docker/config.json`, `daemon.json`)
- Git user config (`~/.gitconfig`)
- SSL private keys and certificates (`/etc/ssl/private/`)
"""

import os
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class KeysScanner(BaseScanner):
    """Scans and securely catalogues SSH, GPG, credential stores, and SSL keys."""

    def scan(self) -> Dict[str, Any]:
        ssh_items = self._scan_ssh()
        gpg_items = self._scan_gpg()
        pass_store = self._scan_pass_store()
        cloudflared_items = self._scan_cloudflared()
        git_items = self._scan_git()
        ssl_items = self._scan_ssl()

        return {
            'ssh_keys': ssh_items,
            'gpg': gpg_items,
            'password_store': pass_store,
            'cloudflared': cloudflared_items,
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
            if f.is_file() and not f.name.endswith('~'):
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
        """Scan GPG configuration and key directories."""
        gpg_dir = self.user_home / '.gnupg'
        if not gpg_dir.exists():
            return {'exists': False, 'private_keys_count': 0}

        priv_keys = []
        priv_dir = gpg_dir / 'private-keys-v1.d'
        if priv_dir.exists():
            priv_keys = [f.name for f in priv_dir.glob('*.key')]

        return {
            'exists': True,
            'private_keys_count': len(priv_keys),
            'has_trustdb': (gpg_dir / 'trustdb.gpg').exists(),
            'has_common_conf': (gpg_dir / 'common.conf').exists()
        }

    def _scan_pass_store(self) -> Dict[str, Any]:
        """Scan ~/.password-store repository."""
        ps_dir = self.user_home / '.password-store'
        if not ps_dir.exists():
            return {'exists': False}

        gpg_files = list(ps_dir.rglob('*.gpg'))
        return {
            'exists': True,
            'entry_count': len(gpg_files)
        }

    def _scan_cloudflared(self) -> Dict[str, Any]:
        """Scan ~/.cloudflared tunnels and certificates."""
        cf_dir = self.user_home / '.cloudflared'
        if not cf_dir.exists():
            return {'exists': False}

        tunnels = [f.name for f in cf_dir.glob('*.json')]
        return {
            'exists': True,
            'has_cert': (cf_dir / 'cert.pem').exists(),
            'has_config': (cf_dir / 'config.yml').exists(),
            'tunnel_count': len(tunnels)
        }

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
        """Return key and credential files for encrypted bundle packaging."""
        collectible = {}

        # 1. SSH directory (all keys and configs)
        ssh_dir = self.user_home / '.ssh'
        if ssh_dir.exists():
            for f in ssh_dir.iterdir():
                if f.is_file() and not f.name.endswith('~'):
                    collectible[f"home/.ssh/{f.name}"] = f

        # 2. GPG configuration and private keys
        gpg_dir = self.user_home / '.gnupg'
        if gpg_dir.exists():
            for root, _, files in os.walk(gpg_dir):
                for f in files:
                    # Exclude active sockets and random seed
                    if f.startswith('S.') or f == 'random_seed':
                        continue
                    rp = Path(root) / f
                    rel_p = rp.relative_to(gpg_dir)
                    collectible[f"home/.gnupg/{rel_p}"] = rp

        # 3. Password Store (~/.password-store)
        ps_dir = self.user_home / '.password-store'
        if ps_dir.exists():
            for root, _, files in os.walk(ps_dir):
                for f in files:
                    rp = Path(root) / f
                    rel_p = rp.relative_to(ps_dir)
                    collectible[f"home/.password-store/{rel_p}"] = rp

        # 4. Cloudflare tunnel credentials (~/.cloudflared)
        cf_dir = self.user_home / '.cloudflared'
        if cf_dir.exists():
            for f in cf_dir.iterdir():
                if f.is_file():
                    collectible[f"home/.cloudflared/{f.name}"] = f

        # 5. GitHub CLI configuration (~/.config/gh)
        gh_dir = self.user_home / '.config/gh'
        if gh_dir.exists():
            for f in gh_dir.glob('*.yml'):
                collectible[f"home/.config/gh/{f.name}"] = f

        # 6. Docker configs (~/.docker/config.json, daemon.json)
        docker_dir = self.user_home / '.docker'
        if docker_dir.exists():
            for df in ['config.json', 'daemon.json']:
                p = docker_dir / df
                if p.exists() and p.is_file():
                    collectible[f"home/.docker/{df}"] = p

        # 7. Git configuration
        gitconfig = self.user_home / '.gitconfig'
        if gitconfig.exists():
            collectible["home/.gitconfig"] = gitconfig

        # 8. SSL keys if accessible
        ssl_dir = Path('/etc/ssl/private')
        if ssl_dir.exists():
            try:
                for f in ssl_dir.glob('*.key'):
                    if 'snakeoil' not in f.name:
                        collectible[f"system/etc/ssl/private/{f.name}"] = f
            except Exception:
                pass

        return collectible
