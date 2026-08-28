#!/usr/bin/env python3
"""
Keys & Security Scanner

Scans and prepares security credentials for encrypted vault packaging:
- SSH keys, public keys, configs, authorized_keys, known_hosts (`~/.ssh/`)
- GPG private and public keys, revocation certs, keyrings (`~/.gnupg/`)
- Password Manager repository (`~/.password-store/`)
- KDE Wallet keyrings, salts, and configs (`~/.local/share/kwalletd/`, `~/.config/kwalletrc`)
- KDE Connect device identity & TLS certificates (`~/.config/kdeconnect/`)
- Android ADB authorization keys & debug keystore (`~/.android/`)
- Ollama node identity key & configs (`~/.ollama/`)
- Claude CLI credentials & project configurations (`~/.claude.json`)
- Gemini & Antigravity credentials & MCP configurations (`~/.gemini/`)
- Citrix Workspace client connection profiles (`~/.ICAClient/`)
- Beekeeper Studio database connection profiles & encryption key (`~/.config/beekeeper-studio/`)
- Cloudflare tunnel credentials and certificates (`~/.cloudflared/`)
- GitHub CLI authentication and configs (`~/.config/gh/`)
- Docker authentication and daemon configs (`~/.docker/config.json`, `daemon.json`)
- Git user config (`~/.gitconfig`)
- SSL private keys and certificates (`/etc/ssl/private/`, `/etc/nginx/ssl/`)
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
        kwallet_items = self._scan_kwallet()
        kdeconnect_items = self._scan_kdeconnect()
        android_items = self._scan_android()
        ollama_items = self._scan_ollama()
        claude_items = self._scan_claude()
        gemini_items = self._scan_gemini()
        ica_items = self._scan_ica_client()
        beekeeper_items = self._scan_beekeeper()
        cloudflared_items = self._scan_cloudflared()
        git_items = self._scan_git()
        ssl_items = self._scan_ssl()

        return {
            'ssh_keys': ssh_items,
            'gpg': gpg_items,
            'password_store': pass_store,
            'kwallet': kwallet_items,
            'kdeconnect': kdeconnect_items,
            'android': android_items,
            'ollama': ollama_items,
            'claude': claude_items,
            'gemini': gemini_items,
            'ica_client': ica_items,
            'beekeeper': beekeeper_items,
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

    def _scan_kwallet(self) -> Dict[str, Any]:
        """Scan KDE Wallet keyrings, salts, and configuration."""
        kwallet_dir = self.user_home / '.local/share/kwalletd'
        kwalletrc = self.user_home / '.config/kwalletrc'
        wallets = []
        if kwallet_dir.exists():
            for f in kwallet_dir.iterdir():
                if f.is_file() and not f.name.endswith('~'):
                    wallets.append({
                        'name': f.name,
                        'size': f.stat().st_size
                    })
        return {
            'exists': bool(wallets or kwalletrc.exists()),
            'wallet_files_count': len(wallets),
            'files': wallets,
            'has_config': kwalletrc.exists()
        }

    def _scan_kdeconnect(self) -> Dict[str, Any]:
        """Scan KDE Connect device certificates and configuration."""
        kc_dir = self.user_home / '.config/kdeconnect'
        if not kc_dir.exists():
            return {'exists': False}
        return {
            'exists': True,
            'has_private_key': (kc_dir / 'privateKey.pem').exists(),
            'has_certificate': (kc_dir / 'certificate.pem').exists(),
            'has_trusted_devices': (kc_dir / 'trusted_devices').exists()
        }

    def _scan_android(self) -> Dict[str, Any]:
        """Scan Android adb keys and debug keystore."""
        adb_dir = self.user_home / '.android'
        if not adb_dir.exists():
            return {'exists': False}
        return {
            'exists': True,
            'has_adbkey': (adb_dir / 'adbkey').exists(),
            'has_debug_keystore': (adb_dir / 'debug.keystore').exists()
        }

    def _scan_ollama(self) -> Dict[str, Any]:
        """Scan Ollama identity key."""
        ollama_dir = self.user_home / '.ollama'
        if not ollama_dir.exists():
            return {'exists': False}
        return {
            'exists': True,
            'has_key': (ollama_dir / 'id_ed25519').exists(),
            'has_config': (ollama_dir / 'config.json').exists()
        }

    def _scan_claude(self) -> Dict[str, Any]:
        """Scan Claude CLI configuration."""
        claude_file = self.user_home / '.claude.json'
        return {
            'exists': claude_file.exists(),
            'size': claude_file.stat().st_size if claude_file.exists() else 0
        }

    def _scan_gemini(self) -> Dict[str, Any]:
        """Scan Gemini / Antigravity developer credentials."""
        gemini_dir = self.user_home / '.gemini'
        if not gemini_dir.exists():
            return {'exists': False}
        return {
            'exists': True,
            'has_oauth': (gemini_dir / 'oauth_creds.json').exists(),
            'has_mcp_config': (gemini_dir / 'config/mcp_config.json').exists()
        }

    def _scan_ica_client(self) -> Dict[str, Any]:
        """Scan Citrix ICA client configuration."""
        ica_dir = self.user_home / '.ICAClient'
        if not ica_dir.exists():
            return {'exists': False}
        ini_files = [f.name for f in ica_dir.glob('*.ini')]
        return {
            'exists': True,
            'ini_files_count': len(ini_files)
        }

    def _scan_beekeeper(self) -> Dict[str, Any]:
        """Scan Beekeeper Studio database profiles."""
        bk_dir = self.user_home / '.config/beekeeper-studio'
        if not bk_dir.exists():
            return {'exists': False}
        return {
            'exists': True,
            'has_app_db': (bk_dir / 'app.db').exists(),
            'has_key': (bk_dir / '.key').exists()
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
        """Scan SSL keys in /etc/ssl/private and /etc/nginx/ssl."""
        keys = []
        ssl_dirs = [Path('/etc/ssl/private'), Path('/etc/nginx/ssl')]
        for sdir in ssl_dirs:
            if sdir.exists():
                try:
                    for f in sdir.glob('*.key'):
                        if 'snakeoil' not in f.name and '.backup' not in f.name:
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

        # 8. SSL keys and certificates if accessible
        ssl_dir = Path('/etc/ssl/private')
        if ssl_dir.exists():
            try:
                for f in ssl_dir.glob('*.key'):
                    if 'snakeoil' not in f.name:
                        collectible[f"system/etc/ssl/private/{f.name}"] = f
            except Exception:
                pass

        nginx_ssl = Path('/etc/nginx/ssl')
        if nginx_ssl.exists():
            try:
                for f in nginx_ssl.iterdir():
                    if f.is_file() and (f.suffix in ['.key', '.crt', '.pem']) and '.backup' not in f.name:
                        collectible[f"system/etc/nginx/ssl/{f.name}"] = f
            except Exception:
                pass

        # 9. KDE Wallet keyrings and daemon configuration
        kwallet_dir = self.user_home / '.local/share/kwalletd'
        if kwallet_dir.exists():
            for f in kwallet_dir.iterdir():
                if f.is_file() and not f.name.endswith('~'):
                    collectible[f"home/.local/share/kwalletd/{f.name}"] = f

        kwalletrc = self.user_home / '.config/kwalletrc'
        if kwalletrc.exists() and kwalletrc.is_file():
            collectible["home/.config/kwalletrc"] = kwalletrc

        # 10. KDE Connect device certificates and pairing info
        kc_dir = self.user_home / '.config/kdeconnect'
        if kc_dir.exists():
            for kcf in ['privateKey.pem', 'certificate.pem', 'config', 'trusted_devices']:
                p = kc_dir / kcf
                if p.exists() and p.is_file():
                    collectible[f"home/.config/kdeconnect/{kcf}"] = p

        # 11. Android ADB authorization keys and debug keystore
        adb_dir = self.user_home / '.android'
        if adb_dir.exists():
            for adbf in ['adbkey', 'adbkey.pub', 'debug.keystore', 'adb_known_hosts.pb']:
                p = adb_dir / adbf
                if p.exists() and p.is_file():
                    collectible[f"home/.android/{adbf}"] = p

        # 12. Ollama node identity key and configuration
        ollama_dir = self.user_home / '.ollama'
        if ollama_dir.exists():
            for of in ['id_ed25519', 'id_ed25519.pub', 'config.json']:
                p = ollama_dir / of
                if p.exists() and p.is_file():
                    collectible[f"home/.ollama/{of}"] = p

        # 13. Claude CLI credentials and settings
        claude_file = self.user_home / '.claude.json'
        if claude_file.exists() and claude_file.is_file():
            collectible["home/.claude.json"] = claude_file

        # 14. Gemini / Antigravity credentials and MCP server configurations
        gemini_dir = self.user_home / '.gemini'
        if gemini_dir.exists():
            for gf in ['oauth_creds.json', 'settings.json', 'google_accounts.json', 'installation_id', 'state.json']:
                p = gemini_dir / gf
                if p.exists() and p.is_file():
                    collectible[f"home/.gemini/{gf}"] = p
            g_cfg = gemini_dir / 'config'
            if g_cfg.exists():
                for root, _, files in os.walk(g_cfg):
                    for f in files:
                        rp = Path(root) / f
                        rel_g = rp.relative_to(gemini_dir)
                        collectible[f"home/.gemini/{rel_g}"] = rp

        # 15. Citrix Workspace client configurations
        ica_dir = self.user_home / '.ICAClient'
        if ica_dir.exists():
            for ica_f in ica_dir.iterdir():
                if ica_f.is_file() and (ica_f.suffix == '.ini' or ica_f.name in ['config', 'LastConnectedGateway', '.eula_accepted']):
                    collectible[f"home/.ICAClient/{ica_f.name}"] = ica_f

        # 16. Beekeeper Studio connection profiles and key
        bk_dir = self.user_home / '.config/beekeeper-studio'
        if bk_dir.exists():
            for bk_f in ['app.db', '.key', 'Preferences']:
                p = bk_dir / bk_f
                if p.exists() and p.is_file():
                    collectible[f"home/.config/beekeeper-studio/{bk_f}"] = p

        return collectible
