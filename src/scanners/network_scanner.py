#!/usr/bin/env python3
"""
Network Configuration Scanner

Scans:
- NetworkManager saved connections (`/etc/NetworkManager/system-connections/`)
- WireGuard VPN tunnels (`/etc/wireguard/`)
- `/etc/hosts`, `/etc/hostname`, `/etc/nsswitch.conf`
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class NetworkScanner(BaseScanner):
    """Scans network connections and VPN configs."""

    def scan(self) -> Dict[str, Any]:
        nm_conns = self._scan_networkmanager()
        wg_conns = self._scan_wireguard()
        hosts_info = self._scan_hosts()

        return {
            'network_manager_connections': nm_conns,
            'wireguard_profiles': wg_conns,
            'hosts': hosts_info
        }

    def _scan_networkmanager(self) -> List[Dict[str, str]]:
        """List NetworkManager connection profiles."""
        profiles = []
        nm_dir = Path('/etc/NetworkManager/system-connections')
        if nm_dir.exists():
            try:
                for f in nm_dir.glob('*.nmconnection'):
                    profiles.append({
                        'name': f.name,
                        'path': str(f)
                    })
            except Exception:
                pass

        # Try nmcli if available
        if not profiles and shutil.which('nmcli'):
            try:
                res = subprocess.run(
                    ['nmcli', '-t', '-f', 'NAME,TYPE,UUID', 'connection', 'show'],
                    capture_output=True, text=True
                )
                for line in res.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        profiles.append({
                            'name': parts[0],
                            'type': parts[1],
                            'uuid': parts[2]
                        })
            except Exception:
                pass

        return profiles

    def _scan_wireguard(self) -> List[str]:
        """Scan WireGuard config files in /etc/wireguard."""
        profiles = []
        wg_dir = Path('/etc/wireguard')
        if wg_dir.exists():
            try:
                for f in wg_dir.glob('*.conf'):
                    profiles.append(f.name)
            except Exception:
                pass
        return profiles

    def _scan_hosts(self) -> Dict[str, Any]:
        """Scan /etc/hosts and /etc/hostname."""
        info = {}
        for p in ['/etc/hosts', '/etc/hostname']:
            path = Path(p)
            if path.exists():
                try:
                    info[p] = path.read_text(encoding='utf-8').strip()
                except Exception:
                    pass
        return info

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return network config files for encrypted backup."""
        collectible = {}

        # Hosts and hostname
        for f in ['/etc/hosts', '/etc/hostname']:
            p = Path(f)
            if p.exists():
                collectible[f"system{f}"] = p

        # NM connections (if readable by current user or sudo)
        nm_dir = Path('/etc/NetworkManager/system-connections')
        if nm_dir.exists():
            try:
                for f in nm_dir.glob('*.nmconnection'):
                    collectible[f"system/etc/NetworkManager/system-connections/{f.name}"] = f
            except Exception:
                pass

        # WireGuard configs
        wg_dir = Path('/etc/wireguard')
        if wg_dir.exists():
            try:
                for f in wg_dir.glob('*.conf'):
                    collectible[f"system/etc/wireguard/{f.name}"] = f
            except Exception:
                pass

        return collectible
