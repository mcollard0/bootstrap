#!/usr/bin/env python3
"""
Distro Package Scanner

Scans installed software packages:
- Arch Linux: pacman explicit packages (`pacman -Qqe`), AUR packages (`pacman -Qqm` via yay/paru)
- Debian/Ubuntu: APT packages (`apt-mark showmanual` / `dpkg`), Snaps (`snap list`)
- Flatpaks: `flatpak list --app`
- Python: `pip3 list --user` / system modules
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class DistroPackageScanner(BaseScanner):
    """Scans packages according to detected distribution family."""

    def scan(self) -> Dict[str, Any]:
        os_family = self.system_info.get('os', {}).get('family', 'unknown')
        packages = {
            'family': os_family,
            'arch_native': [],
            'arch_aur': [],
            'apt': [],
            'snap': [],
            'flatpak': [],
            'python_user': []
        }

        if os_family == 'arch':
            packages['arch_native'] = self._scan_pacman_explicit()
            packages['arch_aur'] = self._scan_arch_aur()
        elif os_family == 'debian':
            packages['apt'] = self._scan_apt_packages()
            packages['snap'] = self._scan_snap_packages()

        packages['flatpak'] = self._scan_flatpaks()
        packages['python_user'] = self._scan_python_packages()

        return packages

    def _scan_pacman_explicit(self) -> List[Dict[str, str]]:
        """Scan explicitly installed native Arch packages."""
        pkgs = []
        if not shutil.which('pacman'):
            return pkgs

        try:
            # Native explicitly installed packages (excluding AUR)
            res = subprocess.run(
                ['pacman', '-Qne'],
                capture_output=True, text=True, check=True
            )
            for line in res.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    parts = line.split()
                    pkgs.append({
                        'name': parts[0],
                        'version': parts[1] if len(parts) > 1 else 'unknown'
                    })
        except Exception as e:
            print(f"    ⚠️  Failed to scan pacman native packages: {e}")

        return pkgs

    def _scan_arch_aur(self) -> List[Dict[str, str]]:
        """Scan foreign/AUR packages installed via yay/paru."""
        pkgs = []
        if not shutil.which('pacman'):
            return pkgs

        try:
            # Foreign explicitly installed packages (AUR)
            res = subprocess.run(
                ['pacman', '-Qme'],
                capture_output=True, text=True, check=True
            )
            for line in res.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    parts = line.split()
                    pkgs.append({
                        'name': parts[0],
                        'version': parts[1] if len(parts) > 1 else 'unknown'
                    })
        except Exception as e:
            print(f"    ⚠️  Failed to scan Arch AUR packages: {e}")

        return pkgs

    def _scan_apt_packages(self) -> List[Dict[str, str]]:
        """Scan manually installed APT packages on Debian/Ubuntu."""
        pkgs = []
        if not shutil.which('apt-mark') and not shutil.which('dpkg'):
            return pkgs

        try:
            # Try getting manually installed packages first
            res = subprocess.run(
                ['apt-mark', 'showmanual'],
                capture_output=True, text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                for name in res.stdout.strip().split('\n'):
                    name = name.strip()
                    if name:
                        pkgs.append({'name': name, 'status': 'installed'})
                return pkgs
        except Exception:
            pass

        # Fallback to dpkg
        try:
            res = subprocess.run(
                ['dpkg', '--get-selections'],
                capture_output=True, text=True, check=True
            )
            for line in res.stdout.strip().split('\n'):
                if '\t' in line:
                    name, status = line.split('\t', 1)
                    if status.strip() == 'install':
                        pkgs.append({'name': name, 'status': 'installed'})
        except Exception as e:
            print(f"    ⚠️  Failed to scan APT packages: {e}")

        return pkgs

    def _scan_snap_packages(self) -> List[Dict[str, str]]:
        """Scan Snap packages."""
        pkgs = []
        if not shutil.which('snap'):
            return pkgs

        try:
            res = subprocess.run(['snap', 'list'], capture_output=True, text=True, check=True)
            lines = res.stdout.strip().split('\n')[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    pkgs.append({
                        'name': parts[0],
                        'version': parts[1],
                        'channel': parts[2] if len(parts) > 2 else 'stable'
                    })
        except Exception:
            pass

        return pkgs

    def _scan_flatpaks(self) -> List[Dict[str, str]]:
        """Scan installed Flatpak applications."""
        pkgs = []
        if not shutil.which('flatpak'):
            return pkgs

        try:
            res = subprocess.run(
                ['flatpak', 'list', '--app', '--columns=application,version,origin'],
                capture_output=True, text=True, check=True
            )
            for line in res.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 1:
                        pkgs.append({
                            'name': parts[0].strip(),
                            'version': parts[1].strip() if len(parts) > 1 else 'unknown',
                            'origin': parts[2].strip() if len(parts) > 2 else 'flathub'
                        })
        except Exception:
            pass

        return pkgs

    def _scan_python_packages(self) -> List[Dict[str, str]]:
        """Scan user-installed python packages."""
        pkgs = []
        if not shutil.which('pip3'):
            return pkgs

        try:
            res = subprocess.run(
                ['pip3', 'list', '--user', '--format=json'],
                capture_output=True, text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                pip_data = json.loads(res.stdout)
                for item in pip_data:
                    pkgs.append({
                        'name': item.get('name'),
                        'version': item.get('version')
                    })
        except Exception:
            pass

        return pkgs

    def get_collectible_files(self) -> Dict[str, Path]:
        return {}
