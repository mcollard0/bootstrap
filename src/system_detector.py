#!/usr/bin/env python3
"""
Bootstrap System - System & Environment Detector

Automatically detects:
- Linux distribution and family (Arch, CachyOS, Ubuntu, Debian, Fedora, etc.)
- Package managers (pacman, yay, paru, apt, snap, flatpak)
- Shells in use and installed (fish, bash, zsh)
- Desktop environment (KDE Plasma, GNOME, etc.)
- Storage mounts and archive drives (fstab entries, active mounts)
"""

import os
import sys
import shutil
import socket
import datetime
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional


class SystemDetector:
    """Detects host operating system, hardware, shells, and package manager capabilities."""

    def __init__(self):
        self.os_info = self._detect_os()
        self.package_managers = self._detect_package_managers()
        self.shells = self._detect_shells()
        self.desktop = self._detect_desktop()
        self.storage = self._detect_storage()

    def _detect_os(self) -> Dict[str, str]:
        """Detect operating system distribution and version."""
        info = {
            'id': 'unknown',
            'id_like': 'unknown',
            'pretty_name': 'Unknown Linux',
            'version_id': 'rolling',
            'family': 'unknown',
            'hostname': socket.gethostname(),
            'kernel': os.uname().release,
            'timestamp': datetime.datetime.now().isoformat()
        }

        # Parse /etc/os-release
        os_release_path = Path('/etc/os-release')
        if os_release_path.exists():
            try:
                with open(os_release_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"\'')
                        if k == 'ID':
                            info['id'] = v.lower()
                        elif k == 'ID_LIKE':
                            info['id_like'] = v.lower()
                        elif k == 'PRETTY_NAME':
                            info['pretty_name'] = v
                        elif k == 'VERSION_ID':
                            info['version_id'] = v
            except Exception as e:
                info['parse_error'] = str(e)

        # Classify family
        all_ids = f"{info['id']} {info['id_like']}".split()
        if any(x in all_ids for x in ['arch', 'cachyos', 'manjaro', 'endeavouros', 'artix']):
            info['family'] = 'arch'
        elif any(x in all_ids for x in ['ubuntu', 'debian', 'pop', 'mint', 'elementary', 'kali']):
            info['family'] = 'debian'
        elif any(x in all_ids for x in ['fedora', 'rhel', 'centos', 'rocky', 'alma']):
            info['family'] = 'redhat'
        elif any(x in all_ids for x in ['opensuse', 'suse']):
            info['family'] = 'suse'
        else:
            info['family'] = 'unknown'

        return info

    def _detect_package_managers(self) -> Dict[str, Any]:
        """Detect installed package managers and helpers."""
        pm = {
            'primary': None,
            'aur_helper': None,
            'available': []
        }

        tools = [
            ('pacman', '/usr/bin/pacman'),
            ('yay', '/usr/bin/yay'),
            ('paru', '/usr/bin/paru'),
            ('apt', '/usr/bin/apt'),
            ('dpkg', '/usr/bin/dpkg'),
            ('snap', '/usr/bin/snap'),
            ('flatpak', '/usr/bin/flatpak'),
            ('pip3', '/usr/bin/pip3'),
            ('pipx', '/usr/bin/pipx')
        ]

        for name, default_path in tools:
            path = shutil.which(name) or (default_path if os.path.exists(default_path) else None)
            if path:
                pm['available'].append(name)
                pm[name] = path

        if self.os_info['family'] == 'arch':
            pm['primary'] = 'pacman' if 'pacman' in pm['available'] else None
            if 'paru' in pm['available']:
                pm['aur_helper'] = 'paru'
            elif 'yay' in pm['available']:
                pm['aur_helper'] = 'yay'
        elif self.os_info['family'] == 'debian':
            pm['primary'] = 'apt' if 'apt' in pm['available'] else None

        return pm

    def _detect_shells(self) -> Dict[str, Any]:
        """Detect current and installed shells and configuration files."""
        current_shell = os.environ.get('SHELL', '')
        user_home = Path.home()

        shells_info = {
            'current': current_shell,
            'default_name': Path(current_shell).name if current_shell else 'unknown',
            'installed': [],
            'has_fish_config': (user_home / '.config/fish/config.fish').exists(),
            'has_bash_config': (user_home / '.bashrc').exists(),
            'has_zsh_config': (user_home / '.zshrc').exists(),
            'fish_config_dir': str(user_home / '.config/fish'),
            'bashrc_path': str(user_home / '.bashrc')
        }

        for shell_name in ['fish', 'bash', 'zsh', 'sh']:
            if shutil.which(shell_name):
                shells_info['installed'].append(shell_name)

        return shells_info

    def _detect_desktop(self) -> Dict[str, Any]:
        """Detect desktop environment and window manager."""
        desktop_env = os.environ.get('XDG_CURRENT_DESKTOP', '')
        session_type = os.environ.get('XDG_SESSION_TYPE', '')
        desktop_session = os.environ.get('DESKTOP_SESSION', '')

        de_name = 'unknown'
        env_upper = desktop_env.upper()
        if 'KDE' in env_upper or 'PLASMA' in env_upper or 'plasma' in desktop_session.lower():
            de_name = 'kde'
        elif 'GNOME' in env_upper or 'ubuntu' in env_upper:
            de_name = 'gnome'
        elif 'XFCE' in env_upper:
            de_name = 'xfce'
        elif 'HYPRLAND' in env_upper:
            de_name = 'hyprland'
        elif 'SWAY' in env_upper:
            de_name = 'sway'

        return {
            'name': de_name,
            'raw_xdg_current_desktop': desktop_env,
            'session_type': session_type,
            'desktop_session': desktop_session
        }

    def _detect_storage(self) -> Dict[str, Any]:
        """Detect root filesystem and mounted archive/data drives."""
        storage = {
            'root_fstype': 'unknown',
            'fstab_exists': os.path.exists('/etc/fstab'),
            'crypttab_exists': os.path.exists('/etc/crypttab'),
            'archive_mounts': []
        }

        # Check mount table for root and archive mounts
        try:
            with open('/proc/mounts', 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        dev, mountpoint, fstype = parts[0], parts[1], parts[2]
                        if mountpoint == '/':
                            storage['root_fstype'] = fstype
                        elif 'ARCHIVE' in mountpoint.upper() or 'SHARD' in mountpoint.upper() or mountpoint.startswith('/run/media/'):
                            storage['archive_mounts'].append({
                                'device': dev,
                                'mountpoint': mountpoint,
                                'fstype': fstype
                            })
        except Exception as e:
            storage['mount_error'] = str(e)

        return storage

    def to_dict(self) -> Dict[str, Any]:
        """Return complete detection dictionary."""
        return {
            'os': self.os_info,
            'package_managers': self.package_managers,
            'shells': self.shells,
            'desktop': self.desktop,
            'storage': self.storage
        }

    def print_summary(self):
        """Print user-friendly system summary."""
        print("🖥️  System & Environment Detection:")
        print(f"   Distribution: {self.os_info['pretty_name']} (Family: {self.os_info['family'].upper()})")
        print(f"   Kernel:       {self.os_info['kernel']}")
        print(f"   Hostname:     {self.os_info['hostname']}")
        print(f"   Primary PM:   {self.package_managers.get('primary', 'none')}")
        if self.package_managers.get('aur_helper'):
            print(f"   AUR Helper:   {self.package_managers['aur_helper']}")
        print(f"   Active Shell: {self.shells['default_name']} ({self.shells['current']})")
        print(f"   Desktop:      {self.desktop['name'].upper()} ({self.desktop['session_type']})")
        print(f"   Root FS:      {self.storage['root_fstype']}")
        print(f"   Archive Mounts Found: {len(self.storage['archive_mounts'])}")
        for m in self.storage['archive_mounts']:
            print(f"     • {m['mountpoint']} ({m['fstype']})")


if __name__ == '__main__':
    detector = SystemDetector()
    detector.print_summary()
