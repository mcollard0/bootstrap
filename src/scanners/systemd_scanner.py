#!/usr/bin/env python3
"""
Systemd & Automation Scanner

Scans:
- Enabled system services, sockets, and timers
- Enabled user systemd services and timers
- User and system crontabs
- Custom systemd unit files and drop-in overrides (/etc/systemd/system/)
- Custom kernel tuning (/etc/sysctl.d/)
- Custom hardware udev rules (/etc/udev/rules.d/)
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class SystemdScanner(BaseScanner):
    """Scans systemd services, timers, and cron configurations."""

    def scan(self) -> Dict[str, Any]:
        system_units = self._scan_system_units()
        user_units = self._scan_user_units()
        cron_jobs = self._scan_cron()
        custom_units = self._scan_custom_system_units()

        return {
            'system_enabled_units': system_units,
            'user_enabled_units': user_units,
            'cron_jobs': cron_jobs,
            'custom_system_units': custom_units
        }

    def _scan_system_units(self) -> List[Dict[str, str]]:
        """Scan enabled system units."""
        if not shutil.which('systemctl'):
            return []

        units = []
        try:
            res = subprocess.run(
                ['systemctl', 'list-unit-files', '--state=enabled', '--no-legend', '--no-pager'],
                capture_output=True, text=True
            )
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    units.append({
                        'unit': parts[0],
                        'state': parts[1]
                    })
        except Exception:
            pass

        return units

    def _scan_user_units(self) -> List[Dict[str, str]]:
        """Scan enabled user-level systemd units."""
        if not shutil.which('systemctl'):
            return []

        units = []
        try:
            res = subprocess.run(
                ['systemctl', '--user', 'list-unit-files', '--state=enabled', '--no-legend', '--no-pager'],
                capture_output=True, text=True
            )
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    units.append({
                        'unit': parts[0],
                        'state': parts[1]
                    })
        except Exception:
            pass

        return units

    def _scan_custom_system_units(self) -> List[str]:
        """List custom system unit files in /etc/systemd/system."""
        custom = []
        etc_sysd = Path('/etc/systemd/system')
        if etc_sysd.exists():
            for f in etc_sysd.iterdir():
                if f.is_file() and not f.is_symlink():
                    custom.append(f.name)
        return custom

    def _scan_cron(self) -> Dict[str, Any]:
        """Scan crontab jobs."""
        cron = {'user': [], 'system_dirs': []}

        # User crontab
        if shutil.which('crontab'):
            try:
                res = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if res.returncode == 0:
                    for line in res.stdout.strip().split('\n'):
                        line_clean = line.strip()
                        if line_clean and not line_clean.startswith('#'):
                            cron['user'].append(line_clean)
            except Exception:
                pass

        # System cron directories
        for cdir in ['/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly', '/etc/cron.d']:
            p = Path(cdir)
            if p.exists() and p.is_dir():
                try:
                    files = [f.name for f in p.iterdir() if f.is_file()]
                    if files:
                        cron['system_dirs'].append({'dir': cdir, 'files': files})
                except Exception:
                    pass

        return cron

    def get_collectible_files(self) -> Dict[str, Path]:
        """Collect custom user and system systemd unit files, sysctl, and udev rules."""
        collectible = {}

        # 1. User systemd units (~/.config/systemd/user/)
        user_sysd = self.user_home / '.config/systemd/user'
        if user_sysd.exists():
            for root, _, files in os.walk(user_sysd):
                for f in files:
                    rp = Path(root) / f
                    collectible[f"home/.config/systemd/user/{rp.relative_to(user_sysd)}"] = rp

        # 2. Custom system units (/etc/systemd/system/)
        etc_sysd = Path('/etc/systemd/system')
        if etc_sysd.exists():
            for f in etc_sysd.iterdir():
                # Collect real custom unit files (e.g. cloudflared.service, ollama.service)
                if f.is_file() and not f.is_symlink():
                    collectible[f"system/etc/systemd/system/{f.name}"] = f
                # Collect drop-in override directories (e.g. ollama.service.d/*.conf)
                elif f.is_dir() and f.name.endswith('.d') and not f.name.endswith('.wants'):
                    for sub_f in f.glob('*.conf'):
                        collectible[f"system/etc/systemd/system/{f.name}/{sub_f.name}"] = sub_f

        # 3. Kernel tuning (/etc/sysctl.d/*.conf)
        sysctl_dir = Path('/etc/sysctl.d')
        if sysctl_dir.exists():
            for f in sysctl_dir.glob('*.conf'):
                collectible[f"system/etc/sysctl.d/{f.name}"] = f

        # 4. Hardware udev rules (/etc/udev/rules.d/*.rules)
        udev_dir = Path('/etc/udev/rules.d')
        if udev_dir.exists():
            for f in udev_dir.glob('*.rules'):
                collectible[f"system/etc/udev/rules.d/{f.name}"] = f

        return collectible
