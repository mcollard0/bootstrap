#!/usr/bin/env python3
"""
Storage & Filesystem Scanner

Scans storage topology and critical system configs for disaster recovery:
- `/etc/fstab` and `/etc/crypttab`
- Block device UUIDs, labels, filesystems (`lsblk -f -J` / `blkid`)
- Archive mounts (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SHARD_*`)
- Btrfs subvolume layout
- Bootloader & kernel configs (`/etc/default/grub`, `/etc/modules-load.d/`)
- System & server configs (`/etc/docker/daemon.json`, `/etc/sddm.conf`, `/etc/nginx/`)
- Console, Locale, & Security limits (`/etc/vconsole.conf`, `/etc/locale.conf`, `/etc/security/limits.d/`)
- Snapper snapshot configurations (`/etc/snapper/configs/`)
- Arch packaging & initramfs (`/etc/pacman.conf`, `/etc/mkinitcpio.conf`)
- Console & Locale boot configs (`/etc/vconsole.conf`, `/etc/locale.conf`)
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class StorageScanner(BaseScanner):
    """Captures mount configuration and storage layouts for disaster recovery."""

    def scan(self) -> Dict[str, Any]:
        fstab_content = self._read_fstab()
        crypttab_content = self._read_crypttab()
        block_devices = self._scan_block_devices()
        btrfs_subvols = self._scan_btrfs_subvolumes()
        archive_drives = self._identify_archive_drives(block_devices)
        boot_configs = self._scan_boot_configs()

        return {
            'fstab': fstab_content,
            'crypttab': crypttab_content,
            'block_devices': block_devices,
            'btrfs_subvolumes': btrfs_subvols,
            'archive_drives': archive_drives,
            'boot_configs': boot_configs
        }

    def _read_fstab(self) -> Dict[str, Any]:
        """Read and parse /etc/fstab."""
        p = Path('/etc/fstab')
        if not p.exists():
            return {'exists': False, 'content': '', 'entries': []}

        try:
            content = p.read_text(encoding='utf-8')
            entries = []
            for line in content.split('\n'):
                line_clean = line.strip()
                if not line_clean or line_clean.startswith('#'):
                    continue
                parts = line_clean.split()
                if len(parts) >= 4:
                    entries.append({
                        'device': parts[0],
                        'mountpoint': parts[1],
                        'fstype': parts[2],
                        'options': parts[3],
                        'dump': parts[4] if len(parts) > 4 else '0',
                        'pass': parts[5] if len(parts) > 5 else '0'
                    })
            return {'exists': True, 'content': content, 'entries': entries}
        except Exception as e:
            return {'exists': True, 'error': str(e), 'content': '', 'entries': []}

    def _read_crypttab(self) -> Dict[str, Any]:
        """Read /etc/crypttab if it exists, using sudo -n fallback if permission denied."""
        p = Path('/etc/crypttab')
        if not p.exists():
            return {'exists': False, 'content': ''}

        content = ""
        try:
            content = p.read_text(encoding='utf-8')
        except PermissionError:
            try:
                res = subprocess.run(['sudo', '-n', 'cat', str(p)], capture_output=True, text=True)
                if res.returncode == 0:
                    content = res.stdout
            except Exception:
                pass
        except Exception as e:
            return {'exists': True, 'error': str(e), 'content': ''}

        return {'exists': True, 'content': content}

    def _scan_block_devices(self) -> List[Dict[str, Any]]:
        """Scan block devices with lsblk JSON output."""
        if not shutil.which('lsblk'):
            return []

        try:
            res = subprocess.run(
                ['lsblk', '-f', '-J', '-o', 'NAME,FSTYPE,FSVER,LABEL,UUID,FSAVAIL,FSUSE%,MOUNTPOINTS'],
                capture_output=True, text=True, check=True
            )
            data = json.loads(res.stdout)
            return data.get('blockdevices', [])
        except Exception:
            return []

    def _scan_btrfs_subvolumes(self) -> List[str]:
        """Scan Btrfs subvolumes on root if applicable."""
        if not shutil.which('btrfs'):
            return []

        try:
            res = subprocess.run(
                ['btrfs', 'subvolume', 'list', '/'],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                return res.stdout.strip().split('\n')
        except Exception:
            pass

        return []

    def _scan_boot_configs(self) -> Dict[str, str]:
        """Scan boot, kernel, locale, and server system configurations."""
        configs = {}
        target_files = [
            '/etc/vconsole.conf',
            '/etc/locale.conf',
            '/etc/locale.gen',
            '/etc/mkinitcpio.conf',
            '/etc/pacman.conf',
            '/etc/default/grub',
            '/etc/docker/daemon.json',
            '/etc/sddm.conf',
            '/etc/nginx/nginx.conf'
        ]
        for f in target_files:
            p = Path(f)
            if p.exists() and p.is_file():
                try:
                    configs[f] = p.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    pass
        return configs

    def _identify_archive_drives(self, block_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify non-root data/archive drives."""
        archives = []

        def recurse_devices(dev_list):
            for dev in dev_list:
                label = dev.get('label') or ''
                mounts = dev.get('mountpoints') or []
                uuid = dev.get('uuid') or ''
                fstype = dev.get('fstype') or ''

                is_archive = False
                for m in mounts:
                    if m and ('ARCHIVE' in m.upper() or 'SHARD' in m.upper() or m.startswith('/run/media/')):
                        is_archive = True
                        break
                if not is_archive and ('ARCHIVE' in label.upper() or 'SHARD' in label.upper()):
                    is_archive = True

                if is_archive:
                    archives.append({
                        'name': dev.get('name'),
                        'label': label,
                        'uuid': uuid,
                        'fstype': fstype,
                        'mountpoints': mounts
                    })

                if 'children' in dev:
                    recurse_devices(dev['children'])

        recurse_devices(block_devices)
        return archives

    def get_collectible_files(self) -> Dict[str, Path]:
        """Return files for vault inclusion."""
        collectible = {}
        candidate_files = [
            '/etc/fstab',
            '/etc/crypttab',
            '/etc/vconsole.conf',
            '/etc/locale.conf',
            '/etc/locale.gen',
            '/etc/mkinitcpio.conf',
            '/etc/pacman.conf',
            '/etc/default/grub',
            '/etc/docker/daemon.json',
            '/etc/sddm.conf',
            '/etc/nginx/nginx.conf'
        ]
        for f in candidate_files:
            p = Path(f)
            if p.exists() and p.is_file():
                collectible[f"system{f}"] = p

        # Module autoloading configs
        mod_load = Path('/etc/modules-load.d')
        if mod_load.exists():
            for f in mod_load.glob('*.conf'):
                collectible[f"system{f}"] = f

        # Security limits (e.g. 20-audio.conf)
        limits_d = Path('/etc/security/limits.d')
        if limits_d.exists():
            for f in limits_d.glob('*.conf'):
                collectible[f"system{f}"] = f

        # Snapper snapshot configuration
        snapper_d = Path('/etc/snapper/configs')
        if snapper_d.exists():
            for f in snapper_d.iterdir():
                if f.is_file():
                    collectible[f"system{f}"] = f

        # Nginx virtual host configurations
        nginx_sites = Path('/etc/nginx/sites-available')
        if nginx_sites.exists():
            for f in nginx_sites.glob('*.conf'):
                if '.backup' not in f.name:
                    collectible[f"system/etc/nginx/sites-available/{f.name}"] = f

        return collectible
