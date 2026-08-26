#!/usr/bin/env python3
"""
Storage & Filesystem Scanner

Scans storage topology critical for disaster recovery:
- `/etc/fstab` and `/etc/crypttab`
- Block device UUIDs, labels, filesystems (`lsblk -f -J` / `blkid`)
- Archive mounts (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SHARD_*`)
- Btrfs subvolume layout
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

        return {
            'fstab': fstab_content,
            'crypttab': crypttab_content,
            'block_devices': block_devices,
            'btrfs_subvolumes': btrfs_subvols,
            'archive_drives': archive_drives
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
        """Read /etc/crypttab if it exists."""
        p = Path('/etc/crypttab')
        if not p.exists():
            return {'exists': False, 'content': ''}

        try:
            return {'exists': True, 'content': p.read_text(encoding='utf-8')}
        except Exception as e:
            return {'exists': True, 'error': str(e), 'content': ''}

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
        for f in ['/etc/fstab', '/etc/crypttab']:
            p = Path(f)
            if p.exists():
                collectible[f"system{f}"] = p
        return collectible
