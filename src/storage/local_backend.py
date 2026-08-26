#!/usr/bin/env python3
"""
Local / External Disk Storage Backend
"""

import shutil
import datetime
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend


class LocalStorageBackend(BaseStorageBackend):
    """Stores encrypted backup archives on local filesystem or mounted archive drives."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        dest_dir = config.get('destination_dir', './backup')
        self.dest_path = Path(dest_dir).expanduser()
        if self.enabled:
            self.dest_path.mkdir(parents=True, exist_ok=True)

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path).resolve()
        if not local_file.exists():
            return {'success': False, 'error': f"Local file not found: {local_file}"}

        target_name = remote_filename or local_file.name
        target_path = (self.dest_path / target_name).resolve()

        try:
            self.dest_path.mkdir(parents=True, exist_ok=True)
            if target_path != local_file:
                shutil.copy2(local_file, target_path)

            cleaned = self.cleanup_old_backups()
            return {
                'success': True,
                'location': str(target_path),
                'size_bytes': target_path.stat().st_size,
                'cleaned_old_backups': cleaned
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def list_backups(self) -> List[Dict[str, Any]]:
        backups = []
        if not self.dest_path.exists():
            return backups

        for f in self.dest_path.glob('bootstrap_vault_*.tar.enc'):
            if f.is_file():
                backups.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'mtime': f.stat().st_mtime
                })

        # Sort newest first
        backups.sort(key=lambda x: x['mtime'], reverse=True)
        return backups

    def cleanup_old_backups(self) -> int:
        backups = self.list_backups()
        if len(backups) <= self.retention_count:
            return 0

        to_remove = backups[self.retention_count:]
        count = 0
        for item in to_remove:
            try:
                Path(item['path']).unlink()
                count += 1
            except Exception:
                pass
        return count
