#!/usr/bin/env python3
"""
Rclone Universal Cloud Storage Backend

Provides integration with Google Drive, OneDrive, Dropbox, Nextcloud, Box, etc. via rclone.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend


class RcloneStorageBackend(BaseStorageBackend):
    """Integrates with cloud providers using the rclone tool."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.remote = config.get('remote_name', '').rstrip(':') + ':'
        self.remote_path = config.get('remote_path', 'Bootstrap_Backups').strip('/')
        self.rclone_bin = config.get('rclone_binary') or shutil.which('rclone') or 'rclone'

    def is_available(self) -> bool:
        """Check if rclone is installed and configured."""
        if not shutil.which(self.rclone_bin):
            return False
        try:
            res = subprocess.run([self.rclone_bin, 'listremotes'], capture_output=True, text=True)
            return self.remote in res.stdout
        except Exception:
            return False

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"File not found: {local_file}"}

        if not shutil.which(self.rclone_bin):
            return {
                'success': False,
                'error': f"rclone binary not found. Install with pacman -S rclone or apt install rclone"
            }

        target_name = remote_filename or local_file.name
        destination = f"{self.remote}{self.remote_path}/{target_name}"

        try:
            cmd = [self.rclone_bin, 'copyto', str(local_file), destination]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.cleanup_old_backups()
            return {
                'success': True,
                'location': destination,
                'size_bytes': local_file.stat().st_size
            }
        except subprocess.CalledProcessError as e:
            return {'success': False, 'error': f"rclone error: {e.stderr.strip() or str(e)}"}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def list_backups(self) -> List[Dict[str, Any]]:
        if not shutil.which(self.rclone_bin):
            return []

        target_dir = f"{self.remote}{self.remote_path}"
        try:
            res = subprocess.run([self.rclone_bin, 'lsjson', target_dir], capture_output=True, text=True, check=True)
            items = json.loads(res.stdout)
            backups = []
            for it in items:
                if not it.get('IsDir', False) and it.get('Name', '').startswith('bootstrap_'):
                    backups.append({
                        'name': it.get('Name'),
                        'size': it.get('Size', 0),
                        'mod_time': it.get('ModTime'),
                        'path': f"{target_dir}/{it.get('Name')}"
                    })
            return backups
        except Exception:
            return []

    def cleanup_old_backups(self) -> int:
        backups = self.list_backups()
        if len(backups) <= self.retention_count:
            return 0

        to_remove = backups[self.retention_count:]
        count = 0
        for item in to_remove:
            try:
                subprocess.run([self.rclone_bin, 'deletefile', item['path']], capture_output=True, check=True)
                count += 1
            except Exception:
                pass
        return count
