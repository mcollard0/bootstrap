#!/usr/bin/env python3
"""
Rclone Universal Cloud Storage Backend

Provides integration with Google Drive, OneDrive, Dropbox, Nextcloud, Box, etc. via rclone.
Outputs detailed warnings if rclone is uninstalled or unconfigured, and diagnostics on error.
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
        raw_remote = config.get('remote_name', '')
        self.remote = raw_remote.rstrip(':') + ':' if raw_remote else ''
        self.remote_path = config.get('remote_path', 'Bootstrap_Backups').strip('/')
        self.rclone_bin = config.get('rclone_binary') or shutil.which('rclone') or 'rclone'

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Check if rclone is installed and remote is configured."""
        if not shutil.which(self.rclone_bin):
            return False, (
                f"rclone binary not found in PATH!\n"
                f"       To install on Arch/CachyOS: sudo pacman -S rclone\n"
                f"       To install on Ubuntu/Debian: sudo apt install rclone"
            )

        if not self.remote:
            return False, "No rclone remote name configured (e.g. 'gdrive', 'onedrive')."

        try:
            res = subprocess.run([self.rclone_bin, 'listremotes'], capture_output=True, text=True, check=True)
            configured_remotes = [r.strip() for r in res.stdout.strip().split('\n') if r.strip()]
            if self.remote not in configured_remotes:
                return False, (
                    f"Remote '{self.remote}' is NOT configured in rclone!\n"
                    f"       Configured remotes found: {configured_remotes or 'None'}\n"
                    f"       To configure this remote, run: rclone config"
                )
        except Exception as e:
            return False, f"Failed to query rclone listremotes: {e}"

        return True, "Ready"

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"Local file not found: {local_file}"}

        ready, msg = self.check_prerequisites()
        if not ready:
            print(f"      ⚠️  [Rclone Warning] {msg}")
            return {'success': False, 'error': msg}

        target_name = remote_filename or local_file.name
        destination = f"{self.remote}{self.remote_path}/{target_name}"

        try:
            cmd = [self.rclone_bin, 'copyto', str(local_file), destination]
            res = subprocess.run(cmd, capture_output=True, text=True)

            if res.returncode != 0:
                err_detail = (
                    f"rclone copyto failed (exit code {res.returncode}):\n"
                    f"       Command: {' '.join(cmd)}\n"
                    f"       Stderr:  {res.stderr.strip()}\n"
                    f"       Stdout:  {res.stdout.strip()}\n"
                    f"       Tip: Check if OAuth token expired or cloud storage quota is exceeded."
                )
                print(f"      ⚠️  {err_detail}")
                return {'success': False, 'error': err_detail}

            self.cleanup_old_backups()
            return {
                'success': True,
                'location': destination,
                'size_bytes': local_file.stat().st_size
            }
        except Exception as e:
            return {'success': False, 'error': f"Unexpected error during rclone execution: {e}"}

    def list_backups(self) -> List[Dict[str, Any]]:
        ready, _ = self.check_prerequisites()
        if not ready:
            return []

        target_dir = f"{self.remote}{self.remote_path}"
        try:
            res = subprocess.run([self.rclone_bin, 'lsjson', target_dir], capture_output=True, text=True)
            if res.returncode != 0:
                return []
            items = json.loads(res.stdout)
            backups = []
            for it in items:
                if not it.get('IsDir', False) and 'bootstrap_vault_' in it.get('Name', ''):
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
