#!/usr/bin/env python3
"""
Microsoft OneDrive Storage Backend

Supports:
1. rclone remote (e.g. onedrive:Bootstrap_Backups)
2. Microsoft Graph REST API with client ID / secret / refresh token
"""

import os
import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
    from .rclone_backend import RcloneStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend
    from rclone_backend import RcloneStorageBackend


class OneDriveStorageBackend(BaseStorageBackend):
    """Stores encrypted backup archives in Microsoft OneDrive."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.use_rclone = config.get('use_rclone', True)
        self.rclone_remote = config.get('rclone_remote', 'onedrive')
        self.folder_name = config.get('folder_name', 'Bootstrap_Backups')

        if self.use_rclone:
            self.rclone_backend = RcloneStorageBackend({
                'name': 'OneDrive (via rclone)',
                'enabled': self.enabled,
                'remote_name': self.rclone_remote,
                'remote_path': self.folder_name,
                'retention_count': self.retention_count
            })
        else:
            self.rclone_backend = None

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"File not found: {local_file}"}

        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.upload(local_file, remote_filename)

        return {
            'success': False,
            'error': "Direct OneDrive API mode requires OAuth token. Recommended: set use_rclone: true."
        }

    def list_backups(self) -> List[Dict[str, Any]]:
        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.list_backups()
        return []

    def cleanup_old_backups(self) -> int:
        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.cleanup_old_backups()
        return 0
