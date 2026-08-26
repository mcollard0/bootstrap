#!/usr/bin/env python3
"""
Google Drive Storage Backend

Supports:
1. rclone remote (e.g. gdrive:Bootstrap_Backups)
2. Direct Google Drive API (OAuth2 or Service Account)
"""

import os
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
    from .rclone_backend import RcloneStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend
    from rclone_backend import RcloneStorageBackend


class GoogleDriveStorageBackend(BaseStorageBackend):
    """Stores encrypted backup archives in Google Drive."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.use_rclone = config.get('use_rclone', True)
        self.rclone_remote = config.get('rclone_remote', 'gdrive')
        self.folder_name = config.get('folder_name', 'Bootstrap_Backups')
        self.credentials_file = config.get('credentials_file')

        if self.use_rclone:
            self.rclone_backend = RcloneStorageBackend({
                'name': 'Google Drive (via rclone)',
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

        # If rclone mode
        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.upload(local_file, remote_filename)

        # Direct Google Drive API upload if google-api-python-client is installed
        try:
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload
            from google.oauth2 import service_account

            if not self.credentials_file or not os.path.exists(self.credentials_file):
                return {'success': False, 'error': "Google Drive credentials file not found"}

            creds = service_account.Credentials.from_service_account_file(
                self.credentials_file,
                scopes=['https://www.googleapis.com/auth/drive.file']
            )
            service = build('drive', 'v3', credentials=creds)

            target_name = remote_filename or local_file.name
            file_metadata = {'name': target_name}
            media = MediaFileUpload(str(local_file), mimetype='application/octet-stream')
            uploaded = service.files().create(body=file_metadata, media_body=media, fields='id').execute()

            return {
                'success': True,
                'location': f"gdrive://{uploaded.get('id')}",
                'size_bytes': local_file.stat().st_size
            }
        except ImportError:
            return {
                'success': False,
                'error': "Direct Google Drive API requires google-api-python-client. Consider setting use_rclone: true."
            }
        except Exception as e:
            return {'success': False, 'error': f"Google Drive error: {e}"}

    def list_backups(self) -> List[Dict[str, Any]]:
        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.list_backups()
        return []

    def cleanup_old_backups(self) -> int:
        if self.use_rclone and self.rclone_backend:
            return self.rclone_backend.cleanup_old_backups()
        return 0
