#!/usr/bin/env python3
"""
Storage Dispatcher

Orchestrates multi-destination backup dispatch.
Reads configured destinations and uploads encrypted vault to all enabled targets:
- Local / FAST_ARCHIVE
- AWS S3 / Compatible
- Google Drive
- Microsoft OneDrive
- Email (SMTP)
- Generic Rclone remotes
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any

try:
    from .local_backend import LocalStorageBackend
    from .s3_backend import S3StorageBackend
    from .email_backend import EmailStorageBackend
    from .gdrive_backend import GoogleDriveStorageBackend
    from .onedrive_backend import OneDriveStorageBackend
    from .rclone_backend import RcloneStorageBackend
except ImportError:
    # Running directly as script
    sys.path.insert(0, str(Path(__file__).parent))
    from local_backend import LocalStorageBackend
    from s3_backend import S3StorageBackend
    from email_backend import EmailStorageBackend
    from gdrive_backend import GoogleDriveStorageBackend
    from onedrive_backend import OneDriveStorageBackend
    from rclone_backend import RcloneStorageBackend


class StorageDispatcher:
    """Manages upload dispatch to multiple untrusted cloud and local destinations."""

    def __init__(self, config_path: str = None, base_dir: Path = None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent.parent.parent
        self.config_path = Path(config_path) if config_path else self._find_config()
        self.destinations = self._load_destinations()
        self.backends = self._initialize_backends()

    def _find_config(self) -> Path:
        candidates = [
            self.base_dir / 'data/destinations.json',
            self.base_dir / 'config/destinations.json',
            self.base_dir / 'config/destinations.example.json'
        ]
        for c in candidates:
            if c.exists():
                return c
        return self.base_dir / 'data/destinations.json'

    def _load_destinations(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: could not read {self.config_path}: {e}", file=sys.stderr)

        # Default configuration
        default_cfg = {
            'local_project_backup': {
                'type': 'local',
                'enabled': True,
                'destination_dir': str(self.base_dir / 'backup'),
                'retention_count': 25
            },
            'local_fast_archive': {
                'type': 'local',
                'enabled': os.path.exists('/run/media/michael/FAST_ARCHIVE'),
                'destination_dir': '/run/media/michael/FAST_ARCHIVE/SystemBackups',
                'retention_count': 15
            },
            'aws_s3': {
                'type': 's3',
                'enabled': False,
                'bucket_name': '',
                'access_key_id': '',
                'secret_access_key': '',
                'region_name': 'us-east-1',
                'prefix': 'bootstrap-backups/',
                'retention_count': 10
            },
            'google_drive': {
                'type': 'gdrive',
                'enabled': False,
                'use_rclone': True,
                'rclone_remote': 'gdrive',
                'folder_name': 'Bootstrap_Backups',
                'retention_count': 10
            },
            'onedrive': {
                'type': 'onedrive',
                'enabled': False,
                'use_rclone': True,
                'rclone_remote': 'onedrive',
                'folder_name': 'Bootstrap_Backups',
                'retention_count': 10
            },
            'email_smtp': {
                'type': 'email',
                'enabled': False,
                'smtp_host': 'smtp.gmail.com',
                'smtp_port': 587,
                'use_tls': True,
                'smtp_username': '',
                'smtp_password': '',
                'recipient_email': ''
            }
        }
        return default_cfg

    def save_config(self, filepath: Path = None):
        target = filepath or self.config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'w', encoding='utf-8') as f:
            json.dump(self.destinations, f, indent=2)

    def _initialize_backends(self) -> List[Any]:
        backends = []
        for dest_key, cfg in self.destinations.items():
            if not cfg.get('enabled', False):
                continue

            cfg_type = cfg.get('type')
            cfg['name'] = dest_key

            try:
                if cfg_type == 'local':
                    backends.append(LocalStorageBackend(cfg))
                elif cfg_type == 's3':
                    backends.append(S3StorageBackend(cfg))
                elif cfg_type == 'gdrive':
                    backends.append(GoogleDriveStorageBackend(cfg))
                elif cfg_type == 'onedrive':
                    backends.append(OneDriveStorageBackend(cfg))
                elif cfg_type == 'email':
                    backends.append(EmailStorageBackend(cfg))
                elif cfg_type == 'rclone':
                    backends.append(RcloneStorageBackend(cfg))
            except Exception as e:
                print(f"Warning: could not initialize backend {dest_key}: {e}", file=sys.stderr)

        return backends

    def dispatch(self, local_vault_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        """Dispatch encrypted archive to all enabled destinations."""
        print(f"\n📡 Dispatched encrypted vault to storage destinations:")
        print(f"   Archive file: {local_vault_path.name}")
        print(f"   Size: {local_vault_path.stat().st_size / (1024*1024):.2f} MB")

        results = {}
        if not self.backends:
            print("   ⚠️  No storage destinations are enabled!")
            return results

        for backend in self.backends:
            b_name = backend.name
            print(f"   🚀 Uploading to [{b_name}]...")
            try:
                res = backend.upload(local_vault_path, remote_filename)
                results[b_name] = res
                if res.get('success'):
                    print(f"      ✅ Success: {res.get('location')}")
                else:
                    print(f"      ❌ Failed: {res.get('error')}")
            except Exception as e:
                results[b_name] = {'success': False, 'error': str(e)}
                print(f"      ❌ Exception: {e}")

        return results


if __name__ == '__main__':
    dispatcher = StorageDispatcher()
    print("Configured backends:")
    for b in dispatcher.backends:
        print(f"  • {b.name} (type: {b.__class__.__name__})")
