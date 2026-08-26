"""
Multi-Destination Storage Subsystem
"""

from .base_backend import BaseStorageBackend
from .local_backend import LocalStorageBackend
from .s3_backend import S3StorageBackend
from .email_backend import EmailStorageBackend
from .gdrive_backend import GoogleDriveStorageBackend
from .onedrive_backend import OneDriveStorageBackend
from .rclone_backend import RcloneStorageBackend
from .storage_dispatcher import StorageDispatcher

__all__ = [
    'BaseStorageBackend',
    'LocalStorageBackend',
    'S3StorageBackend',
    'EmailStorageBackend',
    'GoogleDriveStorageBackend',
    'OneDriveStorageBackend',
    'RcloneStorageBackend',
    'StorageDispatcher'
]
