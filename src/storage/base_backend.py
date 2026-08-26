#!/usr/bin/env python3
"""
Base Storage Backend Class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path


class BaseStorageBackend(ABC):
    """Abstract base class for all backup storage providers."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', self.__class__.__name__)
        self.enabled = config.get('enabled', False)
        self.retention_count = config.get('retention_count', 10)

    @abstractmethod
    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        """
        Upload local file to destination.
        Returns:
            Dict with 'success': bool, 'location': str, 'error': Optional[str]
        """
        pass

    @abstractmethod
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups on remote storage."""
        return []

    def cleanup_old_backups(self) -> int:
        """Enforce retention policy by removing backups beyond retention_count."""
        return 0
