#!/usr/bin/env python3
"""
Base Scanner Class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from pathlib import Path


class BaseScanner(ABC):
    """Abstract base class for all system inventory scanners."""

    def __init__(self, system_info: Dict[str, Any], user_home: Path = None):
        self.system_info = system_info
        self.user_home = user_home or Path.home()

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """Execute scan and return structured inventory data."""
        pass

    @abstractmethod
    def get_collectible_files(self) -> Dict[str, Path]:
        """Return mapping of virtual archive path -> real disk path for file archiving."""
        return {}
