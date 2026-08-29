"""
Universal Linux Bootstrap - Version Information
"""

__version__ = "0.0.1"
__app_name__ = "Universal Linux Bootstrap"
__author__ = "Universal Linux Bootstrap Team"
__license__ = "MIT"


def get_version() -> str:
    """Return the semantic version string."""
    return __version__


def get_full_program_name(component_name: str) -> str:
    """Format the full formal program name with version."""
    return f"{__app_name__} - {component_name} v{__version__}"
