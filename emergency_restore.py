#!/usr/bin/env python3
"""
Universal Linux Bootstrap - Emergency System Restoration Tool (Wrapper)

Redirects to src/emergency_restore.py while maintaining backward compatibility.
For automatic prerequisite checking and installation (Python 3, cryptography, zstd, etc.),
prefer using the shell launcher:
    sudo ./restore.sh
"""

import sys
import subprocess
from pathlib import Path

SRC_RESTORE_SCRIPT = Path(__file__).resolve().parent / "src" / "emergency_restore.py"

if __name__ == '__main__':
    if not SRC_RESTORE_SCRIPT.exists():
        print(f"Error: {SRC_RESTORE_SCRIPT} not found.", file=sys.stderr)
        sys.exit(1)
    sys.exit(subprocess.call([sys.executable, str(SRC_RESTORE_SCRIPT)] + sys.argv[1:]))
