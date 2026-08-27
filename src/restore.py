#!/usr/bin/env python3
"""
Backward compatibility wrapper for emergency_restore.py.
Redirects directly to the root emergency_restore.py script.
"""

import sys
import subprocess
from pathlib import Path

RESTORE_SCRIPT = Path(__file__).resolve().parent / "emergency_restore.py"

if __name__ == '__main__':
    sys.exit(subprocess.call([sys.executable, str(RESTORE_SCRIPT)] + sys.argv[1:]))
