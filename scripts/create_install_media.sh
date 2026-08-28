#!/usr/bin/env bash
# ==============================================================================
# Universal Linux Bootstrap - Install & Recovery Media Creator (Launcher)
#
# Delegates directly to the dynamic upstream resolver and partitioner engine:
#   scripts/create_install_media.py
#
# Usage:
#   sudo ./create_install_media.sh [options]
#   sudo ./scripts/create_install_media.sh [options]
# ==============================================================================

set -eo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
PYTHON_ENGINE="$SCRIPT_DIR/create_install_media.py"

if [ ! -f "$PYTHON_ENGINE" ]; then
    echo "Error: Python engine not found at $PYTHON_ENGINE" >&2
    exit 1
fi

# Auto-elevate with sudo if not already root, unless dry-run or help is requested
if [ "$EUID" -ne 0 ] && [[ ! " $* " =~ " --dry-run " ]] && [[ ! " $* " =~ " --help " ]] && [[ ! " $* " =~ " -h " ]]; then
    exec sudo python3 "$PYTHON_ENGINE" "$@"
else
    exec python3 "$PYTHON_ENGINE" "$@"
fi
