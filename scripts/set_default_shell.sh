#!/usr/bin/env bash
# ==============================================================================
# Set Default Login Shell Helper
# Usage: ./scripts/set_default_shell.sh [fish|bash|zsh] [username]
# ==============================================================================
set -euo pipefail

TARGET_SHELL_NAME="${1:-fish}"
TARGET_USER="${2:-${SUDO_USER:-$USER}}"

# Resolve binary path
SHELL_BIN=$(which "$TARGET_SHELL_NAME" 2>/dev/null || true)
if [[ -z "$SHELL_BIN" ]]; then
    if [[ -x "/usr/bin/$TARGET_SHELL_NAME" ]]; then
        SHELL_BIN="/usr/bin/$TARGET_SHELL_NAME"
    elif [[ -x "/bin/$TARGET_SHELL_NAME" ]]; then
        SHELL_BIN="/bin/$TARGET_SHELL_NAME"
    else
        echo "❌ Shell '$TARGET_SHELL_NAME' is not installed."
        echo "   Install it first with: sudo pacman -S $TARGET_SHELL_NAME (or sudo apt install $TARGET_SHELL_NAME)"
        exit 1
    fi
fi

# Ensure shell is listed in /etc/shells
if ! grep -Fxq "$SHELL_BIN" /etc/shells; then
    echo "⚙️  Adding $SHELL_BIN to /etc/shells..."
    echo "$SHELL_BIN" | sudo tee -a /etc/shells >/dev/null
fi

# Change shell for target user
CURRENT_SHELL=$(getent passwd "$TARGET_USER" | cut -d: -f7)
if [[ "$CURRENT_SHELL" == "$SHELL_BIN" ]]; then
    echo "✓ Default shell for user '$TARGET_USER' is already $SHELL_BIN"
else
    echo "🐚 Changing default shell for '$TARGET_USER' from '$CURRENT_SHELL' to '$SHELL_BIN'..."
    sudo usermod -s "$SHELL_BIN" "$TARGET_USER"
    echo "✅ Successfully set default shell to $SHELL_BIN for '$TARGET_USER'."
    echo "   (New terminal sessions and SSH logins will now open with $TARGET_SHELL_NAME)"
fi
