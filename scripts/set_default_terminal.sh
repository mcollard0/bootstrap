#!/usr/bin/env bash
# ==============================================================================
# Set Default Terminal & Ctrl+Alt+T Shortcut Helper
# Supports KDE Plasma 6/5, GNOME, and xdg-terminal-exec
# Usage: ./scripts/set_default_terminal.sh [warp|alacritty|konsole|kitty|wezterm] [username]
# ==============================================================================
set -euo pipefail

TARGET_TERM="${1:-warp}"
TARGET_USER="${2:-${SUDO_USER:-$USER}}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
TARGET_UID=$(getent passwd "$TARGET_USER" | cut -d: -f3)

case "$TARGET_TERM" in
    warp|warp-terminal)
        APP_BIN="warp-terminal"
        DESKTOP_FILE="dev.warp.Warp.desktop"
        SERVICE_NAME="dev.warp.Warp.desktop"
        ;;
    alacritty)
        APP_BIN="alacritty"
        DESKTOP_FILE="Alacritty.desktop"
        SERVICE_NAME="Alacritty.desktop"
        ;;
    konsole)
        APP_BIN="konsole"
        DESKTOP_FILE="org.kde.konsole.desktop"
        SERVICE_NAME="org.kde.konsole.desktop"
        ;;
    kitty)
        APP_BIN="kitty"
        DESKTOP_FILE="kitty.desktop"
        SERVICE_NAME="kitty.desktop"
        ;;
    wezterm)
        APP_BIN="wezterm"
        DESKTOP_FILE="org.wezfurlong.wezterm.desktop"
        SERVICE_NAME="org.wezfurlong.wezterm.desktop"
        ;;
    *)
        echo "❌ Unknown terminal: $TARGET_TERM"
        echo "   Supported: warp, alacritty, konsole, kitty, wezterm"
        exit 1
        ;;
esac

# 1. Verify binary is installed
REAL_BIN=$(which "$APP_BIN" 2>/dev/null || true)
if [[ -z "$REAL_BIN" ]]; then
    echo "⚠️  Warning: Terminal binary '$APP_BIN' is not currently in PATH."
    echo "   Ensure it is installed before testing shortcuts."
fi

echo "🖥️  Configuring default terminal to '$TARGET_TERM' ($APP_BIN / $DESKTOP_FILE) for '$TARGET_USER'..."

# 2. Configure KDE Plasma 6 / 5 settings if running KDE or config exists
KWRITE_BIN=$(which kwriteconfig6 2>/dev/null || which kwriteconfig5 2>/dev/null || true)
QDBUS_BIN=$(which qdbus6 2>/dev/null || which qdbus 2>/dev/null || true)

KDEGLOBALS="$TARGET_HOME/.config/kdeglobals"
KSHORTCUTS="$TARGET_HOME/.config/kglobalshortcutsrc"

# Update KDE configuration files
if [[ -n "$KWRITE_BIN" ]] || [[ -f "$KDEGLOBALS" ]]; then
    # General Default Terminal
    sudo -u "$TARGET_USER" kwriteconfig6 --file kdeglobals --group General --key TerminalApplication "$APP_BIN" 2>/dev/null || true
    sudo -u "$TARGET_USER" kwriteconfig6 --file kdeglobals --group General --key TerminalService "$DESKTOP_FILE" 2>/dev/null || true

    # Assign Ctrl+Alt+T to chosen terminal, clear from others
    for term_svc in "dev.warp.Warp.desktop" "Alacritty.desktop" "org.kde.konsole.desktop" "kitty.desktop" "org.wezfurlong.wezterm.desktop"; do
        if [[ "$term_svc" == "$SERVICE_NAME" ]]; then
            sudo -u "$TARGET_USER" kwriteconfig6 --file kglobalshortcutsrc --group services --group "$term_svc" --key _launch "Ctrl+Alt+T" 2>/dev/null || true
        else
            sudo -u "$TARGET_USER" kwriteconfig6 --file kglobalshortcutsrc --group services --group "$term_svc" --key _launch "none" 2>/dev/null || true
        fi
    done

    # Notify running KDE Plasma session to reload shortcuts live
    if [[ -n "$QDBUS_BIN" ]] && [[ -S "/run/user/$TARGET_UID/bus" ]]; then
        sudo -u "$TARGET_USER" bash -c "
            export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$TARGET_UID/bus
            $QDBUS_BIN org.kde.KGlobalAccel /kglobalaccel org.kde.KGlobalAccel.reloadConfig 2>/dev/null || true
        " || true
    fi
    echo "  ✓ KDE Plasma default terminal and Ctrl+Alt+T shortcuts updated."
fi

# 3. Configure xdg-terminal-exec (Freedesktop specification)
XDG_CONF_DIR="$TARGET_HOME/.config"
XDG_CONF_FILE="$XDG_CONF_DIR/xdg-terminal-exec.conf"
if [[ -d "$XDG_CONF_DIR" ]]; then
    sudo -u "$TARGET_USER" bash -c "echo '$DESKTOP_FILE' > '$XDG_CONF_FILE'" 2>/dev/null || true
    echo "  ✓ Configured freedesktop xdg-terminal-exec: $DESKTOP_FILE"
fi

# 4. Configure Debian/Ubuntu alternatives if available
if which update-alternatives >/dev/null 2>&1; then
    if [[ -x "/usr/bin/$APP_BIN" ]]; then
        sudo update-alternatives --set x-terminal-emulator "/usr/bin/$APP_BIN" 2>/dev/null || true
        echo "  ✓ Configured update-alternatives x-terminal-emulator: /usr/bin/$APP_BIN"
    fi
fi

echo "✅ Terminal configuration complete! '$TARGET_TERM' is now bound to Ctrl+Alt+T."
echo ""
echo -e "\033[1;33m🔔 Post-Configuration Note:\033[0m"
echo "  Some changes (such as keyboard shortcuts like Ctrl+Alt+T) require a session reload to take effect."
echo "  👉 Restart your display manager (or log out and back in):"
echo -e "     \033[0;36msudo systemctl restart display-manager\033[0m"
echo "  👉 Restart your terminal or reload your shell for environment variables to take effect:"
echo -e "     \033[0;36mexec fish\033[0m  (or open a new terminal window)"
