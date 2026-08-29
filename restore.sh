#!/usr/bin/env bash
# ==============================================================================
# Universal Linux Bootstrap - Emergency Disaster Recovery Launcher
#
# Idempotently checks, installs, and provisions runtime prerequisites
# (Python 3, cryptography, zstd, tar, curl) across any Linux distribution
# before delegating to the primary recovery engine (src/emergency_restore.py).
#
# Usage:
#   sudo ./restore.sh [options]
#   sudo ./restore.sh -s 1 -y
#   sudo ./restore.sh -s 2 --password "<PASSWORD>"
# ==============================================================================

set -eo pipefail

# ANSI Colors
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[0;32m"
    YELLOW="\033[1;33m"
    CYAN="\033[0;36m"
    RED="\033[0;31m"
    NC="\033[0m"
else
    BOLD=""
    GREEN=""
    YELLOW=""
    CYAN=""
    RED=""
    NC=""
fi

VERSION="0.0.1"
PROGRAM_NAME="Universal Linux Bootstrap - Disaster Recovery Pre-Flight & Launcher v${VERSION}"

if [[ "$1" == "--version" || "$1" == "-v" ]]; then
    echo "$PROGRAM_NAME"
    exit 0
fi

log_ts() {
    date '+[%Y-%m-%d %H:%M:%S]'
}

log_msg() {
    echo -e "$(log_ts) $1"
}

# 1. Privilege & sudo helper resolution
if [ "$EUID" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESTORE_PY="$SCRIPT_DIR/src/emergency_restore.py"

# 2. Self-bootstrapping fallback if recovery engine is not found locally
if [ ! -f "$RESTORE_PY" ]; then
    log_msg "${YELLOW}⚡ Recovery engine not found at $RESTORE_PY${NC}"
    log_msg "${CYAN}📥 Standalone mode: Bootstrapping full repository into /tmp/bootstrap...${NC}"

    # Ensure git or curl/tar is available
    if ! command -v git >/dev/null 2>&1; then
        log_msg "  ${YELLOW}📦 git is missing. Attempting automatic installation...${NC}"
        if command -v pacman >/dev/null 2>&1; then
            $SUDO pacman -Sy --needed --noconfirm git
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get update -y
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git
        elif command -v dnf >/dev/null 2>&1; then
            $SUDO dnf install -y git
        elif command -v zypper >/dev/null 2>&1; then
            $SUDO zypper --non-interactive install git
        elif command -v apk >/dev/null 2>&1; then
            $SUDO apk add --no-cache git
        fi
    fi

    # Clone or pull repo
    mkdir -p /tmp/bootstrap
    if command -v git >/dev/null 2>&1; then
        if [ -d "/tmp/bootstrap/.git" ]; then
            log_msg "  ${CYAN}🔄 Existing /tmp/bootstrap found; syncing latest changes...${NC}"
            git -C /tmp/bootstrap pull origin main 2>/dev/null || true
        else
            log_msg "  ${CYAN}🚀 Cloning https://github.com/mcollard0/bootstrap.git...${NC}"
            rm -rf /tmp/bootstrap
            git clone --depth 1 https://github.com/mcollard0/bootstrap.git /tmp/bootstrap
        fi
    elif command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        log_msg "  ${YELLOW}⚠️ git unavailable; downloading source tarball via curl...${NC}"
        rm -rf /tmp/bootstrap
        mkdir -p /tmp/bootstrap
        curl -sSL https://github.com/mcollard0/bootstrap/archive/refs/heads/main.tar.gz | tar -xz -C /tmp/bootstrap --strip-components=1
    else
        log_msg "${RED}❌ Fatal: Neither git nor curl could download the repository.${NC}" >&2
        log_msg "   Please install git manually: sudo pacman -S git (or sudo apt install git)" >&2
        exit 1
    fi

    if [ -f "/tmp/bootstrap/restore.sh" ]; then
        log_msg "  ${GREEN}✅ Successfully bootstrapped repository in /tmp/bootstrap.${NC}"
        log_msg "  ${CYAN}🚀 Transferring execution to /tmp/bootstrap/restore.sh...${NC}\n"
        cd /tmp/bootstrap
        chmod +x /tmp/bootstrap/restore.sh
        exec /tmp/bootstrap/restore.sh "$@"
    else
        log_msg "${RED}❌ Fatal: Downloaded repository did not contain restore.sh.${NC}" >&2
        exit 1
    fi
fi

log_msg "${BOLD}${CYAN}======================================================================${NC}"
log_msg "${BOLD}${CYAN}   $PROGRAM_NAME           ${NC}"
log_msg "${BOLD}${CYAN}======================================================================${NC}"

# 3. Configure passwordless sudo for target user during disaster recovery
TARGET_USER="${SUDO_USER:-$USER}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
    if [ "$EUID" -eq 0 ] || [ -n "$SUDO" ]; then
        if [ ! -f /etc/sudoers.d/99-bootstrap-nopasswd ]; then
            log_msg "  ${CYAN}🔑 Configuring passwordless sudo for disaster recovery ($TARGET_USER)...${NC}"
            $SUDO mkdir -p /etc/sudoers.d
            TMP_SUDO=$(mktemp)
            cat <<EOF > "$TMP_SUDO"
# Created by Universal Linux Bootstrap Disaster Recovery
%wheel ALL=(ALL:ALL) NOPASSWD: ALL
%sudo ALL=(ALL:ALL) NOPASSWD: ALL
$TARGET_USER ALL=(ALL:ALL) NOPASSWD: ALL
EOF
            chmod 0440 "$TMP_SUDO"
            if command -v visudo >/dev/null 2>&1; then
                if visudo -cf "$TMP_SUDO" >/dev/null 2>&1; then
                    $SUDO cp "$TMP_SUDO" /etc/sudoers.d/99-bootstrap-nopasswd
                    $SUDO chmod 0440 /etc/sudoers.d/99-bootstrap-nopasswd
                else
                    log_msg "  ${YELLOW}⚠️  visudo syntax check failed; skipping sudoers modification.${NC}"
                fi
            else
                $SUDO cp "$TMP_SUDO" /etc/sudoers.d/99-bootstrap-nopasswd
                $SUDO chmod 0440 /etc/sudoers.d/99-bootstrap-nopasswd
            fi
            rm -f "$TMP_SUDO"
        fi
    fi
fi

# 4. Arch/CachyOS Live USB tmpfs overlay expansion
if [ -d "/run/archiso/cowspace" ] && [ "$EUID" -eq 0 ]; then
    log_msg "  ${YELLOW}⚡ Detected Live ISO environment. Expanding cowspace overlay to 32G...${NC}"
    mount -o remount,size=32G /run/archiso/cowspace 2>/dev/null || true
fi

# 5. Detect Missing Prerequisites
NEED_PKGS=()
NEED_PYTHON=false
NEED_CRYPTO=false
NEED_TAR=false
NEED_ZSTD=false
NEED_CURL=false

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    NEED_PYTHON=true
fi

if ! command -v tar >/dev/null 2>&1; then
    NEED_TAR=true
fi

if ! command -v zstd >/dev/null 2>&1; then
    NEED_ZSTD=true
fi

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    NEED_CURL=true
fi

# Check Python cryptography module
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if [ -n "$PYTHON_BIN" ]; then
    if ! "$PYTHON_BIN" -c "import cryptography" 2>/dev/null; then
        NEED_CRYPTO=true
    fi
else
    NEED_CRYPTO=true
fi

# 4. Auto-install Missing Prerequisites if needed
if [ "$NEED_PYTHON" = true ] || [ "$NEED_CRYPTO" = true ] || [ "$NEED_TAR" = true ] || [ "$NEED_ZSTD" = true ] || [ "$NEED_CURL" = true ]; then
    log_msg "  ${YELLOW}📦 Missing prerequisites detected:${NC}"
    [ "$NEED_PYTHON" = true ] && log_msg "     • Python 3 runtime"
    [ "$NEED_CRYPTO" = true ] && log_msg "     • Python Cryptography library"
    [ "$NEED_TAR" = true ]    && log_msg "     • tar archive utility"
    [ "$NEED_ZSTD" = true ]   && log_msg "     • zstd compression utility"
    [ "$NEED_CURL" = true ]   && log_msg "     • curl network downloader"

    log_msg "  ${CYAN}🚀 Installing missing dependencies via host package manager...${NC}"

    if command -v pacman >/dev/null 2>&1; then
        PACMAN_PKGS=()
        [ "$NEED_PYTHON" = true ] && PACMAN_PKGS+=("python")
        [ "$NEED_CRYPTO" = true ] && PACMAN_PKGS+=("python-cryptography")
        [ "$NEED_TAR" = true ]    && PACMAN_PKGS+=("tar")
        [ "$NEED_ZSTD" = true ]   && PACMAN_PKGS+=("zstd")
        [ "$NEED_CURL" = true ]   && PACMAN_PKGS+=("curl")
        if [ ${#PACMAN_PKGS[@]} -gt 0 ]; then
            $SUDO pacman -Sy --needed --noconfirm "${PACMAN_PKGS[@]}"
        fi

    elif command -v apt-get >/dev/null 2>&1; then
        APT_PKGS=()
        [ "$NEED_PYTHON" = true ] && APT_PKGS+=("python3")
        [ "$NEED_CRYPTO" = true ] && APT_PKGS+=("python3-cryptography")
        [ "$NEED_TAR" = true ]    && APT_PKGS+=("tar")
        [ "$NEED_ZSTD" = true ]   && APT_PKGS+=("zstd")
        [ "$NEED_CURL" = true ]   && APT_PKGS+=("curl")
        if [ ${#APT_PKGS[@]} -gt 0 ]; then
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get update -y
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${APT_PKGS[@]}"
        fi

    elif command -v dnf >/dev/null 2>&1; then
        DNF_PKGS=()
        [ "$NEED_PYTHON" = true ] && DNF_PKGS+=("python3")
        [ "$NEED_CRYPTO" = true ] && DNF_PKGS+=("python3-cryptography")
        [ "$NEED_TAR" = true ]    && DNF_PKGS+=("tar")
        [ "$NEED_ZSTD" = true ]   && DNF_PKGS+=("zstd")
        [ "$NEED_CURL" = true ]   && DNF_PKGS+=("curl")
        if [ ${#DNF_PKGS[@]} -gt 0 ]; then
            $SUDO dnf install -y "${DNF_PKGS[@]}"
        fi

    elif command -v zypper >/dev/null 2>&1; then
        ZYPPER_PKGS=()
        [ "$NEED_PYTHON" = true ] && ZYPPER_PKGS+=("python3")
        [ "$NEED_CRYPTO" = true ] && ZYPPER_PKGS+=("python3-cryptography")
        [ "$NEED_TAR" = true ]    && ZYPPER_PKGS+=("tar")
        [ "$NEED_ZSTD" = true ]   && ZYPPER_PKGS+=("zstd")
        [ "$NEED_CURL" = true ]   && ZYPPER_PKGS+=("curl")
        if [ ${#ZYPPER_PKGS[@]} -gt 0 ]; then
            $SUDO zypper --non-interactive install "${ZYPPER_PKGS[@]}"
        fi

    elif command -v apk >/dev/null 2>&1; then
        APK_PKGS=()
        [ "$NEED_PYTHON" = true ] && APK_PKGS+=("python3")
        [ "$NEED_CRYPTO" = true ] && APK_PKGS+=("py3-cryptography")
        [ "$NEED_TAR" = true ]    && APK_PKGS+=("tar")
        [ "$NEED_ZSTD" = true ]   && APK_PKGS+=("zstd")
        [ "$NEED_CURL" = true ]   && APK_PKGS+=("curl")
        if [ ${#APK_PKGS[@]} -gt 0 ]; then
            $SUDO apk add --no-cache "${APK_PKGS[@]}"
        fi
    else
        log_msg "  ${RED}⚠️  No recognized package manager (pacman/apt/dnf/zypper/apk) found.${NC}" >&2
    fi

    # Fallback verification for cryptography
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi

    if [ -n "$PYTHON_BIN" ]; then
        if ! "$PYTHON_BIN" -c "import cryptography" 2>/dev/null; then
            log_msg "  ${YELLOW}⚙️  Distro cryptography package not detected. Attempting pip fallback...${NC}"
            $SUDO "$PYTHON_BIN" -m pip install cryptography --break-system-packages 2>/dev/null || \
            $SUDO "$PYTHON_BIN" -m pip install cryptography 2>/dev/null || true
        fi
    fi
fi

# 5. Final Sanity Check
if command -v python3 >/dev/null 2>&1; then
    FINAL_PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    FINAL_PYTHON="python"
else
    log_msg "${RED}❌ Fatal: Python 3 could not be installed automatically.${NC}" >&2
    log_msg "   Please install python3 manually and re-run this script." >&2
    exit 1
fi

if ! "$FINAL_PYTHON" -c "import cryptography" 2>/dev/null; then
    log_msg "${RED}❌ Fatal: Python 'cryptography' library could not be loaded.${NC}" >&2
    log_msg "   Install it with: sudo apt install python3-cryptography (or sudo pacman -S python-cryptography)" >&2
    exit 1
fi

log_msg "  ${GREEN}✅ Prerequisites verified (Python 3, cryptography, zstd, tar, curl).${NC}"
log_msg "${BOLD}${CYAN}======================================================================${NC}\n"

# 6. Transfer control to the Python recovery engine
exec "$FINAL_PYTHON" "$RESTORE_PY" "$@"
