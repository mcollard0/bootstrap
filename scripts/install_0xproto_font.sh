#!/bin/bash
#
# Install 0xProto Nerd Font
# Downloads and installs the latest 0xProto Nerd Font from GitHub releases
#
# Usage: ./install_0xproto_font.sh [TARGET_USER]
#

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'  # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Get target user from argument or environment
TARGET_USER="${1:-${SUDO_USER:-$USER}}"

# Validate target user exists
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    log_error "Target user '$TARGET_USER' does not exist"
    exit 1
fi

USER_HOME="/home/$TARGET_USER"
FONT_NAME="0xProto"
NERD_FONT_NAME="0xProtoNerdFont"
FONT_DIR="$USER_HOME/.local/share/fonts/nerd-fonts"
TEMP_DIR="/tmp/0xproto-font-install"

log_info "Installing 0xProto Nerd Font for user: $TARGET_USER"

# Check if unzip is available
if ! command -v unzip >/dev/null 2>&1; then
    log_info "Installing unzip...";
    apt update && apt install -y unzip
fi

# Create font directory
mkdir -p "$FONT_DIR"
chown "$TARGET_USER:$TARGET_USER" "$FONT_DIR"

# Create temporary directory
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Get the latest release URL
log_info "Fetching latest 0xProto Nerd Font release information..."

# Use GitHub API to get the latest release
RELEASE_URL="https://api.github.com/repos/ryanoasis/nerd-fonts/releases/latest"

# Get the download URL for 0xProto font
DOWNLOAD_URL=$(curl -s "$RELEASE_URL" | grep -o "https://github.com/ryanoasis/nerd-fonts/releases/download/[^\"]*0xProto[^\"]*\.zip" | head -1)

if [[ -z "$DOWNLOAD_URL" ]]; then
    log_error "Could not find 0xProto Nerd Font download URL"
    exit 1
fi

log_info "Found font download URL: $DOWNLOAD_URL"

# Download the font zip file
ZIP_FILE="0xProto.zip"
log_info "Downloading 0xProto Nerd Font..."

if curl -L -o "$ZIP_FILE" "$DOWNLOAD_URL"; then
    log_success "Font downloaded successfully"
else
    log_error "Failed to download font"
    exit 1
fi

# Extract the zip file
log_info "Extracting font files..."
if unzip -o -q "$ZIP_FILE"; then
    log_success "Font files extracted"
else
    log_error "Failed to extract font files"
    exit 1
fi

# Install font files (copy .ttf and .otf files)
log_info "Installing font files..."
INSTALLED_COUNT=0

# Find and copy all font files
shopt -s nullglob  # Enable nullglob to handle no matches gracefully
set +e  # Temporarily disable exit on error for font installation
for font_file in *.ttf *.otf; do
    if [[ -f "$font_file" ]]; then
        if cp "$font_file" "$FONT_DIR/"; then
            chown "$TARGET_USER:$TARGET_USER" "$FONT_DIR/$font_file" || true
            log_info "Installed: $font_file"
            INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        else
            log_warning "Failed to copy: $font_file"
        fi
    fi
done
set -e  # Re-enable exit on error
shopt -u nullglob  # Disable nullglob

if [[ $INSTALLED_COUNT -eq 0 ]]; then
    log_warning "No font files found to install"
    exit 1
fi

log_success "Installed $INSTALLED_COUNT font files"

# Update font cache for the target user
log_info "Updating font cache..."
if sudo -u "$TARGET_USER" fc-cache -f -v "$FONT_DIR" >/dev/null 2>&1; then
    log_success "Font cache updated"
else
    log_warning "Failed to update font cache, but fonts should still be available"
fi

# Clean up temporary directory
cd /
rm -rf "$TEMP_DIR"
log_info "Cleaned up temporary files"

# Verify installation
log_info "Verifying font installation..."
if sudo -u "$TARGET_USER" fc-list | grep -i "0xproto\|0x proto" >/dev/null; then
    log_success "✅ 0xProto Nerd Font installed successfully!"
    log_info "Font is now available in applications as '0xProtoNerdFont' or similar"
    
    # Show available font variants
    log_info "Available 0xProto font variants:"
    sudo -u "$TARGET_USER" fc-list | grep -i "0xproto\|0x proto" | sed 's/.*: /  - /' | sort
else
    log_warning "Font installation completed, but verification failed"
    log_info "The font may still be available after a system restart"
fi

log_success "0xProto Nerd Font installation completed!"