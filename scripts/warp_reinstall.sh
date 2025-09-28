#!/bin/bash

# =============================================================================
# Warp Terminal Preview Reinstallation Script
# =============================================================================
# 
# This script completely uninstalls Warp Terminal Preview, clears all local
# cache and configuration files, and then reinstalls it from the official
# repository.
# 
# What this script does:
# 1. Uninstalls warp-terminal-preview package
# 2. Removes ~/.config/warp-terminal-preview directory
# 3. Removes ~/.cache/warp-terminal-preview directory  
# 4. Ensures Warp repository is configured
# 5. Reinstalls warp-terminal-preview
#
# Usage: ./warp_reinstall.sh
# 
# Created: $(date +%Y-%m-%d)
# =============================================================================

# Set strict error handling
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Function to ask for user confirmation
confirm() {
    local message="$1"
    local response
    
    echo -e "${YELLOW}$message (y/N): ${NC}"
    read -r response
    
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Cleanup function for script exit
cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Script failed. Check the error messages above."
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# =============================================================================
# MAIN SCRIPT EXECUTION
# =============================================================================

log_info "Starting Warp Terminal Preview reinstallation process..."
echo

# =============================================================================
# Step 1: Uninstall existing package
# =============================================================================

log_info "Step 1: Checking for existing Warp Terminal Preview installation..."

# Check if warp-terminal-preview is installed
if dpkg -l | grep -q "warp-terminal-preview"; then
    INSTALLED_VERSION=$( dpkg -l | grep "warp-terminal-preview" | awk '{print $3}' )
    log_warning "Found warp-terminal-preview version: $INSTALLED_VERSION"
    
    if confirm "Do you want to uninstall warp-terminal-preview?"; then
        log_info "Uninstalling warp-terminal-preview..."
        
        # Kill any running warp processes first
        if pgrep -f "warp-terminal" > /dev/null; then
            log_warning "Terminating running Warp processes..."
            pkill -f "warp-terminal" || true
            sleep 2
        fi
        
        # Uninstall with purge to remove config files
        sudo apt remove --purge warp-terminal-preview -y
        
        if ! dpkg -l | grep -q "warp-terminal-preview"; then
            log_success "Successfully uninstalled warp-terminal-preview"
        else
            log_error "Failed to uninstall warp-terminal-preview"
            exit 1
        fi
    else
        log_warning "Skipping uninstallation. Script will continue with cleanup and reinstallation."
    fi
else
    log_info "warp-terminal-preview is not currently installed"
fi

echo

# =============================================================================
# Step 2: Clean up configuration files
# =============================================================================

log_info "Step 2: Cleaning up configuration files..."

CONFIG_DIR="$HOME/.config/warp-terminal-preview"

if [ -d "$CONFIG_DIR" ]; then
    CONFIG_SIZE=$( du -sh "$CONFIG_DIR" 2>/dev/null | cut -f1 )
    log_warning "Found configuration directory: $CONFIG_DIR ($CONFIG_SIZE)"
    
    if confirm "Do you want to remove the configuration directory?"; then
        log_info "Removing configuration directory..."
        rm -rf "$CONFIG_DIR"
        
        if [ ! -d "$CONFIG_DIR" ]; then
            log_success "Successfully removed configuration directory"
        else
            log_error "Failed to remove configuration directory"
            exit 1
        fi
    else
        log_warning "Skipping configuration directory removal"
    fi
else
    log_info "No configuration directory found at $CONFIG_DIR"
fi

echo

# =============================================================================
# Step 3: Clean up cache files
# =============================================================================

log_info "Step 3: Cleaning up cache files..."

CACHE_DIR="$HOME/.cache/warp-terminal-preview"

if [ -d "$CACHE_DIR" ]; then
    CACHE_SIZE=$( du -sh "$CACHE_DIR" 2>/dev/null | cut -f1 )
    log_warning "Found cache directory: $CACHE_DIR ($CACHE_SIZE)"
    
    if confirm "Do you want to remove the cache directory?"; then
        log_info "Removing cache directory..."
        rm -rf "$CACHE_DIR"
        
        if [ ! -d "$CACHE_DIR" ]; then
            log_success "Successfully removed cache directory"
        else
            log_error "Failed to remove cache directory"
            exit 1
        fi
    else
        log_warning "Skipping cache directory removal"
    fi
else
    log_info "No cache directory found at $CACHE_DIR"
fi

echo

# =============================================================================
# Step 4: Ensure Warp repository is configured
# =============================================================================

log_info "Step 4: Checking Warp repository configuration..."

# Check if Warp repository is already configured
WARP_REPO_FILE="/etc/apt/sources.list.d/warp.list"
WARP_GPG_KEY="/usr/share/keyrings/warp.gpg"

if [ ! -f "$WARP_REPO_FILE" ] || [ ! -f "$WARP_GPG_KEY" ]; then
    log_warning "Warp repository not found or incomplete. Setting up repository..."
    
    # Download and install GPG key
    log_info "Adding Warp GPG key..."
    curl -fsSL https://releases.warp.dev/linux/keys/warp.asc | \
        sudo gpg --dearmor -o "$WARP_GPG_KEY"
    
    # Add repository
    log_info "Adding Warp repository..."
    echo "deb [arch=amd64 signed-by=$WARP_GPG_KEY] https://releases.warp.dev/linux/deb preview main" | \
        sudo tee "$WARP_REPO_FILE" > /dev/null
    
    log_success "Warp repository configured successfully"
else
    log_info "Warp repository is already configured"
fi

# Update package lists
log_info "Updating package lists..."
sudo apt update

if [ $? -eq 0 ]; then
    log_success "Package lists updated successfully"
else
    log_error "Failed to update package lists"
    exit 1
fi

echo

# =============================================================================
# Step 5: Reinstall Warp Terminal Preview
# =============================================================================

log_info "Step 5: Installing Warp Terminal Preview..."

# Install warp-terminal-preview
log_info "Installing warp-terminal-preview package..."
sudo apt install warp-terminal-preview -y

if [ $? -eq 0 ]; then
    # Verify installation
    if dpkg -l | grep -q "warp-terminal-preview"; then
        NEW_VERSION=$( dpkg -l | grep "warp-terminal-preview" | awk '{print $3}' )
        log_success "Successfully installed warp-terminal-preview version: $NEW_VERSION"
    else
        log_error "Installation reported success but package not found"
        exit 1
    fi
else
    log_error "Failed to install warp-terminal-preview"
    exit 1
fi

echo

# =============================================================================
# COMPLETION SUMMARY
# =============================================================================

log_info "=== Warp Terminal Preview Reinstallation Complete ==="
echo
log_success "✓ Process completed successfully!"
echo
log_info "Summary of actions performed:"
echo "  • Checked and uninstalled existing warp-terminal-preview package"
echo "  • Cleaned up configuration files from ~/.config/warp-terminal-preview"
echo "  • Cleaned up cache files from ~/.cache/warp-terminal-preview"
echo "  • Ensured Warp repository configuration is present"
echo "  • Updated package lists"
echo "  • Reinstalled warp-terminal-preview from official repository"
echo
log_info "You can now launch Warp Terminal Preview with the command:"
echo "  warp-terminal"
echo
log_info "Or find it in your applications menu."
echo
