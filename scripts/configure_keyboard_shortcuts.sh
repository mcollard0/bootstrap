#!/bin/bash
#
# Keyboard Shortcuts Configuration Script
# Part of the Ubuntu Bootstrap Restoration System
#
# This script configures custom keyboard shortcuts for GNOME desktop environment
# Usage: ./configure_keyboard_shortcuts.sh [username]
#

set -euo pipefail;  # Exit on any error, undefined vars, pipe failures

# Colors for output
readonly RED='\033[0;31m';
readonly GREEN='\033[0;32m';
readonly YELLOW='\033[1;33m';
readonly BLUE='\033[0;34m';
readonly NC='\033[0m';  # No Color

# Logging functions
log_info() { echo -e "${BLUE}[SHORTCUTS]${NC} $1"; };
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; };
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; };
log_error() { echo -e "${RED}[ERROR]${NC} $1"; };

# Get target user (defaults to current user or SUDO_USER)
get_target_user() {
    if [[ $# -gt 0 && -n "$1" ]]; then
        echo "$1";
    elif [[ -n "${SUDO_USER:-}" ]]; then
        echo "$SUDO_USER";
    else
        echo "$USER";
    fi;
};

# Configure keyboard shortcuts for specified user
configure_shortcuts() {
    local username="$1";
    
    log_info "Configuring keyboard shortcuts for user: $username";
    
    # Run commands as the target user using sudo
    local -r run_as_user="sudo -u $username";
    
    # Set up the custom keybinding paths (including Super+C for Diodon)
    log_info "Setting up custom keybinding paths...";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys custom-keybindings "['/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/', '/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom1/', '/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom2/']";
    
    # Configure Super+R for Run Dialog
    log_info "Configuring Super+R for Run Dialog...";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ name "Run Dialog";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ command "gnome-terminal -- bash -c 'read -p \"Command: \" cmd && eval \$cmd; read -p \"Press Enter to close...\"'";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ binding "<Super>r";
    
    # Configure Super+E for Nautilus File Manager
    log_info "Configuring Super+E for Nautilus...";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom1/ name "Nautilus File Manager";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom1/ command "nautilus";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom1/ binding "<Super>e";
    
    # Configure Super+C for Diodon Clipboard Manager
    log_info "Configuring Super+C for Diodon Clipboard Manager...";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom2/ name "Diodon Clipboard Manager";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom2/ command "diodon";
    $run_as_user gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybindings:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom2/ binding "<Super>c";
    
    # Configure screenshot keybinding: Shift+Super+S for screenshot UI
    log_info "Configuring Shift+Super+S for Screenshot UI...";
    $run_as_user gsettings set org.gnome.shell.keybindings show-screenshot-ui "['Print', '<Shift><Super>s']";
    
    # Disable window tiling keybindings (as configured in old system)
    log_info "Disabling window tiling shortcuts...";
    $run_as_user gsettings set org.gnome.mutter.keybindings toggle-tiled-left "[]";
    $run_as_user gsettings set org.gnome.mutter.keybindings toggle-tiled-right "[]";
    
    # Set edge-tiling to false (from old system config)
    $run_as_user gsettings set org.gnome.mutter edge-tiling false;
    
    log_success "Keyboard shortcuts configured successfully";
    log_info "  • Super+R: Run Dialog (terminal-based command prompt)";
    log_info "  • Super+E: Nautilus File Manager";
};

# Verify shortcuts are properly configured
verify_shortcuts() {
    local username="$1";
    local -r run_as_user="sudo -u $username";
    
    log_info "Verifying keyboard shortcuts configuration...";
    
    # Check if custom keybindings are set
    local custom_keybindings=$($run_as_user gsettings get org.gnome.settings-daemon.plugins.media-keys custom-keybindings 2>/dev/null || echo "");
    
    if [[ "$custom_keybindings" == *"custom0"* && "$custom_keybindings" == *"custom1"* ]]; then
        log_success "Custom keybinding paths verified";
        
        # Check individual shortcuts
        local super_r_name=$($run_as_user gsettings get org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ name 2>/dev/null || echo "");
        local super_e_name=$($run_as_user gsettings get org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom1/ name 2>/dev/null || echo "");
        
        if [[ "$super_r_name" == *"Run Dialog"* ]]; then
            log_success "Super+R shortcut verified";
        else
            log_warning "Super+R shortcut may not be configured correctly";
        fi;
        
        if [[ "$super_e_name" == *"Nautilus"* ]]; then
            log_success "Super+E shortcut verified";
        else
            log_warning "Super+E shortcut may not be configured correctly";
        fi;
    else
        log_warning "Custom keybinding paths not found - configuration may have failed";
        return 1;
    fi;
    
    return 0;
};

# Main function
main() {
    log_info "🔥 Starting Keyboard Shortcuts Configuration";
    log_info "=============================================";
    
    # Get target user
    local target_user=$(get_target_user "$@");
    
    # Verify user exists
    if ! id "$target_user" >/dev/null 2>&1; then
        log_error "User '$target_user' does not exist";
        exit 1;
    fi;
    
    log_info "Target user: $target_user";
    
    # Check if GNOME is available
    if ! command -v gsettings >/dev/null 2>&1; then
        log_error "gsettings command not found - GNOME desktop environment required";
        exit 1;
    fi;
    
    # Configure shortcuts
    configure_shortcuts "$target_user";
    
    # Verify configuration
    if verify_shortcuts "$target_user"; then
        log_success "🎉 Keyboard shortcuts configuration completed successfully!";
        log_info "The shortcuts will be active immediately.";
    else
        log_error "❌ Configuration verification failed";
        exit 1;
    fi;
    
    return 0;
};

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@";
fi;