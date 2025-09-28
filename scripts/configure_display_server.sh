#!/bin/bash
#
# Display Server Configuration Script
# Part of Ubuntu Bootstrap System
#
# Detects current display server (Wayland/X11) and provides functions
# to configure the system for optimal compatibility during deployment.
#
# Usage: source configure_display_server.sh
#        detect_display_server
#        configure_x11_if_needed
#

set -euo pipefail;

# Colors for output
if [[ -z "${RED:-}" ]]; then readonly RED='\033[0;31m'; fi;
if [[ -z "${GREEN:-}" ]]; then readonly GREEN='\033[0;32m'; fi;
if [[ -z "${YELLOW:-}" ]]; then readonly YELLOW='\033[1;33m'; fi;
if [[ -z "${BLUE:-}" ]]; then readonly BLUE='\033[0;34m'; fi;
if [[ -z "${NC:-}" ]]; then readonly NC='\033[0m'; fi;

# Logging functions
log_info() { echo -e "${BLUE}[DISPLAY]${NC} $1"; };
log_success() { echo -e "${GREEN}[DISPLAY]${NC} $1"; };
log_warning() { echo -e "${YELLOW}[DISPLAY]${NC} $1"; };
log_error() { echo -e "${RED}[DISPLAY]${NC} $1"; };

# Detect current display server
detect_display_server() {
    log_info "🖥️  Detecting current display server...";
    
    # Check XDG_SESSION_TYPE first (most reliable)
    if [[ -n "${XDG_SESSION_TYPE:-}" ]]; then
        case "${XDG_SESSION_TYPE,,}" in
            "wayland")
                echo "wayland";
                log_info "Current display server: Wayland (via XDG_SESSION_TYPE)";
                return 0;
                ;;
            "x11")
                echo "x11";
                log_info "Current display server: X11 (via XDG_SESSION_TYPE)";
                return 0;
                ;;
        esac;
    fi;
    
    # Check WAYLAND_DISPLAY environment variable
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        echo "wayland";
        log_info "Current display server: Wayland (via WAYLAND_DISPLAY)";
        return 0;
    fi;
    
    # Check DISPLAY environment variable
    if [[ -n "${DISPLAY:-}" ]]; then
        echo "x11";
        log_info "Current display server: X11 (via DISPLAY)";
        return 0;
    fi;
    
    # Check running processes
    if pgrep -x "Xorg" >/dev/null 2>&1; then
        echo "x11";
        log_info "Current display server: X11 (via running Xorg process)";
        return 0;
    fi;
    
    if pgrep -f "wayland" >/dev/null 2>&1; then
        echo "wayland";
        log_info "Current display server: Wayland (via running wayland process)";
        return 0;
    fi;
    
    # Check GDM configuration as fallback
    if [[ -f "/etc/gdm3/custom.conf" ]]; then
        if grep -q "^WaylandEnable=false" /etc/gdm3/custom.conf 2>/dev/null; then
            echo "x11";
            log_info "Current display server: X11 (via GDM config)";
            return 0;
        fi;
    fi;
    
    # Default assumption for modern Ubuntu
    echo "wayland";
    log_warning "Could not definitively detect display server, assuming Wayland";
    return 0;
};

# Check if X11 packages are installed
check_x11_packages() {
    log_info "Checking X11 package availability...";
    
    local missing_packages=();
    local required_packages=("xserver-xorg-core" "xserver-xorg" "gdm3");
    
    for package in "${required_packages[@]}"; do
        if ! dpkg -l "$package" 2>/dev/null | grep -q '^ii'; then
            missing_packages+=("$package");
        fi;
    done;
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_warning "Missing X11 packages: ${missing_packages[*]}";
        return 1;
    fi;
    
    log_success "All required X11 packages are installed";
    return 0;
};

# Configure system to use X11 (without immediate restart)
configure_x11() {
    log_info "🔧 Configuring system to use X11...";
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This function must be run with sudo privileges";
        return 1;
    fi;
    
    local target_user="${SUDO_USER:-$USER}";
    local user_home="/home/$target_user";
    
    # Create backup of current GDM config
    if [[ -f "/etc/gdm3/custom.conf" ]]; then
        log_info "Creating backup of GDM configuration...";
        cp "/etc/gdm3/custom.conf" "/etc/gdm3/custom.conf.backup.$(date +%Y%m%d-%H%M%S)";
    fi;
    
    # Disable Wayland in GDM
    log_info "Configuring GDM to disable Wayland...";
    
    # Ensure custom.conf exists
    if [[ ! -f "/etc/gdm3/custom.conf" ]]; then
        cat > "/etc/gdm3/custom.conf" << 'EOF'
# GDM configuration storage
[daemon]
# Uncomment the line below to force the login screen to use Xorg
#WaylandEnable=false

[security]

[xdmcp]

[chooser]

[debug]
EOF
    fi;
    
    # Set WaylandEnable=false
    if grep -q "^WaylandEnable=" "/etc/gdm3/custom.conf"; then
        sed -i 's/^WaylandEnable=.*/WaylandEnable=false/' "/etc/gdm3/custom.conf";
    elif grep -q "^#WaylandEnable=false" "/etc/gdm3/custom.conf"; then
        sed -i 's/^#WaylandEnable=false/WaylandEnable=false/' "/etc/gdm3/custom.conf";
    else
        # Add under [daemon] section
        sed -i '/^\[daemon\]/a WaylandEnable=false' "/etc/gdm3/custom.conf";
    fi;
    
    # Set default session preference for user
    log_info "Setting user session preference to X11...";
    
    if [[ -n "$target_user" && "$target_user" != "root" ]]; then
        # Create .dmrc file for session preference
        cat > "$user_home/.dmrc" << 'EOF'
[Desktop]
Session=ubuntu
EOF
        chown "$target_user:$target_user" "$user_home/.dmrc";
        
        # Remove any conflicting Wayland environment variables
        log_info "Cleaning Wayland-specific environment variables...";
        sed -i '/XDG_SESSION_TYPE=wayland/d' /etc/environment 2>/dev/null || true;
        sed -i '/GDK_BACKEND=wayland/d' /etc/environment 2>/dev/null || true;
        sed -i '/QT_QPA_PLATFORM=wayland/d' /etc/environment 2>/dev/null || true;
    fi;
    
    # Ensure X11 packages are installed
    if ! check_x11_packages; then
        log_info "Installing missing X11 packages...";
        apt update -qq;
        apt install -y xserver-xorg-core xserver-xorg gdm3;
    fi;
    
    log_success "X11 configuration completed";
    log_warning "⚠️  Changes will take effect after next reboot";
    log_info "To verify after reboot, run: echo \$XDG_SESSION_TYPE (should show 'x11')";
    
    return 0;
};

# Main configuration function that checks and configures if needed
configure_display_server_if_needed() {
    log_info "🖥️  Checking display server configuration...";
    
    local current_server;
    # Use quiet detection to avoid duplicate log output
    if [[ -n "${XDG_SESSION_TYPE:-}" ]]; then
        case "${XDG_SESSION_TYPE,,}" in
            "wayland")
                current_server="wayland";
                ;;
            "x11")
                current_server="x11";
                ;;
            *)
                current_server=$( detect_display_server );
                ;;
        esac;
    else
        current_server=$( detect_display_server );
    fi;
    
    case "$current_server" in
        "x11")
            log_success "System is already configured for X11";
            return 0;
            ;;
        "wayland")
            log_info "System is currently using Wayland";
            
            # Check if we should configure X11
            if [[ "${FORCE_X11:-}" == "true" ]] || [[ "${1:-}" == "--force-x11" ]]; then
                log_info "Configuring system to use X11...";
                configure_x11;
                return $?;
            else
                log_info "Wayland detected but no forced X11 configuration requested";
                log_info "To force X11 configuration, set FORCE_X11=true or pass --force-x11";
                return 0;
            fi;
            ;;
        *)
            log_warning "Unknown display server state: $current_server";
            return 1;
            ;;
    esac;
};

# Function to display current display server information
show_display_info() {
    echo;
    log_info "=== Display Server Information ===";
    
    local current_server;
    current_server=$( detect_display_server );
    
    echo "Current Display Server: $current_server";
    
    if [[ -n "${XDG_SESSION_TYPE:-}" ]]; then
        echo "XDG_SESSION_TYPE: $XDG_SESSION_TYPE";
    fi;
    
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        echo "WAYLAND_DISPLAY: $WAYLAND_DISPLAY";
    fi;
    
    if [[ -n "${DISPLAY:-}" ]]; then
        echo "DISPLAY: $DISPLAY";
    fi;
    
    # Check GDM configuration
    if [[ -f "/etc/gdm3/custom.conf" ]]; then
        echo;
        echo "GDM Configuration:";
        if grep -q "^WaylandEnable=false" "/etc/gdm3/custom.conf" 2>/dev/null; then
            echo "  WaylandEnable=false (X11 forced)";
        elif grep -q "^WaylandEnable=true" "/etc/gdm3/custom.conf" 2>/dev/null; then
            echo "  WaylandEnable=true (Wayland preferred)";
        else
            echo "  WaylandEnable not explicitly set (default behavior)";
        fi;
    fi;
    
    # Check running display processes
    echo;
    echo "Running Display Processes:";
    if pgrep -x "Xorg" >/dev/null 2>&1; then
        echo "  ✅ Xorg is running";
    else
        echo "  ❌ Xorg is not running";
    fi;
    
    if pgrep -f "wayland" >/dev/null 2>&1; then
        echo "  ✅ Wayland processes detected";
    else
        echo "  ❌ No Wayland processes detected";
    fi;
    
    echo;
};

# If script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-info}" in
        "detect")
            detect_display_server;
            ;;
        "configure-x11")
            configure_x11;
            ;;
        "check")
            configure_display_server_if_needed "${2:-}";
            ;;
        "info"|*)
            show_display_info;
            ;;
    esac;
fi;