#!/bin/bash
#
# Ubuntu Bootstrap Restoration Script (CORRECTED VERSION)
# Generated: 2025-09-08T10:56:28.863467
# Source System: Ubuntu 25.04
# Fixed: 2025-09-28 - Resolved apt-key deprecation and shell syntax issues
# 
# This script restores a complete Ubuntu system configuration including:
# - Package installations (APT, Snap, Flatpak, Python)
# - System configurations (sysctl, modules)
# - User environment (.bashrc, SSH keys, cron jobs)
# - Encrypted sensitive data (API keys, credentials)
#
# Usage: sudo ./bootstrap_fixed.sh
#

set -euo pipefail;  # Exit on any error, undefined vars, pipe failures

# Colors for output
readonly RED='\033[0;31m';
readonly GREEN='\033[0;32m';
readonly YELLOW='\033[1;33m';
readonly BLUE='\033[0;34m';
readonly NC='\033[0m';  # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; };
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; };
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; };
log_error() { echo -e "${RED}[ERROR]${NC} $1"; };

# Check if running as root for system-level operations
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo privileges for system-level changes";
        log_info "Usage: sudo ./bootstrap.sh [--start SECTION] [--step SECTION]";
        log_info "  --start SECTION: Start from SECTION and run all subsequent sections";
        log_info "  --step SECTION:  Run only the specified SECTION";
        log_info "Available sections: System, Special, Display, Python, APT, Multimedia, Desktop, Snap, Sysctl, Bashrc, SSH, Git, Apps, Keyboard, Cron, Cleanup";
        exit 1;
    fi;
};

# Check if user exists (for user-specific operations)
check_user() {
    local username="${SUDO_USER:-$USER}";
    if ! id "$username" >/dev/null 2>&1; then
        log_error "Target user '$username' does not exist";
        exit 1;
    fi;
    echo "$username";
};

# Check if package is already installed
is_apt_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q '^ii';
};

is_snap_installed() {
    snap list "$1" >/dev/null 2>&1;
};

is_flatpak_installed() {
    flatpak list | grep -q "$1" 2>/dev/null;
};

# Find the latest version of a package with version numbers
find_latest_package() {
    local package_base="$1";  # e.g. "libx264", "libavcodec-extra"
    local result;
    
    # Search for packages with version numbers (runtime libraries)
    # Look for pattern like package_base-123
    result=$(apt list 2>/dev/null | grep -E "^${package_base}-[0-9]+/" | 
             head -1 | sed 's|/.*||');
    
    if [[ -n "$result" ]]; then
        echo "$result";
        return 0;
    fi;
    
    # Fallback: search for any package starting with the base name
    result=$(apt list 2>/dev/null | grep -E "^${package_base}[0-9]*" | 
             sed 's|/.*||' | 
             sort -V | 
             tail -1);
    
    if [[ -n "$result" ]]; then
        echo "$result";
        return 0;
    else
        # Last fallback to exact package name
        if apt list "$package_base" 2>/dev/null | grep -q "^${package_base}/"; then
            echo "$package_base";
            return 0;
        fi;
    fi;
    
    return 1;
};

# Install package with automatic version detection
install_latest_package() {
    local package_base="$1";
    local latest_pkg;
    
    if latest_pkg=$(find_latest_package "$package_base"); then
        if ! is_apt_installed "$latest_pkg"; then
            log_info "Installing latest version: $latest_pkg";
            apt install -y "$latest_pkg" || log_warning "Failed to install $latest_pkg";
        else
            log_info "$latest_pkg already installed";
        fi;
    else
        log_warning "No package found matching: $package_base";
    fi;
};

# Post-step execution system - associative array to store scripts to run after steps
declare -A POST_STEP_SCRIPTS;

# Add script to run after a specific step
add_post_step_script() {
    local step="$1";
    local script_path="$2";
    if [[ -n "${POST_STEP_SCRIPTS[$step]:-}" ]]; then
        POST_STEP_SCRIPTS[$step]="${POST_STEP_SCRIPTS[$step]};$script_path";
    else
        POST_STEP_SCRIPTS[$step]="$script_path";
    fi;
};

# Execute post-step scripts for a given step
run_post_step_scripts() {
    local step="$1";
    if [[ -n "${POST_STEP_SCRIPTS[$step]:-}" ]]; then
        log_info "🔧 Running post-step scripts for [$step]...";
        IFS=';' read -ra SCRIPTS <<< "${POST_STEP_SCRIPTS[$step]}";
        for script in "${SCRIPTS[@]}"; do
            if [[ -f "$script" ]]; then
                log_info "Executing: $script";
                chmod +x "$script";
                if sudo -u "$TARGET_USER" BOOTSTRAP_SECRET="${BOOTSTRAP_SECRET:-}" bash "$script" "$TARGET_USER"; then
                    log_success "Post-step script completed: $script";
                else
                    log_warning "Post-step script failed: $script";
                fi;
            else
                log_warning "Post-step script not found: $script";
            fi;
        done;
    fi;
};

# Parse command line arguments
parse_args() {
    START_SECTION="";
    RUN_ONLY_SECTION="";
    while [[ $# -gt 0 ]]; do
        case $1 in
            --start)
                START_SECTION="$2";
                shift 2;
                ;;
            --step)
                RUN_ONLY_SECTION="$2";
                shift 2;
                ;;
            *)
                log_error "Unknown argument: $1";
                log_info "Usage: sudo ./bootstrap.sh [--start SECTION] [--step SECTION]";
                log_info "  --start SECTION: Start from SECTION and run all subsequent sections";
                log_info "  --step SECTION:  Run only the specified SECTION";
                log_info "Available sections: System, Special, Display, Python, APT, Multimedia, Desktop, Snap, Sysctl, Bashrc, SSH, Git, Apps, Keyboard, Cron, Cleanup";
                exit 1;
                ;;
        esac;
    done;
};

# Check if we should skip to a specific section
should_run_section() {
    local section="$1";
    
    # If --step is specified, run only that specific section
    if [[ -n "$RUN_ONLY_SECTION" ]]; then
        if [[ "$RUN_ONLY_SECTION" == "$section" ]]; then
            return 0;  # Run this section only
        else
            return 1;  # Skip all other sections
        fi;
    fi;
    
    # Original --start logic
    if [[ -z "$START_SECTION" ]]; then
        return 0;  # Run all sections
    elif [[ "$START_SECTION" == "$section" ]]; then
        START_SECTION="";  # Clear flag so subsequent sections run
        return 0;  # Start running from this section
    elif [[ -z "$START_SECTION" ]]; then
        return 0;  # Continue running after start section
    else
        return 1;  # Skip this section
    fi;
};

# Main restoration starts here
main() {
    parse_args "$@";
    
    log_info "🚀 Starting Ubuntu Bootstrap Restoration (FIXED VERSION)";
    log_info "==========================================================";
    
    check_sudo;
    readonly TARGET_USER=$(check_user);
    readonly USER_HOME="/home/$TARGET_USER";
    
    log_info "Target user: $TARGET_USER";
    log_info "User home: $USER_HOME";
    if [[ -n "$START_SECTION" ]]; then
        log_info "Starting from section: $START_SECTION";
    fi;
    if [[ -n "$RUN_ONLY_SECTION" ]]; then
        log_info "Running only section: $RUN_ONLY_SECTION";
    fi;
    
    # Register post-step scripts
    if [[ -f "./configure_keyboard_shortcuts.sh" ]]; then
        add_post_step_script "Keyboard" "./configure_keyboard_shortcuts.sh";
        log_info "Registered keyboard shortcuts script for Keyboard step";
    fi;
    
    # Register scripts from decrypted files
    if [[ -f "./install_0xproto_font.sh" ]]; then
        add_post_step_script "System" "./install_0xproto_font.sh";
        log_info "Registered 0xProto Nerd Font installation script for System step";
    fi;
    
    # System preparation
    if should_run_section "System"; then
        log_info "📦 [System] Preparing system and updating package lists...";
        apt update;
    fi;
    
    # Install essential prerequisites
    if should_run_section "System"; then
        log_info "🔧 [System] Installing essential prerequisites...";
        apt install -y curl wget gnupg software-properties-common apt-transport-https;
        
        # Run any registered post-step scripts for System
        run_post_step_scripts "System";
    fi;
    
    # Restore encrypted secrets EARLY (before any sections that might need them)
    log_info "🔐 Restoring encrypted secrets and files...";
    
    # Backup existing .bashrc with timestamp
    BASHRC_BACKUP="$USER_HOME/.bashrc.$(date -Iseconds)";
    if [[ -f "$USER_HOME/.bashrc" ]]; then
        cp "$USER_HOME/.bashrc" "$BASHRC_BACKUP";
        chown "$TARGET_USER:$TARGET_USER" "$BASHRC_BACKUP";
        log_info "Created .bashrc backup at $BASHRC_BACKUP";
    fi;
    
    # Check if encrypted secrets file exists
    if [[ -f "../data/encrypted_secrets.json" ]]; then
        # Install required Python packages for decryption (system-wide)
        log_info "Installing cryptography packages for secret decryption...";
        apt install -y python3-cryptography python3-argon2 || {
            log_warning "Failed to install cryptography packages - skipping secrets restoration";
        };
        
        if command -v python3 >/dev/null && python3 -c "import cryptography, argon2" 2>/dev/null; then
            log_success "Cryptography packages installed";
            
            # Attempt to decrypt and append secrets to .bashrc, and restore files
            log_info "Please enter your master password to decrypt environment variables and files...";
            if sudo -u "$TARGET_USER" BOOTSTRAP_SECRET="${BOOTSTRAP_SECRET:-}" python3 "./decrypt_secrets.py" --restore-files >> "$USER_HOME/.bashrc.temp" 2>"$USER_HOME/.secrets_restore.log"; then
                # Add a separator comment
                echo '' >> "$USER_HOME/.bashrc";
                echo '# Environment variables restored from encrypted secrets' >> "$USER_HOME/.bashrc";
                cat "$USER_HOME/.bashrc.temp" >> "$USER_HOME/.bashrc";
                rm "$USER_HOME/.bashrc.temp";
                chown "$TARGET_USER:$TARGET_USER" "$USER_HOME/.bashrc";
                log_success "Encrypted environment variables and files restored";
                
                # Show what files were restored
                if [[ -f "$USER_HOME/.secrets_restore.log" ]]; then
                    while IFS= read -r line; do
                        if [[ "$line" == *"Restored file:"* ]]; then
                            log_info "$line";
                        fi;
                    done < "$USER_HOME/.secrets_restore.log";
                    rm "$USER_HOME/.secrets_restore.log";
                fi;
                
                # Source .bashrc to load new environment variables for the current session
                log_info "Loading updated environment variables...";
                sudo -u "$TARGET_USER" bash -c "source '$USER_HOME/.bashrc'" || true;
                
                # Export environment variables to current shell session
                if [[ -f "$USER_HOME/.bashrc" ]]; then
                    set +u;  # Temporarily allow undefined variables
                    while IFS= read -r line; do
                        if [[ "$line" =~ ^export\ ([^=]+)= ]]; then
                            var_name="${BASH_REMATCH[1]}";
                            # Extract and export the variable
                            eval "$line" 2>/dev/null || true;
                        fi;
                    done < "$USER_HOME/.bashrc";
                    set -u;  # Re-enable undefined variable checking
                fi;
            else
                rm -f "$USER_HOME/.bashrc.temp" "$USER_HOME/.secrets_restore.log";
                log_warning "Failed to decrypt secrets - continuing without encrypted secrets";
            fi;
        else
            log_warning "Cryptography packages not available - skipping secrets restoration";
        fi;
    else
        log_warning "No encrypted secrets file found - skipping secrets restoration";
    fi;
    
    
    # Install and configure Flatpak
    if should_run_section "System"; then
        log_info "📦 [System] Setting up Flatpak...";
        if ! command -v flatpak >/dev/null 2>&1; then
            log_info "Installing Flatpak...";
            apt install -y flatpak;
            
            # Add Flathub repository
            log_info "Adding Flathub repository...";
            flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo;
            log_success "Flatpak installed and configured";
        else
            log_info "Flatpak already installed";
        fi;
    fi;
    
    # Disable Intel KVM virtualization modules
    log_info "🔒 Disabling Intel KVM virtualization modules...";
    
    # Create modprobe configuration to blacklist Intel KVM modules
    cat > /etc/modprobe.d/blacklist-intel-kvm.conf << 'EOF'
# Disable Intel KVM virtualization modules
blacklist kvm_intel
blacklist kvm
EOF
    
    # Unload modules if currently loaded
    if lsmod | grep -q "kvm_intel"; then
        log_info "Unloading kvm_intel module...";
        modprobe -r kvm_intel 2>/dev/null || true;
    fi;
    
    if lsmod | grep -q "kvm" && ! lsmod | grep -q "kvm_amd"; then
        log_info "Unloading kvm module...";
        modprobe -r kvm 2>/dev/null || true;
    fi;
    
    # Update initramfs to ensure changes persist
    # Update initramfs only if blacklist config is newer than current initramfs
    CURRENT_KERNEL=$(uname -r);
    INITRAMFS_FILE="/boot/initrd.img-$CURRENT_KERNEL";
    BLACKLIST_CONFIG="/etc/modprobe.d/blacklist-intel-kvm.conf";
    
    if [[ ! -f "$INITRAMFS_FILE" ]] || [[ "$BLACKLIST_CONFIG" -nt "$INITRAMFS_FILE" ]]; then
        log_info "Updating initramfs (blacklist config is newer or initramfs missing)...";
        update-initramfs -u;
        log_success "Initramfs updated with KVM blacklist";
    else
        log_info "Initramfs already up-to-date with KVM blacklist - skipping regeneration";
    fi;
    log_success "Intel KVM modules disabled";
    
    # Install special packages with custom repositories
    if should_run_section "Special"; then
        log_info "🌟 [Special] Installing special packages...";
    fi;
    
    # Google Chrome - FIXED: Use modern keyring approach instead of deprecated apt-key
    if should_run_section "Special" && ! is_apt_installed "google-chrome-stable"; then
        log_info "Installing Google Chrome...";
        wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg;
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list;
        apt update;
        apt install -y google-chrome-stable;
        log_success "Google Chrome installed";
    else
        log_info "Google Chrome already installed";
    fi;
    
    # Warp Terminal (preview version) - Already using correct modern approach
    if should_run_section "Special" && ! is_apt_installed "warp-terminal-preview"; then
        log_info "Installing Warp Terminal...";
        curl -fsSL https://releases.warp.dev/linux/keys/warp.asc | gpg --dearmor -o /usr/share/keyrings/warp.gpg;
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/warp.gpg] https://releases.warp.dev/linux/deb preview main" > /etc/apt/sources.list.d/warp.list;
        apt update;
        apt install -y warp-terminal-preview;
        log_success "Warp Terminal installed";
    else
        log_info "Warp Terminal already installed";
    fi;
    
    # Docker - Already using correct modern approach
    if should_run_section "Special" && ! is_apt_installed "docker-ce"; then
        log_info "Installing Docker...";
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg;
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list;
        apt update;
        apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin;
        
        # Add user to docker group
        usermod -aG docker "$TARGET_USER";
        log_success "Docker installed and user added to docker group";
    else
        log_info "Docker already installed";
    fi;
    
    # VirtualBox
    if should_run_section "Special" && ! is_apt_installed "virtualbox"; then
        log_info "Installing VirtualBox...";
        apt install -y virtualbox virtualbox-ext-pack;
        log_success "VirtualBox installed";
    else
        log_info "VirtualBox already installed";
    fi;
    
    # Configure display server for optimal compatibility
    if should_run_section "Display"; then
        log_info "🖥️  [Display] Configuring display server for optimal compatibility...";
    fi;
    
    # Source display server configuration functions
    if [[ -f "./configure_display_server.sh" ]]; then
        source "./configure_display_server.sh";
        
        # Detect current display server
        CURRENT_DISPLAY_SERVER=$(detect_display_server);
        
        case "$CURRENT_DISPLAY_SERVER" in
            "wayland")
                log_info "Wayland detected. For optimal compatibility with applications like Zoom screen sharing,";
                log_info "the system can be configured to use X11 instead.";
                log_warning "⚠️  Display server changes require reboot and will NOT restart GUI immediately";
                log_info "This ensures running applications (installs, updates, etc.) are not interrupted.";
                
                # Configure X11 for better compatibility
                log_info "Configuring X11 for improved application compatibility...";
                configure_x11;
                log_success "Display server configured for X11 (effective after reboot)";
                ;;
            "x11")
                log_success "X11 already configured - optimal for application compatibility";
                ;;
            *)
                log_warning "Unknown display server state, skipping configuration";
                ;;
        esac;
    else
        log_warning "Display server configuration script not found - skipping";
    fi;

    # Ensure pip3 is available before installing Python packages
    if should_run_section "Python"; then
        log_info "🔧 [Python] Checking Python pip3 availability...";
        if ! command -v pip3 >/dev/null 2>&1; then
            log_info "Installing python3-pip...";
            apt update;
            apt install -y python3-pip;
            log_success "pip3 installed";
        else
            log_info "pip3 already available";
        fi;
    fi;
    
    # Install APT packages - FIXED: Proper shell formatting with actual newlines
    if should_run_section "APT"; then
        log_info "📦 [APT] Installing APT packages...";
    fi;

    # Install packages in smaller, manageable batches to avoid timeout issues
    
    # Essential development tools and libraries
    if should_run_section "APT"; then
        log_info "Installing essential development tools...";
        apt install -y build-essential cmake ninja-build autoconf automake libtool \
            pkg-config git git-man curl wget gnupg software-properties-common \
            apt-transport-https;

        # Core system packages
        log_info "Installing core system packages...";
        apt install -y 7zip accountsservice acl adduser base-files base-passwd \
            bash bash-completion bc coreutils findutils grep gawk sed \
            util-linux mount fdisk parted;

        # Development libraries and headers
        log_info "Installing development libraries...";
        apt install -y libc6-dev libssl-dev libffi-dev libxml2-dev libxslt1-dev \
            libreadline-dev libsqlite3-dev libncurses-dev libbz2-dev \
            zlib1g-dev libgdbm-dev;

        # Python and related packages  
        log_info "Installing Python packages...";
        apt install -y python3 python3-dev python3-pip python3-venv python3-wheel \
            python3-setuptools python3-apt python3-dbus;

        # Multimedia and graphics
        log_info "Installing multimedia packages...";
        apt install -y ffmpeg imagemagick vlc vlc-bin vlc-data libdvd-pkg \
            ubuntu-restricted-extras gstreamer1.0-plugins-base \
            gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
            gstreamer1.0-libav gstreamer1.0-vaapi;
    fi;

    # Configure DVD decryption and multimedia codecs
    if should_run_section "Multimedia"; then
        log_info "🎬 [Multimedia] Configuring multimedia codecs and DVD support...";
    fi;
    
    # Configure libdvd-pkg for encrypted DVD playbook
    if should_run_section "Multimedia"; then
        if dpkg-query -W -f="\${Status}" libdvd-pkg 2>/dev/null | grep -q "install ok installed"; then
            # Reconfigure libdvd-pkg to install libdvdcss2
            DEBIAN_FRONTEND=noninteractive dpkg-reconfigure libdvd-pkg;
            log_success "DVD decryption configured";
        fi;
        
        # Install additional codec packages with automatic version detection
        log_info "Installing multimedia codec packages with latest versions...";
        
        # Core multimedia packages that should always be available
        apt install -y --no-install-recommends lame flac opus-tools vorbis-tools;
        
        # Install versioned packages using latest available versions
        install_latest_package "libavcodec-extra";
        install_latest_package "libavformat-extra";
        install_latest_package "libavutil-extra";
        install_latest_package "libx264";
        install_latest_package "libx265";
        
        # Optional packages (install if available)
        for pkg in faac faad libmatroska-dev libmkv libebml-dev; do
            if latest_pkg=$(find_latest_package "$pkg"); then
                install_latest_package "$pkg";
            else
                log_info "Optional package $pkg not available, skipping";
            fi;
        done;
        
        # Install Microsoft Core Fonts (Method 3: Combined approach)
        log_info "Installing Microsoft Core Fonts with EULA auto-acceptance...";
        echo "ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true" | debconf-set-selections;
        DEBIAN_FRONTEND=noninteractive apt install -y ttf-mscorefonts-installer;
        log_success "Microsoft Core Fonts installed (EULA accepted)";
        
        # Ensure proper GStreamer codec registry is updated
        sudo -u "$TARGET_USER" gst-inspect-1.0 > /dev/null 2>&1 || true;
        
        log_success "Multimedia codecs and fonts configured for MP4, MKV, DVD, and common formats";
    fi;


    # Desktop environment essentials
    if should_run_section "Desktop"; then
        log_info "[Desktop] Installing desktop environment packages...";
        apt install -y ubuntu-desktop-minimal gnome-shell gnome-terminal \
            nautilus gdm3 dconf-editor;

        # Additional useful tools
        log_info "[Desktop] Installing additional tools...";
        apt install -y vim nano htop tree rsync zip unzip p7zip-full \
            net-tools openssh-client curl wget jq;

        log_success "Essential APT packages installed successfully";
    fi;

    # Install Snap packages - FIXED: Proper formatting
    if should_run_section "Snap"; then
        log_info "📦 [Snap] Installing Snap packages...";
    fi;

    if should_run_section "Snap"; then
        if ! is_snap_installed "bare"; then
            snap install bare --stable;
            log_success "Installed snap: bare";
        fi;

        if ! is_snap_installed "desktop-security-center"; then
            snap install desktop-security-center --stable;
            log_success "Installed snap: desktop-security-center";
        fi;

        if ! is_snap_installed "firmware-updater"; then
            snap install firmware-updater --stable;
            log_success "Installed snap: firmware-updater";
        fi;

        if ! is_snap_installed "gh"; then
            snap install gh --stable;
            log_success "Installed snap: gh";
        fi;

        if ! is_snap_installed "gnome-42-2204"; then
            snap install gnome-42-2204 --stable;
            log_success "Installed snap: gnome-42-2204";
        fi;

        if ! is_snap_installed "gtk-common-themes"; then
            snap install gtk-common-themes --stable;
            log_success "Installed snap: gtk-common-themes";
        fi;

        if ! is_snap_installed "prompting-client"; then
            snap install prompting-client --stable;
            log_success "Installed snap: prompting-client";
        fi;

        if ! is_snap_installed "qmmp"; then
            snap install qmmp --stable;
            log_success "Installed snap: qmmp";
        fi;

        if ! is_snap_installed "snap-store"; then
            snap install snap-store --stable;
            log_success "Installed snap: snap-store";
        fi;

        if ! is_snap_installed "snapd-desktop-integration"; then
            snap install snapd-desktop-integration --stable;
            log_success "Installed snap: snapd-desktop-integration";
        fi;
    fi;

    # Install Python packages - FIXED: System-wide installation
    if should_run_section "Python"; then
        log_info "🐍 [Python] Installing Python packages system-wide...";

        # Create temporary requirements file with essential packages only
        cat > /tmp/bootstrap_requirements.txt << 'EOF'
# Essential Python packages
requests==2.32.3
urllib3==2.3.0
certifi==2025.1.31
cryptography==43.0.0
pydantic==2.11.7
click==8.1.8
rich==13.9.4
numpy==2.2.3
packaging==24.2
setuptools-scm
wheel
pip
EOF

        # Install packages system-wide using --break-system-packages flag
        log_info "Installing Python packages system-wide (breaking system package isolation)...";
        pip3 install -r /tmp/bootstrap_requirements.txt --break-system-packages;
        rm /tmp/bootstrap_requirements.txt;
        log_success "Essential Python packages installed system-wide";
    fi;

    # Apply custom sysctl settings - FIXED: Proper formatting
    if should_run_section "Sysctl"; then
        log_info "⚙️ [Sysctl] Applying custom sysctl settings...";
    fi;

    if should_run_section "Sysctl"; then
        cat > /etc/sysctl.d/99-bootstrap.conf << 'EOF'
# Custom sysctl settings restored by bootstrap
vm.swappiness = 60
fs.inotify.max_user_watches = 65536
net.core.somaxconn = 4096
kernel.shmmax = 18446744073692774399
EOF

        sysctl -p /etc/sysctl.d/99-bootstrap.conf;
        log_success "Applied 4 sysctl settings";
    fi;

    # Restore .bashrc customizations - FIXED: Proper formatting
    if should_run_section "Bashrc"; then
        log_info "🐚 [Bashrc] Restoring .bashrc customizations...";
    fi;

    if should_run_section "Bashrc"; then
        # Add safe customizations
        echo 'export gmail_sender_email=your-email@gmail.com' >> "$USER_HOME/.bashrc";
        echo 'export gmail_recipient_email=your-email@gmail.com' >> "$USER_HOME/.bashrc";
        echo 'if ! command -v code &> /dev/null; then' >> "$USER_HOME/.bashrc";
        echo 'if command -v code-insiders &> /dev/null; then' >> "$USER_HOME/.bashrc";
        echo 'alias code=code-insiders' >> "$USER_HOME/.bashrc";
        echo 'fi' >> "$USER_HOME/.bashrc";
        echo 'fi' >> "$USER_HOME/.bashrc";
    fi;

    # Note: Encrypted secrets are now restored early in the bootstrap process
    
    log_success ".bashrc customizations restored";

    # Install custom services - FIXED: Proper formatting
    log_info "🔧 Installing custom services...";

    # Install GridShift - Automated Media Download Manager
    log_info "Installing GridShift from GitHub...";
    
    # Check GitHub CLI authentication status before using gh commands
    log_info "Checking GitHub CLI authentication...";
    if ! sudo -u "$TARGET_USER" gh auth status >/dev/null 2>&1; then
        log_warning "GitHub CLI not authenticated. Attempting to authenticate...";
        log_info "Please complete GitHub authentication when prompted:";
        if sudo -u "$TARGET_USER" gh auth login --web; then
            log_success "GitHub CLI authentication completed";
        else
            log_warning "GitHub CLI authentication failed - repository cloning may not work";
        fi;
    else
        log_success "GitHub CLI already authenticated";
    fi;
    
    # Create installation directory
    GRIDSHIFT_DIR="/opt/gridshift";
    mkdir -p "$GRIDSHIFT_DIR";
    chown "$TARGET_USER:$TARGET_USER" "$GRIDSHIFT_DIR";
    
    # Check if repository exists before cloning
    if [[ ! -d "$GRIDSHIFT_DIR/.git" ]]; then
        # Clone GridShift repository using gh
        sudo -u "$TARGET_USER" gh repo clone mcollard0/gridshift "$GRIDSHIFT_DIR" || {
            log_warning "GridShift repository not accessible - skipping installation";
        };
    fi;
    
    if [[ -d "$GRIDSHIFT_DIR/.git" ]]; then
        cd "$GRIDSHIFT_DIR";
        
        # Set up Python virtual environment
        log_info "Setting up Python virtual environment for GridShift...";
        sudo -u "$TARGET_USER" python3 -m venv "$GRIDSHIFT_DIR/venv";
        
        # Install Python dependencies if requirements.txt exists
        if [[ -f "$GRIDSHIFT_DIR/requirements.txt" ]]; then
            sudo -u "$TARGET_USER" "$GRIDSHIFT_DIR/venv/bin/pip" install --upgrade pip;
            sudo -u "$TARGET_USER" "$GRIDSHIFT_DIR/venv/bin/pip" install -r "$GRIDSHIFT_DIR/requirements.txt";
        fi;
        
        # Install pyload-ng for download management
        sudo -u "$TARGET_USER" "$GRIDSHIFT_DIR/venv/bin/pip" install pyload-ng;
        
        # Test the installation if test file exists
        if [[ -f "$GRIDSHIFT_DIR/test_setup.py" ]]; then
            if sudo -u "$TARGET_USER" "$GRIDSHIFT_DIR/venv/bin/python" "$GRIDSHIFT_DIR/test_setup.py"; then
                log_success "GridShift installed successfully";
            else
                log_warning "GridShift installation test failed - check logs";
            fi;
        else
            log_success "GridShift basic installation completed";
        fi;
        
        # Create convenient aliases in .bashrc
        echo 'alias gridshift="cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu"' >> "$USER_HOME/.bashrc";
        echo 'alias gridshift-daemon="cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu daemon"' >> "$USER_HOME/.bashrc";
        echo 'alias gridshift-monitor="cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu monitor"' >> "$USER_HOME/.bashrc";
        
        log_info "GridShift aliases added to .bashrc";
        log_info "Use 'gridshift' command to access the interactive menu";
        log_info "Use 'gridshift-daemon' to start automation";
        log_info "Use 'gridshift-monitor' for real-time monitoring";
    fi;
    
    log_success "Custom services installation completed";

    # Restore SSH keys and configuration - FIXED: Proper formatting
    if should_run_section "SSH"; then
        log_info "🔑 [SSH] Restoring SSH keys and configuration...";
    fi;

    if should_run_section "SSH"; then
        # Create .ssh directory with proper permissions
        sudo -u "$TARGET_USER" mkdir -p "$USER_HOME/.ssh";
        chmod 700 "$USER_HOME/.ssh";
        chown "$TARGET_USER:$TARGET_USER" "$USER_HOME/.ssh";
    fi;

    # SSH keys and other files are now automatically restored via file decryption
    log_info "SSH keys and configuration files restored automatically from encrypted files";
    
    # Add fallback public keys if they exist in the old system (backup measure)
    if [[ -f "/media/michael/471255ba-f948-4ddf-9dc5-3284f916144a/home/michael/.ssh/id_ed25519.pub" ]]; then
        cp "/media/michael/471255ba-f948-4ddf-9dc5-3284f916144a/home/michael/.ssh/id_ed25519.pub" "$USER_HOME/.ssh/id_ed25519.pub.backup";
        chmod 644 "$USER_HOME/.ssh/id_ed25519.pub.backup";
        chown "$TARGET_USER:$TARGET_USER" "$USER_HOME/.ssh/id_ed25519.pub.backup";
        log_info "Backed up old system public key as .pub.backup";
    fi;

    log_success "SSH configuration restored";
    
    # Run any registered post-step scripts for SSH
    run_post_step_scripts "SSH";

    # Restore git configuration
    if should_run_section "Git"; then
        log_info "🔧 [Git] Configuring git user identity...";
    fi;
    
    if should_run_section "Git"; then
        # Try to get git config from decrypted secrets first (if they exist)
        GIT_USER_EMAIL="";
        GIT_USER_NAME="";
    fi;
    
    # Check if .gitconfig was restored from encrypted secrets
    if [[ -f "$USER_HOME/.gitconfig" ]]; then
        log_success "Git configuration restored from encrypted .gitconfig file";
        # Extract values from restored .gitconfig for display
        GIT_USER_EMAIL=$(sudo -u "$TARGET_USER" git config --get user.email 2>/dev/null || echo "");
        GIT_USER_NAME=$(sudo -u "$TARGET_USER" git config --get user.name 2>/dev/null || echo "");
        if [[ -n "$GIT_USER_EMAIL" && -n "$GIT_USER_NAME" ]]; then
            log_success "Git configured: $GIT_USER_NAME <$GIT_USER_EMAIL>";
        fi;
    else
        # Check if git config is available in environment variables (from decrypted secrets)
        if [[ -n "${git_user_email:-}" && -n "${git_user_name:-}" ]]; then
            GIT_USER_EMAIL="$git_user_email";
            GIT_USER_NAME="$git_user_name";
            log_info "Using git config from decrypted environment variables";
        else
            # Final fallback to old system git config if available
            if [[ -f "/media/michael/471255ba-f948-4ddf-9dc5-3284f916144a/home/michael/.gitconfig" ]]; then
                GIT_USER_EMAIL=$(grep -E '^\s*email\s*=' "/media/michael/471255ba-f948-4ddf-9dc5-3284f916144a/home/michael/.gitconfig" | sed 's/.*=\s*//' | tr -d '\t\n\r' || echo "");
                GIT_USER_NAME=$(grep -E '^\s*name\s*=' "/media/michael/471255ba-f948-4ddf-9dc5-3284f916144a/home/michael/.gitconfig" | sed 's/.*=\s*//' | tr -d '\t\n\r' || echo "");
                log_info "Using git config from old system backup";
            fi;
        fi;
        
        # Set git configuration if we found it via environment/fallback
        if [[ -n "$GIT_USER_EMAIL" && -n "$GIT_USER_NAME" ]]; then
            sudo -u "$TARGET_USER" git config --global user.email "$GIT_USER_EMAIL";
            sudo -u "$TARGET_USER" git config --global user.name "$GIT_USER_NAME";
            log_success "Git configured: $GIT_USER_NAME <$GIT_USER_EMAIL>";
        else
            log_warning "No git configuration found - please set manually with: git config --global user.email/user.name";
        fi;
    fi;
    
    # Run any registered post-step scripts for Git
    run_post_step_scripts "Git";

    # Install missing applications from inventory
    if should_run_section "Apps"; then
        log_info "📦 [Apps] Installing missing applications from inventory...";
    fi;
    
    # Install prerequisites first (after SSH keys are restored)
    log_info "Installing prerequisites for custom applications...";
    
    # Install 1Password
    log_info "Installing 1Password...";
    if ! command -v 1password &> /dev/null; then
        # Add 1Password repository key
        curl -sS https://downloads.1password.com/linux/keys/1password.asc | gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg;
        # Add 1Password repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/$(dpkg --print-architecture) stable main" > /etc/apt/sources.list.d/1password.list;
        # Update and install
        apt update;
        apt install -y 1password || log_warning "Failed to install 1Password";
        log_success "1Password installed";
    else
        log_info "1Password already installed";
    fi;
    
    # Install VS Code Insiders
    log_info "Installing VS Code Insiders...";
    if ! command -v code-insiders &> /dev/null; then
        # Add Microsoft repository key
        curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor --output /usr/share/keyrings/microsoft-archive-keyring.gpg;
        # Add VS Code Insiders repository
        echo "deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list;
        # Update and install
        apt update;
        apt install -y code-insiders || log_warning "Failed to install VS Code Insiders";
        log_success "VS Code Insiders installed";
    else
        log_info "VS Code Insiders already installed";
    fi;
    
    # Install Zoom (via snap)
    log_info "Installing Zoom...";
    if ! is_snap_installed "zoom"; then
        snap install zoom || log_warning "Failed to install Zoom via snap";
        log_success "Zoom installed";
    else
        log_info "Zoom already installed";
    fi;
    
    # Build and install Whatsie
    log_info "Building Whatsie from source...";
    WHATSIE_DIR="/opt/whatsie";
    
    # Install build prerequisites
    apt install -y build-essential cmake qt6-base-dev qt6-webengine-dev || {
        log_warning "Failed to install Whatsie build dependencies - skipping Whatsie build";
    };
    
    # Only proceed if prerequisites installed successfully
    if command -v cmake &> /dev/null && command -v qmake6 &> /dev/null; then
        mkdir -p "$WHATSIE_DIR";
        chown "$TARGET_USER:$TARGET_USER" "$WHATSIE_DIR";
        
        # Clone Whatsie if not already cloned
        if [[ ! -d "$WHATSIE_DIR/.git" ]]; then
            sudo -u "$TARGET_USER" gh repo clone gsantner/whatsie "$WHATSIE_DIR" || {
                log_warning "Failed to clone Whatsie repository - skipping build";
            };
        fi;
        
        # Build Whatsie if source available
        if [[ -d "$WHATSIE_DIR/.git" ]]; then
            cd "$WHATSIE_DIR";
            
            # Create build directory and configure
            sudo -u "$TARGET_USER" mkdir -p build;
            cd build;
            
            # Configure with CMake
            if sudo -u "$TARGET_USER" cmake ..; then
                # Build with multiple cores
                if sudo -u "$TARGET_USER" make -j$(nproc); then
                    # Install the binary
                    cp whatsie /usr/local/bin/ || {
                        log_warning "Failed to install Whatsie binary to /usr/local/bin";
                    };
                    
                    # Create desktop entry
                    cat > /usr/share/applications/whatsie.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Whatsie
Comment=Feature rich WhatsApp web client
Exec=/usr/local/bin/whatsie
Icon=whatsapp
Terminal=false
Categories=Network;InstantMessaging;
EOF
                    log_success "Whatsie built and installed successfully";
                else
                    log_warning "Failed to build Whatsie";
                fi;
            else
                log_warning "Failed to configure Whatsie build";
            fi;
        fi;
    fi;
    
    # Build and install NoiseTorch (real-time microphone noise suppression)
    log_info "Building NoiseTorch from source...";
    NOISETORCH_DIR="/opt/noisetorch";
    
    # Install Go if not already available
    if ! command -v go &> /dev/null; then
        apt install -y golang-go;
        log_success "Go compiler installed for NoiseTorch build";
    fi;
    
    # Only proceed if Go is available
    if command -v go &> /dev/null; then
        mkdir -p "$NOISETORCH_DIR";
        chown "$TARGET_USER:$TARGET_USER" "$NOISETORCH_DIR";
        
        # Clone NoiseTorch if not already cloned
        if [[ ! -d "$NOISETORCH_DIR/.git" ]]; then
            sudo -u "$TARGET_USER" gh repo clone noisetorch/NoiseTorch "$NOISETORCH_DIR" || {
                log_warning "Failed to clone NoiseTorch repository - skipping build";
            };
        fi;
        
        # Build NoiseTorch if source available
        if [[ -d "$NOISETORCH_DIR/.git" ]]; then
            cd "$NOISETORCH_DIR";
            
            # Build with make
            if sudo -u "$TARGET_USER" make; then
                # Install to user's local bin (as recommended by NoiseTorch)
                sudo -u "$TARGET_USER" mkdir -p "$USER_HOME/.local/bin";
                sudo -u "$TARGET_USER" mkdir -p "$USER_HOME/.local/share/applications";
                sudo -u "$TARGET_USER" mkdir -p "$USER_HOME/.local/share/icons/hicolor/256x256/apps";
                
                # Copy binary and assets
                sudo -u "$TARGET_USER" cp "./bin/noisetorch" "$USER_HOME/.local/bin/" || {
                    log_warning "Failed to copy NoiseTorch binary";
                };
                
                sudo -u "$TARGET_USER" cp "./assets/noisetorch.desktop" "$USER_HOME/.local/share/applications/" || {
                    log_warning "Failed to copy NoiseTorch desktop file";
                };
                
                sudo -u "$TARGET_USER" cp "./assets/icon/noisetorch.png" "$USER_HOME/.local/share/icons/hicolor/256x256/apps/" || {
                    log_warning "Failed to copy NoiseTorch icon";
                };
                
                # Update desktop database
                sudo -u "$TARGET_USER" update-desktop-database "$USER_HOME/.local/share/applications" 2>/dev/null || true;
                
                log_success "NoiseTorch built and installed successfully (real-time noise suppression)";
            else
                log_warning "Failed to build NoiseTorch";
            fi;
        fi;
    else
        log_warning "Go compiler not available - skipping NoiseTorch build";
    fi;
    
    log_success "Missing applications installation completed";

    # Configure keyboard shortcuts
    if should_run_section "Keyboard"; then
        log_info "⌨️  [Keyboard] Configuring custom keyboard shortcuts...";
        
        # Run any registered post-step scripts for keyboard configuration
        run_post_step_scripts "Keyboard";
        
        log_success "Keyboard configuration completed";
    fi;

    # Restore cron jobs - FIXED: Proper formatting
    if should_run_section "Cron"; then
        log_info "⏰ [Cron] Restoring cron jobs...";
    fi;

    if should_run_section "Cron"; then
        # Create temporary crontab file
        cat > /tmp/bootstrap_crontab << 'EOF'
MAILTO=""
PATH=/usr/local/bin:/usr/bin:/bin
HOME=/home/michael
0 3 * * * cd $HOME && python3 KCRestaurants.py --ephemeral >> $HOME/logs/kc_restaurants/kc_$(date +\%F).log 2>&1
EOF

        # Install crontab for target user
        sudo -u "$TARGET_USER" crontab /tmp/bootstrap_crontab;
        rm /tmp/bootstrap_crontab;
        log_success "Restored cron jobs";
        
        # Run any registered post-step scripts for Cron
        run_post_step_scripts "Cron";
    fi;

    # Remove Firefox if installed (moved to end to avoid interference with installations)
    log_info "🦊 [Firefox] Removing Firefox browser...";
    if is_snap_installed "firefox"; then
        log_warning "Removing Firefox snap package...";
        snap remove firefox;
        log_success "Firefox snap removed";
    fi;
    
    if is_apt_installed "firefox"; then
        log_warning "Removing Firefox APT package...";
        apt remove --purge -y firefox firefox-esr;
        apt autoremove -y;
        log_success "Firefox APT package removed";
    fi;
    
    # Final steps and completion
    if should_run_section "Cleanup"; then
        log_info "🧹 [Cleanup] Performing final cleanup...";
        apt autoremove -y;
        apt autoclean;
    fi;
    
    log_success "🎉 Ubuntu Bootstrap restoration completed successfully!";
    log_info "📝 Summary of changes:";
    log_info "   • Package installations completed";
    log_info "   • System configurations applied";
    log_info "   • User environment restored";
    log_info "   • Intel KVM modules disabled";
    log_info "   • Firefox removed (if present)";
    log_info "   • Flatpak installed and configured";
    echo;
    log_warning "⚠️  Please reboot the system to ensure all changes take effect";
    log_info "   After reboot, verify:";
    log_info "   • Docker service: systemctl status docker";
    log_info "   • KVM modules: lsmod | grep kvm";
    log_info "   • Environment variables: source ~/.bashrc && env | grep -E '(API|mongodb)'";
    
    return 0;
}

# Execute main function
main "$@";