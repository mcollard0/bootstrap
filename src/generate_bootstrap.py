#!/usr/bin/env python3
"""
Ubuntu Bootstrap System - Bootstrap Script Generator

This module reads the system inventory and generates a comprehensive bash script
that can restore the complete system configuration on a fresh Ubuntu installation.
Includes special handling for Intel KVM disabling and flatpak setup.
"""

import os;
import json;
import base64;
import datetime;
from pathlib import Path;
from typing import Dict, List, Any, Optional;

from crypto_utils import SecureBootstrapCrypto, prompt_for_password;


class BootstrapScriptGenerator:
    """Generate comprehensive system restoration scripts."""
    
    def __init__( self, base_dir: str = None ):
        """
        Initialize the bootstrap generator.
        
        Args:
            base_dir: Base directory for bootstrap project (auto-detect if None)
        """
        if base_dir is None:
            current_dir = Path( __file__ ).parent;
            self.base_dir = current_dir.parent;
        else:
            self.base_dir = Path( base_dir );
        
        self.data_dir = self.base_dir / 'data';
        self.scripts_dir = self.base_dir / 'scripts';
        self.scripts_dir.mkdir( exist_ok=True );
        
        self.crypto = SecureBootstrapCrypto();
        
        print( f"🔧 Bootstrap Script Generator initialized" );
        print( f"   Base directory: {self.base_dir}" );
    
    def load_inventory( self, inventory_file: str = 'inventory.json' ) -> Dict[str, Any]:
        """Load system inventory from JSON file."""
        inventory_path = self.data_dir / inventory_file;
        
        if not inventory_path.exists():
            raise FileNotFoundError( f"Inventory file not found: {inventory_path}" );
        
        with open( inventory_path, 'r' ) as f:
            inventory = json.load( f );
        
        print( f"📖 Loaded inventory from: {inventory_path}" );
        return inventory;
    
    def load_encrypted_secrets( self, secrets_file: str = 'encrypted_secrets.json' ) -> Optional[Dict[str, Any]]:
        """Load encrypted secrets if they exist."""
        secrets_path = self.data_dir / secrets_file;
        
        if not secrets_path.exists():
            print( "🔓 No encrypted secrets file found" );
            return None;
        
        with open( secrets_path, 'r' ) as f:
            encrypted_data = json.load( f );
        
        print( f"🔐 Loaded encrypted secrets from: {secrets_path}" );
        return encrypted_data;
    
    def generate_script_header( self, inventory: Dict[str, Any] ) -> str:
        """Generate bash script header with metadata."""
        timestamp = datetime.datetime.now().isoformat();
        ubuntu_version = inventory.get( 'system_info', {} ).get( 'ubuntu_version', 'unknown' );
        
        return f'''#!/bin/bash
#
# Ubuntu Bootstrap Restoration Script
# Generated: {timestamp}
# Source System: Ubuntu {ubuntu_version}
# 
# This script restores a complete Ubuntu system configuration including:
# - Package installations (APT, Snap, Flatpak, Python)
# - System configurations (sysctl, modules)
# - User environment (.bashrc, SSH keys, cron jobs)
# - Encrypted sensitive data (API keys, credentials)
#
# Usage: sudo ./bootstrap.sh
#

set -euo pipefail;  # Exit on any error, undefined vars, pipe failures

# Colors for output
readonly RED='\\033[0;31m';
readonly GREEN='\\033[0;32m';
readonly YELLOW='\\033[1;33m';
readonly BLUE='\\033[0;34m';
readonly NC='\\033[0m';  # No Color

# Logging functions
log_info() {{ echo -e "${{BLUE}}[INFO]${{NC}} $1"; }};
log_success() {{ echo -e "${{GREEN}}[SUCCESS]${{NC}} $1"; }};
log_warning() {{ echo -e "${{YELLOW}}[WARNING]${{NC}} $1"; }};
log_error() {{ echo -e "${{RED}}[ERROR]${{NC}} $1"; }};

# Check if running as root for system-level operations
check_sudo() {{
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo privileges for system-level changes";
        log_info "Usage: sudo ./bootstrap.sh";
        exit 1;
    fi;
}};

# Check if user exists (for user-specific operations)
check_user() {{
    local username="${{SUDO_USER:-$USER}}";
    if ! id "$username" >/dev/null 2>&1; then
        log_error "Target user '$username' does not exist";
        exit 1;
    fi;
    echo "$username";
}};

# Check if package is already installed
is_apt_installed() {{
    dpkg -l "$1" 2>/dev/null | grep -q '^ii';
}};

is_snap_installed() {{
    snap list "$1" >/dev/null 2>&1;
}};

is_flatpak_installed() {{
    flatpak list | grep -q "$1" 2>/dev/null;
}};

# Main restoration starts here
main() {{
    log_info "🚀 Starting Ubuntu Bootstrap Restoration";
    log_info "=========================================";
    
    check_sudo;
    readonly TARGET_USER=$(check_user);
    readonly USER_HOME="/home/$TARGET_USER";
    
    log_info "Target user: $TARGET_USER";
    log_info "User home: $USER_HOME";
    echo;
''';
    
    def generate_system_preparation( self ) -> str:
        """Generate system preparation and updates."""
        return '''    # System preparation
    log_info "📦 Preparing system and updating package lists...";
    apt update;
    
    # Install essential prerequisites
    log_info "🔧 Installing essential prerequisites...";
    apt install -y curl wget gnupg software-properties-common apt-transport-https;
    
''';
    
    def generate_firefox_removal( self ) -> str:
        """Generate Firefox removal if present."""
        return '''    # Remove Firefox if installed (as requested)
    log_info "🦊 Checking Firefox installation...";
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
    
''';
    
    def generate_flatpak_setup( self ) -> str:
        """Generate flatpak installation and configuration."""
        return '''    # Install and configure Flatpak
    log_info "📦 Setting up Flatpak...";
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
    
''';
    
    def generate_intel_kvm_disable( self ) -> str:
        """Generate Intel KVM module disabling."""
        return '''    # Disable Intel KVM virtualization modules
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
    update-initramfs -u;
    log_success "Intel KVM modules disabled";
    
''';
    
    def generate_special_packages( self ) -> str:
        """Generate installation of special packages (Chrome, Warp Terminal, etc.)."""
        return '''    # Install special packages with custom repositories
    log_info "🌟 Installing special packages...";
    
    # Google Chrome
    if ! is_apt_installed "google-chrome-stable"; then
        log_info "Installing Google Chrome...";
        wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add -;
        echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list;
        apt update;
        apt install -y google-chrome-stable;
        log_success "Google Chrome installed";
    else
        log_info "Google Chrome already installed";
    fi;
    
    # Warp Terminal (preview version)
    if ! is_apt_installed "warp-terminal-preview"; then
        log_info "Installing Warp Terminal...";
        curl -fsSL https://releases.warp.dev/linux/keys/warp.asc | gpg --dearmor -o /usr/share/keyrings/warp.gpg;
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/warp.gpg] https://releases.warp.dev/linux/deb stable main" > /etc/apt/sources.list.d/warp.list;
        apt update;
        apt install -y warp-terminal-preview;
        log_success "Warp Terminal installed";
    else
        log_info "Warp Terminal already installed";
    fi;
    
    # Docker
    if ! is_apt_installed "docker-ce"; then
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
    if ! is_apt_installed "virtualbox"; then
        log_info "Installing VirtualBox...";
        apt install -y virtualbox virtualbox-ext-pack;
        log_success "VirtualBox installed";
    else
        log_info "VirtualBox already installed";
    fi;
    
''';
    
    def generate_apt_packages( self, apt_packages: List[Dict[str, str]] ) -> str:
        """Generate APT package installation commands."""
        if not apt_packages:
            return "    # No APT packages to install\\n\\n";
        
        # Filter out packages that are already handled specially or are problematic
        skip_packages = {
            'google-chrome-stable', 'warp-terminal-preview', 'docker-ce', 
            'docker-ce-cli', 'containerd.io', 'virtualbox', 'firefox',
            'firefox-esr', 'linux-image-', 'linux-headers-'  # Skip kernel packages
        };
        
        filtered_packages = [];
        for pkg in apt_packages:
            pkg_name = pkg['name'];
            should_skip = False;
            
            for skip_pattern in skip_packages:
                if skip_pattern in pkg_name:
                    should_skip = True;
                    break;
            
            if not should_skip:
                filtered_packages.append( pkg );
        
        # Group packages into batches for installation
        batch_size = 50;
        packages_script = "    # Install APT packages\\n";
        packages_script += "    log_info \"📦 Installing APT packages...\";\\n";
        
        for i in range( 0, len( filtered_packages ), batch_size ):
            batch = filtered_packages[i:i + batch_size];
            package_names = [pkg['name'] for pkg in batch];
            
            packages_script += f"\\n    # Batch {i//batch_size + 1}\\n";
            packages_script += "    apt install -y";
            
            for name in package_names:
                packages_script += f" {name}";
            
            packages_script += ";\\n";
        
        packages_script += f"    log_success \"Installed {len(filtered_packages)} APT packages\";\\n\\n";
        return packages_script;
    
    def generate_snap_packages( self, snap_packages: List[Dict[str, str]] ) -> str:
        """Generate Snap package installation commands."""
        if not snap_packages:
            return "    # No Snap packages to install\\n\\n";
        
        packages_script = "    # Install Snap packages\\n";
        packages_script += "    log_info \"📦 Installing Snap packages...\";\\n\\n";
        
        for pkg in snap_packages:
            name = pkg['name'];
            channel = pkg.get( 'channel', 'stable' );
            
            # Skip core snaps that are typically pre-installed
            if name in ['core18', 'core20', 'core22', 'core24', 'snapd']:
                continue;
            
            packages_script += f"    if ! is_snap_installed \"{name}\"; then\\n";
            packages_script += f"        snap install {name}";
            
            if channel != 'stable':
                packages_script += f" --channel={channel}";
            
            packages_script += f";\\n";
            packages_script += f"        log_success \"Installed snap: {name}\";\\n";
            packages_script += "    fi;\\n\\n";
        
        return packages_script;
    
    def generate_python_packages( self, python_packages: List[Dict[str, str]] ) -> str:
        """Generate Python package installation commands."""
        if not python_packages:
            return "    # No Python packages to install\\n\\n";
        
        # Filter out system packages that shouldn't be installed via pip
        system_packages = {
            'pip', 'setuptools', 'wheel', 'apt-pkg', 'PyGObject', 
            'ubuntu-drivers-common', 'systemd-python'
        };
        
        user_packages = [];
        for pkg in python_packages:
            if pkg['name'] not in system_packages and not pkg['name'].startswith( 'ubuntu-' ):
                user_packages.append( pkg );
        
        if not user_packages:
            return "    # No user Python packages to install\\n\\n";
        
        packages_script = "    # Install Python packages\\n";
        packages_script += "    log_info \"🐍 Installing Python packages...\";\\n\\n";
        
        # Create requirements.txt content
        requirements_content = "\\n".join( [f"{pkg['name']}=={pkg['version']}" for pkg in user_packages] );
        
        packages_script += "    # Create temporary requirements file\\n";
        packages_script += "    cat > /tmp/bootstrap_requirements.txt << 'EOF'\\n";
        packages_script += requirements_content + "\\n";
        packages_script += "EOF\\n\\n";
        
        packages_script += "    # Install packages as target user\\n";
        packages_script += "    sudo -u \"$TARGET_USER\" pip3 install -r /tmp/bootstrap_requirements.txt --user;\\n";
        packages_script += "    rm /tmp/bootstrap_requirements.txt;\\n";
        packages_script += f"    log_success \"Installed {len(user_packages)} Python packages\";\\n\\n";
        
        return packages_script;
    
    def generate_sysctl_config( self, sysctl_settings: Dict[str, str] ) -> str:
        """Generate sysctl configuration restoration."""
        if not sysctl_settings:
            return "    # No custom sysctl settings to apply\\n\\n";
        
        config_script = "    # Apply custom sysctl settings\\n";
        config_script += "    log_info \"⚙️ Applying custom sysctl settings...\";\\n\\n";
        
        config_script += "    cat > /etc/sysctl.d/99-bootstrap.conf << 'EOF'\\n";
        config_script += "# Custom sysctl settings restored by bootstrap\\n";
        
        for key, value in sysctl_settings.items():
            config_script += f"{key} = {value}\\n";
        
        config_script += "EOF\\n\\n";
        config_script += "    sysctl -p /etc/sysctl.d/99-bootstrap.conf;\\n";
        config_script += f"    log_success \"Applied {len(sysctl_settings)} sysctl settings\";\\n\\n";
        
        return config_script;
    
    def generate_bashrc_restoration( self, bashrc_additions: List[str], encrypted_secrets: Optional[Dict[str, Any]] ) -> str:
        """Generate .bashrc customization restoration with encrypted secrets."""
        if not bashrc_additions and not encrypted_secrets:
            return "    # No .bashrc customizations to restore\\n\\n";
        
        script = "    # Restore .bashrc customizations\\n";
        script += "    log_info \"🐚 Restoring .bashrc customizations...\";\\n\\n";
        
        # Add safe customizations first
        if bashrc_additions:
            script += "    # Add safe customizations\\n";
            for line in bashrc_additions:
                script += f"    echo '{line}' >> \"$USER_HOME/.bashrc\";\\n";
            script += "\\n";
        
        # Handle encrypted secrets if present
        if encrypted_secrets:
            script += self.generate_secrets_decryption( encrypted_secrets );
        
        script += "    log_success \".bashrc customizations restored\";\\n\\n";
        return script;
    
    def generate_secrets_decryption( self, encrypted_secrets: Dict[str, Any] ) -> str:
        """Generate inline Python decryption for secrets."""
        # Encode the encrypted secrets as base64 for embedding
        secrets_json = json.dumps( encrypted_secrets );
        secrets_b64 = base64.b64encode( secrets_json.encode( 'utf-8' ) ).decode( 'ascii' );
        
        script = '''    # Decrypt and restore sensitive environment variables
    log_info "🔐 Decrypting sensitive environment variables...";
    
    # Embedded encrypted secrets (base64 encoded)
    ENCRYPTED_SECRETS_B64="''' + secrets_b64 + '''";
    
    # Python decryption inline script
    python3 - <<PYTHON_SCRIPT
import json, base64, sys, getpass, os;
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;
from argon2.low_level import hash_secret, Type;

# Recreate crypto functions inline
def derive_key(password, salt):
    return hash_secret(
        password.encode('utf-8'), salt,
        time_cost=3, memory_cost=65536, parallelism=4,
        hash_len=32, type=Type.ID
    ), salt;

def decrypt(encrypted_data, password):
    try:
        ciphertext = base64.b64decode(encrypted_data['ciphertext']);
        nonce = base64.b64decode(encrypted_data['nonce']);
        salt = base64.b64decode(encrypted_data['salt']);
        key, _ = derive_key(password, salt);
        cipher = ChaCha20Poly1305(key);
        plaintext_bytes = cipher.decrypt(nonce, ciphertext, None);
        return plaintext_bytes.decode('utf-8');
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}");

# Load encrypted data
try:
    encrypted_json = base64.b64decode("$ENCRYPTED_SECRETS_B64").decode('utf-8');
    encrypted_data = json.loads(encrypted_json);
    
    # Get password from user or environment variable
    password = os.environ.get('BOOTSTRAP_SECRET')
    if not password:
        password = getpass.getpass("Enter master password to decrypt secrets: ")
    else:
        print("Using password from BOOTSTRAP_SECRET environment variable")
    
    # Decrypt each secret and append to .bashrc
    user_home = os.environ.get('USER_HOME', '/home/' + os.environ.get('SUDO_USER', 'user'));
    bashrc_path = f"{user_home}/.bashrc";
    
    with open(bashrc_path, 'a') as f:
        f.write("\\n# Decrypted sensitive environment variables\\n");
        
        encrypted_items = encrypted_data.get('encrypted_data', {});
        for var_name, encrypted_value in encrypted_items.items():
            if isinstance(encrypted_value, dict) and 'ciphertext' in encrypted_value:
                try:
                    decrypted_value = decrypt(encrypted_value, password);
                    f.write(f'export {var_name}="{decrypted_value}"\\n');
                    print(f"✅ Decrypted: {var_name}");
                except Exception as e:
                    print(f"❌ Failed to decrypt {var_name}: {e}");
                    sys.exit(1);
    
    print("🔓 All secrets decrypted successfully");
    
except Exception as e:
    print(f"❌ Decryption process failed: {e}");
    sys.exit(1);
PYTHON_SCRIPT

    if [[ $? -eq 0 ]]; then
        log_success "Sensitive environment variables restored";
    else
        log_error "Failed to decrypt sensitive data";
        return 1;
    fi;

''';
        return script;
    
    def generate_ssh_restoration( self, ssh_keys: List[Dict[str, str]] ) -> str:
        """Generate SSH keys and configuration restoration."""
        if not ssh_keys:
            return "    # No SSH keys to restore\\n\\n";
        
        script = "    # Restore SSH keys and configuration\\n";
        script += "    log_info \"🔑 Restoring SSH keys and configuration...\";\\n\\n";
        
        script += "    # Create .ssh directory with proper permissions\\n";
        script += "    sudo -u \"$TARGET_USER\" mkdir -p \"$USER_HOME/.ssh\";\\n";
        script += "    chmod 700 \"$USER_HOME/.ssh\";\\n";
        script += "    chown \"$TARGET_USER:$TARGET_USER\" \"$USER_HOME/.ssh\";\\n\\n";
        
        for ssh_item in ssh_keys:
            path = ssh_item['path'];
            content = ssh_item['content'];
            permissions = ssh_item['permissions'];
            filename = path.split( '/' )[-1];  # Extract filename from path
            
            if content == '[PRIVATE_KEY_EXISTS]':
                script += f"    # Note: Private key {filename} needs to be manually restored\\n";
                script += f"    log_warning \"Private key {filename} must be manually restored for security\";\\n\\n";
            else:
                script += f"    # Restore {filename}\\n";
                script += f"    cat > \"$USER_HOME/.ssh/{filename}\" << 'EOF'\\n";
                script += content + "\\n";
                script += "EOF\\n";
                script += f"    chmod {permissions} \"$USER_HOME/.ssh/{filename}\";\\n";
                script += f"    chown \"$TARGET_USER:$TARGET_USER\" \"$USER_HOME/.ssh/{filename}\";\\n\\n";
        
        script += "    log_success \"SSH configuration restored\";\\n\\n";
        return script;
    
    def generate_cron_restoration( self, cron_jobs: List[str] ) -> str:
        """Generate cron jobs restoration."""
        if not cron_jobs:
            return "    # No cron jobs to restore\\n\\n";
        
        script = "    # Restore cron jobs\\n";
        script += "    log_info \"⏰ Restoring cron jobs...\";\\n\\n";
        
        script += "    # Create temporary crontab file\\n";
        script += "    cat > /tmp/bootstrap_crontab << 'EOF'\\n";
        
        for job in cron_jobs:
            script += job + "\\n";
        
        script += "EOF\\n\\n";
        script += "    # Install crontab for target user\\n";
        script += "    sudo -u \"$TARGET_USER\" crontab /tmp/bootstrap_crontab;\\n";
        script += "    rm /tmp/bootstrap_crontab;\\n";
        script += f"    log_success \"Restored {len(cron_jobs)} cron jobs\";\\n\\n";
        
        return script;
    
    def generate_custom_services_installation( self, custom_services: List[Dict[str, Any]] ) -> str:
        """Generate custom services installation."""
        if not custom_services:
            return "    # No custom services to install\\n\\n";
        
        script = "    # Install custom services\\n";
        script += "    log_info \"🔧 Installing custom services...\";\\n\\n";
        
        for service in custom_services:
            if service['name'] == 'gridshift':
                script += "    # Install GridShift - Automated Media Download Manager\\n";
                script += "    log_info \"Installing GridShift from GitHub...\";\\n";
                script += "    \\n";
                script += "    # Create installation directory\\n";
                script += "    GRIDSHIFT_DIR=\"/opt/gridshift\";\\n";
                script += "    sudo mkdir -p \"$GRIDSHIFT_DIR\";\\n";
                script += "    sudo chown \"$TARGET_USER:$TARGET_USER\" \"$GRIDSHIFT_DIR\";\\n";
                script += "    \\n";
                script += "    # Clone GridShift repository\\n";
                script += "    sudo -u \"$TARGET_USER\" git clone https://github.com/mcollard0/gridshift.git \"$GRIDSHIFT_DIR\";\\n";
                script += "    cd \"$GRIDSHIFT_DIR\";\\n";
                script += "    \\n";
                script += "    # Set up Python virtual environment\\n";
                script += "    log_info \"Setting up Python virtual environment for GridShift...\";\\n";
                script += "    sudo -u \"$TARGET_USER\" python3 -m venv \"$GRIDSHIFT_DIR/venv\";\\n";
                script += "    \\n";
                script += "    # Install Python dependencies\\n";
                script += "    sudo -u \"$TARGET_USER\" \"$GRIDSHIFT_DIR/venv/bin/pip\" install --upgrade pip;\\n";
                script += "    sudo -u \"$TARGET_USER\" \"$GRIDSHIFT_DIR/venv/bin/pip\" install -r \"$GRIDSHIFT_DIR/requirements.txt\";\\n";
                script += "    \\n";
                script += "    # Install pyload-ng for download management\\n";
                script += "    sudo -u \"$TARGET_USER\" \"$GRIDSHIFT_DIR/venv/bin/pip\" install pyload-ng;\\n";
                script += "    \\n";
                script += "    # Test the installation\\n";
                script += "    if sudo -u \"$TARGET_USER\" \"$GRIDSHIFT_DIR/venv/bin/python\" \"$GRIDSHIFT_DIR/test_setup.py\"; then\\n";
                script += "        log_success \"GridShift installed successfully\";\\n";
                script += "    else\\n";
                script += "        log_warning \"GridShift installation test failed - check logs\";\\n";
                script += "    fi;\\n";
                script += "    \\n";
                script += "    # Create convenient aliases in .bashrc\\n";
                script += "    echo 'alias gridshift=\"cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu\"' >> \"$USER_HOME/.bashrc\";\\n";
                script += "    echo 'alias gridshift-daemon=\"cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu daemon\"' >> \"$USER_HOME/.bashrc\";\\n";
                script += "    echo 'alias gridshift-monitor=\"cd /opt/gridshift && source venv/bin/activate && python -m src.cli.menu monitor\"' >> \"$USER_HOME/.bashrc\";\\n";
                script += "    \\n";
                script += "    log_info \"GridShift aliases added to .bashrc\";\\n";
                script += "    log_info \"Use 'gridshift' command to access the interactive menu\";\\n";
                script += "    log_info \"Use 'gridshift-daemon' to start automation\";\\n";
                script += "    log_info \"Use 'gridshift-monitor' for real-time monitoring\";\\n";
                script += "    \\n";
        
        script += "    log_success \"Custom services installation completed\";\\n\\n";
        return script;
    
    def generate_script_footer( self ) -> str:
        """Generate script footer with completion message."""
        return '''    # Final steps and completion
    log_info "🧹 Performing final cleanup...";
    apt autoremove -y;
    apt autoclean;
    
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
''';
    
    def generate_bootstrap_script( self, inventory: Dict[str, Any], encrypted_secrets: Optional[Dict[str, Any]] = None ) -> str:
        """Generate complete bootstrap script."""
        print( "🔨 Generating bootstrap restoration script..." );
        
        script_parts = [];
        
        # Header and setup
        script_parts.append( self.generate_script_header( inventory ) );
        script_parts.append( self.generate_system_preparation() );
        
        # Special configurations
        script_parts.append( self.generate_firefox_removal() );
        script_parts.append( self.generate_flatpak_setup() );
        script_parts.append( self.generate_intel_kvm_disable() );
        script_parts.append( self.generate_special_packages() );
        
        # Package installations
        packages = inventory.get( 'packages', {} );
        script_parts.append( self.generate_apt_packages( packages.get( 'apt', [] ) ) );
        script_parts.append( self.generate_snap_packages( packages.get( 'snap', [] ) ) );
        script_parts.append( self.generate_python_packages( packages.get( 'python', [] ) ) );
        
        # System configurations
        system_config = inventory.get( 'system_config', {} );
        script_parts.append( self.generate_sysctl_config( system_config.get( 'sysctl', {} ) ) );
        script_parts.append( self.generate_bashrc_restoration( 
            system_config.get( 'bashrc_additions', [] ), encrypted_secrets 
        ) );
        
        # Custom services installation
        custom_services = inventory.get( 'custom_services', [] );
        script_parts.append( self.generate_custom_services_installation( custom_services ) );
        
        # User files and settings
        files = inventory.get( 'files', {} );
        script_parts.append( self.generate_ssh_restoration( files.get( 'ssh_keys', [] ) ) );
        script_parts.append( self.generate_cron_restoration( system_config.get( 'cron_jobs', [] ) ) );
        
        # Footer
        script_parts.append( self.generate_script_footer() );
        
        return ''.join( script_parts );
    
    def save_bootstrap_script( self, script_content: str, filename: str = 'bootstrap.sh' ) -> str:
        """Save bootstrap script to file."""
        script_path = self.scripts_dir / filename;
        
        with open( script_path, 'w' ) as f:
            f.write( script_content );
        
        # Make script executable
        os.chmod( script_path, 0o755 );
        
        print( f"💾 Bootstrap script saved to: {script_path}" );
        print( f"🔧 Script made executable (chmod 755)" );
        
        return str( script_path );


def main():
    """Main generator execution."""
    print( "🚀 Ubuntu Bootstrap Script Generator" );
    print( "====================================\\n" );
    
    generator = BootstrapScriptGenerator();
    
    # Load inventory and encrypted secrets
    try:
        inventory = generator.load_inventory();
        encrypted_secrets = generator.load_encrypted_secrets();
        
        # Generate bootstrap script
        script_content = generator.generate_bootstrap_script( inventory, encrypted_secrets );
        
        # Save script
        script_path = generator.save_bootstrap_script( script_content );
        
        print( f"\\n📊 Script Generation Summary:" );
        packages = inventory.get( 'packages', {} );
        print( f"   APT packages: {len(packages.get('apt', []))}" );
        print( f"   Snap packages: {len(packages.get('snap', []))}" );
        print( f"   Python packages: {len(packages.get('python', []))}" );
        print( f"   Custom services: {len(inventory.get('custom_services', []))}" );
        
        system_config = inventory.get( 'system_config', {} );
        files = inventory.get( 'files', {} );
        print( f"   Sysctl settings: {len(system_config.get('sysctl', {}))}" );
        print( f"   SSH keys: {len(files.get('ssh_keys', []))}" );
        print( f"   Cron jobs: {len(system_config.get('cron_jobs', []))}" );
        print( f"   Encrypted secrets: {len(inventory.get('encrypted_refs', []))}" );
        
        print( f"\\n💡 Next steps:" );
        print( f"   1. Review the generated script: {script_path}" );
        print( f"   2. Test on a clean Ubuntu 25.04 system" );
        print( f"   3. Run with: sudo ./scripts/bootstrap.sh" );
        
    except Exception as e:
        print( f"❌ Error generating bootstrap script: {e}" );
        return 1;
    
    return 0;


if __name__ == '__main__':
    exit( main() );
