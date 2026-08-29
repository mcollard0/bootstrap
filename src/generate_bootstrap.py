#!/usr/bin/env python3
"""
Bootstrap System - Restoration Script Generator

Generates idempotent system restoration scripts:
- Arch Linux / CachyOS: pacman, yay/paru, fish/bash, fstab mount points, systemd
- Ubuntu / Debian: apt, snap, bash, flatpak, systemd
"""

import os
import sys
import json
import base64
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from system_detector import SystemDetector
from crypto_utils import SecureBootstrapCrypto
from version import __version__, get_full_program_name


class UniversalBootstrapScriptGenerator:
    """Generates distro-specific bash restoration scripts based on inventory."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else SRC_DIR.parent
        self.data_dir = self.base_dir / 'data'
        self.scripts_dir = self.base_dir / 'scripts'
        self.scripts_dir.mkdir(exist_ok=True)

        self.detector = SystemDetector()

    def load_inventory(self, inventory_file: str = 'inventory.json') -> Dict[str, Any]:
        p = self.data_dir / inventory_file
        if not p.exists():
            raise FileNotFoundError(f"Inventory not found: {p}. Run bootstrap_scanner.py first.")
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)

    def generate(self, inventory: Dict[str, Any]) -> str:
        family = inventory.get('system_info', {}).get('os', {}).get('family', 'arch')
        if family == 'arch':
            return self._generate_arch_script(inventory)
        else:
            return self._generate_ubuntu_script(inventory)

    def _generate_arch_script(self, inventory: Dict[str, Any]) -> str:
        """Generate Arch Linux / CachyOS restoration bash script."""
        timestamp = datetime.datetime.now().isoformat()
        os_info = inventory.get('system_info', {}).get('os', {})
        pretty_name = os_info.get('pretty_name', 'Arch Linux')

        packages = inventory.get('packages', {})
        native_pkgs = [p['name'] for p in packages.get('arch_native', []) if 'name' in p]
        aur_pkgs = [p['name'] for p in packages.get('arch_aur', []) if 'name' in p]
        flatpaks = [p['name'] for p in packages.get('flatpak', []) if 'name' in p]

        # Filter out kernel-specific meta packages that might conflict
        skip_pkgs = {'linux', 'linux-firmware', 'base'}
        filtered_native = [p for p in native_pkgs if p not in skip_pkgs]

        # Format packages into bash array
        native_str = ' '.join(filtered_native)
        aur_str = ' '.join(aur_pkgs)
        flatpak_str = ' '.join(flatpaks)

        # External archive mount points from fstab
        fstab_entries = inventory.get('storage', {}).get('fstab', {}).get('entries', [])
        mount_dirs = []
        for e in fstab_entries:
            mp = e.get('mountpoint', '')
            if mp.startswith('/run/media/') or mp.startswith('/mnt/') or mp.startswith('/media/'):
                mount_dirs.append(mp)

        mount_dirs_script = ""
        for md in mount_dirs:
            mount_dirs_script += f"    mkdir -p '{md}'\n"

        script = f'''#!/bin/bash
#
# Arch Linux / CachyOS Bootstrap Restoration Script
# Generated: {timestamp}
# Source System: {pretty_name}
#

set -euo pipefail

# Colors
readonly RED='\\033[0;31m'
readonly GREEN='\\033[0;32m'
readonly YELLOW='\\033[1;33m'
readonly BLUE='\\033[0;34m'
readonly NC='\\033[0m'

log_info() {{ echo -e "${{BLUE}}[INFO]${{NC}} $1"; }}
log_success() {{ echo -e "${{GREEN}}[SUCCESS]${{NC}} $1"; }}
log_warning() {{ echo -e "${{YELLOW}}[WARNING]${{NC}} $1"; }}
log_error() {{ echo -e "${{RED}}[ERROR]${{NC}} $1"; }}

check_sudo() {{
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be executed with root/sudo privileges."
        log_info "Usage: sudo $0"
        exit 1
    fi
}}

main() {{
    log_info "🚀 Starting Arch / CachyOS Bootstrap Restoration"
    log_info "==============================================="
    check_sudo

    readonly TARGET_USER="${{SUDO_USER:-$USER}}"
    readonly USER_HOME="/home/$TARGET_USER"

    log_info "Target User: $TARGET_USER"
    log_info "User Home:   $USER_HOME"
    echo

    # 1. Update package databases and install base development tools
    log_info "📦 Synchronizing pacman mirrors and installing base-devel..."
    pacman -Sy --needed --noconfirm base-devel git curl wget

    # 2. Recreate mount points for external archive drives
    log_info "💾 Ensuring archive drive mount directories exist..."
{mount_dirs_script}
    log_success "Archive mount points verified."

    # 3. Check/Install AUR Helper (paru or yay)
    log_info "🔧 Verifying AUR helper..."
    local aur_helper=""
    if sudo -u "$TARGET_USER" command -v paru >/dev/null 2>&1; then
        aur_helper="paru"
    elif sudo -u "$TARGET_USER" command -v yay >/dev/null 2>&1; then
        aur_helper="yay"
    else
        log_info "Installing paru from AUR..."
        local tmp_paru=$(mktemp -d)
        chown "$TARGET_USER:$TARGET_USER" "$tmp_paru"
        sudo -u "$TARGET_USER" git clone https://aur.archlinux.org/paru-bin.git "$tmp_paru/paru-bin"
        (cd "$tmp_paru/paru-bin" && sudo -u "$TARGET_USER" makepkg -si --noconfirm)
        rm -rf "$tmp_paru"
        aur_helper="paru"
    fi
    log_success "AUR helper available: $aur_helper"

    # 4. Check & Install Native Pacman Packages
    local native_packages=({native_str})
    if [[ ${{#native_packages[@]}} -gt 0 ]]; then
        log_info "Checking which native packages are missing via pacman -T..."
        local missing_native=($(pacman -T "${{native_packages[@]}}" 2>/dev/null || true))
        if [[ ${{#missing_native[@]}} -eq 0 ]]; then
            log_success "All ${{#native_packages[@]}} native packages are already installed - skipping."
        else
            log_info "Installing ${{#missing_native[@]}} missing native packages (out of ${{#native_packages[@]}})..."
            for ((i=0; i<${{#missing_native[@]}}; i+=50)); do
                local batch=("${{missing_native[@]:i:50}}")
                pacman -S --needed --noconfirm "${{batch[@]}}" || log_warning "Some packages in batch failed to install."
            done
            log_success "Native packages installation step completed."
        fi
    fi

    # 5. Check & Install AUR Packages
    local aur_packages=({aur_str})
    if [[ ${{#aur_packages[@]}} -gt 0 ]]; then
        log_info "Checking which AUR packages are missing via pacman -T..."
        local missing_aur=($(pacman -T "${{aur_packages[@]}}" 2>/dev/null || true))
        if [[ ${{#missing_aur[@]}} -eq 0 ]]; then
            log_success "All ${{#aur_packages[@]}} AUR packages are already installed - skipping."
        else
            log_info "Installing ${{#missing_aur[@]}} missing AUR packages via $aur_helper (out of ${{#aur_packages[@]}})..."
            sudo -u "$TARGET_USER" "$aur_helper" -S --needed --noconfirm "${{missing_aur[@]}}" || log_warning "Some AUR packages failed to install."
            log_success "AUR packages installation step completed."
        fi
    fi

    # 6. Set user default shell to fish if installed
    if command -v fish >/dev/null 2>&1; then
        log_info "🐚 Setting default shell to Fish..."
        chsh -s "$(which fish)" "$TARGET_USER" || true
        log_success "Default shell set to Fish for $TARGET_USER."
    fi

    # 7. Enable system services
    log_info "⚙️  Enabling essential system services..."
    systemctl enable --now NetworkManager 2>/dev/null || true
    systemctl enable --now fstrim.timer 2>/dev/null || true

    log_success "🎉 System bootstrap restoration complete!"
    log_info "To restore encrypted dotfiles, SSH keys, and fstab directly from a vault, run:"
    log_info "   python3 src/restore.py"
}}

main "$@"
'''
        return script

    def _generate_ubuntu_script(self, inventory: Dict[str, Any]) -> str:
        """Generate Ubuntu / Debian restoration script."""
        timestamp = datetime.datetime.now().isoformat()
        packages = inventory.get('packages', {})
        apt_pkgs = [p['name'] for p in packages.get('apt', []) if 'name' in p]
        snap_pkgs = packages.get('snap', [])

        skip = {'linux-image', 'linux-headers', 'base-files'}
        filtered_apt = [p for p in apt_pkgs if not any(s in p for s in skip)]
        apt_str = ' '.join(filtered_apt)

        snap_commands = ""
        for s in snap_pkgs:
            s_name = s.get('name')
            s_chan = s.get('channel', 'stable')
            if s_name and s_name not in ['core', 'core20', 'core22', 'core24', 'snapd']:
                snap_commands += f"    snap install {s_name} --channel={s_chan} || true\n"

        return f'''#!/bin/bash
#
# Ubuntu / Debian Bootstrap Restoration Script
# Generated: {timestamp}
#

set -euo pipefail

log_info() {{ echo -e "\\033[0;34m[INFO]\\033[0m $1"; }}
log_success() {{ echo -e "\\033[0;32m[SUCCESS]\\033[0m $1"; }}
log_warning() {{ echo -e "\\033[1;33m[WARNING]\\033[0m $1"; }}

check_sudo() {{
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root/sudo."
        exit 1
    fi
}}

main() {{
    check_sudo
    readonly TARGET_USER="${{SUDO_USER:-$USER}}"
    readonly USER_HOME="/home/$TARGET_USER"

    log_info "Updating APT repositories..."
    apt update

    log_info "Installing APT packages..."
    local apt_packages=({apt_str})
    for ((i=0; i<${{#apt_packages[@]}}; i+=50)); do
        local batch=("${{apt_packages[@]:i:50}}")
        apt install -y "${{batch[@]}}" || log_warning "Batch installation error."
    done

    log_info "Installing Snap packages..."
{snap_commands}

    log_success "Ubuntu restoration script finished."
}}

main "$@"
'''

    def save(self, script_content: str, filename: str = 'bootstrap.sh') -> Path:
        p = self.scripts_dir / filename
        with open(p, 'w', encoding='utf-8') as f:
            f.write(script_content)
        os.chmod(p, 0o755)
        print(f"💾 Saved executable restoration script: {p}")
        return p


def main():
    prog_title = get_full_program_name("Restoration Script Generator")
    parser = argparse.ArgumentParser(description=prog_title)
    parser.add_argument('--version', '-v', action='version', version=prog_title)
    parser.add_argument('--output', type=str, default='bootstrap.sh', help="Output filename in scripts/")

    args = parser.parse_args()

    gen = UniversalBootstrapScriptGenerator()
    inventory = gen.load_inventory()
    content = gen.generate(inventory)
    gen.save(content, filename=args.output)


if __name__ == '__main__':
    main()
