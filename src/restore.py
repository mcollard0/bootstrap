#!/usr/bin/env python3
"""
Bootstrap System - Disaster Recovery & Vault Restoration Tool

Standalone CLI tool to authenticate, decrypt, and selectively or fully restore:
- Storage mounts & `/etc/fstab` (mount points for FAST_ARCHIVE, LARGE_ARCHIVE, etc.)
- Shell environments (Fish & Bash dotfiles, variables, functions, MOTD)
- Security keys (SSH, GPG, Git config, SSL private keys)
- Software packages (Pacman/AUR for Arch, APT/Snap for Ubuntu)
- Network connections & systemd units

Usage:
    python3 src/restore.py --vault backup/bootstrap_vault_hostname_timestamp.tar.enc
    python3 src/restore.py --list-backups
"""

import os
import sys
import json
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Ensure src directory is in sys.path
SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from crypto_utils import SecureBootstrapCrypto, prompt_for_password
from system_detector import SystemDetector


class BootstrapRestorer:
    """Handles disaster recovery and restoration from an encrypted vault."""

    def __init__(self, vault_path: str, target_user: str = None):
        self.vault_path = Path(vault_path).expanduser().resolve()
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_path}")

        self.crypto = SecureBootstrapCrypto()
        self.detector = SystemDetector()
        self.current_os = self.detector.to_dict()

        self.target_user = target_user or os.environ.get('SUDO_USER') or os.environ.get('USER') or 'michael'
        self.user_home = Path(f"/home/{self.target_user}") if self.target_user != 'root' else Path('/root')

    def inspect_vault(self, password: str) -> Tuple[Dict[str, Any], Path]:
        """Decrypt vault to temporary folder and read metadata and inventory."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="bootstrap_restore_"))
        try:
            meta = self.crypto.extract_encrypted_vault(self.vault_path, tmp_dir, password)
            return meta, tmp_dir
        except Exception as e:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise e

    def restore_fstab_and_mounts(self, stage_dir: Path, apply_changes: bool = False):
        """Restore /etc/fstab and create mount directories for archive drives."""
        print("\n💾 Inspecting storage topology and /etc/fstab...")
        staged_fstab = stage_dir / "system/etc/fstab"

        if not staged_fstab.exists():
            print("  ⚠️  No /etc/fstab found in vault.")
            return

        fstab_lines = staged_fstab.read_text(encoding='utf-8')
        print(f"  ✓ Staged /etc/fstab contains {len(fstab_lines.splitlines())} lines.")

        # Identify mount directories in fstab
        mount_dirs = []
        for line in fstab_lines.splitlines():
            line_clean = line.strip()
            if not line_clean or line_clean.startswith('#'):
                continue
            parts = line_clean.split()
            if len(parts) >= 2:
                mp = parts[1]
                if mp.startswith('/run/media/') or mp.startswith('/mnt/') or mp.startswith('/media/'):
                    mount_dirs.append(mp)

        print(f"  📁 Found {len(mount_dirs)} external archive mount points:")
        for mp in mount_dirs:
            exists = os.path.exists(mp)
            print(f"     • {mp} ({'exists' if exists else 'missing - will create'})")

        if apply_changes:
            # Create mount directories
            for mp in mount_dirs:
                try:
                    os.makedirs(mp, exist_ok=True)
                    print(f"     ✅ Created mount directory: {mp}")
                except Exception as e:
                    print(f"     ⚠️  Could not create {mp}: {e}")

            # Backup current /etc/fstab and overwrite/merge
            if os.path.exists('/etc/fstab'):
                backup_fstab = f"/etc/fstab.backup.{os.getpid()}"
                try:
                    shutil.copy2('/etc/fstab', backup_fstab)
                    print(f"  ✓ Backed up current /etc/fstab -> {backup_fstab}")
                except Exception:
                    pass

            try:
                shutil.copy2(staged_fstab, '/etc/fstab')
                print("  ✅ Restored /etc/fstab successfully!")
            except PermissionError:
                print("  ⚠️  Need root/sudo privileges to write to /etc/fstab. Run with sudo or manually copy:")
                print(f"     sudo cp {staged_fstab} /etc/fstab")

    def restore_shell_configs(self, stage_dir: Path):
        """Restore Fish and Bash dotfiles, variables, functions, and MOTD."""
        print("\n🐚 Restoring Shell Configurations (Fish & Bash)...")

        # 1. Restore Fish configuration
        staged_fish = stage_dir / "home/.config/fish"
        target_fish = self.user_home / ".config/fish"

        if staged_fish.exists():
            target_fish.mkdir(parents=True, exist_ok=True)
            for root, _, files in os.walk(staged_fish):
                for f in files:
                    src_f = Path(root) / f
                    rel_f = src_f.relative_to(staged_fish)
                    dest_f = target_fish / rel_f
                    dest_f.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_f, dest_f)
            self._set_user_ownership(target_fish)
            print(f"  ✅ Restored Fish configuration -> {target_fish}")

        # 2. Restore Bash configuration
        for bf in ['.bashrc', '.bash_profile', '.bash_aliases', '.profile']:
            src_bf = stage_dir / f"home/{bf}"
            if src_bf.exists():
                dest_bf = self.user_home / bf
                shutil.copy2(src_bf, dest_bf)
                self._set_user_ownership(dest_bf)
                print(f"  ✅ Restored {bf} -> {dest_bf}")

        # 3. Restore Prompts & Tools
        starship_src = stage_dir / "home/.config/starship.toml"
        if starship_src.exists():
            starship_dest = self.user_home / ".config/starship.toml"
            starship_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(starship_src, starship_dest)
            self._set_user_ownership(starship_dest)
            print(f"  ✅ Restored Starship prompt config -> {starship_dest}")

        # 4. Restore MOTD & environment
        for sys_f in ['/etc/motd', '/etc/issue', '/etc/environment']:
            staged_sys = stage_dir / f"system{sys_f}"
            if staged_sys.exists():
                try:
                    shutil.copy2(staged_sys, sys_f)
                    print(f"  ✅ Restored {sys_f}")
                except Exception:
                    print(f"  ⚠️  Could not write {sys_f} (run as root/sudo to restore system files)")

    def restore_security_keys(self, stage_dir: Path):
        """Restore SSH, GPG, and Git configurations with strict permissions."""
        print("\n🔑 Restoring Security Keys & Credentials...")

        # 1. SSH directory
        staged_ssh = stage_dir / "home/.ssh"
        target_ssh = self.user_home / ".ssh"

        if staged_ssh.exists():
            target_ssh.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(target_ssh, 0o700)
            except Exception:
                pass

            for f in staged_ssh.iterdir():
                if f.is_file():
                    dest_f = target_ssh / f.name
                    shutil.copy2(f, dest_f)
                    # Set proper permissions
                    if f.suffix == '.pub' or f.name in ['config', 'known_hosts', 'authorized_keys']:
                        os.chmod(dest_f, 0o644)
                    else:
                        os.chmod(dest_f, 0o600)  # Private keys
                    self._set_user_ownership(dest_f)

            self._set_user_ownership(target_ssh)
            print(f"  ✅ Restored SSH keys with secure permissions (chmod 700/600) -> {target_ssh}")

        # 2. Git config
        staged_git = stage_dir / "home/.gitconfig"
        if staged_git.exists():
            dest_git = self.user_home / ".gitconfig"
            shutil.copy2(staged_git, dest_git)
            self._set_user_ownership(dest_git)
            print(f"  ✅ Restored .gitconfig -> {dest_git}")

        # 3. GPG configs
        staged_gpg = stage_dir / "home/.gnupg"
        target_gpg = self.user_home / ".gnupg"
        if staged_gpg.exists():
            target_gpg.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(target_gpg, 0o700)
            except Exception:
                pass
            for f in staged_gpg.iterdir():
                if f.is_file():
                    dest_f = target_gpg / f.name
                    shutil.copy2(f, dest_f)
                    os.chmod(dest_f, 0o600)
                    self._set_user_ownership(dest_f)
            self._set_user_ownership(target_gpg)
            print(f"  ✅ Restored GPG configuration -> {target_gpg}")

    def restore_desktop_configs(self, stage_dir: Path):
        """Restore KDE Plasma and desktop shortcut configurations."""
        print("\n🖥️  Restoring Desktop & Window Manager Configurations...")
        staged_config = stage_dir / "home/.config"
        target_config = self.user_home / ".config"

        if staged_config.exists():
            for kf in ['kglobalshortcutsrc', 'kwinrc', 'kdeglobals', 'khotkeysrc', 'plasmarc']:
                src_kf = staged_config / kf
                if src_kf.exists():
                    dest_kf = target_config / kf
                    dest_kf.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_kf, dest_kf)
                    self._set_user_ownership(dest_kf)
                    print(f"  ✅ Restored KDE setting: {kf}")

    def install_packages(self, inventory: Dict[str, Any]):
        """Install software packages using pacman/yay or apt/snap."""
        print("\n📦 Software Package Restoration...")
        packages = inventory.get('packages', {})
        current_family = self.current_os.get('os', {}).get('family')

        if current_family == 'arch':
            native_pkgs = [p['name'] for p in packages.get('arch_native', []) if 'name' in p]
            aur_pkgs = [p['name'] for p in packages.get('arch_aur', []) if 'name' in p]

            print(f"  Arch packages in inventory: {len(native_pkgs)} pacman, {len(aur_pkgs)} AUR")

            if native_pkgs:
                print(f"  Installing {len(native_pkgs)} pacman packages...")
                cmd = ['sudo', 'pacman', '-S', '--needed', '--noconfirm'] + native_pkgs
                try:
                    subprocess.run(cmd, check=True)
                    print("  ✅ Pacman packages installed successfully.")
                except Exception as e:
                    print(f"  ⚠️  Pacman installation error: {e}")

            if aur_pkgs:
                aur_helper = shutil.which('paru') or shutil.which('yay')
                if aur_helper:
                    print(f"  Installing {len(aur_pkgs)} AUR packages via {Path(aur_helper).name}...")
                    cmd = [aur_helper, '-S', '--needed', '--noconfirm'] + aur_pkgs
                    try:
                        subprocess.run(cmd, check=True)
                        print("  ✅ AUR packages installed successfully.")
                    except Exception as e:
                        print(f"  ⚠️  AUR installation error: {e}")
                else:
                    print(f"  ⚠️  No AUR helper (paru/yay) found. Install paru or yay to restore {len(aur_pkgs)} AUR packages.")

        elif current_family == 'debian':
            apt_pkgs = [p['name'] for p in packages.get('apt', []) if 'name' in p]
            if apt_pkgs:
                print(f"  Installing {len(apt_pkgs)} APT packages...")
                cmd = ['sudo', 'apt', 'install', '-y'] + apt_pkgs
                try:
                    subprocess.run(cmd, check=True)
                    print("  ✅ APT packages installed.")
                except Exception as e:
                    print(f"  ⚠️  APT error: {e}")

    def _set_user_ownership(self, path: Path):
        """Set file ownership to target user."""
        try:
            import pwd
            pw = pwd.getpwnam(self.target_user)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass

    def run_interactive(self):
        """Run interactive restoration workflow."""
        print("🚀 Bootstrap System - Vault Restoration & Disaster Recovery")
        print("=============================================================")
        print(f"Target Vault: {self.vault_path}")
        print(f"Target User:  {self.target_user} (Home: {self.user_home})")
        print(f"Host System:  {self.current_os.get('os', {}).get('pretty_name')}\n")

        password = prompt_for_password("vault decryption")

        print("\n🔓 Authenticating and decrypting vault...")
        try:
            meta, stage_dir = self.inspect_vault(password)
            print(f"✅ Authentication verified! Vault metadata:")
            print(f"   Source Host: {meta.get('hostname')}")
            print(f"   Distribution: {meta.get('distribution')}")
            print(f"   Created At:   {meta.get('created_at')}")
            print(f"   Total Files:  {meta.get('total_files')}")
        except Exception as e:
            print(f"❌ Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

        # Load inventory
        inv_file = stage_dir / "inventory.json"
        inventory = {}
        if inv_file.exists():
            with open(inv_file, 'r', encoding='utf-8') as f:
                inventory = json.load(f)

        try:
            # Menu
            print("\nSelect restoration actions:")
            print("  1. Full Restoration (Storage/fstab, Shells, Keys, Desktop, Packages)")
            print("  2. Restore Configuration & Keys only (fstab, Fish/Bash, SSH/GPG, Desktop)")
            print("  3. Restore Storage / Mounts & /etc/fstab only")
            print("  4. Restore Shell configs (Fish & Bash) only")
            print("  5. Restore SSH & Security Keys only")
            print("  6. Install Software Packages only")
            print("  q. Quit")

            choice = input("\nEnter choice [1-6, default: 2]: ").strip() or "2"

            if choice == '1':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
                self.restore_shell_configs(stage_dir)
                self.restore_security_keys(stage_dir)
                self.restore_desktop_configs(stage_dir)
                self.install_packages(inventory)
            elif choice == '2':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
                self.restore_shell_configs(stage_dir)
                self.restore_security_keys(stage_dir)
                self.restore_desktop_configs(stage_dir)
            elif choice == '3':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
            elif choice == '4':
                self.restore_shell_configs(stage_dir)
            elif choice == '5':
                self.restore_security_keys(stage_dir)
            elif choice == '6':
                self.install_packages(inventory)
            elif choice.lower() == 'q':
                print("Restoration cancelled.")
                return

            print("\n🎉 Restoration tasks completed successfully!")

        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Bootstrap Vault Restoration Tool")
    parser.add_argument('--vault', type=str, help="Path to encrypted vault (.tar.enc)")
    parser.add_argument('--user', type=str, default=None, help="Target username (default: current user)")
    parser.add_argument('--list-backups', action='store_true', help="List local and archive backups")

    args = parser.parse_args()

    if args.list_backups:
        print("🔍 Searching for backup vaults in ./backup and archive drives...")
        search_dirs = [Path('./backup'), Path('/run/media/michael/FAST_ARCHIVE/SystemBackups')]
        found = []
        for s_dir in search_dirs:
            if s_dir.exists():
                for f in s_dir.glob('bootstrap_vault_*.tar.enc'):
                    found.append((f, f.stat().st_size, f.stat().st_mtime))

        if not found:
            print("No backup vaults found.")
        else:
            print(f"Found {len(found)} vault(s):")
            for f, sz, mt in sorted(found, key=lambda x: x[2], reverse=True):
                print(f"  • {f} ({sz/(1024*1024):.2f} MB)")
        return

    vault_path = args.vault
    if not vault_path:
        # Look for most recent vault in ./backup
        backup_dir = Path('./backup')
        vaults = sorted(backup_dir.glob('bootstrap_vault_*.tar.enc'), key=lambda x: x.stat().st_mtime, reverse=True)
        if vaults:
            vault_path = str(vaults[0])
            print(f"ℹ️  No vault specified, using most recent: {vault_path}")
        else:
            print("Error: Please specify --vault <path_to_vault.tar.enc>", file=sys.stderr)
            sys.exit(1)

    restorer = BootstrapRestorer(vault_path, target_user=args.user)
    restorer.run_interactive()


if __name__ == '__main__':
    main()
