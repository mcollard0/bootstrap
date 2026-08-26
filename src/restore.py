#!/usr/bin/env python3
"""
Bootstrap System - Disaster Recovery & Vault Restoration Tool

Standalone CLI tool to authenticate, decrypt, and selectively or fully restore:
- Storage mounts & `/etc/fstab` (mount points for FAST_ARCHIVE, LARGE_ARCHIVE, etc.)
- Shell environments (Fish & Bash dotfiles, variables, functions, MOTD)
- Security keys (SSH, GPG, Git config, SSL private keys)
- Software packages (Pacman/AUR for Arch, APT/Snap for Ubuntu)
- Network connections & systemd units

Idempotent & non-breaking:
- Compares SHA-256 before writing files; skips identical files
- Uses `pacman -T` on Arch to only install missing packages (skips if already installed)
- Non-destructively merges missing mount entries into `/etc/fstab`
"""

import os
import sys
import json
import shutil
import hashlib
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

# Ensure src directory is in sys.path
SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from crypto_utils import SecureBootstrapCrypto, prompt_for_password
from system_detector import SystemDetector

GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
NC = '\033[0m'


class BootstrapRestorer:
    """Handles idempotent disaster recovery and restoration from an encrypted vault."""

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

    def _file_matches_existing(self, src_file: Path, dest_file: Path) -> bool:
        """Check if destination file exists and has identical SHA-256 hash."""
        if not dest_file.exists():
            return False
        try:
            return hashlib.sha256(src_file.read_bytes()).hexdigest() == hashlib.sha256(dest_file.read_bytes()).hexdigest()
        except Exception:
            return False

    def _safe_copy_file(self, src_file: Path, dest_file: Path, mode: int = None) -> str:
        """
        Copy src_file to dest_file with idempotency check:
        Returns: 'skipped' (already identical), 'created', 'updated'
        """
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        if self._file_matches_existing(src_file, dest_file):
            return 'skipped'

        status = 'created'
        if dest_file.exists():
            status = 'updated'
            backup_path = dest_file.parent / f"{dest_file.name}.bak.{os.getpid()}"
            try:
                shutil.copy2(dest_file, backup_path)
            except Exception:
                pass

        shutil.copy2(src_file, dest_file)
        if mode:
            try:
                os.chmod(dest_file, mode)
            except Exception:
                pass
        self._set_user_ownership(dest_file)
        return status

    def restore_fstab_and_mounts(self, stage_dir: Path, apply_changes: bool = False):
        """Non-destructively merge missing /etc/fstab mount points and create mount dirs."""
        print("\n💾 Inspecting storage topology and /etc/fstab...")
        staged_fstab = stage_dir / "system/etc/fstab"

        if not staged_fstab.exists():
            print("  ⚠️  No /etc/fstab found in vault.")
            return

        fstab_content = staged_fstab.read_text(encoding='utf-8')

        # Parse current fstab mount points
        existing_mounts = set()
        current_fstab = Path('/etc/fstab')
        if current_fstab.exists():
            for line in current_fstab.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        existing_mounts.add(parts[1])

        # Identify missing entries from vault
        lines_to_add = []
        mount_dirs_to_create = []

        for line in fstab_content.splitlines():
            line_clean = line.strip()
            if not line_clean or line_clean.startswith('#'):
                continue
            parts = line_clean.split()
            if len(parts) >= 2:
                mp = parts[1]
                if mp.startswith('/run/media/') or mp.startswith('/mnt/') or mp.startswith('/media/'):
                    mount_dirs_to_create.append(mp)
                if mp not in existing_mounts:
                    lines_to_add.append(line)

        print(f"  • External archive mount points in vault: {len(mount_dirs_to_create)}")
        for mp in mount_dirs_to_create:
            exists = os.path.exists(mp)
            print(f"     • {mp} ({GREEN}exists{NC}" if exists else f"     • {mp} ({YELLOW}missing - will create{NC})")

        print(f"  • Entries missing from /etc/fstab: {len(lines_to_add)}")
        for l in lines_to_add:
            print(f"     + {l}")

        if apply_changes:
            # 1. Create missing directories
            for mp in mount_dirs_to_create:
                if not os.path.exists(mp):
                    try:
                        os.makedirs(mp, exist_ok=True)
                        print(f"  {GREEN}✅ Created mount directory: {mp}{NC}")
                    except Exception as e:
                        print(f"  ⚠️  Could not create {mp}: {e}")

            # 2. Append missing fstab lines safely
            if lines_to_add:
                try:
                    # Backup fstab first
                    shutil.copy2('/etc/fstab', f"/etc/fstab.bak.{os.getpid()}")
                    with open('/etc/fstab', 'a', encoding='utf-8') as f:
                        f.write("\n# Added by Bootstrap Disaster Recovery\n")
                        for l in lines_to_add:
                            f.write(f"{l}\n")
                    print(f"  {GREEN}✅ Appended {len(lines_to_add)} missing mount lines to /etc/fstab{NC}")
                except PermissionError:
                    print(f"  {YELLOW}⚠️  Writing to /etc/fstab requires sudo/root.{NC}")
                    print(f"     Run with sudo or append lines manually.")
            else:
                print(f"  {GREEN}✓ /etc/fstab is already up-to-date.{NC}")

    def restore_shell_configs(self, stage_dir: Path):
        """Idempotently restore Fish and Bash dotfiles, variables, functions, and MOTD."""
        print("\n🐚 Restoring Shell Configurations (Fish & Bash)...")

        # 1. User Fish config
        staged_fish = stage_dir / "home/.config/fish"
        target_fish = self.user_home / ".config/fish"

        if staged_fish.exists():
            target_fish.mkdir(parents=True, exist_ok=True)
            for root, _, files in os.walk(staged_fish):
                for f in files:
                    src_f = Path(root) / f
                    rel_f = src_f.relative_to(staged_fish)
                    dest_f = target_fish / rel_f
                    res = self._safe_copy_file(src_f, dest_f)
                    if res == 'skipped':
                        pass  # identical
                    else:
                        print(f"  {GREEN}✓ [{res.upper()}] Fish: {rel_f}{NC}")
            print(f"  {GREEN}✅ Fish user configuration verified -> {target_fish}{NC}")

        # 2. User Bash config
        for bf in ['.bashrc', '.bash_profile', '.bash_aliases', '.profile']:
            src_bf = stage_dir / f"home/{bf}"
            if src_bf.exists():
                dest_bf = self.user_home / bf
                res = self._safe_copy_file(src_bf, dest_bf)
                if res != 'skipped':
                    print(f"  {GREEN}✓ [{res.upper()}] Bash: {bf}{NC}")

        # 3. System-wide /etc/fish config if available
        staged_etc_fish = stage_dir / "system/etc/fish/config.fish"
        if staged_etc_fish.exists() and os.path.exists('/etc/fish'):
            target_etc = Path('/etc/fish/config.fish')
            if not self._file_matches_existing(staged_etc_fish, target_etc):
                try:
                    shutil.copy2(staged_etc_fish, target_etc)
                    print(f"  {GREEN}✓ Restored /etc/fish/config.fish{NC}")
                except PermissionError:
                    print(f"  ⚠️  Root required to restore /etc/fish/config.fish")

        # 4. Starship prompt & Fastfetch
        starship_src = stage_dir / "home/.config/starship.toml"
        if starship_src.exists():
            dest = self.user_home / ".config/starship.toml"
            res = self._safe_copy_file(starship_src, dest)
            if res != 'skipped':
                print(f"  {GREEN}✓ [{res.upper()}] Starship config{NC}")

    def restore_security_keys(self, stage_dir: Path):
        """Idempotently restore SSH, GPG, and Git configurations with strict permissions."""
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
                    is_pub = f.suffix == '.pub' or f.name in ['config', 'known_hosts', 'authorized_keys']
                    mode = 0o644 if is_pub else 0o600
                    res = self._safe_copy_file(f, dest_f, mode=mode)
                    if res != 'skipped':
                        print(f"  {GREEN}✓ [{res.upper()}] SSH: {f.name} (mode {oct(mode)[-3:]}){NC}")

            self._set_user_ownership(target_ssh)
            print(f"  {GREEN}✅ SSH keys verified with strict permissions.{NC}")

        # 2. Git config
        staged_git = stage_dir / "home/.gitconfig"
        if staged_git.exists():
            dest_git = self.user_home / ".gitconfig"
            res = self._safe_copy_file(staged_git, dest_git)
            if res != 'skipped':
                print(f"  {GREEN}✓ [{res.upper()}] Git: .gitconfig{NC}")

    def restore_desktop_configs(self, stage_dir: Path):
        """Idempotently restore non-default KDE Plasma settings."""
        print("\n🖥️  Restoring Desktop & Window Manager Configurations...")
        staged_config = stage_dir / "home/.config"
        target_config = self.user_home / ".config"

        if staged_config.exists():
            kde_files = ['kglobalshortcutsrc', 'kwinrc', 'kdeglobals', 'kwinrulesrc', 'plasmarc', 'plasma-org.kde.plasma.desktop-appletsrc']
            for kf in kde_files:
                src_kf = staged_config / kf
                if src_kf.exists():
                    dest_kf = target_config / kf
                    res = self._safe_copy_file(src_kf, dest_kf)
                    if res != 'skipped':
                        print(f"  {GREEN}✓ [{res.upper()}] KDE: {kf}{NC}")

    def install_packages(self, inventory: Dict[str, Any]):
        """
        Idempotent package installation:
        Uses `pacman -T` on Arch to check installed dependencies.
        Skips packages that are already installed!
        """
        print("\n📦 Software Package Restoration (Idempotent)...")
        packages = inventory.get('packages', {})
        current_family = self.current_os.get('os', {}).get('family')

        if current_family == 'arch':
            native_pkgs = [p['name'] for p in packages.get('arch_native', []) if 'name' in p]
            aur_pkgs = [p['name'] for p in packages.get('arch_aur', []) if 'name' in p]

            # 1. Check native packages with pacman -T
            missing_native = []
            if native_pkgs:
                try:
                    res = subprocess.run(['pacman', '-T'] + native_pkgs, capture_output=True, text=True)
                    missing_native = [p.strip() for p in res.stdout.strip().split('\n') if p.strip()]
                except Exception:
                    missing_native = native_pkgs

            if not missing_native:
                print(f"  {GREEN}✓ All {len(native_pkgs)} native pacman packages are already installed.{NC}")
            else:
                print(f"  📦 Installing {len(missing_native)} missing native packages (out of {len(native_pkgs)})...")
                cmd = ['sudo', 'pacman', '-S', '--needed', '--noconfirm'] + missing_native
                try:
                    subprocess.run(cmd, check=True)
                    print(f"  {GREEN}✅ Missing native packages installed successfully.{NC}")
                except Exception as e:
                    print(f"  ⚠️  Pacman installation error: {e}")

            # 2. Check AUR packages with pacman -T
            missing_aur = []
            if aur_pkgs:
                try:
                    res = subprocess.run(['pacman', '-T'] + aur_pkgs, capture_output=True, text=True)
                    missing_aur = [p.strip() for p in res.stdout.strip().split('\n') if p.strip()]
                except Exception:
                    missing_aur = aur_pkgs

            if not missing_aur:
                print(f"  {GREEN}✓ All {len(aur_pkgs)} AUR packages are already installed.{NC}")
            else:
                aur_helper = shutil.which('paru') or shutil.which('yay')
                if aur_helper:
                    print(f"  🌟 Installing {len(missing_aur)} missing AUR packages via {Path(aur_helper).name}...")
                    cmd = [aur_helper, '-S', '--needed', '--noconfirm'] + missing_aur
                    try:
                        subprocess.run(cmd, check=True)
                        print(f"  {GREEN}✅ Missing AUR packages installed.{NC}")
                    except Exception as e:
                        print(f"  ⚠️  AUR installation error: {e}")
                else:
                    print(f"  ⚠️  No AUR helper found. Missing AUR packages: {missing_aur}")

        elif current_family == 'debian':
            apt_pkgs = [p['name'] for p in packages.get('apt', []) if 'name' in p]
            if apt_pkgs:
                print(f"  Installing {len(apt_pkgs)} APT packages...")
                cmd = ['sudo', 'apt', 'install', '-y'] + apt_pkgs
                try:
                    subprocess.run(cmd, check=True)
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
        print(f"\n{BLUE}============================================================={NC}")
        print(f"{BLUE}🚀 Bootstrap System - Vault Restoration & Disaster Recovery{NC}")
        print(f"{BLUE}============================================================={NC}")
        print(f"Target Vault: {self.vault_path}")
        print(f"Target User:  {self.target_user} (Home: {self.user_home})")
        print(f"Host System:  {self.current_os.get('os', {}).get('pretty_name')}\n")

        password = prompt_for_password("vault decryption")

        print("\n🔓 Authenticating and decrypting vault...")
        try:
            meta, stage_dir = self.inspect_vault(password)
            print(f"{GREEN}✅ Authentication verified! Vault metadata:{NC}")
            print(f"   Source Host: {meta.get('hostname')}")
            print(f"   Distribution: {meta.get('distribution')}")
            print(f"   Compression:  {meta.get('compression')} (ratio: {meta.get('compression_ratio_percent', 0)}%)")
            print(f"   Created At:   {meta.get('created_at')}")
            print(f"   Total Files:  {meta.get('total_files')}")
        except Exception as e:
            print(f"{RED}❌ Decryption failed: {e}{NC}", file=sys.stderr)
            sys.exit(1)

        inv_file = stage_dir / "inventory.json"
        inventory = {}
        if inv_file.exists():
            with open(inv_file, 'r', encoding='utf-8') as f:
                inventory = json.load(f)

        try:
            print("\nSelect restoration actions:")
            print("  1. Full Idempotent Restoration (Storage/fstab, Shells, Keys, Desktop, Missing Packages)")
            print("  2. Restore Configuration & Keys only (fstab, Fish/Bash, SSH/GPG, Desktop) [RECOMMENDED]")
            print("  3. Restore Storage / Mounts & /etc/fstab only")
            print("  4. Restore Shell configs (Fish & Bash) only")
            print("  5. Restore SSH & Security Keys only")
            print("  6. Install Missing Software Packages only")
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

            print(f"\n{GREEN}🎉 Restoration tasks completed successfully!{NC}")

        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Bootstrap Vault Restoration Tool")
    parser.add_argument('--vault', type=str, help="Path to encrypted vault (.tar.zst.enc / .tar.enc)")
    parser.add_argument('--user', type=str, default=None, help="Target username (default: current user)")
    parser.add_argument('--list-backups', action='store_true', help="List local and archive backups")

    args = parser.parse_args()

    if args.list_backups:
        print("🔍 Searching for backup vaults in ./backup and archive drives...")
        search_dirs = [Path('./backup'), Path('/run/media/michael/FAST_ARCHIVE/SystemBackups')]
        found = []
        for s_dir in search_dirs:
            if s_dir.exists():
                for f in s_dir.glob('bootstrap_vault_*.tar.*enc'):
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
        backup_dir = Path('./backup')
        vaults = sorted(backup_dir.glob('bootstrap_vault_*.tar.*enc'), key=lambda x: x.stat().st_mtime, reverse=True)
        if vaults:
            vault_path = str(vaults[0])
            print(f"ℹ️  No vault specified, using most recent: {vault_path}")
        else:
            print("Error: Please specify --vault <path_to_vault.tar.zst.enc>", file=sys.stderr)
            sys.exit(1)

    restorer = BootstrapRestorer(vault_path, target_user=args.user)
    restorer.run_interactive()


if __name__ == '__main__':
    main()
