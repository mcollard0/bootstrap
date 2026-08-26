#!/usr/bin/env python3
"""
Universal Linux Bootstrap - Emergency System Restoration Tool

Run directly from Live USB, recovery shell, or fresh installation to authenticate,
decrypt, and restore:
- Storage mounts & /etc/fstab (FAST_ARCHIVE, LARGE_ARCHIVE, SLOW_ARCHIVE, SHARD_*)
- Shell configurations (Fish, Bash, Zsh, prompts, MOTD)
- Security keys (SSH, GPG private keys, Unix pass store, Cloudflare, Docker, Git)
- Custom typography and one-off files (0xProto fonts, application configs)
- Hardware & kernel overrides (udev rules, sysctl tuning, custom systemd units)
- Software packages (idempotent batch installation via pacman -T or apt)
"""

import os
import sys
import time
import json
import shutil
import hashlib
import argparse
import tempfile
import subprocess
import select
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

# Ensure src/ is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Ensure required crypto dependency is available
try:
    import cryptography
except ImportError:
    if shutil.which('pacman'):
        if os.geteuid() == 0:
            print("📦 Required dependency 'python-cryptography' is missing. Auto-installing via pacman -Sy...")
            try:
                subprocess.run(['pacman', '-Sy', '--needed', '--noconfirm', 'python-cryptography'], check=True)
                import cryptography
            except Exception as e:
                print(f"Error: Could not auto-install python-cryptography ({e}).", file=sys.stderr)
                print("Install with: sudo pacman -Sy python-cryptography", file=sys.stderr)
                sys.exit(1)
        else:
            print("Error: cryptography library is required.", file=sys.stderr)
            print("Install with: sudo pacman -Sy python-cryptography OR run with sudo: sudo python3 emergency_restore.py", file=sys.stderr)
            sys.exit(1)
    elif shutil.which('apt'):
        print("Error: cryptography library is required.", file=sys.stderr)
        print("Install with: sudo apt update && sudo apt install -y python3-cryptography", file=sys.stderr)
        sys.exit(1)
    else:
        print("Error: cryptography library is required.", file=sys.stderr)
        print("Install with: pip3 install cryptography", file=sys.stderr)
        sys.exit(1)

from crypto_utils import SecureBootstrapCrypto, prompt_for_password
from system_detector import SystemDetector

# Colors
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
BOLD = '\033[1m'
CYAN = '\033[0;36m'
NC = '\033[0m'


def print_emergency_banner():
    """Display prominent emergency restoration banner."""
    banner = f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════════════════════════════╗
║               🆘 UNIVERSAL LINUX EMERGENCY SYSTEM RESTORATION 🆘                     ║
╠══════════════════════════════════════════════════════════════════════════════════════╣{NC}
║ {BOLD}Disaster Recovery & Vault Unpacking Engine{NC}                                           ║
║                                                                                      ║
║ This tool restores system configurations, credentials, and mounts after a root (/)   ║
║ drive replacement or bare-metal Linux installation.                                  ║
║                                                                                      ║
║ {CYAN}Operations Performed:{NC}                                                                ║
║   • {BOLD}Authenticate & Decrypt{NC}: Poly1305 MAC validated before ChaCha20 decryption.        ║
║   • {BOLD}Storage Topology{NC}: Safely restores & merges mount points into /etc/fstab.         ║
║   • {BOLD}Shell Environments{NC}: Restores Fish, Bash, Zsh, Starship prompt & system MOTD.       ║
║   • {BOLD}Keys & Credentials{NC}: Restores SSH keys, GPG private keys, pass store, and tokens. ║
║   • {BOLD}Custom Files{NC}: Restores typography (0xProto fonts) and one-off dotfiles.           ║
║   • {BOLD}Hardware & Kernel{NC}: Restores udev rules, sysctl tuning & custom systemd units.    ║
║   • {BOLD}Idempotent Safety{NC}: Compares SHA-256 before writing; skips matching files.        ║
{RED}{BOLD}╚══════════════════════════════════════════════════════════════════════════════════════╝{NC}
"""
    print(banner)


def prompt_confirmation_with_countdown(timeout_seconds: int = 900) -> bool:
    """
    Prompt user for Y/n confirmation with a live in-place countdown timer (default 900s).
    Returns True if confirmed (Y/Enter), False if cancelled (n) or timed out.
    """
    if not sys.stdin.isatty():
        rlist, _, _ = select.select([sys.stdin], [], [], 0.2)
        if rlist:
            line = sys.stdin.readline().strip().lower()
            if line in ['', 'y', 'yes']:
                return True
            else:
                print(f"{RED}❌ Emergency restoration aborted by user.{NC}")
                return False
        return True

    print(f"{YELLOW}⚠️  CONFIRMATION REQUIRED:{NC}")
    print(f"   Please confirm that you want to proceed with emergency system restoration.")
    print(f"   A 15-minute countdown is active. Press {GREEN}[Enter]{NC} or {GREEN}[Y]{NC} to proceed, or {RED}[n]{NC} to abort.\n")

    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        remaining = int(timeout_seconds - elapsed)

        if remaining <= 0:
            sys.stdout.write(f"\r\033[K{RED}⏰ Timeout reached ({timeout_seconds}s). Emergency restoration cancelled.{NC}\n")
            sys.stdout.flush()
            return False

        mins = remaining // 60
        secs = remaining % 60
        prompt_str = f"\r\033[K{BOLD}[{mins:02d}:{secs:02d}]{NC} Proceed with emergency restoration? [{GREEN}Y{NC}/n] (Auto-cancels in {remaining}s): "
        sys.stdout.write(prompt_str)
        sys.stdout.flush()

        # Wait up to 1.0 second for user input
        rlist, _, _ = select.select([sys.stdin], [], [], 1.0)
        if rlist:
            user_input = sys.stdin.readline().strip().lower()
            if user_input in ['', 'y', 'yes']:
                sys.stdout.write(f"\r\033[K{GREEN}✅ Confirmation received. Proceeding with emergency restoration...{NC}\n\n")
                sys.stdout.flush()
                return True
            else:
                sys.stdout.write(f"\r\033[K{RED}❌ Emergency restoration aborted by user.{NC}\n\n")
                sys.stdout.flush()
                return False


class TeeLogger:
    """Duplicates all stdout and stderr output to both the interactive terminal and log files."""
    def __init__(self, log_paths: List[Path], original_stream):
        self.log_paths = log_paths
        self.original_stream = original_stream
        self.files = []
        for lp in log_paths:
            try:
                lp.parent.mkdir(parents=True, exist_ok=True)
                self.files.append(open(lp, 'a', encoding='utf-8', buffering=1))
            except Exception:
                pass

    def write(self, data):
        try:
            self.original_stream.write(data)
            self.original_stream.flush()
        except Exception:
            pass
        if self.files:
            try:
                import re
                clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', data)
                for f in self.files:
                    try:
                        f.write(clean)
                        f.flush()
                    except Exception:
                        pass
            except Exception:
                pass

    def flush(self):
        try:
            self.original_stream.flush()
        except Exception:
            pass
        for f in self.files:
            try:
                f.flush()
            except Exception:
                pass

    def isatty(self):
        return getattr(self.original_stream, 'isatty', lambda: False)()

    def fileno(self):
        return getattr(self.original_stream, 'fileno', lambda: None)()


class EmergencyRestorer:
    """Handles idempotent disaster recovery and restoration from an encrypted vault."""

    def __init__(self, vault_path: str, target_user: str = None):
        self.vault_path = Path(vault_path).expanduser().resolve()
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {self.vault_path}")

        self.crypto = SecureBootstrapCrypto()
        self.detector = SystemDetector()
        self.current_os = self.detector.to_dict()

        # Determine target non-root user (never use root for user files or AUR builds)
        resolved_user = target_user or os.environ.get('SUDO_USER')
        if not resolved_user or resolved_user == 'root':
            env_user = os.environ.get('USER')
            if env_user and env_user != 'root':
                resolved_user = env_user
        if not resolved_user or resolved_user == 'root':
            import pwd
            try:
                pwd.getpwnam('michael')
                resolved_user = 'michael'
            except KeyError:
                regular_users = [u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 and u.pw_name != 'nobody']
                resolved_user = regular_users[0] if regular_users else 'michael'

        self.target_user = resolved_user
        self.user_home = Path(f"/home/{self.target_user}")

        # In a Live ISO environment, auto-expand tmpfs cowspace to 32G to prevent out-of-space issues
        cowspace = Path('/run/archiso/cowspace')
        if cowspace.exists() and os.geteuid() == 0:
            try:
                subprocess.run(['mount', '-o', 'remount,size=32G', '/run/archiso/cowspace'], check=False)
            except Exception:
                pass

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
        
        # Only set non-root user ownership if destination is inside user's home directory
        try:
            if str(dest_file).startswith(str(self.user_home)):
                self._set_user_ownership(dest_file)
            else:
                os.chown(dest_file, 0, 0)
                if not mode:
                    os.chmod(dest_file, 0o644)
        except Exception:
            pass

        return status

    def _set_user_ownership(self, path: Path):
        """Set file ownership to target user."""
        try:
            import pwd
            pw = pwd.getpwnam(self.target_user)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass

    def restore_fstab_and_mounts(self, stage_dir: Path, apply_changes: bool = False):
        """Non-destructively merge missing /etc/fstab mount points and create mount dirs."""
        print("\n💾 Inspecting storage topology and /etc/fstab...")
        staged_fstab = stage_dir / "system/etc/fstab"

        if not staged_fstab.exists():
            print("  ⚠️  No /etc/fstab found in vault.")
            return

        fstab_content = staged_fstab.read_text(encoding='utf-8')

        existing_mounts = set()
        current_fstab = Path('/etc/fstab')
        if current_fstab.exists():
            for line in current_fstab.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        existing_mounts.add(parts[1])

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
                    # Automatically harden secondary archive mounts with non-blocking, nofail, and automount options
                    if len(parts) >= 4 and (mp.startswith('/run/media/') or mp.startswith('/mnt/') or mp.startswith('/media/')):
                        dev, mount_point, fstype, opts = parts[0], parts[1], parts[2], parts[3]
                        opts_list = [o.strip() for o in opts.split(',')]
                        for safe_opt in ['nofail', 'x-systemd.device-timeout=5s', 'x-systemd.automount']:
                            opt_prefix = safe_opt.split('=')[0]
                            if not any(o.startswith(opt_prefix) for o in opts_list):
                                opts_list.append(safe_opt)
                        new_opts = ','.join(opts_list)
                        hardened_line = f"{dev:<45} {mount_point:<35} {fstype:<10} {new_opts:<65} 0 0"
                        lines_to_add.append(hardened_line)
                    else:
                        lines_to_add.append(line)

        print(f"  • External archive mount points in vault: {len(mount_dirs_to_create)}")
        for mp in mount_dirs_to_create:
            exists = os.path.exists(mp)
            print(f"     • {mp} ({GREEN}exists{NC}" if exists else f"     • {mp} ({YELLOW}missing - will create{NC})")

        print(f"  • Entries to merge into /etc/fstab (Hardened with nofail & automount): {len(lines_to_add)}")
        for l in lines_to_add:
            print(f"     + {l}")

        if apply_changes:
            # 1. Create missing mount directories
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

    def restore_user_files(self, stage_dir: Path):
        """Recursively restore all user configurations and credentials under home/."""
        staged_home = stage_dir / "home"
        if not staged_home.exists():
            return

        print(f"\n🏠 Restoring User Files & Credentials to {self.user_home}...")
        count_created = 0
        count_skipped = 0
        count_updated = 0

        for root, _, files in os.walk(staged_home):
            for f in files:
                src_f = Path(root) / f
                rel_f = src_f.relative_to(staged_home)
                dest_f = self.user_home / rel_f

                # Sanitize .gitconfig so it doesn't force git@github.com before SSH keys are loaded
                if str(rel_f) == ".gitconfig":
                    try:
                        import re
                        gtext = src_f.read_text(encoding='utf-8')
                        gtext = re.sub(r'(\[url\s*"git@github\.com:"\])', r'# \1 (disabled during disaster recovery)', gtext)
                        gtext = re.sub(r'(insteadOf\s*=\s*https://github\.com/)', r'# \1', gtext)
                        with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as tmp_g:
                            tmp_g.write(gtext)
                            tmp_g_path = Path(tmp_g.name)
                        try:
                            res = self._safe_copy_file(tmp_g_path, dest_f, mode=0o644)
                            if res == 'created':
                                count_created += 1
                                print(f"  {GREEN}+ [CREATED]{NC} {rel_f} (with HTTPS sanitization)")
                            elif res == 'updated':
                                count_updated += 1
                                print(f"  {YELLOW}~ [UPDATED]{NC} {rel_f} (with HTTPS sanitization)")
                            else:
                                count_skipped += 1
                        finally:
                            tmp_g_path.unlink()
                        continue
                    except Exception as e:
                        print(f"  ⚠️  Notice on .gitconfig: {e}")

                # Preserve strict permissions for keys
                mode = None
                if ".ssh" in str(rel_f) or ".gnupg" in str(rel_f) or ".password-store" in str(rel_f) or ".cloudflared" in str(rel_f):
                    is_pub = src_f.suffix == '.pub' or src_f.name in ['config', 'known_hosts', 'authorized_keys', 'common.conf']
                    mode = 0o644 if is_pub else 0o600

                res = self._safe_copy_file(src_f, dest_f, mode=mode)
                if res == 'skipped':
                    count_skipped += 1
                elif res == 'created':
                    count_created += 1
                    print(f"  {GREEN}+ [CREATED]{NC} {rel_f}")
                else:
                    count_updated += 1
                    print(f"  {YELLOW}~ [UPDATED]{NC} {rel_f}")

        # Secure directory permissions and user ownership
        for d in ['.ssh', '.gnupg', '.password-store', '.cloudflared']:
            dp = self.user_home / d
            if dp.exists():
                try:
                    os.chmod(dp, 0o700)
                    self._set_user_ownership(dp)
                    for root, dirs, fnames in os.walk(dp):
                        for name in dirs:
                            p = Path(root) / name
                            try:
                                os.chmod(p, 0o700)
                                self._set_user_ownership(p)
                            except Exception:
                                pass
                        for name in fnames:
                            p = Path(root) / name
                            try:
                                self._set_user_ownership(p)
                            except Exception:
                                pass
                except Exception:
                    pass

        print(f"  {GREEN}✅ User files restored: {count_created} created, {count_updated} updated, {count_skipped} already matching.{NC}")

    def restore_system_files(self, stage_dir: Path):
        """Restore system-level configurations, custom fonts, udev rules, and sysctl under system/."""
        staged_system = stage_dir / "system"
        if not staged_system.exists():
            return

        print(f"\n⚙️  Restoring System Files, Fonts & Hardware Rules...")
        count_created = 0
        count_skipped = 0
        count_updated = 0

        for root, _, files in os.walk(staged_system):
            for f in files:
                src_f = Path(root) / f
                rel_f = src_f.relative_to(staged_system)
                dest_f = Path("/") / rel_f

                # Skip fstab as it is handled non-destructively
                if str(rel_f) == "etc/fstab":
                    continue

                # Ensure custom repos in pacman.conf don't fail due to PGP trust issues
                if str(rel_f) == "etc/pacman.conf":
                    try:
                        import re
                        pconf_text = src_f.read_text(encoding='utf-8')
                        # Ensure custom repos like warpdotdev have SigLevel = Optional TrustAll
                        pconf_text = re.sub(r'(\[warpdotdev[^\]]*\]\n)', r'\1SigLevel = Optional TrustAll\n', pconf_text)
                        with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as tmp_pconf:
                            tmp_pconf.write(pconf_text)
                            tmp_pconf_path = Path(tmp_pconf.name)
                        try:
                            res = self._safe_copy_file(tmp_pconf_path, dest_f, mode=0o644)
                        finally:
                            tmp_pconf_path.unlink()
                        if res != 'skipped':
                            print(f"  {GREEN}+ [{res.upper()}]{NC} /etc/pacman.conf (with SigLevel hardening)")
                            subprocess.run(['pacman-key', '--recv-keys', '19A1E427461B1795F73F629631F4254AFE49E02E'], check=False)
                            subprocess.run(['pacman-key', '--lsign-key', '19A1E427461B1795F73F629631F4254AFE49E02E'], check=False)
                            subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm'], check=False)
                        continue
                    except Exception as e:
                        print(f"  ⚠️  Notice on pacman.conf: {e}")

                try:
                    res = self._safe_copy_file(src_f, dest_f)
                    if res == 'skipped':
                        count_skipped += 1
                    elif res == 'created':
                        count_created += 1
                        print(f"  {GREEN}+ [CREATED]{NC} /{rel_f}")
                    else:
                        count_updated += 1
                        print(f"  {YELLOW}~ [UPDATED]{NC} /{rel_f}")
                except PermissionError:
                    print(f"  {YELLOW}⚠️  Root permission required to restore: /{rel_f}{NC}")

        print(f"  {GREEN}✅ System files restored: {count_created} created, {count_updated} updated, {count_skipped} already matching.{NC}")

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

            # 1. Synchronize package databases first so any restored repos are known (non-interactive)
            print("  🔄 Synchronizing pacman package databases...")
            subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm'], check=False)

            # Ensure base-devel and default Java runtime are installed so AUR compiles and packages like openwebstart-bin do not trigger 28-provider selection prompts
            subprocess.run(['sudo', 'pacman', '-S', '--needed', '--noconfirm', 'base-devel', 'jre17-openjdk'], check=False)

            # 2. Check native packages with pacman -T
            missing_native = []
            if native_pkgs:
                try:
                    res = subprocess.run(['pacman', '-T'] + native_pkgs, capture_output=True, text=True)
                    missing_native = [p.strip() for p in res.stdout.strip().split('\n') if p.strip()]
                except Exception:
                    missing_native = native_pkgs

            missing_aur = []
            if aur_pkgs:
                try:
                    res = subprocess.run(['pacman', '-T'] + aur_pkgs, capture_output=True, text=True)
                    missing_aur = [p.strip() for p in res.stdout.strip().split('\n') if p.strip()]
                except Exception:
                    missing_aur = aur_pkgs

            if not missing_native:
                print(f"  {GREEN}✓ All {len(native_pkgs)} native pacman packages are already installed.{NC}")
            else:
                print(f"  📦 Installing {len(missing_native)} missing native packages (out of {len(native_pkgs)})...")
                cmd = ['sudo', 'pacman', '-S', '--needed', '--noconfirm'] + missing_native
                # Stream default newlines to auto-select default provider alternatives if prompted
                newlines = chr(10) * 100
                res = subprocess.run(cmd, input=newlines, text=True, capture_output=True)

                if res.returncode == 0:
                    print(f"  {GREEN}✅ Missing native packages installed successfully.{NC}")
                else:
                    import re
                    not_found = re.findall(r"target not found:\s*(\S+)", res.stderr)
                    print(f"  ⚠️  Batch installation encountered dependency/target conflicts. Switching to resilient batching...")
                    filtered = [p for p in missing_native if p not in not_found]

                    # Install in chunks of 25, falling back to item-by-item for failing chunks
                    batch_size = 25
                    successful = 0
                    for i in range(0, len(filtered), batch_size):
                        chunk = filtered[i:i + batch_size]
                        chunk_res = subprocess.run(['sudo', 'pacman', '-S', '--needed', '--noconfirm'] + chunk, input=newlines, text=True, capture_output=True)
                        if chunk_res.returncode == 0:
                            successful += len(chunk)
                        else:
                            for single_pkg in chunk:
                                s_res = subprocess.run(['sudo', 'pacman', '-S', '--needed', '--noconfirm', single_pkg], input=newlines, text=True, capture_output=True)
                                if s_res.returncode == 0:
                                    successful += 1
                                else:
                                    if single_pkg not in missing_aur:
                                        missing_aur.append(single_pkg)

                    print(f"  {GREEN}✅ Resilient native installation completed: {successful} packages installed.{NC}")

                    # Automatically clean pacman package cache to keep disk space free
                    subprocess.run(['sudo', 'pacman', '-Sc', '--noconfirm'], check=False)

                    # Move missing targets to AUR queue
                    for nf in not_found:
                        if nf not in missing_aur:
                            missing_aur.append(nf)

            # 3. Check & Install AUR packages
            if not missing_aur:
                print(f"  {GREEN}✓ All AUR packages are already installed.{NC}")
            else:
                aur_helper = shutil.which('paru') or shutil.which('yay')
                if not aur_helper:
                    print(f"  🌟 Installing paru from AUR...")
                    try:
                        tmp_paru = tempfile.mkdtemp(prefix="paru_install_")
                        self._set_user_ownership(Path(tmp_paru))
                        subprocess.run(['sudo', '-u', self.target_user, 'git', 'clone', 'https://aur.archlinux.org/paru-bin.git', f"{tmp_paru}/paru-bin"], check=True)
                        subprocess.run(['sudo', '-u', self.target_user, 'makepkg', '-si', '--noconfirm'], cwd=f"{tmp_paru}/paru-bin", check=True)
                        shutil.rmtree(tmp_paru, ignore_errors=True)
                        aur_helper = shutil.which('paru')
                    except Exception as e:
                        print(f"  ⚠️  Could not auto-install paru helper: {e}")

                if aur_helper:
                    # Prioritize critical interactive applications like chrome and warp first
                    missing_aur.sort(key=lambda x: 0 if 'chrome' in x.lower() else (1 if 'warp' in x.lower() else 2))
                    print(f"  🌟 Installing {len(missing_aur)} missing AUR packages via {Path(aur_helper).name}...")
                    flags = ['--needed', '--noconfirm']
                    if 'paru' in str(aur_helper):
                        flags.extend(['--skipreview', '--noprovides'])
                    cmd = ['sudo', '-u', self.target_user, aur_helper, '-S'] + flags + missing_aur
                    try:
                        aur_newlines = chr(10) * (len(missing_aur) * 5 + 100)
                        res = subprocess.run(cmd, input=aur_newlines, text=True)
                        if res.returncode == 0:
                            print(f"  {GREEN}✅ AUR packages step completed.{NC}")
                        else:
                            print(f"  ⚠️  AUR batch finished with return code {res.returncode}. Switching to resilient item-by-item AUR installation...")
                            for aur_pkg in missing_aur:
                                item_cmd = ['sudo', '-u', self.target_user, aur_helper, '-S'] + flags + [aur_pkg]
                                try:
                                    subprocess.run(item_cmd, input=aur_newlines, text=True)
                                except Exception:
                                    pass
                    except Exception as e:
                        print(f"  ⚠️  AUR installation notice: {e}")
                else:
                    print(f"  ⚠️  No AUR helper available. Missing AUR/custom packages: {missing_aur}")

            # Explicit verification & installation for critical developer applications: Chrome & Warp
            print(f"\n🌐 Verifying Developer Applications (Google Chrome & Warp Terminal)...")
            chrome_bin = shutil.which('google-chrome-beta') or shutil.which('google-chrome') or shutil.which('chrome')
            if not chrome_bin and aur_helper:
                print(f"  🌟 Installing Google Chrome Beta via {Path(aur_helper).name}...")
                try:
                    subprocess.run(['sudo', '-u', self.target_user, aur_helper, '-S', '--needed', '--noconfirm', '--skipreview', '--noprovides', 'google-chrome-beta'], input=chr(10)*20, text=True, check=False)
                    chrome_bin = shutil.which('google-chrome-beta') or shutil.which('google-chrome') or shutil.which('chrome')
                except Exception as e:
                    print(f"  ⚠️  Google Chrome installation notice: {e}")

            if chrome_bin:
                for target_link in ['/usr/bin/chrome', '/usr/bin/google-chrome', '/usr/local/bin/chrome', '/usr/local/bin/google-chrome']:
                    try:
                        if not os.path.exists(target_link):
                            subprocess.run(['ln', '-sf', chrome_bin, target_link], check=False)
                    except Exception:
                        pass
                print(f"  {GREEN}✅ Google Chrome is verified and runnable: {chrome_bin}{NC}")
            else:
                print(f"  ⚠️  Google Chrome binary not found.")

            warp_bin = shutil.which('warp-terminal') or shutil.which('warp-terminal-preview') or shutil.which('warp')
            if not warp_bin:
                print(f"  🌟 Installing Warp Terminal via pacman...")
                try:
                    subprocess.run(['sudo', 'pacman', '-S', '--needed', '--noconfirm', 'warp-terminal'], check=False)
                    warp_bin = shutil.which('warp-terminal') or shutil.which('warp-terminal-preview') or shutil.which('warp')
                except Exception as e:
                    print(f"  ⚠️  Warp Terminal installation notice: {e}")

            if warp_bin:
                for target_link in ['/usr/bin/warp', '/usr/local/bin/warp']:
                    try:
                        if not os.path.exists(target_link):
                            subprocess.run(['ln', '-sf', warp_bin, target_link], check=False)
                    except Exception:
                        pass
                print(f"  {GREEN}✅ Warp Terminal is verified and runnable: {warp_bin}{NC}")
            else:
                print(f"  ⚠️  Warp Terminal binary not found.")

        elif current_family == 'debian':
            apt_pkgs = [p['name'] for p in packages.get('apt', []) if 'name' in p]
            if apt_pkgs:
                print(f"  Installing {len(apt_pkgs)} APT packages...")
                cmd = ['sudo', 'apt', 'install', '-y'] + apt_pkgs
                try:
                    subprocess.run(cmd, check=True)
                except Exception as e:
                    print(f"  ⚠️  APT error: {e}")

    def restore_shell_and_desktop_preferences(self, inventory: Dict[str, Any]):
        """Restore the user's default login shell and notify desktop of shortcut reload."""
        print(f"\n🐚 Restoring User Shell & Desktop Preferences...")

        # 1. Shell restoration
        shell_info = inventory.get('shells', {})
        target_shell_bin = shell_info.get('current') or shell_info.get('default_name')
        if target_shell_bin:
            resolved_shell = (
                shutil.which(target_shell_bin) or 
                shutil.which(Path(target_shell_bin).name) or 
                (f"/usr/bin/{target_shell_bin}" if Path(f"/usr/bin/{target_shell_bin}").exists() else None)
            )
            if resolved_shell:
                try:
                    # Ensure in /etc/shells
                    etc_shells = Path('/etc/shells').read_text(encoding='utf-8') if Path('/etc/shells').exists() else ""
                    if resolved_shell not in etc_shells:
                        with open('/etc/shells', 'a', encoding='utf-8') as f:
                            f.write(f"\n{resolved_shell}\n")

                    # Check current shell
                    import pwd
                    current_shell = pwd.getpwnam(self.target_user).pw_shell
                    if current_shell != resolved_shell:
                        subprocess.run(['usermod', '-s', resolved_shell, self.target_user], check=False)
                        print(f"  {GREEN}✓{NC} Default login shell set to {resolved_shell} for {self.target_user}.")
                    else:
                        print(f"  {GREEN}✓{NC} Default login shell is already {resolved_shell}.")
                except Exception as e:
                    print(f"  ⚠️  Shell restoration note: {e}")
            else:
                print(f"  ⚠️  Target shell '{target_shell_bin}' not yet found on system.")

        # 2. KDE Plasma Global Accel reload
        try:
            import pwd
            uid = pwd.getpwnam(self.target_user).pw_uid
            bus_path = f"/run/user/{uid}/bus"
            qdbus = shutil.which('qdbus6') or shutil.which('qdbus')
            if qdbus and Path(bus_path).exists():
                env = os.environ.copy()
                env['DBUS_SESSION_BUS_ADDRESS'] = f"unix:path={bus_path}"
                subprocess.run(
                    ['sudo', '-u', self.target_user, qdbus, 'org.kde.KGlobalAccel', '/kglobalaccel', 'org.kde.KGlobalAccel.reloadConfig'],
                    env=env, check=False, capture_output=True
                )
                print(f"  {GREEN}✓{NC} KDE Plasma global shortcuts reloaded live.")
        except Exception:
            pass

    def run_interactive(self, skip_confirmation: bool = False, password: str = None, scope: str = None):
        """Run interactive restoration workflow."""
        print_emergency_banner()

        if os.geteuid() != 0:
            print(f"{YELLOW}⚠️  NOTE: Not running as root (sudo).{NC}")
            print(f"   Writing /etc/fstab, creating /run/media mounts, and installing fonts require root permissions.")
            print(f"   {BOLD}Recommended:{NC} {GREEN}sudo python3 emergency_restore.py{NC}\n")

        if not skip_confirmation:
            if not prompt_confirmation_with_countdown(timeout_seconds=900):
                sys.exit(1)

        print(f"Target Vault: {self.vault_path}")
        print(f"Target User:  {self.target_user} (Home: {self.user_home})")
        print(f"Host System:  {self.current_os.get('os', {}).get('pretty_name')}\n")

        max_attempts = 1 if password else 3
        stage_dir = None
        meta = None

        for attempt in range(1, max_attempts + 1):
            current_password = password or prompt_for_password("vault decryption")
            print("\n🔓 Authenticating and decrypting vault...")
            try:
                meta, stage_dir = self.inspect_vault(current_password)
                print(f"{GREEN}✅ Authentication verified! Vault metadata:{NC}")
                print(f"   Source Host: {meta.get('hostname')}")
                print(f"   Distribution: {meta.get('distribution')}")
                print(f"   Compression:  {meta.get('compression')} (ratio: {meta.get('compression_ratio_percent', 0)}%)")
                print(f"   Created At:   {meta.get('created_at')}")
                print(f"   Total Files:  {meta.get('total_files')}")
                break
            except Exception as e:
                print(f"{RED}❌ Decryption failed: {e}{NC}", file=sys.stderr)
                if attempt < max_attempts:
                    print(f"{YELLOW}⚠️  Incorrect password or typo. Please try again ({attempt}/{max_attempts}). Check Caps Lock!{NC}\n")
                else:
                    print(f"{RED}💥 Maximum decryption attempts exceeded.{NC}", file=sys.stderr)
                    sys.exit(1)

        inv_file = stage_dir / "inventory.json"
        inventory = {}
        if inv_file.exists():
            try:
                with open(inv_file, 'r', encoding='utf-8') as f:
                    inventory = json.load(f)
            except Exception:
                pass

        try:
            print("\nSelect restoration scope:")
            print("  1. Full Restoration (Mounts/fstab, User Dotfiles/Keys, System Files/Fonts, Missing Packages)")
            print("  2. Restore Configurations & Keys only (fstab, Shells, SSH/GPG, Desktop, Fonts) [RECOMMENDED]")
            print("  3. Restore Storage / Mounts & /etc/fstab only")
            print("  4. Restore User Dotfiles & Keys only (~/.config, ~/.ssh, ~/.gnupg, pass)")
            print("  5. Install Missing Software Packages only")
            print("  q. Quit")

            if scope:
                choice = str(scope).strip()
                print(f"\nRestoration scope provided via CLI: {choice}")
            else:
                choice = input("\nEnter choice [1-5, default: 2]: ").strip() or "2"

            if choice == '1':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
                self.restore_user_files(stage_dir)
                self.restore_system_files(stage_dir)
                self.install_packages(inventory)
                self.restore_shell_and_desktop_preferences(inventory)
            elif choice == '2':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
                self.restore_user_files(stage_dir)
                self.restore_system_files(stage_dir)
                self.restore_shell_and_desktop_preferences(inventory)
            elif choice == '3':
                self.restore_fstab_and_mounts(stage_dir, apply_changes=True)
            elif choice == '4':
                self.restore_user_files(stage_dir)
                self.restore_shell_and_desktop_preferences(inventory)
            elif choice == '5':
                self.install_packages(inventory)
                self.restore_shell_and_desktop_preferences(inventory)
            elif choice.lower() == 'q':
                print("Restoration cancelled.")
                return

            print(f"\n{GREEN}🎉 Emergency restoration completed successfully!{NC}")

        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)


def find_latest_vault() -> Optional[Path]:
    """Search for the most recent vault file in ./data, ./backup, and archive mounts."""
    search_dirs = [
        PROJECT_ROOT / 'data',
        PROJECT_ROOT / 'backup',
        Path('/run/media/michael/FAST_ARCHIVE/SystemBackups')
    ]
    found = []
    for s_dir in search_dirs:
        if s_dir.exists():
            for pat in ['bootstrap_vault_*.tar.zst.enc', 'bootstrap_vault_*.tar.gz.enc', 'bootstrap_vault_*.tar.enc']:
                for f in s_dir.glob(pat):
                    if f.is_file():
                        found.append((f, f.stat().st_size, f.stat().st_mtime))

    if not found:
        return None
    found.sort(key=lambda x: x[2], reverse=True)
    return found[0][0]


def main():
    parser = argparse.ArgumentParser(description="Universal Linux Bootstrap - Emergency System Restoration Tool")
    parser.add_argument('--vault', type=str, help="Path to encrypted vault (.tar.zst.enc / .tar.enc)")
    parser.add_argument('--user', type=str, default=None, help="Target username (default: current user)")
    parser.add_argument('--password', '-p', type=str, default=None, help="Vault decryption password (or set BOOTSTRAP_SECRET env var)")
    parser.add_argument('--yes', '-y', action='store_true', help="Skip countdown confirmation prompt")
    parser.add_argument('--scope', '-s', type=str, default=None, choices=['1', '2', '3', '4', '5'], help="Restoration scope (1: Full, 2: Configs/Keys, 3: Storage/fstab, 4: User Dotfiles, 5: Packages)")
    parser.add_argument('--list-backups', action='store_true', help="List local and archive backups")

    args = parser.parse_args()

    # Initialize automatic dual-logging to emergency_restore.log and failure.txt
    log_files = [
        PROJECT_ROOT / "emergency_restore.log",
        PROJECT_ROOT / "failure.txt",
        Path("/tmp/emergency_restore.log")
    ]
    sys.stdout = TeeLogger(log_files, sys.stdout)
    sys.stderr = TeeLogger(log_files, sys.stderr)

    if args.list_backups:
        print("🔍 Searching for backup vaults in ./data, ./backup, and archive mounts...")
        search_dirs = [
            PROJECT_ROOT / 'data',
            PROJECT_ROOT / 'backup',
            Path('/run/media/michael/FAST_ARCHIVE/SystemBackups')
        ]
        found = []
        for s_dir in search_dirs:
            if s_dir.exists():
                for pat in ['bootstrap_vault_*.tar.zst.enc', 'bootstrap_vault_*.tar.gz.enc', 'bootstrap_vault_*.tar.enc']:
                    for f in s_dir.glob(pat):
                        if f.is_file():
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
        latest = find_latest_vault()
        if latest:
            vault_path = str(latest)
            print(f"ℹ️  No vault specified, using latest found: {vault_path}")
        else:
            print("Error: Please specify --vault <path_to_vault.tar.zst.enc>", file=sys.stderr)
            sys.exit(1)

    restorer = EmergencyRestorer(vault_path, target_user=args.user)
    restorer.run_interactive(skip_confirmation=args.yes, password=args.password, scope=args.scope)


if __name__ == '__main__':
    main()
