#!/usr/bin/env python3
"""
Bootstrap System - Universal System Scanner & Vault Creator

Detects distribution (Arch/CachyOS vs Ubuntu/Debian), active shells (Fish, Bash),
storage topology (/etc/fstab, UUIDs, Btrfs), systemd units, network configs, and keys.
Compiles a comprehensive inventory, generates a verified manifest (SHA-256 and SHA-1),
packages all configurations into an authenticated encrypted vault (ChaCha20-Poly1305 + Argon2id / zstd),
and dispatches it to configured storage targets.
"""

import os
import sys
import json
import socket
import shutil
import hashlib
import argparse
import datetime
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Ensure src directory is in sys.path
SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from system_detector import SystemDetector
from crypto_utils import SecureBootstrapCrypto, prompt_for_password, HAS_ZSTD
from scanners import (
    DistroPackageScanner,
    ShellScanner,
    StorageScanner,
    SystemdScanner,
    NetworkScanner,
    KeysScanner,
    DesktopScanner
)
from storage import StorageDispatcher


class UniversalSystemScanner:
    """Orchestrates system inventory scanning, manifest generation, vault encryption, and backup dispatch."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else SRC_DIR.parent
        self.data_dir = self.base_dir / 'data'
        self.backup_dir = self.base_dir / 'backup'
        self.data_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)

        self.crypto = SecureBootstrapCrypto()
        self.detector = SystemDetector()
        self.system_info = self.detector.to_dict()

    def scan_all(self) -> Dict[str, Any]:
        """Run all scanners and assemble unified system inventory."""
        print("🔍 Executing comprehensive system inventory scans...")

        pkg_scanner = DistroPackageScanner(self.system_info)
        shell_scanner = ShellScanner(self.system_info)
        storage_scanner = StorageScanner(self.system_info)
        systemd_scanner = SystemdScanner(self.system_info)
        net_scanner = NetworkScanner(self.system_info)
        keys_scanner = KeysScanner(self.system_info)
        desktop_scanner = DesktopScanner(self.system_info)

        print("  📦 Scanning software packages...")
        packages = pkg_scanner.scan()

        print("  🐚 Scanning shells (Fish, Bash, MOTD, System-wide)...")
        shells = shell_scanner.scan()

        print("  💾 Scanning storage topology (/etc/fstab, UUIDs, crypttab)...")
        storage = storage_scanner.scan()

        print("  ⚙️  Scanning systemd services and timers...")
        systemd = systemd_scanner.scan()

        print("  🌐 Scanning network profiles...")
        network = net_scanner.scan()

        print("  🔑 Scanning SSH, GPG, and security keys...")
        keys = keys_scanner.scan()

        print("  🖥️  Scanning desktop environment and shortcuts...")
        desktop = desktop_scanner.scan()

        inventory = {
            'version': '3.0',
            'timestamp': datetime.datetime.now().isoformat(),
            'system_info': self.system_info,
            'packages': packages,
            'shells': shells,
            'storage': storage,
            'systemd': systemd,
            'network': network,
            'keys': keys,
            'desktop': desktop
        }

        return inventory

    def collect_all_files(self) -> Dict[str, Path]:
        """Aggregate all collectible configuration and key files from all scanners."""
        all_files = {}

        scanners = [
            ShellScanner(self.system_info),
            StorageScanner(self.system_info),
            SystemdScanner(self.system_info),
            NetworkScanner(self.system_info),
            KeysScanner(self.system_info),
            DesktopScanner(self.system_info)
        ]

        for s in scanners:
            files_map = s.get_collectible_files()
            all_files.update(files_map)

        return all_files

    def _generate_manifest(self, staged_files: List[Dict[str, Any]], hostname: str) -> Tuple[Dict[str, Any], str]:
        """Generate manifest.json and manifest.txt with SHA-256 and SHA-1 checksums."""
        timestamp = datetime.datetime.now().isoformat()
        manifest_data = {
            'version': '3.0',
            'timestamp': timestamp,
            'hostname': hostname,
            'total_files': len(staged_files),
            'files': staged_files
        }

        # Text manifest table
        txt_lines = [
            "=" * 120,
            "BOOTSTRAP ENCRYPTED VAULT FILE MANIFEST",
            f"Generated: {timestamp}",
            f"Host:      {hostname}",
            f"Files:     {len(staged_files)}",
            "=" * 120,
            f"{'PERMS':<6} {'SIZE':>10}  {'SHA256':<64}  {'VIRTUAL PATH':<35}",
            "-" * 120
        ]

        for item in sorted(staged_files, key=lambda x: x['virtual_path']):
            perms = item.get('mode', '0644')
            sz = str(item.get('size_bytes', 0))
            sha256 = item.get('sha256', '')
            vp = item.get('virtual_path', '')
            txt_lines.append(f"{perms:<6} {sz:>10}  {sha256:<64}  {vp}")

        txt_lines.append("-" * 120)
        return manifest_data, "\n".join(txt_lines) + "\n"

    def create_encrypted_vault(self, inventory: Dict[str, Any], password: str) -> Path:
        """
        Stage inventory, configuration files, and manifest into an authenticated encrypted vault.
        """
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.system_info.get('os', {}).get('hostname', 'unknown')
        ext = '.tar.zst.enc' if HAS_ZSTD else '.tar.gz.enc'
        vault_filename = f"bootstrap_vault_{hostname}_{timestamp_str}{ext}"
        vault_path = self.backup_dir / vault_filename

        print(f"\n🔐 Packaging files into encrypted vault container ({ext})...")

        with tempfile.TemporaryDirectory() as stage_dir:
            stage_path = Path(stage_dir)

            # Write inventory.json
            inv_file = stage_path / "inventory.json"
            with open(inv_file, 'w', encoding='utf-8') as f:
                json.dump(inventory, f, indent=2, ensure_ascii=False)

            # Copy all collected config/key files into staging
            collectible_files = self.collect_all_files()
            print(f"  📁 Staging {len(collectible_files)} configuration and key files...")

            staged_manifest_entries = []

            for virt_rel_path, real_file in collectible_files.items():
                target_file = stage_path / virt_rel_path
                target_file.parent.mkdir(parents=True, exist_ok=True)

                copied = False
                file_bytes = b""
                mode_str = "0644"

                # Try regular copy
                if real_file.exists() and real_file.is_file():
                    try:
                        shutil.copy2(real_file, target_file)
                        copied = True
                        file_bytes = real_file.read_bytes()
                        mode_str = oct(real_file.stat().st_mode)[-4:]
                    except PermissionError:
                        # Try sudo -n fallback for root-only files like /etc/crypttab
                        try:
                            res = subprocess.run(['sudo', '-n', 'cat', str(real_file)], capture_output=True, check=True)
                            target_file.write_bytes(res.stdout)
                            copied = True
                            file_bytes = res.stdout
                            mode_str = "0600"
                        except Exception:
                            print(f"    ⚠️  Permission denied reading: {real_file}")
                    except Exception as e:
                        print(f"    ⚠️  Could not copy {real_file}: {e}")

                if copied:
                    staged_manifest_entries.append({
                        'virtual_path': virt_rel_path,
                        'source_path': str(real_file),
                        'size_bytes': len(file_bytes),
                        'mode': mode_str,
                        'sha256': hashlib.sha256(file_bytes).hexdigest(),
                        'sha1': hashlib.sha1(file_bytes).hexdigest()
                    })

            # Record inventory.json in manifest
            inv_bytes = inv_file.read_bytes()
            staged_manifest_entries.append({
                'virtual_path': 'inventory.json',
                'source_path': str(self.data_dir / 'inventory.json'),
                'size_bytes': len(inv_bytes),
                'mode': '0644',
                'sha256': hashlib.sha256(inv_bytes).hexdigest(),
                'sha1': hashlib.sha1(inv_bytes).hexdigest()
            })

            # Copy existing encrypted_secrets.json if present
            existing_secrets = self.data_dir / 'encrypted_secrets.json'
            if existing_secrets.exists():
                shutil.copy2(existing_secrets, stage_path / 'encrypted_secrets.json')
                sec_bytes = existing_secrets.read_bytes()
                staged_manifest_entries.append({
                    'virtual_path': 'encrypted_secrets.json',
                    'source_path': str(existing_secrets),
                    'size_bytes': len(sec_bytes),
                    'mode': '0600',
                    'sha256': hashlib.sha256(sec_bytes).hexdigest(),
                    'sha1': hashlib.sha1(sec_bytes).hexdigest()
                })

            # Generate manifest.json & manifest.txt and save to staging
            manifest_json, manifest_txt = self._generate_manifest(staged_manifest_entries, hostname)
            (stage_path / 'manifest.json').write_text(json.dumps(manifest_json, indent=2), encoding='utf-8')
            (stage_path / 'manifest.txt').write_text(manifest_txt, encoding='utf-8')

            # Create sealed vault
            metadata = {
                'hostname': hostname,
                'distribution': self.system_info.get('os', {}).get('pretty_name'),
                'os_family': self.system_info.get('os', {}).get('family'),
                'created_at': datetime.datetime.now().isoformat(),
                'total_files': len(staged_manifest_entries) + 2  # plus manifest files
            }

            _, vault_meta = self.crypto.create_encrypted_vault(stage_path, vault_path, password, metadata=metadata)

        print(f"✅ Created encrypted vault: {vault_path.name}")
        print(f"   Compression: {vault_meta.get('compression')} (ratio: {vault_meta.get('compression_ratio_percent')}%)")
        print(f"   Size: {vault_path.stat().st_size / (1024*1024):.2f} MB ({vault_path.stat().st_size:,} bytes)")
        return vault_path

    def run(self, encrypt_and_dispatch: bool = True, custom_password: str = None) -> Dict[str, Any]:
        """Execute full scan, vault generation, and storage dispatch."""
        self.detector.print_summary()
        echo_sep = "=" * 50
        print(f"\n{echo_sep}")

        # Scan
        inventory = self.scan_all()

        # Save local unencrypted inventory snapshot in data/
        inv_path = self.data_dir / 'inventory.json'
        with open(inv_path, 'w', encoding='utf-8') as f:
            json.dump(inventory, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Saved raw inventory snapshot: {inv_path}")

        # Summary
        pkg_data = inventory.get('packages', {})
        arch_native = len(pkg_data.get('arch_native', []))
        arch_aur = len(pkg_data.get('arch_aur', []))
        apt_pkgs = len(pkg_data.get('apt', []))
        flatpaks = len(pkg_data.get('flatpak', []))

        print(f"\n📊 Inventory Summary:")
        if self.system_info.get('os', {}).get('family') == 'arch':
            print(f"   Pacman explicit packages: {arch_native}")
            print(f"   AUR packages:             {arch_aur}")
        else:
            print(f"   APT packages:             {apt_pkgs}")
        print(f"   Flatpaks:                 {flatpaks}")
        print(f"   Fish shell (user):        {inventory['shells']['fish']['exists']}")
        print(f"   Fish shell (system /etc): {inventory['shells'].get('system_fish', {}).get('exists')}")
        print(f"   Bash shell files found:   {inventory['shells']['bash']['found_files']}")
        print(f"   Storage mounts captured:  {len(inventory['storage']['fstab'].get('entries', []))}")
        print(f"   Archive drives tracked:   {len(inventory['storage']['archive_drives'])}")
        print(f"   Systemd enabled units:    {len(inventory['systemd']['system_enabled_units'])}")
        print(f"   Network connections:      {len(inventory['network']['network_manager_connections'])}")
        print(f"   SSH items catalogued:     {len(inventory['keys']['ssh_keys'])}")

        if encrypt_and_dispatch:
            password = custom_password or prompt_for_password("system vault encryption")
            vault_path = self.create_encrypted_vault(inventory, password)

            # Dispatch to storage backends
            dispatcher = StorageDispatcher(base_dir=self.base_dir)
            dispatcher.dispatch(vault_path)

        return inventory


def main():
    parser = argparse.ArgumentParser(description="Universal System Scanner & Encrypted Vault Backup")
    parser.add_argument('--no-encrypt', action='store_true', help="Only scan inventory without building encrypted vault")
    parser.add_argument('--password', type=str, default=None, help="Master password for non-interactive backup")
    parser.add_argument('--base-dir', type=str, default=None, help="Base directory override")

    args = parser.parse_args()

    scanner = UniversalSystemScanner(base_dir=args.base_dir)
    scanner.run(encrypt_and_dispatch=not args.no_encrypt, custom_password=args.password)


if __name__ == '__main__':
    main()
