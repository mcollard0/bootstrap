#!/usr/bin/env python3
"""
Bootstrap System - Universal System Scanner & Vault Creator

Detects distribution (Arch/CachyOS vs Ubuntu/Debian), active shells (Fish, Bash),
storage topology (/etc/fstab, UUIDs, Btrfs), systemd units, network configs, and keys.
Compiles a comprehensive inventory, packages all configurations into an authenticated
encrypted vault (ChaCha20-Poly1305 + Argon2id), and dispatches it to configured storage targets.
"""

import os
import sys
import json
import socket
import shutil
import argparse
import datetime
import tempfile
from pathlib import Path
from typing import Dict, Any

# Ensure src directory is in sys.path
SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from system_detector import SystemDetector
from crypto_utils import SecureBootstrapCrypto, prompt_for_password
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
    """Orchestrates system inventory scanning, vault encryption, and backup dispatch."""

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

        print("  🐚 Scanning shells (Fish, Bash, MOTD)...")
        shells = shell_scanner.scan()

        print("  💾 Scanning storage topology (/etc/fstab, UUIDs, mounts)...")
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

    def create_encrypted_vault(self, inventory: Dict[str, Any], password: str) -> Path:
        """
        Stage inventory and configuration files into an authenticated encrypted vault.
        """
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.system_info.get('os', {}).get('hostname', 'unknown')
        vault_filename = f"bootstrap_vault_{hostname}_{timestamp_str}.tar.enc"
        vault_path = self.backup_dir / vault_filename

        print("\n🔐 Packaging files into encrypted vault container...")

        with tempfile.TemporaryDirectory() as stage_dir:
            stage_path = Path(stage_dir)

            # Write inventory.json
            inv_file = stage_path / "inventory.json"
            with open(inv_file, 'w', encoding='utf-8') as f:
                json.dump(inventory, f, indent=2, ensure_ascii=False)

            # Copy all collected config/key files into staging
            collectible_files = self.collect_all_files()
            print(f"  📁 Staging {len(collectible_files)} configuration and key files...")

            copied_count = 0
            for virt_rel_path, real_file in collectible_files.items():
                if real_file.exists() and real_file.is_file():
                    target_file = stage_path / virt_rel_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.copy2(real_file, target_file)
                        copied_count += 1
                    except Exception as e:
                        print(f"    ⚠️  Could not copy {real_file}: {e}")

            # Also stage existing encrypted_secrets.json if present
            existing_secrets = self.data_dir / 'encrypted_secrets.json'
            if existing_secrets.exists():
                shutil.copy2(existing_secrets, stage_path / 'encrypted_secrets.json')

            # Create sealed vault
            metadata = {
                'hostname': hostname,
                'distribution': self.system_info.get('os', {}).get('pretty_name'),
                'os_family': self.system_info.get('os', {}).get('family'),
                'created_at': datetime.datetime.now().isoformat(),
                'total_files': copied_count + 1
            }

            self.crypto.create_encrypted_vault(stage_path, vault_path, password, metadata=metadata)

        print(f"✅ Created encrypted vault: {vault_path.name}")
        print(f"   Size: {vault_path.stat().st_size / (1024*1024):.2f} MB")
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
        print(f"   Fish shell configured:    {inventory['shells']['fish']['exists']}")
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
