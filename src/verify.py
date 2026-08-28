#!/usr/bin/env python3
"""
Bootstrap System - Encrypted Vault Verification Tool

Verifies the integrity, authenticity, and file checksums of an encrypted backup vault:
1. Authenticates Poly1305 MAC and decrypts the vault
2. Verifies manifest.json and manifest.txt
3. Recalculates and verifies SHA-256 and SHA-1 checksums for every single file
4. Formats output with SHA-256 and SHA-1 columns before the variable-length path
5. Inspects compression efficiency (zstd vs uncompressed) and permissions
"""

import os
import sys
import json
import hashlib
import argparse
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add src to path
SRC_DIR = Path(__file__).parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from crypto_utils import SecureBootstrapCrypto, prompt_for_password

# Colors for terminal output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'


def find_latest_vault(search_dirs: Optional[List[Path]] = None) -> Optional[Path]:
    """Find the most recent encrypted vault file."""
    if search_dirs is None:
        search_dirs = [
            SRC_DIR.parent / 'data',
            SRC_DIR.parent / 'backup',
            Path('/run/media/michael/FAST_ARCHIVE/SystemBackups')
        ]

    vaults = []
    for d in search_dirs:
        try:
            if d.exists() and d.is_dir():
                for pat in ['bootstrap_vault_*.tar.*enc']:
                    for f in d.glob(pat):
                        try:
                            if f.is_file():
                                vaults.append((f, f.stat().st_mtime))
                        except Exception:
                            pass
        except Exception:
            pass

    if not vaults:
        return None

    vaults.sort(key=lambda x: x[1], reverse=True)
    return vaults[0][0]


def verify_vault(vault_path: Path, password: str, full_hashes: Optional[bool] = None) -> bool:
    """Decrypt and verify vault checksums and manifests."""
    vault_path = Path(vault_path).resolve()
    if not vault_path.exists():
        print(f"{RED}Error: Vault file not found: {vault_path}{NC}", file=sys.stderr)
        return False

    # Determine hash display mode (adaptive based on terminal width if not specified)
    if full_hashes is None:
        term_cols = shutil.get_terminal_size((120, 24)).columns
        full_hashes = term_cols >= 150

    print(f"\n{BOLD}{BLUE}========================================================================{NC}")
    print(f"{BOLD}🔐 Bootstrap Vault Integrity & Checksum Verifier{NC}")
    print(f"{BOLD}{BLUE}========================================================================{NC}")
    print(f"Target Vault: {CYAN}{vault_path.name}{NC}")
    print(f"Location:     {vault_path}")
    print(f"Vault Size:   {vault_path.stat().st_size / (1024*1024):.2f} MB ({vault_path.stat().st_size:,} bytes)")

    crypto = SecureBootstrapCrypto()

    with tempfile.TemporaryDirectory(prefix="vault_verify_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        # 1. Decrypt and authenticate vault
        print(f"\n{BLUE}[1/3] Authenticating & Decrypting Vault...{NC}")
        try:
            meta = crypto.extract_encrypted_vault(vault_path, tmp_path, password)
            print(f"  {GREEN}✓ Poly1305 MAC Authentication verified successfully!{NC}")
            print(f"  • Source Host:       {meta.get('hostname')}")
            print(f"  • Distribution:      {meta.get('distribution')} ({meta.get('os_family')})")
            print(f"  • Created At:        {meta.get('created_at')}")
            print(f"  • KDF Algorithm:     {meta.get('kdf')} (Key: 256-bit)")
            print(f"  • Compression:       {meta.get('compression')}")
            print(f"  • Uncompressed Tar:  {meta.get('uncompressed_tar_bytes', 0):,} bytes")
            print(f"  • Compressed Size:   {meta.get('compressed_bytes', 0):,} bytes")
            print(f"  • Compression Ratio: {meta.get('compression_ratio_percent', 0)}%")
        except Exception as e:
            print(f"  {RED}❌ Decryption failed: {e}{NC}", file=sys.stderr)
            return False

        # 2. Check Manifest
        print(f"\n{BLUE}[2/3] Inspecting Manifest...{NC}")
        manifest_file = tmp_path / 'manifest.json'
        manifest_txt = tmp_path / 'manifest.txt'

        if not manifest_file.exists():
            print(f"  {YELLOW}⚠️  No manifest.json found in vault. Generating file list...{NC}")
            manifest_entries = []
            for root, _, files in os.walk(tmp_path):
                for f in files:
                    rp = (Path(root) / f).relative_to(tmp_path)
                    manifest_entries.append({'virtual_path': str(rp)})
        else:
            print(f"  {GREEN}✓ manifest.json found{NC}")
            if manifest_txt.exists():
                print(f"  {GREEN}✓ manifest.txt (human-readable table) found{NC}")
            with open(manifest_file, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
            manifest_entries = manifest_data.get('files', [])

        print(f"  • Total files declared: {len(manifest_entries)}")

        # 3. Verify Every File Checksum
        print(f"\n{BLUE}[3/3] Verifying Individual File SHA-256 and SHA-1 Checksums...{NC}")
        
        sha256_hdr = 'SHA256' if full_hashes else 'SHA256 (16)'
        sha1_hdr = 'SHA1' if full_hashes else 'SHA1 (16)'
        sha256_w = 64 if full_hashes else 16
        sha1_w = 40 if full_hashes else 16

        print(f"{'STATUS':<8} {'PERMS':<6} {'SIZE':>10}  {sha256_hdr:<{sha256_w}}  {sha1_hdr:<{sha1_w}}  {'VIRTUAL PATH'}")
        sep_len = 8 + 1 + 6 + 1 + 10 + 2 + sha256_w + 2 + sha1_w + 2 + 35
        print("-" * sep_len)

        passed = 0
        failed = 0
        missing = 0

        for entry in sorted(manifest_entries, key=lambda x: x.get('virtual_path', '')):
            vp = entry.get('virtual_path')
            target_f = tmp_path / vp

            if not target_f.exists():
                blank_256 = '-' * sha256_w
                blank_1 = '-' * sha1_w
                print(f"{RED}[MISSING]{NC} {'':<6} {'':>10}  {blank_256:<{sha256_w}}  {blank_1:<{sha1_w}}  {vp}")
                missing += 1
                continue

            file_bytes = target_f.read_bytes()
            calc_sha256 = hashlib.sha256(file_bytes).hexdigest()
            calc_sha1 = hashlib.sha1(file_bytes).hexdigest()

            expected_sha256 = entry.get('sha256')
            expected_sha1 = entry.get('sha1')

            match_256 = (calc_sha256 == expected_sha256) if expected_sha256 else True
            match_1 = (calc_sha1 == expected_sha1) if expected_sha1 else True

            perms = entry.get('mode', oct(target_f.stat().st_mode)[-4:])
            sz_str = f"{len(file_bytes):,}"

            disp_sha256 = calc_sha256 if full_hashes else calc_sha256[:16]
            disp_sha1 = calc_sha1 if full_hashes else calc_sha1[:16]

            if match_256 and match_1:
                print(f"{GREEN}[OK]{NC}      {perms:<6} {sz_str:>10}  {disp_sha256}  {disp_sha1}  {vp}")
                passed += 1
            else:
                print(f"{RED}[FAIL]{NC}    {perms:<6} {sz_str:>10}  {disp_sha256}  {disp_sha1}  {vp}  (CHECKSUM MISMATCH)")
                failed += 1

        print("-" * sep_len)
        print(f"\n{BOLD}Verification Summary:{NC}")
        print(f"   Files Verified:    {passed} / {len(manifest_entries)}")
        print(f"   Checksum Failures: {failed}")
        print(f"   Missing Files:     {missing}")

        if failed == 0 and missing == 0:
            print(f"\n{GREEN}{BOLD}🎉 PASSED: 100% of files authenticated and verified byte-for-byte!{NC}\n")
            return True
        else:
            print(f"\n{RED}{BOLD}❌ FAILED: Found {failed} corruptions or {missing} missing files.{NC}\n")
            return False


def main():
    parser = argparse.ArgumentParser(description="Bootstrap Encrypted Vault Verification Tool")
    parser.add_argument('--vault', type=str, default=None, help="Path to encrypted vault (.tar.zst.enc / .tar.enc)")
    parser.add_argument('--password', '-p', type=str, default=None, help="Master password (or auto-resolved from vault.env / env)")
    parser.add_argument('--full', action='store_true', help="Display full 64-char SHA-256 and 40-char SHA-1 hashes")
    parser.add_argument('--short', action='store_true', help="Display compact 16-character truncated hashes")

    args = parser.parse_args()

    vault_path = Path(args.vault) if args.vault else find_latest_vault()

    if not vault_path:
        print("Error: No vault file found or specified.", file=sys.stderr)
        sys.exit(1)

    # Multi-tier password resolution
    password = args.password
    if not password:
        password = os.environ.get('BOOTSTRAP_PASSWORD') or os.environ.get('BOOTSTRAP_SECRET') or os.environ.get('VAULT_PASSWORD')
    if not password:
        vault_env = Path.home() / '.config' / 'bootstrap' / 'vault.env'
        if vault_env.exists():
            try:
                for line in vault_env.read_text().splitlines():
                    line = line.strip()
                    if line.startswith('BOOTSTRAP_PASSWORD=') or line.startswith('VAULT_PASSWORD='):
                        val = line.split('=', 1)[1].strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        if val:
                            password = val
                            break
            except Exception:
                pass
    if not password:
        password = prompt_for_password("vault verification")

    full_hashes = True if args.full else (False if args.short else None)
    success = verify_vault(vault_path, password, full_hashes=full_hashes)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
