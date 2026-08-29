#!/usr/bin/env python3
"""
Comprehensive secrets management tool - Add SSH keys, files, and environment variables to encrypted secrets.
Enhanced version with file encryption, Fish & Bash shell support, and key-value management.
"""

import json
import sys
import os
import glob
import argparse
from pathlib import Path

# Add src to path
SCRIPT_DIR = Path(__file__).parent
SRC_DIR = SCRIPT_DIR.parent / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from crypto_utils import SecureBootstrapCrypto, prompt_for_password
    from version import __version__, get_full_program_name
except ImportError:
    print("Error: Could not import crypto_utils or version. Please ensure it's in ../src/")
    sys.exit(1)


def main():
    prog_title = get_full_program_name("Secret Management Tool")
    parser = argparse.ArgumentParser(description=prog_title)
    parser.add_argument('--version', '-v', action='version', version=prog_title)
    parser.add_argument('--add-fstab', action='store_true', help='Add /etc/fstab as archive-only file')
    parser.add_argument('--add-ssl-keys', action='store_true', help='Add SSL private keys from /etc/ssl/private/')
    parser.add_argument('--files', nargs='*', help='Additional files to encrypt')
    parser.add_argument('--set-key', nargs=2, metavar=('KEY', 'VALUE'), help='Set an encrypted secret variable (e.g. --set-key OPENAI_API_KEY sk-...)')
    parser.add_argument('--secrets-file', default=str(SCRIPT_DIR.parent / 'data/encrypted_secrets.json'), help='Path to secrets file')
    args = parser.parse_args()

    secrets_file = Path(args.secrets_file)

    # Load existing encrypted secrets if file exists
    encrypted_dict = {}
    if secrets_file.exists():
        try:
            with open(secrets_file, 'r', encoding='utf-8') as f:
                encrypted_dict = json.load(f)
        except Exception as e:
            print(f"Error reading {secrets_file}: {e}", file=sys.stderr)
            sys.exit(1)

    # Get password from user or environment variable
    password = prompt_for_password("secrets decryption and update")

    # Initialize crypto and decrypt existing secrets
    crypto = SecureBootstrapCrypto()
    decrypted_data = {}
    if encrypted_dict:
        try:
            decrypted_data = crypto.decrypt_dict(encrypted_dict, password)
        except ValueError as e:
            print(f"Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

    # Add custom key-value if provided
    if args.set_key:
        k, v = args.set_key
        decrypted_data[k] = v
        print(f"  ✓ Set secret key: {k}")

    # Files to encrypt (SSH keys, Fish/Bash configs, credentials)
    file_patterns = [
        '~/.ssh/id_*',
        '~/.ssh/config',
        '~/.gitconfig',
        '~/.config/fish/config.fish',
        '~/.config/fish/fish_variables',
        '~/.bashrc',
        '~/.bash_aliases',
        '~/.netrc',
        '~/.aws/credentials',
    ]

    if args.files:
        file_patterns.extend(args.files)

    files_to_encrypt = []
    special_files = {}

    print("\nScanning for sensitive files to encrypt...")

    for pattern in file_patterns:
        expanded_pattern = os.path.expanduser(pattern)
        matches = glob.glob(expanded_pattern)
        for match in matches:
            if os.path.isfile(match):
                if match.endswith('.pub'):
                    continue
                files_to_encrypt.append(match)
                print(f"  ✓ Found: {match}")

    # Add /etc/fstab if requested
    if args.add_fstab and os.path.exists('/etc/fstab'):
        special_files['/etc/fstab'] = {
            'not_to_restore': True,
            'ask': True,
            'default': 'no',
            'description': 'System partition table (/etc/fstab)'
        }
        print("  ✓ Adding /etc/fstab as archive-only file")

    # Add SSL private keys
    if args.add_ssl_keys:
        import subprocess
        ssl_private_dir = '/etc/ssl/private'
        if os.path.exists(ssl_private_dir):
            try:
                result = subprocess.run(
                    ['sudo', 'ls', '-1', ssl_private_dir],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    key_files = [f for f in result.stdout.strip().split('\n') if f and f.endswith('.key')]
                    for key_file in key_files:
                        key_path = os.path.join(ssl_private_dir, key_file)
                        if 'snakeoil' in key_file:
                            continue
                        special_files[key_path] = {
                            'ask': True,
                            'default': 'yes',
                            'description': f'SSL private key ({key_file})'
                        }
                        print(f"  ✓ Adding SSL private key: {key_file}")
            except Exception as e:
                print(f"  ⚠ Error scanning SSL keys: {e}")

    # Re-encrypt all data
    new_encrypted_dict = crypto.encrypt_dict(decrypted_data, password, file_paths=files_to_encrypt)

    # Add special files
    if special_files:
        if 'encrypted_files' not in new_encrypted_dict:
            new_encrypted_dict['encrypted_files'] = {}
        for sf_path, sf_flags in special_files.items():
            if os.path.exists(sf_path):
                f_key = os.path.basename(sf_path)
                new_encrypted_dict['encrypted_files'][f_key] = crypto.encrypt_file(sf_path, password, **sf_flags)
        new_encrypted_dict['total_files'] = len(new_encrypted_dict['encrypted_files'])

    # Save updated secrets
    secrets_file.parent.mkdir(parents=True, exist_ok=True)
    with open(secrets_file, 'w', encoding='utf-8') as f:
        json.dump(new_encrypted_dict, f, indent=2)

    total_secrets = new_encrypted_dict.get('total_items', 0)
    total_files_final = new_encrypted_dict.get('total_files', 0)

    print(f"\n✅ Successfully updated {secrets_file}")
    print(f"   Secrets: {total_secrets}")
    print(f"   Files:   {total_files_final}")


if __name__ == '__main__':
    main()