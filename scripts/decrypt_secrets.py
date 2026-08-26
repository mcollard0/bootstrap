#!/usr/bin/env python3
"""
Decrypt encrypted secrets and output as shell environment variables or inspect keys.
"""

import json
import sys
import os
from pathlib import Path

# Add src to path
SCRIPT_DIR = Path(__file__).parent
SRC_DIR = SCRIPT_DIR.parent / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from crypto_utils import SecureBootstrapCrypto, prompt_for_password
except ImportError:
    print("Error: Could not import crypto_utils. Please ensure it's in ../src/")
    sys.exit(1)


def main():
    secrets_file = SCRIPT_DIR.parent / "data/encrypted_secrets.json"
    restore_files = '--restore-files' in sys.argv or '-f' in sys.argv
    list_secrets = '--list-secrets' in sys.argv

    if not secrets_file.exists():
        print(f"Warning: {secrets_file} not found", file=sys.stderr)
        return

    try:
        with open(secrets_file, 'r', encoding='utf-8') as f:
            encrypted_dict = json.load(f)
    except Exception as e:
        print(f"Error reading {secrets_file}: {e}", file=sys.stderr)
        sys.exit(1)

    password = prompt_for_password("secrets decryption")
    crypto = SecureBootstrapCrypto()

    try:
        decrypted_data = crypto.decrypt_dict(encrypted_dict, password, restore_files=restore_files)

        if list_secrets:
            print("\n📋 Decrypted Secrets:")
            for k, v in decrypted_data.items():
                print(f"  • {k} = {v}")
        else:
            for k, v in decrypted_data.items():
                escaped = str(v).replace("'", "'\"'\"'")
                print(f"export {k}='{escaped}'")

    except ValueError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()