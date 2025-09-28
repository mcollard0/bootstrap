#!/usr/bin/env python3
"""
Add SSH keys and other files to encrypted secrets using file encryption.
Enhanced version that stores entire files with paths and permissions.
"""

import json
import sys
import os
import getpass
import glob
sys.path.insert(0, '../src')

try:
    from crypto_utils import SecureBootstrapCrypto
except ImportError:
    print("Error: Could not import crypto_utils. Please ensure it's in ../src/")
    sys.exit(1)

def main():
    secrets_file = "../data/encrypted_secrets.json"
    
    # Load existing encrypted secrets
    try:
        with open(secrets_file, 'r') as f:
            encrypted_dict = json.load(f)
    except Exception as e:
        print(f"Error reading {secrets_file}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Get password from user
    password = getpass.getpass("Enter master password to decrypt and update secrets: ")
    
    # Initialize crypto and decrypt existing secrets
    crypto = SecureBootstrapCrypto()
    try:
        decrypted_data = crypto.decrypt_dict(encrypted_dict, password)
    except ValueError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Add git configuration if not already present
    if 'git_user_email' not in decrypted_data:
        decrypted_data['git_user_email'] = 'mcollard@gmail.com'
        print("  ✓ Added git_user_email")
    
    if 'git_user_name' not in decrypted_data:
        decrypted_data['git_user_name'] = 'Michael Collard'
        print("  ✓ Added git_user_name")
    
    # Files to encrypt (SSH keys and other sensitive files)
    ssh_dir = os.path.expanduser('~/.ssh')
    file_patterns = [
        '~/.ssh/id_*',          # All SSH keys
        '~/.ssh/config',        # SSH config if it exists
        '~/.gitconfig',         # Git configuration
        '~/.netrc',             # Network resource config
        '~/.aws/credentials',   # AWS credentials
    ]
    
    files_to_encrypt = []
    print("\nScanning for files to encrypt...")
    
    for pattern in file_patterns:
        expanded_pattern = os.path.expanduser(pattern)
        matches = glob.glob(expanded_pattern)
        for match in matches:
            if os.path.isfile(match):
                # Skip public keys - we only encrypt private keys
                if match.endswith('.pub'):
                    continue
                files_to_encrypt.append(match)
                print(f"  ✓ Found: {match}")
    
    if not files_to_encrypt:
        print("  ⚠ No files found to encrypt")
    
    # Re-encrypt all data with files
    print(f"\nRe-encrypting {len(decrypted_data)} secrets and {len(files_to_encrypt)} files...")
    new_encrypted_dict = crypto.encrypt_dict(decrypted_data, password, files_to_encrypt)
    
    # Backup original file
    backup_file = f"{secrets_file}.backup.{os.getpid()}"
    with open(backup_file, 'w') as f:
        json.dump(encrypted_dict, f, indent=2)
    print(f"Created backup: {backup_file}")
    
    # Save updated secrets
    with open(secrets_file, 'w') as f:
        json.dump(new_encrypted_dict, f, indent=2)
    
    total_secrets = new_encrypted_dict.get('total_items', 0)
    total_files = new_encrypted_dict.get('total_files', 0)
    
    print(f"✅ Successfully updated {secrets_file}")
    print(f"   Secrets: {total_secrets}")
    print(f"   Files: {total_files}")
    print(f"   Version: {new_encrypted_dict.get('version', 'unknown')}")
    
    # Show what files were encrypted
    if 'encrypted_files' in new_encrypted_dict:
        print(f"\n📁 Encrypted files:")
        for file_key, file_data in new_encrypted_dict['encrypted_files'].items():
            path = file_data.get('path', 'unknown')
            mode = file_data.get('mode', 'unknown')
            print(f"   {file_key}: {path} (mode: {mode})")

if __name__ == '__main__':
    main()