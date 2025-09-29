#!/usr/bin/env python3
"""
Comprehensive secrets management tool - Add SSH keys, files, and environment variables to encrypted secrets.
Enhanced version with file encryption and archive-only support.
Merged from add_ssh_to_secrets.py and add_files_to_secrets.py
"""

import json
import sys
import os
import glob
import argparse
sys.path.insert(0, '../src')

try:
    from crypto_utils import SecureBootstrapCrypto, prompt_for_password
except ImportError:
    print("Error: Could not import crypto_utils. Please ensure it's in ../src/")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Add secrets and files to encrypted secrets storage')
    parser.add_argument('--add-fstab', action='store_true', help='Add /etc/fstab as archive-only file')
    parser.add_argument('--files', nargs='*', help='Additional files to encrypt')
    parser.add_argument('--secrets-file', default='../data/encrypted_secrets.json', help='Path to secrets file')
    args = parser.parse_args()
    
    secrets_file = args.secrets_file
    
    # Load existing encrypted secrets
    try:
        with open(secrets_file, 'r') as f:
            encrypted_dict = json.load(f)
    except Exception as e:
        print(f"Error reading {secrets_file}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Get password from user or environment variable
    password = prompt_for_password("secrets decryption and update")
    
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
    file_patterns = [
        '~/.ssh/id_*',          # All SSH keys
        '~/.ssh/config',        # SSH config if it exists
        '~/.gitconfig',         # Git configuration
        '~/.netrc',             # Network resource config
        '~/.aws/credentials',   # AWS credentials
    ]
    
    # Add additional files from command line
    if args.files:
        file_patterns.extend(args.files)
    
    files_to_encrypt = []
    special_files = {}  # For files with special flags
    
    print("\\nScanning for files to encrypt...")
    
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
    
    # Add /etc/fstab as archive-only file if requested
    if args.add_fstab and os.path.exists('/etc/fstab'):
        special_files['/etc/fstab'] = {
            'not_to_restore': True,
            'ask': True, 
            'default': 'no',
            'description': 'System partition table (/etc/fstab)'
        }
        print("  ✓ Adding /etc/fstab as archive-only file")
    
    if not files_to_encrypt and not special_files:
        print("  ⚠ No files found to encrypt")
    
    # Enhanced encrypt_dict to handle special files
    def encrypt_with_special_files(data, password, regular_files, special_files):
        encrypted_items = {}
        encrypted_files = {}
        
        # Encrypt regular data
        for key, value in data.items():
            if isinstance(value, str) and value.strip():
                encrypted_items[key] = crypto.encrypt(value, password)
            else:
                encrypted_items[key] = value
        
        # Encrypt regular files
        for file_path in regular_files:
            if os.path.exists(os.path.expanduser(file_path)):
                try:
                    file_key = os.path.basename(file_path)
                    encrypted_files[file_key] = crypto.encrypt_file(os.path.expanduser(file_path), password)
                except Exception as e:
                    print(f"Warning: Could not encrypt file {file_path}: {e}")
        
        # Encrypt special files with flags
        for file_path, flags in special_files.items():
            if os.path.exists(file_path):
                try:
                    file_key = os.path.basename(file_path)
                    encrypted_files[file_key] = crypto.encrypt_file(file_path, password, **flags)
                except Exception as e:
                    print(f"Warning: Could not encrypt special file {file_path}: {e}")
        
        result = {
            'encrypted_data': encrypted_items,
            'version': '2.0',
            'total_items': len(encrypted_items)
        }
        
        if encrypted_files:
            result['encrypted_files'] = encrypted_files
            result['total_files'] = len(encrypted_files)
        
        return result
    
    # Re-encrypt all data with files
    total_files = len(files_to_encrypt) + len(special_files)
    print(f"\\nRe-encrypting {len(decrypted_data)} secrets and {total_files} files...")
    new_encrypted_dict = encrypt_with_special_files(decrypted_data, password, files_to_encrypt, special_files)
    
    # Backup original file
    backup_file = f"{secrets_file}.backup.{os.getpid()}"
    with open(backup_file, 'w') as f:
        json.dump(encrypted_dict, f, indent=2)
    print(f"Created backup: {backup_file}")
    
    # Save updated secrets
    with open(secrets_file, 'w') as f:
        json.dump(new_encrypted_dict, f, indent=2)
    
    total_secrets = new_encrypted_dict.get('total_items', 0)
    total_files_final = new_encrypted_dict.get('total_files', 0)
    
    print(f"✅ Successfully updated {secrets_file}")
    print(f"   Secrets: {total_secrets}")
    print(f"   Files: {total_files_final}")
    print(f"   Version: {new_encrypted_dict.get('version', 'unknown')}")
    
    # Show what files were encrypted
    if 'encrypted_files' in new_encrypted_dict:
        print(f"\\n📁 Encrypted files:")
        for file_key, file_data in new_encrypted_dict['encrypted_files'].items():
            path = file_data.get('path', 'unknown')
            mode = file_data.get('mode', 'unknown')
            flags = []
            if file_data.get('not_to_restore'):
                flags.append('archive-only')
            if file_data.get('ask'):
                flags.append('ask-user')
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"   {file_key}: {path} (mode: {mode}){flag_str}")

if __name__ == '__main__':
    main()