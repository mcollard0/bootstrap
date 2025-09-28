#!/usr/bin/env python3
"""
Add SSH private keys to encrypted secrets for automated restoration.
"""

import json
import sys
import os
import getpass
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
    
    # SSH keys to add
    ssh_keys = {
        'ssh_id_ed25519': os.path.expanduser('~/.ssh/id_ed25519'),
        'ssh_id_ed25519_github': os.path.expanduser('~/.ssh/id_ed25519_github'),
        'ssh_id_ed25519_mcollard': os.path.expanduser('~/.ssh/id_ed25519_mcollard'),
    }
    
    # Read SSH private keys and add to decrypted data
    print("Adding SSH private keys to secrets...")
    for key_name, key_path in ssh_keys.items():
        if os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    key_content = f.read().strip()
                decrypted_data[key_name] = key_content
                print(f"  ✓ Added {key_name}")
            except Exception as e:
                print(f"  ✗ Failed to read {key_path}: {e}")
        else:
            print(f"  ⚠ Key not found: {key_path}")
    
    # Add git configuration if not already present
    if 'git_user_email' not in decrypted_data:
        decrypted_data['git_user_email'] = 'mcollard@gmail.com'
        print("  ✓ Added git_user_email")
    
    if 'git_user_name' not in decrypted_data:
        decrypted_data['git_user_name'] = 'Michael Collard'
        print("  ✓ Added git_user_name")
    
    # Re-encrypt all data
    print("\nRe-encrypting secrets...")
    new_encrypted_dict = crypto.encrypt_dict(decrypted_data, password)
    
    # Backup original file
    backup_file = f"{secrets_file}.backup.{os.getpid()}"
    with open(backup_file, 'w') as f:
        json.dump(encrypted_dict, f, indent=2)
    print(f"Created backup: {backup_file}")
    
    # Save updated secrets
    with open(secrets_file, 'w') as f:
        json.dump(new_encrypted_dict, f, indent=2)
    
    print(f"✅ Successfully updated {secrets_file} with {len(decrypted_data)} secrets")
    print(f"   SSH keys: {len([k for k in decrypted_data.keys() if k.startswith('ssh_')])}")
    print(f"   Total secrets: {new_encrypted_dict.get('total_items', 'unknown')}")

if __name__ == '__main__':
    main()