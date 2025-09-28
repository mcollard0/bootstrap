#!/usr/bin/env python3
"""
Decrypt encrypted secrets and output as bash environment variable exports.
"""

import json
import sys
import os
sys.path.insert(0, '../src')

try:
    from crypto_utils import SecureBootstrapCrypto, prompt_for_password
except ImportError:
    print("Error: Could not import crypto_utils. Please ensure it's in ../src/")
    sys.exit(1)

def main():
    secrets_file = "../data/encrypted_secrets.json"
    restore_files = '--restore-files' in sys.argv or '-f' in sys.argv
    
    # Check if secrets file exists
    if not os.path.exists(secrets_file):
        print(f"Warning: {secrets_file} not found", file=sys.stderr)
        return
    
    # Load encrypted secrets
    try:
        with open(secrets_file, 'r') as f:
            encrypted_dict = json.load(f)
    except Exception as e:
        print(f"Error reading {secrets_file}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Get password from user
    password = prompt_for_password("secrets decryption")
    
    # Initialize crypto and decrypt
    crypto = SecureBootstrapCrypto()
    try:
        decrypted_data = crypto.decrypt_dict(encrypted_dict, password, restore_files=restore_files)
        
        if restore_files:
            print(f"Files restored from encrypted secrets", file=sys.stderr)
        
        # Output as bash exports
        for key, value in decrypted_data.items():
            # Shell-escape the value by wrapping in single quotes and escaping single quotes
            escaped_value = value.replace("'", "'\"'\"'")
            print(f"export {key}='{escaped_value}'")
    
    except ValueError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()