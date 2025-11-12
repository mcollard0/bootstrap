# SSL Private Key Encryption and Backup

## Overview
The bootstrap system now automatically encrypts and backs up SSL private keys from `/etc/ssl/private/`. These keys are critical for HTTPS services and must be preserved during system restoration.

## What Gets Backed Up
- **SSL private keys** from `/etc/ssl/private/*.key`
- **Excludes** default system keys (snakeoil)
- **Preserves** file permissions and modes

## Encryption Security
- **Algorithm**: ChaCha20-Poly1305 (authenticated encryption)
- **Key Derivation**: Argon2id (memory-hard, side-channel resistant)
- **Key Size**: 256-bit keys with 128-bit authentication tags

## Current SSL Keys
Based on your system scan, these keys will be encrypted:
- `cloudflare-rcfmanagement.key` (241 bytes)
- `gethasty-selfsigned.key` (1704 bytes)
- `michaelcollard-selfsigned.key` (1708 bytes)

## Usage

### 1. Preview What Would Be Added (Dry Run)
```bash
python3 scripts/preview_ssl_keys.py
```
This shows:
- Current encrypted files
- SSL keys that would be added
- Keys that would be skipped
- Total files after operation

### 2. Add SSL Keys to Encrypted Secrets
```bash
python3 scripts/add_secret.py --add-ssl-keys
```
This will:
- Scan `/etc/ssl/private/` (requires sudo)
- Skip snakeoil default keys
- Encrypt each key with your master password
- Add to `data/encrypted_secrets.json`
- Create backup of original secrets file

### 3. Automatic Integration
When running the full system scan:
```bash
python3 src/bootstrap_scanner.py
```
The scanner now:
- Detects SSL private keys automatically
- Includes them in the inventory
- Encrypts them with other sensitive data
- Saves to `data/encrypted_secrets.json`

### 4. Automated Updates
The weekly cron job and git auto-push script automatically:
- Create backups before commits
- Update inventory including SSL keys
- Commit and push changes to git

## File Structure After Encryption
```json
{
  "version": "2.0",
  "total_items": 6,
  "total_files": 9,
  "encrypted_data": {
    "mongodb_uri": { ... },
    "OPENAI_API_KEY": { ... }
  },
  "encrypted_files": {
    "id_ed25519": { ... },
    "cloudflare-rcfmanagement.key": {
      "ciphertext": "BASE64_ENCRYPTED_KEY",
      "nonce": "BASE64_NONCE",
      "salt": "BASE64_SALT",
      "algorithm": "ChaCha20-Poly1305",
      "kdf": "Argon2id",
      "path": "/etc/ssl/private/cloudflare-rcfmanagement.key",
      "mode": "600",
      "ask": true,
      "default": "yes",
      "description": "SSL private key (cloudflare-rcfmanagement.key)"
    }
  }
}
```

## Restoration
During system restoration with `scripts/bootstrap.sh`:
1. Script prompts for master password
2. Decrypts all files including SSL keys
3. For SSL keys, asks user: "Restore SSL private key (cloudflare-rcfmanagement.key)? [Y/n]"
4. Default is "yes" - just press Enter
5. Restores key to `/etc/ssl/private/` with correct permissions (600)
6. Requires sudo to write to `/etc/ssl/private/`

## Security Notes
- SSL keys never stored in plaintext in git
- Keys are read with sudo during encryption
- Master password required for all operations
- File permissions preserved during encryption/decryption
- Keys can be marked as "ask before restore" for safety

## Verification
After adding SSL keys, verify with:
```bash
python3 scripts/preview_ssl_keys.py
```
Should show keys under "ALREADY encrypted (would be updated)"

## Backup Rotation
SSL key backups follow the standard rotation policy:
- Created before git pushes
- Stored in `backup/` directory
- Named with ISO-8601 dates: `encrypted_secrets.20251111.json`
- Up to 50 copies for files <150KB
- Automatic cleanup of oldest backups

## Integration with Make Backup
The `src/make_backup.py` script automatically backs up:
```python
important_files = [
    'src/crypto_utils.py',
    'src/bootstrap_scanner.py',
    'src/generate_bootstrap.py',
    'data/inventory.json',
    'data/encrypted_secrets.json',  # Contains SSL keys
    'scripts/bootstrap.sh'
]
```

## Troubleshooting

### Permission Denied
```bash
# If you get permission errors, ensure sudo access:
sudo ls -la /etc/ssl/private/
```

### Keys Not Detected
```bash
# Verify keys exist:
sudo ls -1 /etc/ssl/private/*.key

# Check scanner finds them:
python3 -c "from bootstrap_scanner import UbuntuSystemScanner; s=UbuntuSystemScanner(); keys=s.scan_ssl_private_keys(); print(keys)"
```

### Decryption Failed
- Verify you're using the same master password
- Check `data/encrypted_secrets.json` is not corrupted
- Restore from backup if needed: `backup/encrypted_secrets.*.json`

## Related Files
- `src/bootstrap_scanner.py` - Scans and encrypts SSL keys
- `src/crypto_utils.py` - Encryption/decryption functions
- `scripts/add_secret.py` - Manual SSL key addition
- `scripts/preview_ssl_keys.py` - Dry-run preview
- `data/encrypted_secrets.json` - Encrypted storage
