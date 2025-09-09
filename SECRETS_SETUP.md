# Setting Up Your Encrypted Secrets

This guide explains how to set up your own encrypted secrets for the Ubuntu Bootstrap System.

## Overview

The bootstrap system uses **ChaCha20-Poly1305** encryption with **Argon2id** key derivation to securely store sensitive data like:

- API keys (OpenAI, Anthropic, Google Places, etc.)
- Database connection strings
- Email passwords
- Other sensitive configuration

## Quick Setup

### 1. Create Your Secrets File

```bash
# Copy the example template
cp data/encrypted_secrets.example.json data/encrypted_secrets.json

# OR: Start with an empty structure and let the system encrypt your secrets
python3 src/crypto_utils.py
```

### 2. Encrypt Your Secrets Manually

```python
#!/usr/bin/env python3
from src.crypto_utils import SecureBootstrapCrypto, prompt_for_password
import json

crypto = SecureBootstrapCrypto()

# Your actual secrets (replace with real values)
secrets = {
    'mongodb_uri': 'mongodb+srv://username:password@cluster.mongodb.net/database',
    'gmail_sender_password': 'your_gmail_app_password',
    'GOOGLE_PLACES_API_KEY': 'AIzaSy...your_google_places_key',
    'XAI_API_KEY': 'xai-...your_xai_key', 
    'ANTHROPIC_API_KEY': 'sk-ant-...your_anthropic_key',
    'OPENAI_API_KEY': 'sk-...your_openai_key'
}

# Get your master password
password = prompt_for_password("encrypting secrets")

# Encrypt all secrets
encrypted_data = crypto.encrypt_dict(secrets, password)

# Save to file
with open('data/encrypted_secrets.json', 'w') as f:
    json.dump(encrypted_data, f, indent=2)

print("✅ Secrets encrypted and saved!")
```

### 3. Test Decryption

```bash
python3 -c "
from src.crypto_utils import SecureBootstrapCrypto, prompt_for_password
import json

with open('data/encrypted_secrets.json', 'r') as f:
    encrypted_data = json.load(f)

crypto = SecureBootstrapCrypto()
password = prompt_for_password('testing decryption')

decrypted = crypto.decrypt_dict(encrypted_data, password)
print('✅ Decryption successful!')
for key in decrypted:
    print(f'  - {key}: [REDACTED]')
"
```

## Security Best Practices

1. **Use a strong master password** (recommended: 16+ characters with mixed case, numbers, symbols)

2. **Never commit real secrets** - the `.gitignore` prevents `data/encrypted_secrets.json` from being committed

3. **Store master password securely** - consider using a password manager

4. **Regular rotation** - rotate API keys periodically and re-encrypt

5. **Backup separately** - store encrypted secrets backup outside git repository

## Environment Variables

After running the bootstrap script, these environment variables will be available in your shell:

```bash
# Check decrypted variables (after running bootstrap.sh)
source ~/.bashrc
echo $OPENAI_API_KEY        # Your OpenAI API key
echo $ANTHROPIC_API_KEY     # Your Anthropic API key
echo $GOOGLE_PLACES_API_KEY # Your Google Places API key
# ... etc
```

## Standalone Script Generation

To create a standalone script with your encrypted secrets:

```bash
# Generate standalone script (secrets will be embedded)
python3 src/generate_bootstrap.py --standalone

# Result: scripts/bootstrap_standalone.sh contains your encrypted data
```

## Troubleshooting

### "Decryption failed" Error
- Double-check your master password
- Ensure encrypted_secrets.json is valid JSON
- Check that all required fields are present

### Missing Secrets File
```bash
# Create from template
cp data/encrypted_secrets.example.json data/encrypted_secrets.json
# Then follow encryption steps above
```

### Testing Individual Secrets
```python
from src.crypto_utils import SecureBootstrapCrypto
import json, getpass

with open('data/encrypted_secrets.json') as f:
    data = json.load(f)

crypto = SecureBootstrapCrypto()
password = getpass.getpass("Master password: ")

# Test specific secret
secret_name = "OPENAI_API_KEY"  # Change this
encrypted_value = data['encrypted_data'][secret_name]
decrypted = crypto.decrypt(encrypted_value, password)
print(f"{secret_name}: {decrypted[:10]}...")  # Show first 10 chars
```

## Need Help?

- Check `src/crypto_utils.py` for encryption implementation details
- Review `docs/architecture.md` for system overview  
- See `VM_TESTING_INSTRUCTIONS.md` for testing in a virtual machine

---

**⚠️ Security Notice**: Keep your master password safe and never commit real secrets to version control!
