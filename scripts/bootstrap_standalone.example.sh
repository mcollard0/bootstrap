#!/bin/bash
#
# Ubuntu Bootstrap Standalone Script (Example Template)
#
# This is an EXAMPLE template showing how the standalone script works.
# To create your own standalone script with your encrypted secrets:
#
# 1. Set up your encrypted secrets: cp data/encrypted_secrets.example.json data/encrypted_secrets.json  
# 2. Encrypt your real secrets: python3 src/crypto_utils.py
# 3. Generate your standalone script: python3 src/generate_bootstrap.py --standalone
# 
# WARNING: This example script contains NO REAL SECRETS and will not work for actual system restoration.
#          It's provided as a reference for the structure and security model.
#
# Generated: $(date)
# Version: 1.0
#

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m';
readonly GREEN='\033[0;32m';
readonly YELLOW='\033[0;33m';
readonly BLUE='\033[0;34m';
readonly NC='\033[0m';  # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; };
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; };
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; };
log_error() { echo -e "${RED}[ERROR]${NC} $1"; };

# Check if running as root for system-level operations
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo privileges for system-level changes";
        log_info "Usage: sudo ./bootstrap_standalone.example.sh";
        exit 1;
    fi;
};

# Check if user exists (for user-specific operations)
check_user() {
    local username="${SUDO_USER:-$USER}";
    if ! id "$username" >/dev/null 2>&1; then
        log_error "Target user '$username' does not exist";
        exit 1;
    fi;
    echo "$username";
};

# Check if package is already installed
is_apt_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q '^ii';
};

is_snap_installed() {
    snap list "$1" >/dev/null 2>&1;
};

is_flatpak_installed() {
    flatpak list | grep -q "$1" 2>/dev/null;
};

# Install missing cryptography dependencies if needed
install_crypto_deps() {
    log_info "🔧 Checking Python cryptography dependencies...";
    
    if ! python3 -c "import cryptography" 2>/dev/null; then
        log_info "Installing python3-cryptography...";
        apt update;
        apt install -y python3-cryptography;
    fi;
    
    if ! python3 -c "import argon2" 2>/dev/null; then
        log_info "Installing python3-argon2...";
        apt install -y python3-argon2;
    fi;
    
    log_success "Cryptography dependencies ready";
};

# EXAMPLE: Embedded encrypted secrets (base64 encoded)
# NOTE: These are EXAMPLE placeholders - they will NOT decrypt successfully!
ENCRYPTED_SECRETS_B64="eyJlbmNyeXB0ZWRfZGF0YSI6IHsibW9uZ29kYl91cmkiOiB7ImNpcGhlcnRleHQiOiAiRVhBTVBMRV9FTUNSQVBURUQ9REFUQSIsICJub25jZSI6ICJFWEFNUEXFUFRSWF9OT05DRSIsICJzYWx0IjogIkVYQU1QTEVfU0FMVCIsICJhbGdvcml0aG0iOiAiQ2hhQ2hhMjAtUG9seTEzMDUiLCAia2RmIjogIkFyZ29uMmlkIn0sICJnbWFpbF9zZW5kZXJfcGFzc3dvcmQiOiB7ImNpcGhlcnRleHQiOiAiRVhBTVBMRV9FTUNSQVBURUQ=", "nonce": "EXAMPLE_NONCE", "salt": "EXAMPLE_SALT", "algorithm": "ChaCha20-Poly1305", "kdf": "Argon2id"}}, "version": "1.0", "total_items": 6}";

# Decrypt and restore sensitive environment variables
decrypt_secrets() {
    local user_home_dir="$1";
    log_info "🔐 Decrypting and restoring sensitive environment variables...";
    
    log_warning "⚠️  EXAMPLE SCRIPT NOTICE:";
    log_warning "    This is a template script with placeholder encrypted data.";
    log_warning "    It will NOT successfully decrypt secrets.";
    log_warning "    To create your working standalone script:";
    log_warning "    1. Set up real encrypted secrets in data/encrypted_secrets.json";  
    log_warning "    2. Run: python3 src/generate_bootstrap.py --standalone";
    
    # Export the user home directory for Python script
    export BOOTSTRAP_USER_HOME="$user_home_dir";
    
    # Python decryption inline script (THIS IS AN EXAMPLE - WILL FAIL WITH PLACEHOLDER DATA)
    python3 - <<PYTHON_SCRIPT
import json, base64, sys, getpass, os;
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;
from argon2.low_level import hash_secret_raw, Type;

print("🔍 This is the EXAMPLE standalone script template.");
print("🔍 The embedded encrypted data is placeholder text and will not decrypt.");
print("🔍 To create a working script, follow the setup instructions in SECRETS_SETUP.md");

# Recreate crypto functions inline
def derive_key(password, salt):
    return hash_secret_raw(
        password.encode('utf-8'), salt,
        time_cost=3, memory_cost=65536, parallelism=4,
        hash_len=32, type=Type.ID
    ), salt;

def decrypt(encrypted_data, password):
    try:
        ciphertext = base64.b64decode(encrypted_data['ciphertext']);
        nonce = base64.b64decode(encrypted_data['nonce']);
        salt = base64.b64decode(encrypted_data['salt']);
        key, _ = derive_key(password, salt);
        cipher = ChaCha20Poly1305(key);
        plaintext_bytes = cipher.decrypt(nonce, ciphertext, None);
        return plaintext_bytes.decode('utf-8');
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}");

# This will fail because we have placeholder data
print("❌ Example script - decryption will fail as expected with placeholder data");
sys.exit(1);
PYTHON_SCRIPT

    if [[ $? -eq 0 ]]; then
        log_success "Sensitive environment variables restored";
    else
        log_error "Failed to decrypt sensitive data (expected for example script)";
        log_info "To create a working script: python3 src/generate_bootstrap.py --standalone";
        return 1;
    fi;
};

# Main restoration function
main() {
    log_info "🚀 Starting Ubuntu Bootstrap Restoration (Example Script)";
    log_info "================================================================";
    
    log_warning "⚠️  NOTICE: This is an EXAMPLE template script";
    log_warning "    It demonstrates the structure but contains no real secrets";
    log_warning "    For actual system restoration, create your own standalone script";
    echo;
    
    check_sudo;
    readonly TARGET_USER=$(check_user);
    readonly USER_HOME="/home/$TARGET_USER";
    
    log_info "Target user: $TARGET_USER";
    log_info "User home: $USER_HOME";
    echo;
    
    # Install crypto dependencies first
    install_crypto_deps;
    
    # This example script stops here to avoid running system changes with fake data
    log_warning "🛑 Example script stops here to prevent system modifications";
    log_info "📖 To create your working standalone script:";
    log_info "   1. Set up encrypted secrets: see SECRETS_SETUP.md";
    log_info "   2. Generate standalone script: python3 src/generate_bootstrap.py --standalone";
    log_info "   3. Run your generated script: sudo ./scripts/bootstrap_standalone.sh";
    
    log_info "🔍 Example script template completed";
    return 0;
}

# Execute main function
main "$@";
