# Ubuntu Bootstrap System

**Complete system configuration backup and restoration for Ubuntu systems with military-grade encryption.**

> ⚠️ **Public Repository Notice**: This is a template/example repository. Before using:
> 1. Fork or clone this repository to your own account
> 2. Set up your own encrypted secrets (see `SECRETS_SETUP.md`)
> 3. Never commit real API keys or passwords to version control

This is what I wanted NIX to be...

## 🚀 Overview

The Ubuntu Bootstrap System is a comprehensive solution for capturing, encrypting, and restoring complete Ubuntu system configurations. It creates an encrypted inventory of your entire system setup and generates restoration scripts that can recreate your exact environment on a fresh Ubuntu installation. 

### 🔐 Key Security Features

- **ChaCha20-Poly1305 encryption** for sensitive data (used by Signal, WireGuard)
- **Argon2id key derivation** (memory-hard, side-channel resistant)
- **No plaintext secrets** ever stored in version control
- **Inline decryption** during system restoration
- **Automated backup rotation** with secure deletion

### 📊 System Coverage

- **2,556+ APT packages** with version pinning
- **14 Snap packages** with channel tracking
- **108+ Python modules** with exact versions
- **SSH keys and configurations** with permission preservation
- **Environment variables** with encrypted sensitive values
- **System configurations** (sysctl, cron jobs, .bashrc customizations)

## ✨ Features

### 🛡️ Special Security Configurations

- **Intel KVM Module Disabling**: Creates blacklist configuration and unloads virtualization modules
- **Firefox Removal**: Automatically removes Firefox (both snap and APT versions)
- **Flatpak Installation**: Installs flatpak package manager and configures Flathub repository

### 🔧 Smart Package Handling

- **Pre-installation checks**: Skip packages that are already installed
- **Batch installations**: Efficient package installation in groups
- **Special packages**: Custom handling for Chrome, Docker, VirtualBox, Warp Terminal
- **System packages**: Intelligent filtering of system-only packages

### 🕐 Automation

- **Weekly cron scheduling**: Automatic inventory updates every Monday at 3 AM
- **Git integration**: Automated commits and pushes with SSH support
- **Backup rotation**: 50 backups for small files (<150KB), 25 for large files (≥150KB)

## 📁 Project Structure

```
bootstrap/
├── src/                    # Python source code
│   ├── crypto_utils.py     # ChaCha20-Poly1305 + Argon2id encryption
│   ├── bootstrap_scanner.py # System inventory scanner
│   ├── generate_bootstrap.py # Bootstrap script generator
│   └── make_backup.py      # Backup management with rotation
├── scripts/                # Generated and automation scripts
│   ├── bootstrap.sh        # Main restoration script
│   ├── git_auto_push.sh    # Automated git operations
│   └── setup_cron.sh       # Cron job management
├── docs/                   # Documentation
│   ├── architecture.md     # System architecture details
│   ├── DRY_RUN_GUIDE.md   # Dry run mode guide
│   ├── CONTRIBUTING.md     # Development guidelines
│   └── TESTING.md         # VM testing procedures
├── data/                   # System inventory and encrypted data
│   ├── inventory.json      # System state snapshot
│   └── encrypted_secrets.json # Encrypted sensitive data
├── backup/                 # Automated dated backups
└── .git/                   # Version control
```

## 🚀 Quick Start

### 1. Initial System Scan
```bash
cd /path/to/bootstrap
python3 src/bootstrap_scanner.py
```
*Creates encrypted inventory of your current system (prompts for master password)*

### 2. Generate Bootstrap Script
```bash
python3 src/generate_bootstrap.py
```
*Creates `scripts/bootstrap.sh` with restoration commands*

### 3. Setup Automation
```bash
./scripts/setup_cron.sh install
```
*Installs weekly cron job for automatic updates*

### 4. Test on Fresh System
```bash
sudo ./scripts/bootstrap.sh
```
*Restores complete system configuration (prompts for master password)*

## 🧪 Dry Run Mode

Extract settings without modifying your project directory - perfect for testing or setting up a new computer:

```bash
# Extract settings to /tmp/bootstrap (default)
python3 src/bootstrap_scanner.py --dry-run

# Generate bootstrap script from dry run
python3 src/generate_bootstrap.py --dry-run

# Custom output directory
python3 src/bootstrap_scanner.py --dry-run --output-dir /home/user/test-bootstrap
python3 src/generate_bootstrap.py --input-dir /home/user/test-bootstrap
```

**Use cases:**
- Preview what would be extracted from a system
- Test configuration changes without affecting your main bootstrap project
- Extract settings on a new computer before committing
- Share bootstrap configuration with teammates

## 🧪 Testing

Complete VM testing setup included:

```bash
# Creates Ubuntu 24.04.3 VM for testing
VBoxManage createvm --name "Ubuntu-Bootstrap-Test" --ostype "Ubuntu_64" --register

# Comprehensive test verification
# See docs/TESTING.md for complete procedures
```

### Test Results Expected
- ✅ Firefox completely removed
- ✅ Chrome, Docker, VirtualBox installed  
- ✅ Flatpak configured with Flathub
- ✅ Intel KVM modules disabled
- ✅ 100+ Python packages restored
- ✅ All encrypted secrets decrypted
- ✅ SSH keys and cron jobs restored

## 🔒 Security Model

### Encryption Specifications
- **Algorithm**: ChaCha20-Poly1305 (AEAD cipher)
- **Key Size**: 256-bit keys, 96-bit nonces, 128-bit authentication tags
- **KDF**: Argon2id with 64MB memory, 3 iterations, 4 parallelism
- **No Key Storage**: Master password required for each decryption

### Threat Model Protection
- ✅ **Data at Rest**: All sensitive data encrypted in git repository
- ✅ **Memory Safety**: Keys cleared immediately after use
- ✅ **Side Channels**: Argon2id provides resistance to timing attacks  
- ✅ **Brute Force**: Memory-hard KDF makes password cracking expensive
- ✅ **Tampering**: Poly1305 MAC prevents modification attacks

### What's Protected
- API keys (OpenAI, Anthropic, XAI, Google Places, etc.)
- Database connection strings (MongoDB URIs, PostgreSQL, etc.)
- Email passwords and SMTP credentials  
- Custom environment variables containing secrets
- Any sensitive configuration you choose to encrypt

## 📋 System Requirements

### Host System
- **Ubuntu 25.04** (Plucky) - Primary target
- **Ubuntu 24.04** - Tested and supported
- **Python 3.13+** with cryptography and argon2-cffi
- **Git** with SSH key configuration
- **sudo privileges** for system-level operations

### Target System (Restoration)
- **Fresh Ubuntu installation** (24.04+ recommended)
- **Internet connectivity** for package downloads
- **4GB+ RAM** (for large package installations)
- **20GB+ free disk space**

## 🛠️ Advanced Usage

### Manual Backup Creation
```bash
python3 src/make_backup.py
```

### Cron Job Management
```bash
./scripts/setup_cron.sh status    # Check current status
./scripts/setup_cron.sh remove    # Remove cron jobs
./scripts/setup_cron.sh install   # Install weekly job
```

### Git Repository Setup
```bash
# Fork this repository or create your own
git clone https://github.com/mcollard0/bootstrap.git
cd bootstrap

# Set up your own remote (recommended: private repository)
git remote set-url origin git@github.com:YOUR_USERNAME/your-bootstrap.git
git push -u origin main
```

### Setting Up Your Secrets
```bash
# Copy example secrets and encrypt your own data
cp data/encrypted_secrets.example.json data/encrypted_secrets.json

# Use the interactive encryption tool
python3 src/crypto_utils.py

# Or see SECRETS_SETUP.md for detailed instructions
```

### Custom Configuration
Edit `src/bootstrap_scanner.py` to modify:
- Package filtering rules
- Sensitive data detection patterns
- System configuration scanning

## 🔧 Architecture

### Core Components

1. **System Scanner** (`bootstrap_scanner.py`)
   - Inventories all installed packages and configurations
   - Detects sensitive data using regex patterns
   - Encrypts secrets with ChaCha20-Poly1305

2. **Script Generator** (`generate_bootstrap.py`)  
   - Creates idempotent bash restoration script
   - Handles special packages and configurations
   - Embeds encrypted secrets with inline decryption

3. **Backup Manager** (`make_backup.py`)
   - Creates dated backups: `filename.YYYYMMDD.ext`
   - Automatic rotation based on file size
   - LRU deletion for cleanup

4. **Automation Scripts**
   - Weekly cron job scheduling
   - Automated git operations with SSH
   - Comprehensive VM testing framework

### Data Flow
```
Current System → Scanner → Encrypted Inventory → Generator → Bootstrap Script → Fresh System
     ↑                                                                              ↓
 Cron Updates ← Git Push ← Backup Creation ← Weekly Schedule         Master Password Prompt
```

## 🤝 Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Code style guidelines (spaces in function calls, semicolons, long lines)
- Security practices and backup procedures
- Development workflow and testing requirements
- Architecture compliance rules

## 📄 License

This project is intended for personal system administration use. Review and understand the code before running on production systems.

## 🆘 Support

### Common Issues
- **Decryption fails**: Verify master password matches original
- **Package conflicts**: Check Ubuntu version compatibility  
- **Permission errors**: Ensure sudo access for system operations
- **Network timeouts**: Verify internet connectivity during restoration

### Debug Mode
```bash
# Enable verbose logging
export BOOTSTRAP_DEBUG=1
sudo ./scripts/bootstrap.sh
```

### Documentation
- [Architecture](docs/architecture.md) - System design and schemas
- [Dry Run Guide](docs/DRY_RUN_GUIDE.md) - Non-invasive testing and extraction
- [Testing Guide](docs/TESTING.md) - VM testing procedures  
- [Contributing](docs/CONTRIBUTING.md) - Development guidelines

---

**Created**: September 2025  
**Version**: 1.0  
**Ubuntu Support**: 24.04+, 25.04 (Plucky)  
**Security**: ChaCha20-Poly1305 + Argon2id  
**Status**: Production Ready ✅
