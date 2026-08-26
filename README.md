# Universal Linux Bootstrap & Disaster Recovery System

**Comprehensive system configuration backup, sealed vault packaging, and multi-destination untrusted cloud synchronization for Arch Linux, CachyOS, and Ubuntu.**

> 🔐 **Untrusted Storage Paradigm**: All system configurations, shell environments, `/etc/fstab` topologies, SSH/GPG keys, and secrets are packaged into an authenticated encrypted vault (`ChaCha20-Poly1305 + Argon2id AEAD`). No cloud provider, email server, or storage endpoint ever sees plaintext filenames, paths, or data.

---

## 🚀 Overview

The Universal Bootstrap System is a comprehensive disaster recovery and configuration synchronization tool. It captures your entire system setup (packages, storage mounts, dotfiles, shell configs, keys) and generates an encrypted recovery vault and idempotent restoration scripts.

### 🌟 Key Capabilities

- **Auto-Detects Distribution**: Native package managers for **Arch Linux & CachyOS** (`pacman -Qqe`, `paru`/`yay` for AUR) and **Ubuntu & Debian** (`apt-mark showmanual`, `snap list`, Flatpaks).
- **Multi-Shell Support**: Complete recursive backup and restoration of **Fish shell** (`~/.config/fish/config.fish`, `fish_variables`, `functions/`, `conf.d/`), **Bash** (`.bashrc`, `.bash_profile`, `.bash_aliases`), Starship prompt, and system MOTD (`/etc/motd`, `/etc/issue`, `/etc/environment`).
- **Disaster Recovery for Root (`/`) Drive Failure**: Archives `/etc/fstab`, `/etc/crypttab`, drive UUID maps, and Btrfs subvolume layouts. Rebuilds and remounts your external archive drives (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SLOW_ARCHIVE`, `SHARD_*`) without risking bulk data.
- **Untrusted Multi-Destination Cloud Sync**: Simultaneous automated upload of sealed encrypted vaults to:
  - **AWS S3 / S3-Compatible** (Cloudflare R2, Wasabi, MinIO, Backblaze B2)
  - **Google Drive** (via rclone or native API)
  - **Microsoft OneDrive** (via rclone or native API)
  - **Email (SMTP)** (Encrypted attachment with delivery status)
  - **Local & Archive Drives** (`/run/media/michael/FAST_ARCHIVE/SystemBackups/` and `./backup/`)
  - **Git Remote** (Encrypted repository sync)
- **Zero-Dependency Rescue Decryptor (`src/restore.py`)**: Standalone interactive Python restoration tool runnable directly from an Arch or Ubuntu Live USB.

---

## 📁 Project Structure

```
bootstrap/
├── config/
│   └── destinations.example.json   # Template for storage destinations (S3, GDrive, OneDrive, Email, Local)
├── src/
│   ├── system_detector.py          # Auto-detects Distro (Arch/Ubuntu), Shell (Fish/Bash), DE (KDE/GNOME)
│   ├── crypto_utils.py             # ChaCha20-Poly1305 + Argon2id authenticated vault packaging
│   ├── bootstrap_scanner.py        # Orchestrates all scanners, builds inventory, seals vault, and dispatches
│   ├── generate_bootstrap.py       # Generates Arch (pacman/yay) or Ubuntu (apt/snap) restore scripts
│   ├── restore.py                  # Standalone interactive disaster recovery & vault restoration tool
│   ├── scanners/                   # Modular scanning subsystem
│   │   ├── base_scanner.py         # Abstract scanner base class
│   │   ├── distro_scanner.py       # Pacman/Yay/Paru (Arch) & APT/Snap (Ubuntu) scanner
│   │   ├── shell_scanner.py        # Fish & Bash configs, functions, variables, MOTD, prompts
│   │   ├── storage_scanner.py      # /etc/fstab, /etc/crypttab, lsblk UUIDs, Btrfs subvolumes
│   │   ├── systemd_scanner.py      # Enabled system & user units and timers
│   │   ├── network_scanner.py      # NetworkManager connections & WireGuard profiles
│   │   ├── keys_scanner.py         # SSH, GPG, SSL certificates & private keys
│   │   └── desktop_scanner.py      # KDE Plasma shortcuts & GNOME dconf settings
│   └── storage/                    # Multi-destination untrusted storage subsystem
│       ├── base_backend.py         # Base storage provider interface
│       ├── storage_dispatcher.py   # Dispatches encrypted vault to all enabled destinations
│       ├── s3_backend.py           # AWS S3 / Wasabi / Cloudflare R2 / MinIO backend
│       ├── gdrive_backend.py       # Google Drive backend
│       ├── onedrive_backend.py     # Microsoft OneDrive backend
│       ├── email_backend.py        # SMTP email backend with encrypted attachment
│       ├── local_backend.py        # Local & FAST_ARCHIVE drive destination
│       └── rclone_backend.py       # Universal rclone integration
├── scripts/
│   ├── run_backup.sh               # Master one-step backup launcher
│   ├── bootstrap.sh                # Main generated restoration script
│   ├── add_secret.py               # Manage encrypted secrets and file storage
│   ├── decrypt_secrets.py          # Decrypt and inspect environment variables
│   ├── git_auto_push.sh            # Automated git commit and push
│   └── setup_cron.sh               # Automated backup scheduling
├── docs/
│   ├── architecture.md             # System architecture & cryptographic specifications
│   ├── DISASTER_RECOVERY.md        # Comprehensive root drive failure recovery guide
│   └── EMERGENCY_CARD.md           # Quick emergency cheatsheet
└── data/
    ├── destinations.json           # Active storage destinations configuration
    ├── inventory.json              # Unencrypted system state snapshot (local inspection)
    └── encrypted_secrets.json      # Encrypted secrets store
```

---

## ⚡ Quick Start

### 1. Run Complete System Backup
```bash
./scripts/run_backup.sh
```
*Prompts for your master password, scans your system, seals all configs into `bootstrap_vault_*.tar.enc`, and uploads to all active destinations.*

### 2. Configure Cloud Destinations
Edit `data/destinations.json` (or copy from `config/destinations.example.json`):
- Enable **AWS S3 / R2**, **Google Drive**, **OneDrive**, or **Email (SMTP)**.
- Re-run `./scripts/run_backup.sh` to sync across your clouds.

### 3. Disaster Recovery (Fresh System or Replaced `/` Drive)
```bash
# Unpack vault and restore fstab, fish/bash dotfiles, and SSH keys
python3 src/restore.py --vault /path/to/bootstrap_vault_*.tar.enc

# Reinstall all software packages in batch
sudo ./scripts/bootstrap.sh
```

---

## 🔒 Security Specifications

- **Cipher**: ChaCha20-Poly1305 (256-bit symmetric AEAD stream cipher, 128-bit authentication tag)
- **KDF**: Argon2id (64MB memory cost, 3 iterations, 4 parallelism) with automatic `scrypt` fallback
- **Authentication**: Poly1305 MAC verifies data integrity before unpacking
- **Untrusted Storage**: Storage providers only ever receive authenticated ciphertext with random salt and nonce
