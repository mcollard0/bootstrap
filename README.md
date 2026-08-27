# Universal Linux Bootstrap & Disaster Recovery System

**Comprehensive system configuration backup, sealed vault packaging, and multi-destination untrusted cloud synchronization for Arch Linux, CachyOS, and Ubuntu.**

> 🔐 **Untrusted Storage Paradigm**: All system configurations, shell environments, `/etc/fstab` topologies, SSH/GPG keys, credentials, and custom files are packaged into an authenticated encrypted vault (`ChaCha20-Poly1305 + Argon2id AEAD` with `Zstandard` compression). No Git remote, cloud provider, email server, or storage endpoint ever sees plaintext filenames, paths, or data.

---

## 🚀 Overview

The Universal Bootstrap System is a comprehensive disaster recovery and configuration synchronization tool. It captures your entire system setup (packages, storage mounts, dotfiles, shell configs, GPG/SSH keys, custom hardware rules, and fonts) and generates an encrypted recovery vault and idempotent restoration scripts.

### 🌟 Key Capabilities

- **Auto-Detects Distribution**: Native package managers for **Arch Linux & CachyOS** (`pacman -Qqe`, `paru`/`yay` for AUR with fast non-breaking `pacman -T` dependency checks) and **Ubuntu & Debian** (`apt-mark showmanual`, `snap list`, Flatpaks).
- **Multi-Shell Support**: Complete recursive backup and restoration of **Fish shell** (`~/.config/fish/config.fish`, `fish_variables`, `functions/`, `conf.d/`), **Bash** (`.bashrc`, `.bash_profile`, `.bash_aliases`), **Zsh** (`.zshrc`), Starship prompt, and system MOTD (`/etc/motd`, `/etc/issue`, `/etc/environment`).
- **Comprehensive Key & Credential Protection**:
  - **SSH Keys**: Private keys, public keys, config, `known_hosts`, and `authorized_keys`.
  - **GPG Keyrings**: Full recursive backup of `~/.gnupg/` including GPG private keys (`private-keys-v1.d/*.key`), revocation certs, and `pubring.db`.
  - **Password Store**: Unix `pass` repository (`~/.password-store/`), `.gpg-id`, and docker credential helpers.
  - **Cloudflare Tunnels**: `~/.cloudflared/` credentials (`cert.pem`, `config.yml`, tunnel JSONs).
  - **Developer Tools**: GitHub CLI (`~/.config/gh/`), Docker daemon & auth (`~/.docker/config.json`), Git config (`~/.gitconfig`).
- **Hardware, Kernel & Systemd Customizations**:
  - Custom kernel sysctl tuning (`/etc/sysctl.d/*.conf`).
  - Hardware udev rules (`/etc/udev/rules.d/*.rules`).
  - Custom systemd services, timers, and drop-in overrides (`/etc/systemd/system/`).
- **One-Off / Custom Files Manager (`config/custom_files.json`)**:
  - Arbitrary files, directories, or glob patterns can be catalogued and backed up (e.g. system typography such as `/usr/local/share/fonts/0/0xProto*.ttf`).
- **Disaster Recovery for Root (`/`) Drive Failure**:
  - Archives `/etc/fstab`, `/etc/crypttab`, drive UUID maps, and Btrfs subvolume layouts. Rebuilds and remounts your external archive drives (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SLOW_ARCHIVE`, `SHARD_*`) without risking bulk data.
- **Untrusted Multi-Destination Cloud Sync**:
  - **Git Remote (GitHub)**: The encrypted vault is written to `./data/` and automatically committed/pushed as an offsite backup.
  - **AWS S3 / S3-Compatible** (Cloudflare R2, Wasabi, MinIO, Backblaze B2).
  - **Google Drive** & **Microsoft OneDrive** (via rclone with pre-flight checks).
  - **Email (SMTP)** (Automated multi-part chunking for attachments > 20 MB).
  - **Local & Archive Drives** (`/run/media/michael/FAST_ARCHIVE/SystemBackups/` and `./data/`).
- **Zero-Dependency Rescue Decryptor (`restore.sh` / `src/emergency_restore.py`)**: Standalone restoration tool that automatically checks and provisions Python 3, cryptography, zstd, tar, and curl across any Linux distribution before decrypting and restoring system state.

---

## 📁 Project Structure

```
bootstrap/
├── config/
│   ├── destinations.example.json   # Template for storage destinations (S3, GDrive, OneDrive, Email, Local)
│   ├── custom_files.json           # User-defined one-off files/fonts to backup (e.g. 0xProto fonts)
│   └── custom_files.example.json   # Template for custom one-off file definitions
├── src/
│   ├── system_detector.py          # Auto-detects Distro (Arch/Ubuntu), Shell (Fish/Bash), DE (KDE/GNOME)
│   ├── crypto_utils.py             # ChaCha20-Poly1305 + Argon2id + Zstandard vault packaging
│   ├── bootstrap_scanner.py        # Orchestrates all scanners, builds inventory, seals vault, and dispatches
│   ├── generate_bootstrap.py       # Generates Arch (pacman/yay) or Ubuntu (apt/snap) restore scripts
│   ├── restore.py                  # Standalone interactive disaster recovery & vault restoration tool
│   ├── verify.py                   # Validates MAC, extracts to sandbox, and verifies dual SHA-256/SHA-1 hashes
│   ├── scanners/                   # Modular scanning subsystem
│   │   ├── base_scanner.py         # Abstract scanner base class
│   │   ├── distro_scanner.py       # Pacman/Yay/Paru (Arch) & APT/Snap (Ubuntu) scanner
│   │   ├── shell_scanner.py        # Fish, Bash & Zsh configs, functions, variables, MOTD, prompts
│   │   ├── storage_scanner.py      # /etc/fstab, /etc/crypttab, lsblk UUIDs, Btrfs subvolumes
│   │   ├── systemd_scanner.py      # System & user units, timers, /etc/sysctl.d, /etc/udev/rules.d
│   │   ├── network_scanner.py      # NetworkManager connections & WireGuard profiles
│   │   ├── keys_scanner.py         # SSH, GPG private keys, pass store, cloudflared, docker, git
│   │   ├── desktop_scanner.py      # KDE Plasma user shortcuts, window rules & applets
│   │   └── custom_files_scanner.py # Arbitrary user-defined files and glob patterns (fonts, scripts)
│   └── storage/                    # Multi-destination untrusted storage subsystem
│       ├── base_backend.py         # Base storage provider interface
│       ├── storage_dispatcher.py   # Dispatches encrypted vault to all enabled destinations
│       ├── s3_backend.py           # AWS S3 / Wasabi / Cloudflare R2 / MinIO backend
│       ├── gdrive_backend.py       # Google Drive backend
│       ├── onedrive_backend.py     # Microsoft OneDrive backend
│       ├── email_backend.py        # SMTP email backend with automated multi-part splitting
│       ├── local_backend.py        # Local `./data/` & archive drive destinations with retention cleanup
│       └── rclone_backend.py       # Universal rclone integration with pre-flight checks
├── scripts/
│   ├── run_backup.sh               # Master one-step backup launcher
│   ├── setup_systemd.sh            # Configure automated periodic systemd timer & service
│   ├── bootstrap.sh                # Main generated restoration script (with pacman -T checks)
│   └── git_auto_push.sh            # Automated git commit and push
├── docs/
│   ├── architecture.md             # Complete system architecture & cryptographic specifications
│   ├── DISASTER_RECOVERY.md        # Comprehensive root drive failure recovery guide
│   └── EMERGENCY_CARD.md           # Quick emergency cheatsheet
└── data/
    ├── destinations.json           # Active storage destinations configuration
    ├── inventory.json              # Local unencrypted system state snapshot (gitignored)
    └── bootstrap_vault_*.tar.zst.enc # Authenticated encrypted recovery vault (tracked in git)
```

---

## ⚡ Quick Start

### 1. Run Complete System Backup
```bash
./scripts/run_backup.sh
```
*Prompts for your master password, scans your system, seals all configs into `data/bootstrap_vault_*.tar.zst.enc`, uploads to all active destinations, and commits/pushes the encrypted vault to GitHub.*

### 2. Configure Automated Periodic Backups (Systemd Timer)
Arch Linux and CachyOS use native systemd user timers instead of cron:
```bash
# Interactive setup: prompts for SECRET and schedule (Weekly or Daily)
./scripts/setup_systemd.sh

# Or non-interactive setup:
./scripts/setup_systemd.sh --weekly --secret "YourMasterSecret"

# Check timer status anytime:
./scripts/setup_systemd.sh --status
```
*Creates `~/.config/systemd/user/bootstrap-backup.service` (restricted to permissions `0600`) and `bootstrap-backup.timer` with `Persistent=true` to catch up missed runs after sleep or power off.*

### 3. Verify Backup Vault Integrity
```bash
python3 src/verify.py --vault data/bootstrap_vault_*.tar.zst.enc
```
*Decrypts into an isolated sandbox, validates Poly1305 MAC, parses `manifest.json`, and recalculates both SHA-256 and SHA-1 checksums for all 100+ files.*

### 4. Custom One-Off Files (`config/custom_files.json`)
Add arbitrary files, fonts, or scripts to back up:
```json
[
  {
    "name": "0xProto Fonts",
    "description": "0xProto and 0xProto Nerd Font TTF typography in system fonts directory",
    "patterns": [
      "/usr/local/share/fonts/0/0xProto*.ttf"
    ]
  },
  {
    "name": "SQLite Runtime Config",
    "description": "User custom SQLite initialization file",
    "patterns": [
      "~/.sqliterc"
    ]
  }
]
```

### 5. Disaster Recovery (Fresh System or Replaced `/` Drive)
```bash
# Step 1: Unpack vault and restore fstab, fish/bash dotfiles, GPG/SSH keys, and configs
# (restore.sh automatically installs Python 3, cryptography, zstd, and tar if missing)
sudo ./restore.sh --vault data/bootstrap_vault_*.tar.zst.enc

# Step 2: Reinstall missing software packages in batch (skips packages already present)
sudo ./scripts/bootstrap.sh
```

---

## 🔒 Security Specifications

- **Cipher**: ChaCha20-Poly1305 (256-bit symmetric AEAD stream cipher, 128-bit authentication tag).
- **Compression**: Zstandard (`zstd -19`) applied before encryption with automatic fallback to gzip.
- **KDF**: Argon2id (64MB memory cost, 3 iterations, 4 parallelism) with automatic `scrypt` fallback.
- **Untrusted Storage**: Storage endpoints and Git remotes only ever receive authenticated ciphertext envelopes (`.tar.zst.enc`) with random salts and nonces.
- **Zero Plaintext Secrets**: Shell files are packaged whole without regex scraping or plain text key extraction.
