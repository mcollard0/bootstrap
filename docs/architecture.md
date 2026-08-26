# Universal Bootstrap System Architecture

## Overview
The Universal Bootstrap System captures, encrypts, and synchronizes a complete Linux system configuration across untrusted cloud and local storage endpoints. It provides complete disaster recovery for **Arch Linux, CachyOS, and Ubuntu** systems.

## System Architecture

```
bootstrap/
├── config/
│   └── destinations.example.json   # Destination configuration template
├── src/
│   ├── system_detector.py          # Auto-detects Distro (Arch/Ubuntu), Shell (Fish/Bash), DE (KDE/GNOME)
│   ├── crypto_utils.py             # ChaCha20-Poly1305 + Argon2id authenticated vault packaging
│   ├── bootstrap_scanner.py        # Orchestrates scanners, builds inventory, seals vault, and dispatches
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
│   ├── architecture.md             # This document
│   ├── DISASTER_RECOVERY.md        # Root drive failure recovery procedures
│   └── EMERGENCY_CARD.md           # Quick emergency cheatsheet
└── data/
    ├── destinations.json           # Active storage destinations configuration
    ├── inventory.json              # Unencrypted system state snapshot (local inspection)
    └── encrypted_secrets.json      # Encrypted secrets store
```

## Inventory Schema (Version 3.0)

```json
{
  "version": "3.0",
  "timestamp": "2026-08-25T21:35:26.922996",
  "system_info": {
    "os": {
      "id": "cachyos",
      "family": "arch",
      "pretty_name": "CachyOS",
      "kernel": "7.2.0-1-cachyos",
      "hostname": "michael-asus-03"
    },
    "package_managers": {
      "primary": "pacman",
      "aur_helper": "paru"
    },
    "shells": {
      "current": "/bin/fish",
      "default_name": "fish",
      "has_fish_config": true,
      "has_bash_config": true
    },
    "desktop": {
      "name": "kde",
      "session_type": "wayland"
    }
  },
  "packages": {
    "arch_native": [{"name": "package", "version": "1.0"}],
    "arch_aur": [{"name": "aur-package", "version": "1.0"}],
    "apt": [],
    "snap": [],
    "flatpak": [],
    "python_user": []
  },
  "shells": {
    "fish": {"exists": true, "functions": ["..."], "conf_d_files": []},
    "bash": {"found_files": [".bashrc", ".bash_profile"]},
    "motd": {"/etc/motd": {"exists": true}},
    "prompts": {"starship": "~/.config/starship.toml"}
  },
  "storage": {
    "fstab": {"exists": true, "entries": []},
    "block_devices": [],
    "archive_drives": [
      {"label": "FAST_ARCHIVE", "fstype": "btrfs", "mountpoints": ["/run/media/michael/FAST_ARCHIVE"]},
      {"label": "LARGE_ARCHIVE", "fstype": "btrfs", "mountpoints": ["/run/media/michael/LARGE_ARCHIVE"]}
    ]
  },
  "systemd": {
    "system_enabled_units": [{"unit": "NetworkManager.service", "state": "enabled"}],
    "user_enabled_units": [{"unit": "ydotool.service", "state": "enabled"}]
  },
  "network": {
    "network_manager_connections": [],
    "wireguard_profiles": []
  },
  "keys": {
    "ssh_keys": [{"name": "id_ed25519", "is_public": false}],
    "git": {"has_gitconfig": true}
  }
}
```

## Cryptographic Design & Untrusted Storage

### Vault Container Specifications
- **Format**: `BOOTSTRAP_VAULT_V3\n<Base64-Metadata-JSON>\n<ChaCha20-Poly1305 Ciphertext>`
- **Cipher**: ChaCha20-Poly1305 (AEAD)
- **KDF**: Argon2id with automatic scrypt fallback
- **Properties**:
  - Authenticated Encryption: Any tampering with ciphertext immediately fails Poly1305 verification.
  - Zero Metadata Leakage: Storage backends only receive random salt, nonce, and ciphertext. File paths, hostnames, and contents are completely obscured.

## Disaster Recovery Model

1. **Root Drive Failure**: The system drive fails, but external bulk storage drives (`FAST_ARCHIVE`, `LARGE_ARCHIVE`) remain intact.
2. **Reinstallation**: Install fresh base OS (Arch Linux, CachyOS, or Ubuntu).
3. **Rescue Decryption**: `python3 src/restore.py --vault <vault_file>` prompts for password and restores:
   - `/etc/fstab` and mount point directories (`mkdir -p /run/media/michael/FAST_ARCHIVE`)
   - Shell dotfiles (`~/.config/fish/`, `~/.bashrc`)
   - SSH and GPG security keys with chmod 600/700
4. **Package Reinstallation**: `sudo ./scripts/bootstrap.sh` batch reinstalls all native and AUR packages.
