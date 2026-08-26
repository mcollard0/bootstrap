# Universal Bootstrap System Architecture

## Overview
The Universal Bootstrap System captures, encrypts, and synchronizes a complete Linux system configuration across untrusted cloud and local storage endpoints. It provides complete disaster recovery for **Arch Linux, CachyOS, and Ubuntu** systems.

---

## System Architecture

```
bootstrap/
├── config/
│   └── destinations.example.json   # Destination configuration template
├── src/
│   ├── system_detector.py          # Auto-detects Distro (Arch/Ubuntu), Shell (Fish/Bash), DE (KDE/GNOME)
│   ├── crypto_utils.py             # ChaCha20-Poly1305 + Argon2id authenticated vault packaging (Zstd/Gzip)
│   ├── bootstrap_scanner.py        # Orchestrates scanners, builds inventory, seals vault, and dispatches
│   ├── generate_bootstrap.py       # Generates Arch (pacman/yay) or Ubuntu (apt/snap) restore scripts
│   ├── restore.py                  # Standalone interactive disaster recovery & idempotent vault restorer
│   ├── verify.py                   # Vault authenticator, manifest parser, and SHA-256/SHA-1 verifier
│   ├── scanners/                   # Modular scanning subsystem
│   │   ├── base_scanner.py         # Abstract scanner base class
│   │   ├── distro_scanner.py       # Pacman/Yay/Paru (Arch) & APT/Snap (Ubuntu) scanner
│   │   ├── shell_scanner.py        # User & system-wide Fish (/etc/fish), Bash, MOTD, prompts
│   │   ├── storage_scanner.py      # /etc/fstab, /etc/crypttab, lsblk UUIDs, Btrfs subvolumes, boot configs
│   │   ├── systemd_scanner.py      # Enabled system & user units and timers
│   │   ├── network_scanner.py      # NetworkManager connections & WireGuard profiles
│   │   ├── keys_scanner.py         # SSH, GPG, SSL certificates & private keys
│   │   └── desktop_scanner.py      # KDE Plasma non-default customizations & GNOME shortcuts
│   └── storage/                    # Multi-destination untrusted storage subsystem
│       ├── base_backend.py         # Base storage provider interface
│       ├── storage_dispatcher.py   # Dispatches encrypted vault to all enabled destinations
│       ├── s3_backend.py           # AWS S3 / Wasabi / Cloudflare R2 / MinIO backend
│       ├── gdrive_backend.py       # Google Drive backend
│       ├── onedrive_backend.py     # Microsoft OneDrive backend
│       ├── email_backend.py        # SMTP backend with automatic 20MB chunking/splitting
│       ├── local_backend.py        # Local & FAST_ARCHIVE drive destination
│       └── rclone_backend.py       # Universal rclone integration with pre-flight checks
├── scripts/
│   ├── run_backup.sh               # Master one-step backup launcher
│   ├── bootstrap.sh                # Main generated restoration script (with pacman -T checks)
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

---

## Inventory Schema (Version 3.0)

```json
{
  "version": "3.0",
  "timestamp": "2026-08-26T08:52:05.298518",
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
    "system_fish": {"exists": true, "has_config": true, "conf_d_files": []},
    "bash": {"found_files": [".bashrc", ".bash_profile"]},
    "motd": {"/etc/motd": {"exists": true}, "/etc/shells": {"exists": true}},
    "prompts": {"starship": "~/.config/starship.toml"}
  },
  "storage": {
    "fstab": {"exists": true, "entries": []},
    "crypttab": {"exists": true, "content": "..."},
    "block_devices": [],
    "boot_configs": {
      "/etc/mkinitcpio.conf": "...",
      "/etc/pacman.conf": "...",
      "/etc/vconsole.conf": "...",
      "/etc/locale.conf": "..."
    },
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
  },
  "desktop": {
    "detected_de": "kde",
    "kde": {
      "custom_configs": [
        {"file": "kglobalshortcutsrc", "size": 15758},
        {"file": "kdeglobals", "size": 4164},
        {"file": "kwinrc", "size": 1277}
      ]
    }
  }
}
```

---

## Cryptographic Design & Untrusted Storage

### Vault Container Specifications
- **Container Format**:
  ```
  BOOTSTRAP_VAULT_V3\n
  <Base64-JSON-Metadata-Envelope>\n
  <ChaCha20-Poly1305 Ciphertext Payload + 16-byte Poly1305 MAC Tag>
  ```
- **File Extensions**: `.tar.zst.enc` (preferred) or `.tar.gz.enc` (fallback).
- **Symmetric Cipher**: `ChaCha20-Poly1305` (256-bit key, 96-bit random nonce, 128-bit MAC tag).
- **Key Derivation Function (KDF)**:
  - Primary: `Argon2id` (time cost: 3, memory: 64 MB, parallelism: 4, 16-byte random salt).
  - Standard Library Fallback: `hashlib.scrypt` (N=16384, r=8, p=1). Ensures rescue decryption functions in standard Python rescue media without third-party C-extensions.
- **Envelope Header Metadata**:
  ```json
  {
    "version": "3.0",
    "algorithm": "ChaCha20-Poly1305",
    "kdf": "scrypt",
    "compression": "zstd",
    "uncompressed_tar_bytes": 337920,
    "compressed_bytes": 50683,
    "compression_ratio_percent": 15.0,
    "salt": "<base64-salt>",
    "nonce": "<base64-nonce>",
    "sha256_uncompressed_tar": "<sha256>",
    "sha256_compressed": "<sha256>",
    "sha256_ciphertext": "<sha256>",
    "hostname": "michael-asus-03",
    "distribution": "CachyOS",
    "os_family": "arch",
    "created_at": "2026-08-26T08:52:05.298518",
    "total_files": 57
  }
  ```
- **Zero-Knowledge Property**: Remote storage backends only ever see randomized ciphertext and base64 envelope parameters. File trees, names, directory structures, and content are completely hidden.

---

## Compression Subsystem

- **Engine**: Native Zstandard (`zstd -19`) with automatic fallback to Gzip (`tarfile` mode `w:gz`).
- **Compression Ratio**: In practice, configuration trees and text files achieve an ~85% reduction (e.g. 338 KB raw tar compressed to ~50 KB ciphertext).
- **Automatic Decompression**: During decryption, `extract_encrypted_vault()` detects the compression magic bytes (`0x28 0xb5 0x2f 0xfd` for zstd, `0x1f 0x8b` for gzip) or header metadata, invoking `tar --zstd -xf` or `tarfile.open('r:gz')`.

---

## Integrity & Verification Subsystem (`src/verify.py`)

### Embedded Manifests
During vault assembly in `src/bootstrap_scanner.py`, two manifest files are generated and sealed directly inside the vault:
1. `manifest.json`: Machine-readable array containing each file's virtual path, source path, size, octal permissions, SHA-256 checksum, and SHA-1 checksum.
2. `manifest.txt`: Human-readable tabular report.

### Verification CLI Tool (`src/verify.py`)
`src/verify.py` provides independent verification:
1. **Cryptographic Authentication**: Validates the Poly1305 MAC tag before unpacking.
2. **Envelope Extraction**: Extracts files into an isolated temporary directory without touching system files.
3. **Dual Hash Verification**: Recalculates both SHA-256 and SHA-1 checksums for all unpacked files and compares them against `manifest.json`.
4. **Exit Codes**: Returns exit status `0` on 100% verification, or `1` on mismatch or tampering.

---

## Disaster Recovery & Idempotency Model

The system is designed for complete recovery from a **Root (`/`) Drive Failure** while guaranteeing that routine runs on a healthy or partially-configured machine are **fast, idempotent, and non-breaking**.

### 1. Storage & Filesystem Topology
- **`/etc/fstab` Merging**: Does not blindly overwrite the active `/etc/fstab`. Parses existing mount points and only appends missing entries.
- **Mount Point Creation**: Automatically ensures mount directories (e.g. `/run/media/michael/FAST_ARCHIVE`, `/run/media/michael/LARGE_ARCHIVE`) exist without modifying underlying partitions or data.
- **`/etc/crypttab`**: Preserves LUKS volume mapper configurations (UUIDs, options, keyfiles) so encrypted drives automatically unlock on boot.

### 2. Package Management Idempotency (`pacman -T`)
- Both `src/restore.py` and `scripts/bootstrap.sh` query `pacman -T <packages>` to identify which packages are actually missing from the current system.
- If all packages are already satisfied, the package step completes in **< 0.05 seconds** and skips running `pacman` or `paru/yay` entirely, preventing unintended package recompilations or downgrades.

### 3. File Restoration Idempotency
- Before copying any configuration file (Fish, Bash, SSH keys, KDE configs), `restore.py` checks if the target exists and compares its SHA-256 hash.
- Files matching the vault are skipped (`✓ Already up-to-date`).
- Files with modifications create a timestamped backup before writing.
- Strict permissions are enforced (e.g. `0700` for `~/.ssh`, `0600` for private keys).

### 4. Desktop Environment (KDE Plasma & GNOME)
- **Noise Filtering**: Excludes transient caches, window histories, and clipboard buffers (`klipperrc`, `katemetainfos`, `kactivitymanagerdrc`, `kconf_updaterc`).
- **Persistent Settings**: Captures user shortcuts (`kglobalshortcutsrc`), themes and colors (`kdeglobals`), window manager behaviors (`kwinrc`), window rules (`kwinrulesrc`), mouse/touchpad gestures (`kcminputrc`), and desktop layouts (`plasma-org.kde.plasma.desktop-appletsrc`, `plasmashellrc`).

---

## Multi-Destination Storage Subsystem

`src/storage/storage_dispatcher.py` concurrently manages uploads across multiple backends with individual retention policies:

| Backend | Implementation | Key Capabilities |
| :--- | :--- | :--- |
| **Local & Archive** | `local_backend.py` | Stores in `./backup` and `/run/media/michael/FAST_ARCHIVE/SystemBackups/` with automated retention cleanup. |
| **AWS S3 / S3-Compatible** | `s3_backend.py` | Works with AWS S3, Wasabi, Cloudflare R2, MinIO, Backblaze B2 using `boto3` or raw SigV4 HTTP requests. |
| **Google Drive** | `gdrive_backend.py` | Google Drive storage via rclone or direct API. |
| **OneDrive** | `onedrive_backend.py` | Microsoft OneDrive storage via rclone or direct API. |
| **Universal Rclone** | `rclone_backend.py` | Connects to any rclone remote (`rclone copyto`). Features pre-flight checks for binary existence and configured remotes, with detailed error diagnostics. |
| **Email (SMTP)** | `email_backend.py` | Dispatches encrypted vault via SMTP. Features **automatic 20 MB multi-part chunking** (`.part01`, `.part02`, ...) with terminal reassembly instructions if attachment limits are exceeded. |
