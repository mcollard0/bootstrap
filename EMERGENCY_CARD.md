# 🆘 EMERGENCY RECOVERY CARD

Keep a copy of this card accessible (e.g. phone, password manager, printed).

---

## 🔐 Master Password
*(Your memory-hard Argon2id encryption master key)*

---

## ⚡ 4-Step Recovery from Fresh Install / Live USB

### Step 0. Install Prerequisites

Boot into your Live USB or fresh Linux install and open a terminal:

#### 🔹 On Arch Linux / CachyOS Live USB:
*(Python 3 and `zstd` come pre-installed)*
```bash
sudo pacman -Sy --noconfirm git python-cryptography
```
> *Note: `rclone` is **not** pre-installed by default. If downloading your vault from Google Drive or OneDrive, run: `sudo pacman -S --noconfirm rclone`*

#### 🔹 On Ubuntu / Debian Live USB:
*(Python 3 comes pre-installed)*
```bash
sudo apt update && sudo apt install -y git python3-cryptography zstd
```
> *Note: If downloading from Google Drive/OneDrive: `sudo apt install -y rclone`*

---

### Step 1. Retrieve the Encrypted Vault & Repo

Choose whichever source is most accessible:

- **Option A: Local Secondary Drive (Fastest, zero internet required)**
  ```bash
  # Copy repo & vault directly from your archive disk:
  cp -r /run/media/michael/FAST_ARCHIVE/Programming/bootstrap ~/bootstrap
  cd ~/bootstrap
  ```
- **Option B: GitHub (Remote Git Backup)**
  ```bash
  git clone https://github.com/mcollard0/bootstrap.git ~/bootstrap
  cd ~/bootstrap
  # (Vault is located in data/bootstrap_vault_*.tar.zst.enc)
  ```
- **Option C: Google Drive / OneDrive via Rclone**
  ```bash
  rclone copy gdrive:Bootstrap_Backups/ ./data/
  ```
- **Option D: Email Attachment**
  Download `bootstrap_vault_*.tar.zst.enc` from your emergency email inbox and place in `~/bootstrap/data/`.

---

### Step 2. Decrypt & Restore System Configurations

Run the interactive emergency restoration tool as **`sudo`** from the repository root:
```bash
# restore.sh automatically verifies and installs Python 3, cryptography, and zstd if missing
sudo ./restore.sh --vault data/bootstrap_vault_*.tar.zst.enc
```
*(Running with `sudo` is required to safely merge into `/etc/fstab`, create `/run/media/` mount points, and restore system fonts and hardware rules. The tool automatically detects your regular user via `$SUDO_USER` and sets proper user ownership for all home directory dotfiles and keys.)*
1. Review the emergency banner and press **`Y`** (or Enter) at the 900-second countdown confirmation.
2. Enter your master encryption password.
3. Choose **Option 2 (Full Selective Restoration)**:
   - Restores `/etc/fstab` & storage topologies (mounts `FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SLOW_ARCHIVE`, `SHARD_*`).
   - Restores all Shells (`config.fish`, `fish_variables`, functions, `.bashrc`, `.zshrc`, MOTD).
   - Restores all SSH keys, GPG private keys (`~/.gnupg/`), and Password Store (`~/.password-store/`).
   - Restores Cloudflare tunnels, Docker auth, Git config, and Desktop shortcuts.
   - Restores custom one-off files and typography (e.g. `0xProto` fonts).
   - *(All file writes are idempotent: identical files are skipped, backups created for diffs)*.

---

### Step 3. Reinstall Software Packages

Run the generated package installation script:
```bash
sudo ./scripts/bootstrap.sh
```
*(On Arch/CachyOS, uses `pacman -T` to only install missing packages in fast batches, skipping everything already present)*.

---

## 📌 Critical System Mounts
- `/run/media/michael/FAST_ARCHIVE` (Btrfs)
- `/run/media/michael/LARGE_ARCHIVE` (Btrfs)
- `/run/media/michael/SLOW_ARCHIVE` (Ext4)
- `/run/media/michael/SHARD_3`, `/run/media/michael/SHARD_4`, `/run/media/michael/SHARD_9` (Ext4)

---

## 🛠️ Routine Backup Command
To perform a complete scan, encrypted vault creation, and multi-cloud sync at any time:
```bash
./scripts/run_backup.sh
```
Automated backups run periodically via systemd timer:
```bash
./scripts/setup_systemd.sh --status
```
