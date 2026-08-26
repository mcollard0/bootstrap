# 🚨 Disaster Recovery & Reinstallation Guide

## Scenario: Root (`/`) Drive Failure on Arch Linux / CachyOS / Ubuntu

If your root (`/`) system drive fails, your bulk files and archives are safe on your secondary archive drives (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, `SLOW_ARCHIVE`, `SHARD_*`). Follow this guide to reinstall your OS and restore your entire system configuration, package manifest, SSH/GPG keys, Fish/Bash dotfiles, and mount topology in minutes.

---

## 📦 What is Preserved in the Encrypted Vault

Every backup creates a single authenticated encrypted vault (`bootstrap_vault_<hostname>_<timestamp>.tar.enc`):
- **Storage Topology**: Full `/etc/fstab`, `/etc/crypttab`, drive UUID mapping, and mount points (`FAST_ARCHIVE`, `LARGE_ARCHIVE`, etc.).
- **Shells & Dotfiles**: Complete `~/.config/fish/` (`config.fish`, `fish_variables`, `functions/`, `conf.d/`), `~/.bashrc`, `~/.bash_profile`, `~/.bash_aliases`, `~/.profile`, Starship prompt, Fastfetch.
- **Security & Credentials**: SSH private & public keys (`~/.ssh/`), GPG keyring configs (`~/.gnupg/`), Git config (`~/.gitconfig`), SSL private keys (`/etc/ssl/private/`), API keys & secrets.
- **Desktop Environment**: KDE Plasma shortcuts (`kglobalshortcutsrc`), window rules (`kwinrc`), theme (`kdeglobals`) or GNOME settings.
- **Package Manifests**: 340+ native pacman packages, 29+ AUR packages (via `paru`/`yay`), flatpaks, and python modules.
- **System Configs**: NetworkManager connection profiles, WireGuard profiles, `/etc/hosts`, `/etc/environment`, `/etc/motd`.

---

## 🚀 Step 1: Fresh Base OS Installation

1. Install your distribution (e.g. **CachyOS** or **Arch Linux** or **Ubuntu**) on your new root SSD/drive.
2. Create your user account (e.g. `michael`).
3. Ensure internet connectivity is working.

---

## 🔑 Step 2: Retrieve Your Encrypted Vault

Retrieve your latest `bootstrap_vault_*.tar.enc` from any of your configured backup locations:

- **Option A (Secondary Drive)**: If `FAST_ARCHIVE` or `LARGE_ARCHIVE` is attached, the vault is located in `/run/media/michael/FAST_ARCHIVE/SystemBackups/`.
- **Option B (Email Attachment)**: Open your email on any device/webmail and download the attached `bootstrap_vault_*.tar.enc`.
- **Option C (Google Drive / OneDrive / S3)**: Download `bootstrap_vault_*.tar.enc` from your `Bootstrap_Backups` folder or S3 bucket.
- **Option D (Git)**:
  ```bash
  git clone git@github.com:mcollard0/bootstrap.git
  cd bootstrap
  ```

---

## 🛠️ Step 3: Run the Rescue Restorer

```bash
# Navigate to bootstrap project directory
cd /path/to/bootstrap

# Run the interactive restoration tool
python3 src/restore.py --vault /path/to/bootstrap_vault_*.tar.enc
```

When prompted:
1. Enter your **Master Encryption Password**.
2. Select your desired restoration action:
   - **Option 1**: Full Restoration (Storage/fstab, Shells, Keys, Desktop, Packages).
   - **Option 2**: Restore Configuration & Keys (fstab, Fish/Bash, SSH/GPG, Desktop).
   - **Option 3**: Mounts & `/etc/fstab` only.

---

## 💾 Step 4: Re-Attaching Archive Drives (`FAST_ARCHIVE`, `LARGE_ARCHIVE`)

The restorer will:
1. Ensure all mount point directories exist in `/run/media/michael/`:
   ```bash
   /run/media/michael/FAST_ARCHIVE
   /run/media/michael/LARGE_ARCHIVE
   /run/media/michael/SLOW_ARCHIVE
   /run/media/michael/SHARD_3
   /run/media/michael/SHARD_4
   /run/media/michael/SHARD_9
   ```
2. Verify `/etc/fstab` matches your drive UUIDs.
3. Test mount without wiping data:
   ```bash
   sudo mount -a
   ```

---

## 📦 Step 5: Batch Reinstall Packages

To reinstall all your software packages automatically:
```bash
sudo ./scripts/bootstrap.sh
```
This will:
- Synchronize pacman mirrors
- Install AUR helper (`paru` or `yay`)
- Install all native and AUR packages in batch
- Set default shell to Fish (`chsh -s $(which fish)`)
- Enable NetworkManager and fstrim systemd services

---

## ✅ Step 6: Post-Recovery Verification Checklist

- [ ] Check mount points: `lsblk -f` (verify `FAST_ARCHIVE` and `LARGE_ARCHIVE` are mounted)
- [ ] Check shell: `fish` (verify prompts, functions, aliases, and variables)
- [ ] Check SSH keys: `ssh -T git@github.com`
- [ ] Check desktop shortcuts: (KDE Plasma keybindings active)
- [ ] Check packages: `pacman -Qe` and `paru -Qe`
