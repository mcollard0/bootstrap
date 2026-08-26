# 🆘 EMERGENCY RECOVERY CARD

Keep a copy of this card accessible (e.g. phone, password manager, printed).

---

## 🔐 Master Password
*(Your memory-hard Argon2id encryption master key)*

---

## ⚡ 3-Step Recovery from Fresh Install / Live USB

### 1. Retrieve Encrypted Vault
Get `bootstrap_vault_*.tar.enc` from:
- Secondary Mount: `/run/media/michael/FAST_ARCHIVE/SystemBackups/`
- Email: Download attachment from your email
- Cloud: Google Drive / OneDrive (`Bootstrap_Backups`) or AWS S3
- Git: `git clone git@github.com:mcollard0/bootstrap.git`

### 2. Decrypt & Restore Configs
```bash
cd bootstrap
python3 src/restore.py --vault bootstrap_vault_*.tar.enc
```
*(Enter master password, choose option 2 to restore fstab, fish/bash dotfiles, SSH/GPG keys)*

### 3. Reinstall Packages
```bash
sudo ./scripts/bootstrap.sh
```

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
