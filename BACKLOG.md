# Project Backlog & Risk Register

---

## 🚨 Identified Risks & Known Defects

### BUG-001: Systemd Service Manual Run & Password Override Not Honored
- **Type**: Defect / Security Risk
- **Severity**: High
- **Date Reported**: 2026-08-26
- **Status**: Resolved & Verified (2026-08-27)

#### Description
When invoking `setup_systemd.sh` or attempting a manual run of the systemd backup service with a new password on the command line, the new password was not honored. The resulting backup vault committed and dispatched was encrypted using the prior cached password rather than the operator's newly supplied password. This creates a severe recovery failure risk during a disaster if the operator expects their newly chosen password to decrypt the remote vault.

#### Root Causes
1. **Systemctl Inability to Accept Dynamic CLI Arguments**: `systemctl --user start bootstrap-backup.service` executes the static `ExecStart` line in the existing unit file; systemd does not accept runtime parameter overrides via `systemctl start`.
2. **Interactive Overwrite Block in `setup_systemd.sh`**: If `~/.config/systemd/user/bootstrap-backup.service` already exists, `setup_systemd.sh` prompts `Do you want to reconfigure and replace it? [Y/n]`. If run non-interactively or if confirmation is bypassed, the script exits without updating the existing unit.
3. **Hardcoded Password in `ExecStart`**: Storing plaintext or escaped passwords directly in `ExecStart=/bin/bash ... --password "..."` makes password rotation cumbersome and requires `daemon-reload` on every change.

#### Resolution & Implemented Changes
1. **Dedicated Credentials File (`~/.config/bootstrap/vault.env`)**:
   - Master password is now stored with mode `0600` inside `~/.config/bootstrap/vault.env` (directory permissions `0700`).
   - Systemd user service unit references this file securely via `EnvironmentFile=-%h/.config/bootstrap/vault.env`.
   - `ExecStart` no longer contains plaintext secrets, eliminating password exposure in process listings (`ps aux`).
2. **Non-Interactive Force Flag (`--force` / `-f`)**:
   - Added `--force` / `-f` to `scripts/setup_systemd.sh` so password updates and unit reconfigurations execute non-interactively without blocking.
   - Schedule prompt is automatically bypassed when `--force` is provided.
3. **Multi-Tier Password Resolution & Fingerprint Logging**:
   - `src/bootstrap_scanner.py`, `scripts/run_backup.sh`, and `emergency_restore.py` now support the priority order:
     1. Command-line flag (`--password <KEY>`)
     2. Environment variable (`BOOTSTRAP_PASSWORD` / `VAULT_PASSWORD`)
     3. Dedicated credential file (`~/.config/bootstrap/vault.env`)
     4. Interactive prompt
   - All tools log the non-sensitive SHA-256 fingerprint (`sha256:<first-8-hex>`) of the active password when encrypting and decrypting the vault, allowing instantaneous operator verification.

#### Verification
- Verified with rotated test key:
  - Fingerprint logged at vault creation: `sha256:e0cb7389`.
  - Manual systemd service run (`systemctl --user start bootstrap-backup.service`) successfully picked up the new password from `vault.env` and generated a valid encrypted vault (`data/bootstrap_vault_michael-asus-03_20260827_110430.tar.zst.enc`).
  - Tested on clean Omarchy VM disaster recovery where the newly rotated test password successfully decrypted the vault and restored system state.

---

## 📋 Feature Backlog & Improvements

### FEAT-001: Automatic Network Drive Discovery & Re-Mount Validation
- When restoring fstab in a new environment, provide an interactive test-mount helper (`emergency_restore.py --test-mounts`) that queries currently connected block devices by filesystem label (e.g. `LABEL=FAST_ARCHIVE`) and offers to update UUIDs automatically if a drive was re-formatted or replaced.

### FEAT-002: Dynamic Password Verification in Pre-Flight
- In `run_backup.sh`, when run interactively, require password confirmation if the password differs from the cached or systemd secret, and display a warning if the default test key is detected.
