# Project Backlog & Risk Register

---

## 🚨 Identified Risks & Known Defects

### BUG-001: Systemd Service Manual Run & Password Override Not Honored
- **Type**: Defect / Security Risk
- **Severity**: High
- **Date Reported**: 2026-08-26
- **Status**: Open / Triaged

#### Description
When invoking `setup_systemd.sh` or attempting a manual run of the systemd backup service with a new password on the command line, the new password was not honored. The resulting backup vault committed and dispatched was encrypted using the prior/default password (`[REDACTED_TEST_KEY]`) rather than the user's newly supplied password. This creates a severe recovery failure risk during a disaster if the operator expects their newly chosen password to decrypt the remote vault.

#### Root Causes
1. **Systemctl Inability to Accept Dynamic CLI Arguments**: `systemctl --user start bootstrap-backup.service` executes the static `ExecStart` line in the existing unit file; systemd does not accept runtime parameter overrides via `systemctl start`.
2. **Interactive Overwrite Block in `setup_systemd.sh`**: If `~/.config/systemd/user/bootstrap-backup.service` already exists, `setup_systemd.sh` prompts `Do you want to reconfigure and replace it? [Y/n]`. If run non-interactively or if confirmation is bypassed, the script exits without updating the existing unit.
3. **Hardcoded Password in `ExecStart`**: Storing plaintext or escaped passwords directly in `ExecStart=/bin/bash ... --password "..."` makes password rotation cumbersome and requires `daemon-reload` on every change.

#### Proposed Remediation
1. **Dedicated Credentials File**: Store the master secret in a restricted permissions file (`~/.config/bootstrap/vault.env` mode `0600`) or systemd user credential store (`SetCredential=`), referenced via `EnvironmentFile=` in the service unit.
2. **Force / Non-Interactive Flag in `setup_systemd.sh`**: Add `--force` / `-f` to `setup_systemd.sh` so `--password <NEW_PWD>` automatically replaces existing units and reloads `systemd --user` without interactive prompts.
3. **Password Validation & Confirmation Output**: When `run_backup.sh` executes, log the SHA-256 fingerprint (first 8 hex characters) of the derived key or password salt so the user can immediately confirm which password version was used to seal the vault.

---

## 📋 Feature Backlog & Improvements

### FEAT-001: Automatic Network Drive Discovery & Re-Mount Validation
- When restoring fstab in a new environment, provide an interactive test-mount helper (`emergency_restore.py --test-mounts`) that queries currently connected block devices by filesystem label (e.g. `LABEL=FAST_ARCHIVE`) and offers to update UUIDs automatically if a drive was re-formatted or replaced.

### FEAT-002: Dynamic Password Verification in Pre-Flight
- In `run_backup.sh`, when run interactively, require password confirmation if the password differs from the cached or systemd secret, and display a warning if the default test key is detected.
