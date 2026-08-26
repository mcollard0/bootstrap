# Disaster Recovery & System Bootstrap — Lessons Learned

This document records architectural, operational, and practical lessons learned from developing and live-testing the Universal Linux Bootstrap and Emergency Disaster Recovery System.

---

## 1. Avoid Shell Metacharacters in Passwords

> **Core Rule:** Using **shell metacharacters** like `!` and `&` requires complex escaping in Linux. **Don't use them in passwords. It's a headache.**

### The Problem with Shell Metacharacters
In Linux shells (Bash, Zsh, Fish), certain characters are interpreted as syntactic operators or history modifiers rather than literal text:

- **`!` (History Expansion Metacharacter)**:
  - In interactive Bash, `!` triggers history substitution (e.g. `"[REDACTED_TEST_KEY]"` triggers `bash: !SpecialWord: event not found`).
  - Double quotes (`"..."`) do **not** prevent history expansion in interactive shells; escaping (`\!`) or strict single quotes (`'...'`) are required.
- **`&` (Job Control & Stream Operator)**:
  - Unquoted or incorrectly passed `&` characters cause commands to fork into background subshells.
- **`$`, `;`, `\`, `` ` ``, `|`, `*`**:
  - Cause variable interpolation, command separators, or glob expansion across wrappers, environment files, and systemd units (which require `$$` escaping).
- **Virtual Machine & Emergency Console Mappings**:
  - In headless emergency shells, SPICE/VNC consoles, or minimal rescue environments, keyboard layout mismatches (e.g., US vs. UK or European keymaps) frequently mangle shifted symbols like `!`, `@`, `#`, `&`, causing false decryption failures.

### Recommended Best Practice
- **Use High-Entropy Alphanumeric Passphrases**:
  - Instead of short passwords with symbol noise (`P@$$w0rd!&`), use Diceware-style multi-word passphrases using standard alphanumeric characters and hyphens:
    ```text
    CorrectHorseBatteryStaple2026
    CrimsonFalconVelvetKangaroo8492
    cachy-arch-rescue-vault-2026
    ```
  - A 4- or 5-word alphanumeric passphrase provides **80–100+ bits of entropy** (exponentially stronger than complex 12-character strings) with **zero escaping bugs**, zero shell expansion issues, and zero keyboard layout ambiguity.

---

## 2. Non-Blocking Storage Topology (`/etc/fstab`)

- **The Danger**: If secondary storage drives (such as `/run/media/michael/FAST_ARCHIVE` or `/run/media/michael/LARGE_ARCHIVE`) are recorded in `/etc/fstab` with default mount options, systemd halts the boot process into emergency maintenance mode if those drives are destroyed, missing, or disconnected during hardware replacement. Furthermore, systemd stalls boot for 90 seconds waiting for device nodes.
- **The Solution**: All secondary mounts must be automatically injected with:
  `noatime,nofail,x-systemd.device-timeout=5s,x-systemd.automount 0 0`
  - `nofail`: Boots cleanly even if the drive does not exist.
  - `x-systemd.device-timeout=5s`: Caps node detection wait time to 5 seconds instead of 90 seconds.
  - `x-systemd.automount`: Mounts on-demand upon first directory access.

---

## 3. The Package Manager "All-or-Nothing" Trap

- **The Danger**: Handing hundreds of package names to `pacman -S <pkgs...>` in a single batch will fail completely if even a single custom or third-party package is missing (`error: target not found: warp-terminal`). Pacman cancels the entire transaction, leaving zero packages installed.
- **The Solution**:
  1. Always run `pacman -Sy` first to synchronize database indexes for any restored custom repositories.
  2. Parse `target not found` errors from stderr, filter out unavailable targets, and retry installation for the valid native packages.
  3. Forward the missing targets to the AUR helper (`paru` or `yay`) queue.

---

## 4. System File Permissions (`0644` vs. `0600`)

- **The Danger**: When restoring configuration files like `/etc/pacman.conf` through temporary staging files, utilities like Python's `NamedTemporaryFile` assign `0600` permissions. If copied into `/etc/` with `0600`, root can read the file, but unprivileged user-space tools (`paru`, `makepkg`) fail with `Permission denied`.
- **The Solution**: System configuration files written under `/etc/` must be explicitly set to `root:root` ownership and `0644` mode (`-rw-r--r--`).

---

## 5. Live Environments vs. Persistent Media

- **The Danger**: In disaster recovery drills using a Live ISO, all changes reside in volatile RAM (`tmpfs`/`overlayfs`). Rebooting the VM wipes all state unless the OS has been installed to the virtual disk via Calamares.
- **The Solution**: If testing reboots of a live environment, keep the ISO permanently mounted in the virtual CD-ROM tray so the UEFI firmware doesn't drop into Tianocore device selection.
