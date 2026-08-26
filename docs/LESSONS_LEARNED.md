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

---

## 6. The Git `insteadOf` Disaster Recovery Trap

- **The Danger**: Power users frequently add rewriting rules in `~/.gitconfig` to force SSH for all GitHub URLs:
  ```gitconfig
  [url "git@github.com:"]
      insteadOf = https://github.com/
  ```
  When dotfiles are restored onto a freshly booted machine or Live rescue environment, Git immediately begins intercepting **all** HTTPS Git commands (including `git clone`, `git pull`, and AUR helper package sources) and rewriting them to `git@github.com:`. Because the rescue environment has no unlocked SSH agent or loaded keys, GitHub rejects all connections with `git@github.com: Permission denied (publickey)`. Even typing `git clone https://...` fails because Git silently rewrites it!
- **The Solution**:
  - `emergency_restore.py` automatically scans restored `.gitconfig` files and comments out `[url "git@github.com:"] insteadOf = https://github.com/`.
  - Public open-source repositories and package downloads must remain anonymous and credential-free via HTTPS during recovery.
  - SSH keys remain safely restored in `~/.ssh/` for personal use once the workstation is operational.

---

## 7. Live Environment Overlay Limits vs. Full Package Restores (Corrupted Shared Libraries)

- **The Danger**:
  - In Live ISO rescue environments, the root filesystem (`/`) is an in-memory `overlayfs` (`airootfs`) with a fixed space quota (typically 10 GB).
  - A production developer machine inventory contains heavy toolkits (`cuda` at 4.7 GB, `ollama` at 1.0 GB, `dotnet-sdk` at 1.2 GB, `code` at 830 MB, `mingw-w64-gcc` at 1.2 GB, etc.), totaling **over 24.5 GB** uncompressed.
  - Attempting to install all 200+ native packages into a Live ISO fills 100% of the 10 GB filesystem (`No space left on device`).
  - When disk space is exhausted while `pacman` is unpacking dynamic libraries into `/usr/lib/`, the library files are left truncated at 0 or partial bytes with invalid ELF headers.
  - Every subsequent program linking against that library (`sudo`, `sed`, `vim`, `bash`) fails with `[Errno 80] Accessing a corrupted shared library`, crippling the running shell.
- **The Solution**:
  - **Use Scope 2 (`Restore Configurations & Keys only`) in Live/Emergency Environments**: Scope 2 restores storage mounts, fstab, shells, SSH/GPG keys, desktop configs, fonts, and tunnels in under 5 seconds with zero risk of disk exhaustion.
  - **Scope 1 (Full Package Restoration)** should only be performed on an installed OS with a physical NVMe/SSD drive mounted at `/`.

---

## 8. Default Shell & Desktop Shortcut (Ctrl+Alt+T) Synchronization

- **The Danger**:
  - Restoring shell configuration directories (e.g. `~/.config/fish/`) does not automatically change the user's default login shell in `/etc/passwd`. Freshly created users or rescue accounts default to `/bin/bash`, resulting in a mismatch where the user's shell prompt and functions are not loaded upon login.
  - In desktop environments like KDE Plasma 6, shortcuts and default applications are split across `~/.config/kdeglobals` (`TerminalApplication`) and `~/.config/kglobalshortcutsrc` (`[services][<app>.desktop] _launch=Ctrl+Alt+T`).
  - Restoring these config files on disk while KDE is active does not notify the in-memory daemon (`kglobalaccel`). Without an explicit DBus reload signal, Plasma continues using old shortcut mappings until logout.
- **The Solution**:
  - **Automated Shell Synchronization**: `emergency_restore.py` checks `inventory.json`'s `shells.current` (e.g. `/bin/fish`), ensures it exists in `/etc/shells`, and invokes `usermod -s <shell> <user>`.
  - **Live Shortcut Reloading**: After restoring dotfiles, `emergency_restore.py` sends `org.kde.KGlobalAccel.reloadConfig` over the user session DBus (`/run/user/<uid>/bus`) so hotkeys take effect immediately.
  - **Dedicated Switcher Utilities**: Added [`scripts/set_default_shell.sh`](file:///run/media/michael/FAST_ARCHIVE/Programming/bootstrap/scripts/set_default_shell.sh) and [`scripts/set_default_terminal.sh`](file:///run/media/michael/FAST_ARCHIVE/Programming/bootstrap/scripts/set_default_terminal.sh) to quickly switch and verify preferred shells and terminals (`warp`, `alacritty`, `konsole`, `kitty`).


