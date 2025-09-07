# Ubuntu Bootstrap System - Testing Guide

## VirtualBox VM Testing Setup

### VM Configuration Created
- **Name**: Ubuntu-Bootstrap-Test
- **OS**: Ubuntu 64-bit
- **Memory**: 4GB RAM
- **CPU**: 2 cores
- **Storage**: 20GB VDI disk
- **ISO**: ubuntu-24.04.3-desktop-amd64.iso
- **Shared Folder**: `/media/sf_bootstrap` (auto-mounted)

### Pre-Test Checklist

✅ VM created with Ubuntu 24.04.3 Desktop ISO  
✅ Shared folder configured: `/media/michael/FASTESTARCHIVE/Archive/Programming/bootstrap` → `/media/sf_bootstrap`  
✅ Bootstrap script generated with encrypted secrets  
✅ All components tested individually on host system  

## Testing Procedure

### 1. Initial Ubuntu Installation
1. **Boot VM** from Ubuntu ISO
2. **Install Ubuntu 24.04.3** with minimal installation
3. **Create user**: `testuser` (or any username)
4. **Complete installation** and reboot
5. **Install VirtualBox Guest Additions** for shared folder access:
   ```bash
   sudo apt update
   sudo apt install virtualbox-guest-additions-iso
   sudo usermod -aG vboxsf testuser
   # Reboot to apply changes
   ```

### 2. Access Bootstrap Files
```bash
# After reboot, shared folder should be accessible
ls /media/sf_bootstrap/
cd /media/sf_bootstrap/
ls -la scripts/bootstrap.sh
```

### 3. Pre-Restoration System State Check
```bash
# Document initial state before restoration
echo "=== PRE-RESTORATION STATE ===" > /tmp/test_log.txt
echo "Firefox installed:" >> /tmp/test_log.txt
snap list firefox 2>/dev/null && echo "YES (snap)" >> /tmp/test_log.txt || echo "NO (snap)" >> /tmp/test_log.txt
dpkg -l firefox 2>/dev/null && echo "YES (apt)" >> /tmp/test_log.txt || echo "NO (apt)" >> /tmp/test_log.txt

echo "Google Chrome installed:" >> /tmp/test_log.txt
which google-chrome >> /tmp/test_log.txt 2>&1 || echo "NO" >> /tmp/test_log.txt

echo "Docker installed:" >> /tmp/test_log.txt  
which docker >> /tmp/test_log.txt 2>&1 || echo "NO" >> /tmp/test_log.txt

echo "Flatpak installed:" >> /tmp/test_log.txt
which flatpak >> /tmp/test_log.txt 2>&1 || echo "NO" >> /tmp/test_log.txt

echo "KVM modules loaded:" >> /tmp/test_log.txt
lsmod | grep kvm >> /tmp/test_log.txt 2>&1 || echo "NONE" >> /tmp/test_log.txt

echo "Python packages count:" >> /tmp/test_log.txt
pip3 list | wc -l >> /tmp/test_log.txt 2>&1 || echo "ERROR" >> /tmp/test_log.txt
```

### 4. Run Bootstrap Restoration
```bash
# Run the bootstrap script (requires sudo)
sudo /media/sf_bootstrap/scripts/bootstrap.sh
```

**Expected Prompts:**
1. **Master password prompt**: Enter the password used during encryption on host system
2. **Package installation confirmations**: Script should handle automatically
3. **Service restarts**: Docker, systemd services

### 5. Post-Restoration Verification

#### A. Package Installation Verification
```bash
echo "=== POST-RESTORATION STATE ===" >> /tmp/test_log.txt

# Firefox should be removed
echo "Firefox after restoration:" >> /tmp/test_log.txt
snap list firefox 2>/dev/null && echo "STILL PRESENT (snap) - FAIL" >> /tmp/test_log.txt || echo "REMOVED (snap) - PASS" >> /tmp/test_log.txt
dpkg -l firefox 2>/dev/null && echo "STILL PRESENT (apt) - FAIL" >> /tmp/test_log.txt || echo "REMOVED (apt) - PASS" >> /tmp/test_log.txt

# Google Chrome should be installed
echo "Google Chrome after restoration:" >> /tmp/test_log.txt
which google-chrome >> /tmp/test_log.txt 2>&1 && echo "INSTALLED - PASS" >> /tmp/test_log.txt || echo "MISSING - FAIL" >> /tmp/test_log.txt

# Docker should be installed
echo "Docker after restoration:" >> /tmp/test_log.txt
which docker >> /tmp/test_log.txt 2>&1 && echo "INSTALLED - PASS" >> /tmp/test_log.txt || echo "MISSING - FAIL" >> /tmp/test_log.txt
systemctl is-active docker >> /tmp/test_log.txt 2>&1

# Flatpak should be installed and configured
echo "Flatpak after restoration:" >> /tmp/test_log.txt
which flatpak >> /tmp/test_log.txt 2>&1 && echo "INSTALLED - PASS" >> /tmp/test_log.txt || echo "MISSING - FAIL" >> /tmp/test_log.txt
flatpak remotes | grep flathub >> /tmp/test_log.txt 2>&1 && echo "FLATHUB CONFIGURED - PASS" >> /tmp/test_log.txt || echo "FLATHUB MISSING - FAIL" >> /tmp/test_log.txt
```

#### B. Intel KVM Module Verification
```bash
# KVM modules should be blacklisted and unloaded
echo "KVM modules after restoration:" >> /tmp/test_log.txt
lsmod | grep kvm >> /tmp/test_log.txt 2>&1 && echo "STILL LOADED - FAIL" >> /tmp/test_log.txt || echo "UNLOADED - PASS" >> /tmp/test_log.txt

echo "KVM blacklist configuration:" >> /tmp/test_log.txt
cat /etc/modprobe.d/blacklist-intel-kvm.conf >> /tmp/test_log.txt 2>&1 || echo "BLACKLIST FILE MISSING - FAIL" >> /tmp/test_log.txt
```

#### C. Environment Variables Decryption
```bash
# Check if encrypted environment variables were restored
source ~/.bashrc
echo "Environment variables after restoration:" >> /tmp/test_log.txt

# Check for key environment variables (without revealing values)
env | grep -E "(mongodb_uri|GOOGLE_PLACES_API_KEY|XAI_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)" | wc -l >> /tmp/test_log.txt
[[ -n "$mongodb_uri" ]] && echo "mongodb_uri - RESTORED" >> /tmp/test_log.txt || echo "mongodb_uri - MISSING" >> /tmp/test_log.txt
[[ -n "$GOOGLE_PLACES_API_KEY" ]] && echo "GOOGLE_PLACES_API_KEY - RESTORED" >> /tmp/test_log.txt || echo "GOOGLE_PLACES_API_KEY - MISSING" >> /tmp/test_log.txt
```

#### D. System Configuration Verification
```bash
# Check sysctl settings
echo "Sysctl settings after restoration:" >> /tmp/test_log.txt
sysctl vm.swappiness >> /tmp/test_log.txt 2>&1
sysctl fs.inotify.max_user_watches >> /tmp/test_log.txt 2>&1
sysctl net.core.somaxconn >> /tmp/test_log.txt 2>&1
sysctl kernel.shmmax >> /tmp/test_log.txt 2>&1

# Check SSH keys restoration
echo "SSH keys after restoration:" >> /tmp/test_log.txt
ls -la ~/.ssh/ >> /tmp/test_log.txt 2>&1 || echo "NO SSH DIRECTORY" >> /tmp/test_log.txt
```

#### E. Cron Jobs Verification
```bash
# Check if cron jobs were restored
echo "Cron jobs after restoration:" >> /tmp/test_log.txt
crontab -l >> /tmp/test_log.txt 2>&1 || echo "NO CRONTAB" >> /tmp/test_log.txt
```

### 6. Python Package Installation Test
```bash
# Check Python package restoration
echo "Python packages after restoration:" >> /tmp/test_log.txt
pip3 list | wc -l >> /tmp/test_log.txt
echo "Key packages check:" >> /tmp/test_log.txt
pip3 list | grep -E "(cryptography|argon2|anthropic|openai)" >> /tmp/test_log.txt 2>&1
```

### 7. Test Results Analysis
```bash
# Display complete test results
echo "=========================="
echo "BOOTSTRAP TEST RESULTS"
echo "=========================="
cat /tmp/test_log.txt

# Count pass/fail results
echo ""
echo "SUMMARY:"
echo "PASS: $(grep -c "PASS" /tmp/test_log.txt)"
echo "FAIL: $(grep -c "FAIL" /tmp/test_log.txt)"
```

## Expected Test Results

### ✅ Success Criteria
- Firefox completely removed (both snap and apt versions)
- Google Chrome installed and functional
- Docker installed and running
- VirtualBox installed
- Flatpak installed with Flathub repository
- Intel KVM modules blacklisted and unloaded
- All encrypted environment variables decrypted and restored
- Custom sysctl settings applied
- SSH public keys restored with correct permissions
- Python packages installed (100+ packages)
- Cron jobs restored

### 🔍 Key Verification Points
1. **Security**: No plaintext secrets visible in any files
2. **Idempotency**: Running bootstrap script twice should not cause errors
3. **Performance**: Script completes within reasonable time (15-30 minutes)
4. **Compatibility**: Works on fresh Ubuntu 24.04.3 installation

## Troubleshooting

### Common Issues
1. **Shared folder not accessible**: Install VirtualBox Guest Additions and reboot
2. **Permission denied errors**: Ensure script runs with `sudo`
3. **Network connectivity**: VM needs internet access for package downloads
4. **Decryption fails**: Verify master password matches original encryption

### Debug Commands
```bash
# Check VM shared folder mount
mount | grep vboxsf

# Verify script permissions  
ls -la /media/sf_bootstrap/scripts/bootstrap.sh

# Test network connectivity
ping -c 3 google.com

# Check system logs
journalctl -f
```

## Test Documentation

After completing tests, document results in:
1. **Update** `docs/architecture.md` with test results and any issues
2. **Create** test report with performance metrics
3. **Record** any compatibility issues or required modifications
4. **Update** README with tested Ubuntu versions

---

**Test performed on**: [Date]  
**Ubuntu Version**: 24.04.3 Desktop  
**VM Configuration**: 4GB RAM, 2 CPU, 20GB disk  
**Test Result**: [PASS/FAIL with details]
