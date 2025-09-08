# 🚨 Ubuntu Bootstrap System - Disaster Recovery Guide

## Emergency System Recovery Instructions

**If your computer breaks, is stolen, or you need to restore your complete Ubuntu setup on a new machine, follow these steps:**

---

## 📱 **Step 1: Access Your Private Repository**

### Option A: From Any Computer with Git
```bash
# Clone your private bootstrap repository
git clone git@github.com:mcollard0/bootstrap.git
cd bootstrap
```

### Option B: Direct Download (if SSH keys not available)
```bash
# Download the standalone script directly
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3.raw" \
  https://api.github.com/repos/mcollard0/bootstrap/contents/scripts/bootstrap_standalone.sh \
  -o bootstrap_standalone.sh
```

### Option C: GitHub Web Interface
1. Go to `https://github.com/mcollard0/bootstrap`
2. Navigate to `scripts/bootstrap_standalone.sh`
3. Click "Raw" and save the file

---

## 🖥️ **Step 2: Fresh Ubuntu Installation**

1. **Install Ubuntu 24.04+ or 25.04** on your new/repaired computer
2. **Set up internet connection** during installation
3. **Create user account** (any username is fine)
4. **Complete installation** and boot to desktop

---

## 🚀 **Step 3: Execute Disaster Recovery**

```bash
# Make the script executable
chmod +x bootstrap_standalone.sh

# Verify script integrity
bash -n bootstrap_standalone.sh && echo "✅ Script valid" || echo "❌ Script corrupted"

# Run complete system restoration (requires sudo)
sudo bash bootstrap_standalone.sh
```

**⚠️ When prompted for master password:** Use the same encryption password you set up originally.

---

## 🔄 **What Will Be Restored**

### ✅ **Complete Package Environment**
- **2,556 APT packages** restored to exact versions
- **14 Snap packages** with proper channels
- **108+ Python modules** with version pinning
- **Special software**: Chrome, Docker, VirtualBox, etc.

### ✅ **Security & Configurations**
- **Firefox completely removed** (both snap and APT)
- **Intel KVM modules disabled** and blacklisted
- **Flatpak installed** with Flathub repository
- **System settings** (sysctl, kernel parameters)

### ✅ **Encrypted Sensitive Data**
- **6 API keys decrypted**: OpenAI, Anthropic, XAI, Google Places
- **MongoDB connection strings** 
- **Email credentials** and SMTP settings
- **Custom environment variables**

### ✅ **User Environment**
- **.bashrc customizations** with aliases and exports
- **SSH public keys** with correct permissions
- **Cron jobs** restored and scheduled
- **Development environment** (VS Code aliases, etc.)

---

## ⏱️ **Recovery Timeline**

- **Script download**: 1-2 minutes
- **System preparation**: 5 minutes (apt update, dependencies)
- **Package installation**: 15-25 minutes (2,556 packages)
- **Configuration restoration**: 2-5 minutes
- **Total time**: **20-35 minutes for complete system recovery**

---

## 🔍 **Post-Recovery Verification**

After the script completes, verify your restoration:

```bash
# Check key applications
which google-chrome && echo "✅ Chrome installed"
which docker && echo "✅ Docker installed"
which flatpak && echo "✅ Flatpak installed"

# Verify Firefox removal
which firefox || echo "✅ Firefox removed"

# Check KVM modules disabled
lsmod | grep kvm || echo "✅ KVM modules disabled"

# Check encrypted secrets restored (after reboot)
sudo reboot
# After reboot:
source ~/.bashrc
env | grep -E "(mongodb_uri|API_KEY)" | wc -l  # Should show 5-6 variables
```

---

## 🆘 **If Recovery Fails**

### Network Issues
```bash
# Test internet connectivity
ping -c 3 google.com

# Check Ubuntu version compatibility
lsb_release -a  # Should be 24.04+ or 25.04
```

### Permission Issues
```bash
# Ensure you have sudo access
sudo whoami  # Should return 'root'

# Check script permissions
ls -la bootstrap_standalone.sh  # Should be executable
```

### Decryption Issues
```bash
# If you forgot the master password:
# - The encrypted data cannot be recovered without the password
# - You'll need to manually recreate API keys and configurations
# - The package installations will still work correctly
```

---

## 💾 **Alternative Recovery Methods**

### Method 1: HTTP Server (if available)
If you have access to your original system or backups:
```bash
# On working system, serve the files
cd /path/to/bootstrap
python3 scripts/serve_bootstrap.py &

# On recovery system
curl -O http://ORIGINAL_SYSTEM_IP:8080/scripts/bootstrap_standalone.sh
```

### Method 2: USB/External Drive
Keep a backup copy on external storage:
```bash
# Copy to USB (on working system)
cp scripts/bootstrap_standalone.sh /media/usb-drive/

# Use from USB (on recovery system)
cp /media/usb-drive/bootstrap_standalone.sh ./
```

---

## 📋 **Recovery Checklist**

- [ ] Fresh Ubuntu 24.04+ installation completed
- [ ] Internet connection working
- [ ] bootstrap_standalone.sh downloaded from GitHub
- [ ] Script made executable (`chmod +x`)
- [ ] Master password remembered
- [ ] Run with `sudo bash bootstrap_standalone.sh`
- [ ] All packages installed (2,556+ APT packages)
- [ ] Sensitive data decrypted successfully
- [ ] System reboot completed
- [ ] Environment variables verified
- [ ] Development tools working (Chrome, Docker, etc.)

---

## 🔐 **Security Notes**

1. **Private Repository**: Your bootstrap repo is private - only you have access
2. **Encrypted Secrets**: All sensitive data uses military-grade ChaCha20-Poly1305 encryption
3. **Master Password**: Only you know the encryption password - it's not stored anywhere
4. **SSH Keys**: Public keys are restored, but you'll need to regenerate private keys for security
5. **GitHub Access**: You may need to set up new SSH keys for GitHub access after recovery

---

## 📞 **Emergency Contacts**

- **GitHub Repository**: `https://github.com/mcollard0/bootstrap`
- **Script Path**: `scripts/bootstrap_standalone.sh`
- **Repository Size**: ~90KB (fast to download)
- **Last Updated**: Check commit history for latest version

---

**🚀 Your complete Ubuntu system can be restored in under 30 minutes with just this one script!**

*Keep this guide bookmarked or printed for true emergency situations.*
