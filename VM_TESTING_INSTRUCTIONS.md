# 🚀 VM Testing Instructions - Bootstrap Script Remote Execution

## 📡 HTTP Server Status

✅ **HTTP Server Running** on host: `http://192.168.1.233:8080`  
✅ **Bootstrap Script Available** at: `http://192.168.1.233:8080/scripts/bootstrap_standalone.sh`  
✅ **Self-contained Script** - No dependency on guest additions or shared folders  

---

## 🖥️ In Your VirtualBox VM (Ubuntu 24.04.3)

### 1. Complete Ubuntu Installation
- Install Ubuntu 24.04.3 with any username (e.g., `testuser`)
- Set up network connection during installation
- Complete installation and login

### 2. Download and Execute Bootstrap Script

Open terminal in VM and run these commands:

```bash
# Download the self-contained bootstrap script
curl -O http://192.168.1.233:8080/scripts/bootstrap_standalone.sh

# Make it executable
chmod +x bootstrap_standalone.sh

# Verify the script downloaded correctly
ls -la bootstrap_standalone.sh
file bootstrap_standalone.sh

# Run the bootstrap script (requires sudo)
sudo ./bootstrap_standalone.sh
```

### 3. Master Password
**When prompted for master password, use the same password you used when running the scanner on your host system.**

---

## 🧪 Expected Test Results

The bootstrap script will:

1. ✅ **Install cryptography dependencies** (python3-cryptography, python3-argon2)
2. ✅ **Remove Firefox** (both snap and APT versions if present) 
3. ✅ **Install Flatpak** and configure Flathub repository
4. ✅ **Disable Intel KVM modules** and create blacklist configuration
5. ✅ **Install special packages**:
   - Google Chrome
   - Docker CE with user group addition
   - VirtualBox with extensions
6. ✅ **Apply system configurations**:
   - Custom sysctl settings
   - .bashrc environment setup
   - **Decrypt and restore encrypted secrets** (API keys, MongoDB URI, etc.)
7. ✅ **Install key Python packages** (cryptography, argon2-cffi, requests)

---

## 🔍 Verification Commands

After script completion, verify installations:

```bash
# Check Firefox removal
snap list firefox 2>/dev/null && echo "FIREFOX STILL PRESENT" || echo "✅ Firefox removed"
which firefox && echo "FIREFOX STILL PRESENT" || echo "✅ Firefox removed"

# Check new package installations  
which google-chrome && echo "✅ Chrome installed" || echo "❌ Chrome missing"
which docker && echo "✅ Docker installed" || echo "❌ Docker missing"
which flatpak && echo "✅ Flatpak installed" || echo "❌ Flatpak missing"

# Check Docker service
systemctl is-active docker && echo "✅ Docker running" || echo "❌ Docker not running"

# Check Flatpak configuration
flatpak remotes | grep flathub && echo "✅ Flathub configured" || echo "❌ Flathub missing"

# Check KVM modules (should be empty/disabled)
lsmod | grep kvm && echo "❌ KVM modules still loaded" || echo "✅ KVM modules disabled"

# Check blacklist file
cat /etc/modprobe.d/blacklist-intel-kvm.conf

# Check sysctl settings
sysctl vm.swappiness
sysctl fs.inotify.max_user_watches
sysctl net.core.somaxconn

# Check environment variables (after reboot and sourcing .bashrc)
# source ~/.bashrc
# env | grep -E "(mongodb_uri|API_KEY)" | wc -l  # Should show 5-6 variables
```

---

## 🔄 If Script Fails

### Network Issues
```bash
# Test connectivity to host
ping -c 3 192.168.1.233

# Test HTTP server accessibility
curl -I http://192.168.1.233:8080/

# Check VM's IP address
ip addr show
```

### Download Alternative Method
If HTTP download fails, try with wget:
```bash
wget http://192.168.1.233:8080/scripts/bootstrap_standalone.sh
```

### Manual Verification
```bash
# Check script content (first 20 lines)
head -20 bootstrap_standalone.sh

# Check if it's a valid bash script
bash -n bootstrap_standalone.sh && echo "✅ Script syntax valid" || echo "❌ Script syntax error"
```

---

## 📊 Expected Performance

- **Total execution time**: 10-20 minutes (depending on network speed)
- **Internet downloads**: ~200MB for Chrome, Docker, VirtualBox packages
- **Decryption time**: ~2-5 seconds (Argon2id is memory-intensive)
- **Package installations**: Automatic with pre-installation checks

---

## 🛑 Server Management

### Stop HTTP Server (on host)
```bash
# Find the server process
ps aux | grep serve_bootstrap.py

# Kill the server
kill %1
# or
pkill -f serve_bootstrap.py
```

### Restart HTTP Server (on host) 
```bash
cd /media/michael/FASTESTARCHIVE/Archive/Programming/bootstrap
python3 scripts/serve_bootstrap.py &
```

---

## 📝 Test Documentation

After completing the test, document results:

1. **Screenshot** the final success message
2. **Record** total execution time
3. **Verify** all installations with the commands above
4. **Test** environment variables after reboot:
   ```bash
   sudo reboot
   # After reboot and login:
   source ~/.bashrc
   env | grep -E "(mongodb_uri|GOOGLE_PLACES_API_KEY|XAI_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)" | wc -l
   ```

### Success Criteria
- ✅ Script completes without errors
- ✅ Firefox removed, Chrome/Docker/VirtualBox installed
- ✅ Flatpak configured with Flathub
- ✅ Intel KVM modules disabled
- ✅ All 6 encrypted environment variables restored
- ✅ System boots properly after reboot

---

## 🎯 This Test Validates

1. **Self-contained deployment** - No dependency on guest additions
2. **Network-based transfer** - HTTP server method works reliably
3. **Complete system restoration** - All features work on fresh Ubuntu
4. **Encryption/decryption** - ChaCha20-Poly1305 + Argon2id works correctly
5. **Special configurations** - Intel KVM disable, Firefox removal, flatpak setup
6. **Idempotency** - Script can be run multiple times safely

**🚀 Your Ubuntu Bootstrap System is ready for production deployment!**
