# 🚨 EMERGENCY RECOVERY CARD

**📱 PRINT THIS AND KEEP IT SAFE**

---

## **🆘 IF YOUR COMPUTER BREAKS OR IS STOLEN**

### **1. GET THE SCRIPT**
```bash
# From GitHub (need SSH key setup first)
git clone git@github.com:mcollard0/bootstrap.git

# OR download directly via web browser:
# https://github.com/mcollard0/bootstrap
# → scripts/bootstrap_standalone.sh → Raw → Save As
```

### **2. RUN ON FRESH UBUNTU**
```bash
chmod +x bootstrap_standalone.sh
sudo bash bootstrap_standalone.sh
```

### **3. ENTER MASTER PASSWORD**
- Same password you used to encrypt secrets
- **⚠️ NO PASSWORD = NO API KEYS RECOVERED**

---

## **📋 RECOVERY CHECKLIST**
- [ ] Fresh Ubuntu 24.04+ installed
- [ ] Internet working  
- [ ] Script downloaded from GitHub
- [ ] `sudo bash bootstrap_standalone.sh`
- [ ] Master password entered correctly
- [ ] System rebooted after completion

---

## **⏱️ TIMELINE**
- **Download**: 1-2 minutes
- **Install**: 20-30 minutes  
- **Total**: ~30 minutes for complete restore

---

## **🔍 VERIFY SUCCESS**
```bash
# After reboot:
which google-chrome  # ✅ Should work
which firefox        # ❌ Should be removed  
env | grep API_KEY | wc -l  # Should show 5-6 keys
```

---

## **🔑 WHAT'S RESTORED**
- **2,556 APT packages** (exact versions)
- **108+ Python modules** 
- **Chrome, Docker, VirtualBox**
- **6 encrypted API keys**
- **All environment variables**
- **SSH keys & system configs**

---

## **📞 REPOSITORY**
- **URL**: `github.com/mcollard0/bootstrap`
- **Script**: `scripts/bootstrap_standalone.sh`
- **Private repo** - only you have access

---

## **🆘 BACKUP METHODS**
1. **USB**: Copy script to external drive
2. **Email**: Email yourself the GitHub link
3. **Print**: Print this card and DISASTER_RECOVERY.md

---

**💾 ONE SCRIPT = COMPLETE SYSTEM RECOVERY**

*Keep this card accessible for emergencies!*
