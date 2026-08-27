#!/bin/bash
#
# Automated VM Restoration Audit & Interrogation Tool
# Connects to test VM via SSH using $VM_USER and $VM_PASSWORD.
# Checks fstab, dotfiles, keys, mounts, and fonts.
#

set -euo pipefail

VM_USER="${VM_USER:-$(whoami)}"
VM_PASS="${VM_PASSWORD:-}"
if [[ -z "$VM_PASS" ]]; then
    if [[ -t 0 ]]; then
        read -s -p "Enter password for VM user '$VM_USER': " VM_PASS
        echo ""
    else
        echo "ERROR: VM_PASSWORD environment variable is required."
        exit 1
    fi
fi
readonly VM_USER
readonly VM_PASS
VM_IP=$(virsh -c qemu:///system domifaddr cachyos-recovery-test 2>/dev/null | awk '/vnet/ {print $4}' | cut -d/ -f1 || true)
if [[ -z "$VM_IP" ]]; then
    VM_IP="192.168.122.247"
fi
readonly VM_IP
readonly SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"

# Colors
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

vm_ssh() {
    sshpass -p "$VM_PASS" ssh $SSH_OPTS "${VM_USER}@${VM_IP}" "$@"
}

vm_scp_from() {
    sshpass -p "$VM_PASS" scp -r $SSH_OPTS "${VM_USER}@${VM_IP}:$1" "$2"
}

main() {
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}🔍 Auditing Disaster Recovery inside CachyOS Test VM${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "Target: ${BOLD}${VM_USER}@${VM_IP}${NC}\n"

    # 1. Test SSH connectivity
    echo -n "• Testing SSH connection... "
    if ! vm_ssh "echo 'PONG'" >/dev/null 2>&1; then
        echo -e "${RED}FAILED${NC}"
        echo -e "${YELLOW}Ensure sshd is started in the VM: 'sudo systemctl start sshd'${NC}"
        exit 1
    fi
    echo -e "${GREEN}CONNECTED${NC}"

    # 2. Check /etc/fstab for non-blocking flags
    echo -e "\n• Checking ${BOLD}/etc/fstab${NC} for hardened non-blocking mount entries:"
    vm_ssh "grep -E '(/run/media/|FAST_ARCHIVE|SLOW_ARCHIVE|SHARD)' /etc/fstab || echo 'No archive entries found in /etc/fstab yet'"

    # 3. Check mount directories
    echo -e "\n• Checking created mount directories in ${BOLD}/run/media/michael/${NC}:"
    vm_ssh "ls -ld /run/media/michael/* 2>/dev/null || echo 'No mount directories created yet'"

    # 4. Check Shell dotfiles (Fish / Bash)
    echo -e "\n• Checking Shell configurations:"
    vm_ssh "ls -la ~/.config/fish/config.fish ~/.bashrc 2>/dev/null || echo 'Shell dotfiles not yet present'"

    # 5. Check SSH and GPG keys permissions
    echo -e "\n• Checking Security Keys (~/.ssh permissions):"
    vm_ssh "ls -la ~/.ssh 2>/dev/null || echo '~/.ssh directory not yet present'"

    # 6. Check custom typography (0xProto fonts)
    echo -e "\n• Checking custom typography (0xProto fonts in /usr/local/share/fonts/0/):"
    vm_ssh "ls -la /usr/local/share/fonts/0/0xProto*.ttf 2>/dev/null | wc -l | awk '{print \"Found \" \$1 \" / 12 0xProto font files\"}'"

    # 7. Copy out fstab for inspection
    mkdir -p ./vm_inspection
    vm_scp_from "/etc/fstab" "./vm_inspection/fstab_from_vm.txt"
    echo -e "\n${GREEN}✅ Copied /etc/fstab from VM to ./vm_inspection/fstab_from_vm.txt${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
}

main "$@"
