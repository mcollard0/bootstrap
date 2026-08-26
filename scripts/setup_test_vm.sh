#!/bin/bash
#
# CachyOS Disaster Recovery Test VM Setup Script
#
# Automates:
# 1. Download of CachyOS Desktop ISO (260809) with resume support
# 2. Sparse 40 GB qcow2 virtual disk creation on FAST_ARCHIVE
# 3. VM registration and launch via KVM / libvirt (virt-install)
# 4. GUI console access instructions via virt-manager
#

set -euo pipefail

# Configuration
readonly ISO_URL="https://cdn77.cachyos.org/ISO/desktop/260809/cachyos-desktop-linux-260809.iso"
readonly VM_DIR="/run/media/michael/FAST_ARCHIVE/VM"
readonly IMAGES_DIR="$VM_DIR/IMAGES"
readonly ISO_PATH="$IMAGES_DIR/cachyos-desktop-linux-260809.iso"
readonly DISK_PATH="$VM_DIR/cachyos_recovery_test.qcow2"
readonly DISK_SIZE="40G"
readonly VM_NAME="cachyos-recovery-test"
readonly VM_RAM="8192"   # 8 GB
readonly VM_CPUS="4"     # 4 vCPUs

# Colors
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly RED='\033[0;31m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

main() {
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}🚀 CachyOS KVM Disaster Recovery Test Environment Setup${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo

    # Step 1: Ensure directories exist
    mkdir -p "$IMAGES_DIR"

    # Step 2: Download CachyOS Desktop ISO
    log_info "Step 1: Checking CachyOS Desktop ISO..."
    if [[ -f "$ISO_PATH" ]] && [[ $(stat -c%s "$ISO_PATH") -ge 3000000000 ]]; then
        log_success "ISO already downloaded: $ISO_PATH ($(stat -c%s "$ISO_PATH" | awk '{printf "%.2f GB", $1/1073741824}'))"
    else
        log_info "Downloading CachyOS Desktop ISO (~3.0 GB) with resume support..."
        log_info "Source: $ISO_URL"
        log_info "Destination: $ISO_PATH"
        
        if command -v curl >/dev/null 2>&1; then
            curl -C - -L --progress-bar -o "$ISO_PATH" "$ISO_URL"
        elif command -v wget >/dev/null 2>&1; then
            wget -c --show-progress -O "$ISO_PATH" "$ISO_URL"
        else
            log_error "Neither curl nor wget found."
            exit 1
        fi
        log_success "Download complete: $ISO_PATH"
    fi

    # Step 3: Create sparse 40 GB qcow2 virtual disk
    log_info "Step 2: Preparing virtual disk image..."
    if [[ -f "$DISK_PATH" ]]; then
        log_info "Using existing virtual disk: $DISK_PATH"
    else
        qemu-img create -f qcow2 "$DISK_PATH" "$DISK_SIZE"
        log_success "Created sparse $DISK_SIZE virtual disk: $DISK_PATH"
    fi

    # Step 4: Check if VM already exists in libvirt
    log_info "Step 3: Configuring libvirt / KVM virtual machine..."
    if virsh -c qemu:///system dominfo "$VM_NAME" >/dev/null 2>&1; then
        log_warning "VM '$VM_NAME' already exists in libvirt."
        read -rp "Do you want to recreate it? [y/N]: " recreate
        if [[ "$recreate" =~ ^[Yy]$ ]]; then
            virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null || true
            virsh -c qemu:///system undefine "$VM_NAME" --nvram 2>/dev/null || true
            log_info "Removed previous VM definition."
        else
            log_info "Keeping existing VM. You can start it with: virsh -c qemu:///system start $VM_NAME"
            print_usage_instructions
            return 0
        fi
    fi

    # Step 5: Provision VM with virt-install
    log_info "Provisioning '$VM_NAME' with virt-install (UEFI, VirtIO, 8GB RAM, 4 vCPUs)..."
    virt-install \
        --connect qemu:///system \
        --name "$VM_NAME" \
        --memory "$VM_RAM" \
        --vcpus "$VM_CPUS" \
        --cpu host-passthrough \
        --boot uefi,cdrom,hd \
        --cdrom "$ISO_PATH" \
        --disk path="$DISK_PATH",format=qcow2,bus=virtio,cache=writeback \
        --os-variant archlinux \
        --network network=default,model=virtio \
        --graphics spice,listen=127.0.0.1 \
        --video virtio \
        --noautoconsole

    log_success "Virtual machine '$VM_NAME' successfully provisioned and started!"
    print_usage_instructions
}

print_usage_instructions() {
    echo
    echo -e "${BOLD}${GREEN}============================================================${NC}"
    echo -e "${BOLD}🎉 CachyOS Test VM Ready!${NC}"
    echo -e "${BOLD}${GREEN}============================================================${NC}"
    echo -e "To open the graphical desktop display:"
    echo -e "  ${BOLD}virt-manager --connect qemu:///system --show-domain-console $VM_NAME &${NC}"
    echo
    echo -e "VM Management Commands:"
    echo -e "  • Start:    ${CYAN}virsh -c qemu:///system start $VM_NAME${NC}"
    echo -e "  • Status:   ${CYAN}virsh -c qemu:///system dominfo $VM_NAME${NC}"
    echo -e "  • Stop:     ${CYAN}virsh -c qemu:///system shutdown $VM_NAME${NC}"
    echo -e "  • Reset:    ${CYAN}virsh -c qemu:///system reset $VM_NAME${NC}"
    echo -e "  • Force Off:${CYAN}virsh -c qemu:///system destroy $VM_NAME${NC}"
    echo
    echo -e "Once inside the CachyOS live desktop:"
    echo -e "  1. Open terminal"
    echo -e "  2. Run Step 0 prerequisites: ${BOLD}sudo pacman -Sy --noconfirm git python-cryptography${NC}"
    echo -e "  3. Clone or copy repo: ${BOLD}git clone https://github.com/mcollard0/bootstrap.git ~/bootstrap${NC}"
    echo -e "  4. Run disaster recovery: ${BOLD}python3 ~/bootstrap/emergency_restore.py${NC}"
    echo -e "${BOLD}${GREEN}============================================================${NC}"
}

main "$@"
