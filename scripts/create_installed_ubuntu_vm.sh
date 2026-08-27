#!/bin/bash
#
# Universal Linux Bootstrap - Automated Installed Ubuntu VM Provisioner
#
# Provisions an installed Ubuntu 24.04 LTS (Noble Numbat) system on an 80 GB qcow2 virtual disk
# using the official Ubuntu Cloud Image and an automated NoCloud CIDATA disk.
#
# User credentials and passwords are read securely from the environment
# via $VM_USER and $VM_PASSWORD (or prompted securely if unset).
#

set -euo pipefail

readonly VM_NAME="ubuntu-recovery-test"
readonly VM_DIR="/run/media/michael/FAST_ARCHIVE/VM"
readonly IMAGES_DIR="$VM_DIR/IMAGES"
readonly CLOUD_IMG_PATH="$IMAGES_DIR/noble-server-cloudimg-amd64.img"
readonly DISK_PATH="$VM_DIR/ubuntu_recovery_test.qcow2"
readonly CIDATA_PATH="$VM_DIR/ubuntu_cidata.img"
readonly DISK_SIZE="80G"
readonly VM_RAM="16384"
readonly VM_CPUS="4"

readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

main() {
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}🚀 Provisioning Installed Ubuntu 24.04 LTS Virtual Machine${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"

    local vm_user="${VM_USER:-$(whoami)}"
    local vm_password="${VM_PASSWORD:-}"

    if [[ -z "$vm_password" ]]; then
        if [[ -t 0 ]]; then
            read -s -p "Enter password for test VM user '$vm_user': " vm_password
            echo ""
        else
            log_error "VM_PASSWORD environment variable is not set and stdin is not a terminal."
            echo "Please set VM_PASSWORD before executing:"
            echo "  export VM_PASSWORD='YourSecurePassword'"
            exit 1
        fi
    fi

    if [[ ! -f "$CLOUD_IMG_PATH" ]]; then
        log_info "Downloading Ubuntu 24.04 LTS cloud image..."
        mkdir -p "$IMAGES_DIR"
        curl -L -C - --progress-bar -o "$CLOUD_IMG_PATH" "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    fi

    # Step 1: Clean up previous VM and disk
    log_info "Step 1: Destroying any existing VM domain '$VM_NAME'..."
    virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null || true
    virsh -c qemu:///system undefine "$VM_NAME" --nvram 2>/dev/null || virsh -c qemu:///system undefine "$VM_NAME" 2>/dev/null || true
    rm -f "$DISK_PATH" "$CIDATA_PATH"
    log_success "Cleaned up previous domain and storage."

    # Step 2: Create fresh 80 GB qcow2 virtual disk from base cloud image
    log_info "Step 2: Creating $DISK_SIZE virtual disk from base image..."
    cp "$CLOUD_IMG_PATH" "$DISK_PATH"
    qemu-img resize "$DISK_PATH" "$DISK_SIZE"
    log_success "Resized virtual disk to $DISK_SIZE."

    # Step 3: Build cidata autoinstall disk
    log_info "Step 3: Building cidata NoCloud autoinstall disk image..."
    local cidata_stage
    cidata_stage=$(mktemp -d /tmp/ubuntu_cidata_XXXXXX)
    trap 'rm -rf "${cidata_stage:-}"' EXIT

    local p_hash
    p_hash=$(openssl passwd -6 "$vm_password")

    local pubkey_content=""
    local pubkey_path="$HOME/.ssh/id_ed25519.pub"
    if [[ -f "$pubkey_path" ]]; then
        pubkey_content=$(cat "$pubkey_path")
    fi

    cat > "$cidata_stage/meta-data" <<EOF
instance-id: ubuntu-recovery-test-01
local-hostname: ubuntu-recovery-test
EOF

    cat > "$cidata_stage/user-data" <<EOF
#cloud-config
hostname: ubuntu-recovery-test
manage_etc_hosts: true

users:
  - name: $vm_user
    gecos: Michael Collard
    groups: [sudo, adm]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    passwd: "$p_hash"
    ssh_authorized_keys:
      - "$pubkey_content"

ssh_pwauth: true
chpasswd:
  expire: false

package_update: true
packages:
  - qemu-guest-agent
  - curl
  - wget
  - git
  - rsync
  - python3
  - python3-pip
  - python3-venv
  - python3-cryptography

runcmd:
  - systemctl enable --now qemu-guest-agent
  - [ sh, -c, "echo '$vm_user ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/99-michael-nopasswd" ]
  - chmod 0440 /etc/sudoers.d/99-michael-nopasswd
EOF

    # Create VFAT image with volume label CIDATA
    truncate -s 4M "$CIDATA_PATH"
    mkfs.vfat -n CIDATA "$CIDATA_PATH" >/dev/null
    mcopy -i "$CIDATA_PATH" "$cidata_stage"/* ::/
    log_success "Created CIDATA configuration image at $CIDATA_PATH."

    # Step 4: Launch VM with virt-install
    log_info "Step 4: Launching Ubuntu VM with virt-install..."
    virt-install \
        --connect qemu:///system \
        --name "$VM_NAME" \
        --memory "$VM_RAM" \
        --vcpus "$VM_CPUS" \
        --cpu host-passthrough \
        --boot uefi \
        --os-variant ubuntu24.04 \
        --disk path="$DISK_PATH",format=qcow2,bus=virtio,cache=writeback \
        --disk path="$CIDATA_PATH",device=disk,bus=usb \
        --network network=default,model=virtio \
        --graphics spice,listen=127.0.0.1 \
        --video virtio \
        --import \
        --noautoconsole

    log_success "VM '$VM_NAME' imported and started successfully!"
    echo -e "${BOLD}${GREEN}============================================================${NC}"
    echo -e "Ubuntu VM is initializing. Waiting for guest network..."
}

main "$@"
