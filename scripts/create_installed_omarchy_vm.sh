#!/bin/bash
#
# Universal Linux Bootstrap - Automated Installed Omarchy VM Provisioner
#
# Provisions a genuine installed Omarchy Linux system on an 80 GB qcow2 virtual disk
# using the official omarchy-4.0.1.iso and an automated cidata NoCloud autoinstall disk.
#
#
# User credentials and passwords are read securely from the environment
# via $VM_USER and $VM_PASSWORD (or prompted securely if unset).
#

set -euo pipefail

readonly VM_NAME="omarchy-recovery-test"
readonly VM_DIR="/run/media/michael/FAST_ARCHIVE/VM"
readonly IMAGES_DIR="$VM_DIR/IMAGES"
readonly ISO_PATH="$IMAGES_DIR/omarchy-4.0.1.iso"
readonly DISK_PATH="$VM_DIR/omarchy_recovery_test.qcow2"
readonly CIDATA_PATH="$VM_DIR/omarchy_cidata.img"
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
    echo -e "${BOLD}🚀 Provisioning Installed Omarchy Linux Virtual Machine${NC}"
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

    if [[ ! -f "$ISO_PATH" ]]; then
        log_error "Omarchy ISO not found at $ISO_PATH"
        exit 1
    fi

    # Step 1: Clean up previous VM and disk
    log_info "Step 1: Destroying any existing VM domain '$VM_NAME'..."
    virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null || true
    virsh -c qemu:///system undefine "$VM_NAME" --nvram 2>/dev/null || true
    rm -f "$DISK_PATH" "$CIDATA_PATH"
    log_success "Cleaned up previous domain and storage."

    # Step 2: Create fresh 80 GB qcow2 virtual disk
    log_info "Step 2: Creating fresh $DISK_SIZE virtual disk at $DISK_PATH..."
    qemu-img create -f qcow2 "$DISK_PATH" "$DISK_SIZE"

    # Step 3: Build cidata autoinstall disk
    log_info "Step 3: Building cidata NoCloud autoinstall disk image..."
    local cidata_stage
    cidata_stage=$(mktemp -d /tmp/omarchy_cidata_XXXXXX)
    trap 'rm -rf "${cidata_stage:-}"' EXIT

    local p_hash
    p_hash=$(openssl passwd -6 "$vm_password")

    # Generate user_credentials.json
    cat > "$cidata_stage/user_credentials.json" << EOF
{
    "root_enc_password": "$p_hash",
    "users": [
        {
            "enc_password": "$p_hash",
            "groups": ["wheel"],
            "sudo": true,
            "username": "$vm_user"
        }
    ]
}
EOF

    # Disk calculation for 80 GB: 1MiB gap, 2GiB ESP, remaining for btrfs subvolumes
    local disk_bytes=$((80 * 1024 * 1024 * 1024))
    local mib=$((1024 * 1024))
    local gib=$((1024 * 1024 * 1024))
    local boot_start=$mib
    local boot_size=$((2 * gib))
    local main_start=$((boot_size + boot_start))
    local main_size=$((disk_bytes - main_start - mib))

    # Generate user_configuration.json
    cat > "$cidata_stage/user_configuration.json" << EOF
{
    "app_config": null,
    "archinstall-language": "English",
    "auth_config": {},
    "audio_config": { "audio": "pipewire" },
    "bootloader_config": { "bootloader": "Limine", "uki": false, "removable": false },
    "custom_commands": [],
    "omarchy_install": {
        "mode": "full_disk",
        "defer_provisioning": false,
        "target_mount": "/mnt",
        "boot": {
            "esp_mount": "/boot",
            "esp_path": "/EFI/limine",
            "efi_binary": "limine_x64.efi",
            "enable_fallback": true
        },
        "storage": { "kernel": "linux" }
    },
    "disk_config": {
        "config_type": "default_layout",
        "device_modifications": [
            {
                "device": "/dev/vda",
                "partitions": [
                    {
                        "btrfs": [],
                        "dev_path": null,
                        "flags": [ "boot", "esp" ],
                        "fs_type": "fat32",
                        "mount_options": [],
                        "mountpoint": "/boot",
                        "obj_id": "ea21d3f2-82bb-49cc-ab5d-6f81ae94e18d",
                        "size": { "sector_size": { "unit": "B", "value": 512 }, "unit": "B", "value": $boot_size },
                        "start": { "sector_size": { "unit": "B", "value": 512 }, "unit": "B", "value": $boot_start },
                        "status": "create",
                        "type": "primary"
                    },
                    {
                        "btrfs": [
                            { "mountpoint": "/", "name": "@" },
                            { "mountpoint": "/home", "name": "@home" },
                            { "mountpoint": "/var/log", "name": "@log" },
                            { "mountpoint": "/var/cache/pacman/pkg", "name": "@pkg" }
                        ],
                        "dev_path": null,
                        "flags": [],
                        "fs_type": "btrfs",
                        "mount_options": [ "compress=zstd" ],
                        "mountpoint": null,
                        "obj_id": "8c2c2b92-1070-455d-b76a-56263bab24aa",
                        "size": { "sector_size": { "unit": "B", "value": 512 }, "unit": "B", "value": $main_size },
                        "start": { "sector_size": { "unit": "B", "value": 512 }, "unit": "B", "value": $main_start },
                        "status": "create",
                        "type": "primary"
                    }
                ],
                "wipe": true
            }
        ]
    },
    "hostname": "omarchy-recovery-test",
    "kernels": [ "linux" ],
    "network_config": { "type": "iso" },
    "ntp": true,
    "parallel_downloads": 8,
    "script": null,
    "services": [ "qemu-guest-agent" ],
    "swap": true,
    "timezone": "America/Chicago",
    "locale_config": { "kb_layout": "us", "sys_enc": "UTF-8", "sys_lang": "en_US.UTF-8" },
    "mirror_config": {
        "custom_repositories": [],
        "custom_servers": [
            {"url": "https://mirror.omarchy.org/\$repo/os/\$arch"},
            {"url": "https://mirror.rackspace.com/archlinux/\$repo/os/\$arch"},
            {"url": "https://geo.mirror.pkgbuild.com/\$repo/os/\$arch"}
        ],
        "mirror_regions": {},
        "optional_repositories": []
    },
    "packages": [
        "base-devel",
        "git",
        "omarchy-keyring",
        "omarchy-settings",
        "omarchy",
        "qemu-guest-agent"
    ],
    "profile_config": { "gfx_driver": null, "greeter": null, "profile": {} },
    "version": "3.0.9"
}
EOF

    local vm_fullname="${VM_FULL_NAME:-VM Administrator}"
    local vm_email="${VM_EMAIL:-${vm_user}@local.test}"
    echo "$vm_fullname" > "$cidata_stage/user_full_name.txt"
    echo "$vm_email" > "$cidata_stage/user_email_address.txt"
    echo "false" > "$cidata_stage/user_encrypt_installation.txt"

    local pubkey_path="$HOME/.ssh/id_ed25519.pub"
    if [[ -f "$pubkey_path" ]]; then
        cp "$pubkey_path" "$cidata_stage/authorized_keys"
    else
        touch "$cidata_stage/authorized_keys"
    fi

    # Create VFAT image with volume label CIDATA
    truncate -s 4M "$CIDATA_PATH"
    mkfs.vfat -n CIDATA "$CIDATA_PATH" >/dev/null
    mcopy -i "$CIDATA_PATH" "$cidata_stage"/* ::/
    log_success "Created CIDATA autoinstall image at $CIDATA_PATH."

    # Step 4: Launch VM with virt-install
    log_info "Step 4: Launching installer VM with virt-install..."
    virt-install \
        --connect qemu:///system \
        --name "$VM_NAME" \
        --memory "$VM_RAM" \
        --vcpus "$VM_CPUS" \
        --cpu host-passthrough \
        --boot uefi \
        --os-variant archlinux \
        --disk path="$DISK_PATH",format=qcow2,bus=virtio,cache=writeback \
        --disk path="$ISO_PATH",device=cdrom,bus=sata \
        --disk path="$CIDATA_PATH",device=disk,bus=usb \
        --network network=default,model=virtio \
        --graphics spice,listen=127.0.0.1 \
        --video virtio \
        --noautoconsole

    log_success "VM '$VM_NAME' started with unattended autoinstall!"
    echo -e "${BOLD}${GREEN}============================================================${NC}"
    echo -e "Omarchy autoinstall is in progress. Monitoring installation..."
}

main "$@"
