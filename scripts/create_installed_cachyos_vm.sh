#!/bin/bash
#
# Universal Linux Bootstrap - Automated Installed CachyOS VM Provisioner
#
# Directly provisions a genuine installed CachyOS system onto a 40 GB qcow2 virtual disk
# (UEFI systemd-boot, ext4 rootfs, user credentials via $VM_USER / $VM_PASSWORD with passwordless sudo).
#
# Eliminates all Live CD / in-memory tmpfs constraints.
#

set -euo pipefail

readonly VM_NAME="cachyos-recovery-test"
readonly VM_DIR="/run/media/michael/FAST_ARCHIVE/VM"
readonly IMAGES_DIR="$VM_DIR/IMAGES"
readonly ISO_PATH="$IMAGES_DIR/cachyos-desktop-linux-260809.iso"
readonly DISK_PATH="$VM_DIR/cachyos_recovery_test.qcow2"
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
    echo -e "${BOLD}🚀 Provisioning Installed CachyOS Linux Virtual Machine${NC}"
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
        log_error "CachyOS ISO not found at $ISO_PATH"
        exit 1
    fi

    # Step 1: Destroy previous VM domain and remove old disk
    log_info "Step 1: Destroying previous VM domain '$VM_NAME'..."
    virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null || true
    virsh -c qemu:///system undefine "$VM_NAME" --nvram 2>/dev/null || true
    rm -f "$DISK_PATH"
    log_success "Cleaned up previous domain and disk."

    # Step 2: Create fresh 40 GB qcow2 virtual disk
    log_info "Step 2: Creating fresh $DISK_SIZE virtual disk at $DISK_PATH..."
    qemu-img create -f qcow2 "$DISK_PATH" "$DISK_SIZE"

    # Step 3: Connect disk via NBD
    log_info "Step 3: Connecting virtual disk via qemu-nbd..."
    sudo modprobe nbd max_part=8
    sudo qemu-nbd -d /dev/nbd0 2>/dev/null || true
    sudo qemu-nbd -c /dev/nbd0 "$DISK_PATH"
    sleep 1

    # Trap to ensure cleanup of mounts and nbd on exit
    cleanup() {
        log_info "Cleaning up temporary mounts..."
        sudo umount -R "$TARGET_MNT" 2>/dev/null || true
        sudo umount "$SFS_MNT" 2>/dev/null || true
        sudo umount "$ISO_MNT" 2>/dev/null || true
        rmdir "$TARGET_MNT" "$SFS_MNT" "$ISO_MNT" 2>/dev/null || true
        sudo qemu-nbd -d /dev/nbd0 2>/dev/null || true
    }
    trap cleanup EXIT

    # Step 4: Partition disk (1G EFI + 39G Root)
    log_info "Step 4: Partitioning disk into EFI (1GB) and Root (39GB)..."
    sudo parted -s /dev/nbd0 mklabel gpt
    sudo parted -s /dev/nbd0 mkpart "EFI" fat32 1MiB 1024MiB
    sudo parted -s /dev/nbd0 set 1 esp on
    sudo parted -s /dev/nbd0 mkpart "ROOT" ext4 1024MiB 100%
    sudo partprobe /dev/nbd0
    sleep 1

    log_info "Formatting partitions..."
    sudo mkfs.fat -F32 -n "ESP" /dev/nbd0p1
    sudo mkfs.ext4 -F -L "cachyos_root" /dev/nbd0p2

    # Step 5: Mount target disk
    TARGET_MNT=$(mktemp -d /tmp/cachyos_target.XXXXXX)
    sudo mount /dev/nbd0p2 "$TARGET_MNT"
    sudo mkdir -p "$TARGET_MNT/boot"
    sudo mount /dev/nbd0p1 "$TARGET_MNT/boot"

    # Step 6: Mount ISO and SquashFS
    log_info "Step 5: Mounting CachyOS ISO and SquashFS filesystem..."
    ISO_MNT=$(mktemp -d /tmp/cachyos_iso.XXXXXX)
    SFS_MNT=$(mktemp -d /tmp/cachyos_sfs.XXXXXX)
    sudo mount -o loop,ro "$ISO_PATH" "$ISO_MNT"
    sudo mount -o loop,ro "$ISO_MNT/arch/x86_64/airootfs.sfs" "$SFS_MNT"

    # Step 7: Unpack root filesystem
    log_info "Step 6: Unpacking clean CachyOS root filesystem to virtual disk..."
    sudo rsync -aAXH \
        --exclude="/run/*" \
        --exclude="/proc/*" \
        --exclude="/sys/*" \
        --exclude="/dev/*" \
        --exclude="/tmp/*" \
        --exclude="/mnt/*" \
        "$SFS_MNT/" "$TARGET_MNT/"

    # Step 8: Copy kernel, initramfs, and ucode
    log_info "Step 7: Copying kernel and initramfs to /boot..."
    sudo cp -a "$ISO_MNT/arch/boot/x86_64/vmlinuz-linux-cachyos" "$TARGET_MNT/boot/"
    sudo cp -a "$ISO_MNT/arch/boot/x86_64/initramfs-linux-cachyos.img" "$TARGET_MNT/boot/"
    sudo cp -a "$ISO_MNT/arch/boot/x86_64/"*ucode.img "$TARGET_MNT/boot/" 2>/dev/null || true

    # Step 9: Configure installed system
    log_info "Step 8: Configuring bootloader, users, fstab, and services..."
    ROOT_UUID=$(sudo blkid -s UUID -o value /dev/nbd0p2)
    EFI_UUID=$(sudo blkid -s UUID -o value /dev/nbd0p1)

    # Write /etc/fstab
    sudo bash -c "cat <<EOF > '$TARGET_MNT/etc/fstab'
# /etc/fstab: static file system information.
UUID=$ROOT_UUID  /      ext4  noatime  0 1
UUID=$EFI_UUID   /boot  vfat  umask=0077  0 2
EOF"

    # Install and configure systemd-boot
    sudo mkdir -p "$TARGET_MNT/boot/EFI/BOOT" "$TARGET_MNT/boot/EFI/systemd" "$TARGET_MNT/boot/loader/entries"
    if [[ -f "$TARGET_MNT/usr/lib/systemd/boot/efi/systemd-bootx64.efi" ]]; then
        sudo cp "$TARGET_MNT/usr/lib/systemd/boot/efi/systemd-bootx64.efi" "$TARGET_MNT/boot/EFI/BOOT/BOOTX64.EFI"
        sudo cp "$TARGET_MNT/usr/lib/systemd/boot/efi/systemd-bootx64.efi" "$TARGET_MNT/boot/EFI/systemd/systemd-bootx64.efi"
    elif [[ -f /usr/lib/systemd/boot/efi/systemd-bootx64.efi ]]; then
        sudo cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "$TARGET_MNT/boot/EFI/BOOT/BOOTX64.EFI"
        sudo cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "$TARGET_MNT/boot/EFI/systemd/systemd-bootx64.efi"
    fi

    sudo bash -c "cat <<EOF > '$TARGET_MNT/boot/loader/loader.conf'
default cachyos.conf
timeout 3
console-mode max
EOF"

    sudo bash -c "cat <<EOF > '$TARGET_MNT/boot/loader/entries/cachyos.conf'
title   CachyOS Linux
linux   /vmlinuz-linux-cachyos
initrd  /initramfs-linux-cachyos.img
options root=UUID=$ROOT_UUID rw quiet splash
EOF"

    # Generate password hash from secure environment variable
    PASS_HASH=$(openssl passwd -6 "$vm_password")

    # Configure root in /etc/shadow
    sudo sed -i "s|^root:[^:]*:|root:$PASS_HASH:|" "$TARGET_MNT/etc/shadow"

    # Ensure wheel group exists and add user
    if ! grep -q "^wheel:" "$TARGET_MNT/etc/group"; then
        sudo bash -c "echo 'wheel:x:998:$vm_user' >> '$TARGET_MNT/etc/group'"
    else
        sudo sed -i "/^wheel:/ s/$/$vm_user/" "$TARGET_MNT/etc/group"
    fi

    # Add user if not present
    local vm_fullname="${VM_FULL_NAME:-VM Administrator}"
    if ! grep -q "^${vm_user}:" "$TARGET_MNT/etc/passwd"; then
        sudo bash -c "echo '${vm_user}:x:1000:1000:${vm_fullname}:/home/${vm_user}:/usr/bin/fish' >> '$TARGET_MNT/etc/passwd'"
        sudo bash -c "echo '${vm_user}:$PASS_HASH:19950:0:99999:7:::' >> '$TARGET_MNT/etc/shadow'"
        sudo bash -c "echo '${vm_user}:x:1000:' >> '$TARGET_MNT/etc/group'"
        sudo mkdir -p "$TARGET_MNT/home/${vm_user}"
        sudo cp -rT "$TARGET_MNT/etc/skel" "$TARGET_MNT/home/${vm_user}" 2>/dev/null || true
        sudo chown -R 1000:1000 "$TARGET_MNT/home/${vm_user}"
        sudo chmod 700 "$TARGET_MNT/home/${vm_user}"
        if [[ -f "$HOME/.ssh/id_ed25519.pub" ]]; then
            sudo mkdir -p "$TARGET_MNT/home/${vm_user}/.ssh"
            sudo cp "$HOME/.ssh/id_ed25519.pub" "$TARGET_MNT/home/${vm_user}/.ssh/authorized_keys"
            sudo chown -R 1000:1000 "$TARGET_MNT/home/${vm_user}/.ssh"
            sudo chmod 700 "$TARGET_MNT/home/${vm_user}/.ssh"
            sudo chmod 600 "$TARGET_MNT/home/${vm_user}/.ssh/authorized_keys"
        fi
    fi

    # Passwordless sudo for wheel and user
    sudo mkdir -p "$TARGET_MNT/etc/sudoers.d"
    sudo bash -c "echo '%wheel ALL=(ALL:ALL) NOPASSWD: ALL' > '$TARGET_MNT/etc/sudoers.d/wheel'"
    sudo bash -c "echo '${vm_user} ALL=(ALL:ALL) NOPASSWD: ALL' > '$TARGET_MNT/etc/sudoers.d/${vm_user}'"
    sudo chmod 0440 "$TARGET_MNT/etc/sudoers.d/wheel" "$TARGET_MNT/etc/sudoers.d/${vm_user}"

    # System Hostname
    sudo bash -c "echo 'cachyos-installed' > '$TARGET_MNT/etc/hostname'"

    # Configure plasmalogin for target user
    if [[ -f "$TARGET_MNT/etc/plasmalogin.conf" ]]; then
        sudo sed -i "s/User=liveuser/User=$vm_user/" "$TARGET_MNT/etc/plasmalogin.conf"
    fi

    # Clean up liveuser artifacts and autologin
    sudo rm -rf "$TARGET_MNT/home/liveuser" "$TARGET_MNT/etc/systemd/system/getty@tty1.service.d" "$TARGET_MNT/etc/sddm.conf.d/autologin.conf" 2>/dev/null || true
    sudo sed -i '/liveuser/d' "$TARGET_MNT/etc/passwd" "$TARGET_MNT/etc/shadow" "$TARGET_MNT/etc/sudoers" 2>/dev/null || true

    # Enable essential services
    sudo mkdir -p "$TARGET_MNT/etc/systemd/system/multi-user.target.wants"
    for svc in sshd NetworkManager qemu-guest-agent; do
        if [[ -f "$TARGET_MNT/usr/lib/systemd/system/$svc.service" ]]; then
            sudo ln -sf "/usr/lib/systemd/system/$svc.service" "$TARGET_MNT/etc/systemd/system/multi-user.target.wants/$svc.service"
        fi
    done
    if [[ -f "$TARGET_MNT/usr/lib/systemd/system/sddm.service" ]]; then
        sudo ln -sf "/usr/lib/systemd/system/sddm.service" "$TARGET_MNT/etc/systemd/system/display-manager.service"
    fi

    # Remove Live ISO mkinitcpio configs so pure disk-boot initramfs is built
    sudo rm -f "$TARGET_MNT/etc/mkinitcpio.conf.d/archiso.conf" 2>/dev/null || true
    sudo rm -f "$TARGET_MNT/etc/mkinitcpio.d/linux-cachyos-lts.preset" "$TARGET_MNT/etc/mkinitcpio.d/linux.preset" 2>/dev/null || true

    # Bind mount system pseudo-filesystems and build genuine disk initramfs
    log_info "Building genuine desktop initramfs via mkinitcpio inside target..."
    for p in proc sys dev run; do
        sudo mount --bind "/$p" "$TARGET_MNT/$p"
    done
    sudo chroot "$TARGET_MNT" mkinitcpio -p linux-cachyos
    for p in run dev sys proc; do
        sudo umount "$TARGET_MNT/$p" 2>/dev/null || true
    done

    # SSH config to allow password authentication
    sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$TARGET_MNT/etc/ssh/sshd_config" 2>/dev/null || true

    log_success "Target installation configured successfully."

    # Step 10: Unmount and disconnect NBD
    log_info "Step 9: Finalizing disk image and unmounting..."
    sync
    cleanup
    trap - EXIT

    # Step 11: Launch genuine installed VM via virt-install (NO CD-ROM)
    log_info "Step 10: Launching installed VM with virt-install (UEFI, $DISK_PATH)..."
    virt-install \
        --connect qemu:///system \
        --name "$VM_NAME" \
        --memory "$VM_RAM" \
        --vcpus "$VM_CPUS" \
        --cpu host-passthrough \
        --boot uefi \
        --disk path="$DISK_PATH",format=qcow2,bus=virtio,cache=writeback \
        --os-variant archlinux \
        --network network=default,model=virtio \
        --graphics spice,listen=127.0.0.1 \
        --video virtio \
        --noautoconsole

    log_success "Virtual machine '$VM_NAME' provisioned and booted as an INSTALLED OS!"
    echo -e "${BOLD}${GREEN}============================================================${NC}"
    echo -e "Waiting for installed OS to complete first boot..."
}

main "$@"
