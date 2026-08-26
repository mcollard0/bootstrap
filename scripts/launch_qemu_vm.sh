#!/bin/bash
#
# Standalone QEMU Direct VM Launcher with SSH Port Forwarding
#
# Boots CachyOS with KVM acceleration, 8 GB RAM, 4 vCPUs, and forwards:
#   Host localhost:2222 -> Guest VM port 22 (SSH)
#

set -euo pipefail

readonly VM_DIR="/run/media/michael/FAST_ARCHIVE/VM"
readonly ISO_PATH="$VM_DIR/IMAGES/cachyos-desktop-linux-260809.iso"
readonly DISK_PATH="$VM_DIR/cachyos_recovery_test.qcow2"

if [[ ! -f "$ISO_PATH" ]]; then
    echo "Error: CachyOS ISO not found at $ISO_PATH. Run ./scripts/setup_test_vm.sh first."
    exit 1
fi

if [[ ! -f "$DISK_PATH" ]]; then
    qemu-img create -f qcow2 "$DISK_PATH" 40G
fi

echo "🚀 Launching CachyOS Test VM via QEMU with KVM acceleration..."
echo "SSH forward configured: ssh -p 2222 <user>@localhost"

exec qemu-system-x86_64 \
    -enable-kvm \
    -m 8G \
    -smp 4 \
    -cpu host \
    -drive file="$DISK_PATH",format=qcow2,if=virtio,cache=writeback \
    -cdrom "$ISO_PATH" \
    -boot d \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -vga virtio \
    -display default
