#!/bin/bash
# Boot the remastered ISO in QEMU/KVM (UEFI, Secure Boot with Microsoft keys).
# No root needed: the user must be in the kvm group.
#   bash iso/boot-test.sh [ISO]        start (background-friendly)
# Control it through the monitor socket ~/iso-build/vm/mon.sock, e.g.
#   python3 iso/vmctl.py shot /tmp/s.ppm   (also: type, typefile, key, cmd)
set -euo pipefail
ISO="${1:-$(ls -t "$HOME"/iso-build/escrow-os-*-amd64.iso | head -1)}"
VM="$HOME/iso-build/vm"
mkdir -p "$VM"
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$VM/vars.fd"
rm -f "$VM/mon.sock"
exec qemu-system-x86_64 \
    -name escrow-os-test \
    -machine q35,smm=on,accel=kvm -cpu host -smp 4 -m 4096 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive if=pflash,format=raw,unit=1,file="$VM/vars.fd" \
    -drive file="$ISO",media=cdrom,readonly=on,if=none,id=cd0 \
    -device ahci,id=ahci -device ide-cd,drive=cd0,bus=ahci.0 \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -vga virtio -display none \
    -serial file:"$VM/serial.log" \
    -monitor unix:"$VM/mon.sock",server,nowait
