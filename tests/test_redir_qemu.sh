#!/bin/bash
#
# End-to-end test for ss-redir transparent proxy using QEMU.
#
# Architecture:
#   Host: ss-server listens on 0.0.0.0:8389
#   QEMU guest (Alpine Linux):
#     - ss-redir connects to host ss-server via 10.0.2.2:8389
#     - ss-nat sets up iptables OUTPUT chain REDIRECT to ss-redir
#     - curl through the transparent proxy verifies the full chain
#
# Usage: bash tests/test_redir_qemu.sh [BIN_DIR]
#   BIN_DIR: directory containing ss-server and ss-redir binaries
#            (default: build/bin/)
#
# Requirements (Linux only):
#   - qemu-system-x86_64
#   - Internet access (for Alpine download and curl test targets)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${1:-$PROJECT_DIR/build/bin}"

# Resolve to absolute path
BIN_DIR="$(cd "$BIN_DIR" && pwd)"

WORK_DIR=""
SS_SERVER_PID=""
QEMU_PID=""

ALPINE_VERSION="3.21"
ALPINE_ARCH="x86_64"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ALPINE_MINIROOTFS="alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
ALPINE_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/${ALPINE_MINIROOTFS}"

TIMEOUT=240
SS_SERVER_PORT=8389
SS_PASSWORD="test_redir_password"
SS_METHOD="aes-256-gcm"

# --- helpers ----------------------------------------------------------------

log() {
    echo "=== [test_redir_qemu] $* ==="
}

die() {
    echo "FATAL: $*" >&2
    exit 1
}

cleanup() {
    log "Cleaning up"
    if [ -n "$SS_SERVER_PID" ] && kill -0 "$SS_SERVER_PID" 2>/dev/null; then
        kill "$SS_SERVER_PID" 2>/dev/null || true
        wait "$SS_SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        sudo rm -rf "$WORK_DIR"
    fi
}

trap cleanup EXIT

# --- pre-flight checks ------------------------------------------------------

if [ "$(uname -s)" != "Linux" ]; then
    die "This test requires Linux (iptables, QEMU)"
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    die "qemu-system-x86_64 not found. Install with: sudo apt-get install qemu-system-x86"
fi

if [ ! -x "$BIN_DIR/ss-server" ]; then
    die "ss-server not found at $BIN_DIR/ss-server"
fi

if [ ! -x "$BIN_DIR/ss-redir" ]; then
    die "ss-redir not found at $BIN_DIR/ss-redir"
fi

# --- create work directory --------------------------------------------------

WORK_DIR="$(mktemp -d /tmp/ss-redir-test.XXXXXX)"
log "Work directory: $WORK_DIR"

# --- phase 1: collect ss-redir and its shared library dependencies ----------

log "Collecting ss-redir shared library dependencies"

# Copy ss-redir binary
SYSROOT="$WORK_DIR/sysroot"
mkdir -p "$SYSROOT/usr/bin"
cp "$BIN_DIR/ss-redir" "$SYSROOT/usr/bin/ss-redir"

# Copy all shared library dependencies (including the dynamic linker)
ldd "$BIN_DIR/ss-redir" | while read -r line; do
    # Parse lines like: libev.so.4 => /lib/x86_64-linux-gnu/libev.so.4 (0x...)
    # or: /lib64/ld-linux-x86-64.so.2 (0x...)
    lib_path=""
    if echo "$line" | grep -q "=>"; then
        lib_path=$(echo "$line" | awk '{print $3}')
    elif echo "$line" | grep -qE "^\s*/"; then
        lib_path=$(echo "$line" | awk '{print $1}')
    fi
    if [ -n "$lib_path" ] && [ -f "$lib_path" ]; then
        dest="$SYSROOT$lib_path"
        mkdir -p "$(dirname "$dest")"
        cp "$lib_path" "$dest"
    fi
done

log "Shared libraries collected into sysroot"

# --- phase 2: assemble Alpine rootfs ----------------------------------------

log "Downloading Alpine minirootfs"

ROOTFS="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS"

curl -sSL "$ALPINE_URL" -o "$WORK_DIR/$ALPINE_MINIROOTFS"
sudo tar xzf "$WORK_DIR/$ALPINE_MINIROOTFS" -C "$ROOTFS"

log "Installing packages in Alpine rootfs"

# Set up DNS for chroot
sudo cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

# Mount necessary filesystems for chroot
sudo mount --bind /dev "$ROOTFS/dev"
sudo mount --bind /proc "$ROOTFS/proc"
sudo mount --bind /sys "$ROOTFS/sys"

# Install packages inside chroot
sudo chroot "$ROOTFS" /sbin/apk add --no-cache \
    iptables ipset curl iproute2 kmod bash linux-virt

# Unmount after package installation
sudo umount "$ROOTFS/sys" 2>/dev/null || true
sudo umount "$ROOTFS/proc" 2>/dev/null || true
sudo umount "$ROOTFS/dev" 2>/dev/null || true

# Extract kernel
VMLINUZ=$(find "$ROOTFS/boot" -name 'vmlinuz-*' -type f | head -1)
if [ -z "$VMLINUZ" ]; then
    die "No vmlinuz found in Alpine rootfs"
fi
cp "$VMLINUZ" "$WORK_DIR/vmlinuz"
log "Kernel: $(basename "$VMLINUZ")"

# --- phase 3: inject artifacts into rootfs ----------------------------------

log "Injecting test artifacts into rootfs"

# ss-redir binary and its glibc shared library dependencies
# These go into the rootfs at their original absolute paths so the
# ELF dynamic linker (PT_INTERP) can find everything.
sudo cp -a "$SYSROOT/." "$ROOTFS/"

# ss-nat script
sudo cp "$PROJECT_DIR/src/ss-nat" "$ROOTFS/usr/bin/ss-nat"
sudo chmod 755 "$ROOTFS/usr/bin/ss-nat"

# Config file
sudo cp "$SCRIPT_DIR/redir.json" "$ROOTFS/etc/ss-redir.json"

# Guest init script (becomes PID 1)
sudo cp "$SCRIPT_DIR/qemu/guest-init.sh" "$ROOTFS/init"
sudo chmod 755 "$ROOTFS/init"

# --- phase 4: pack initramfs -----------------------------------------------

log "Packing initramfs"

(cd "$ROOTFS" && sudo find . | sudo cpio -o -H newc 2>/dev/null | gzip -1 > "$WORK_DIR/initramfs.gz")

log "Initramfs size: $(du -h "$WORK_DIR/initramfs.gz" | cut -f1)"

# --- phase 5: start ss-server on host --------------------------------------

log "Starting ss-server on host"

"$BIN_DIR/ss-server" \
    -s 0.0.0.0 \
    -p "$SS_SERVER_PORT" \
    -k "$SS_PASSWORD" \
    -m "$SS_METHOD" \
    -v &
SS_SERVER_PID=$!

sleep 2

if ! kill -0 "$SS_SERVER_PID" 2>/dev/null; then
    die "ss-server failed to start"
fi

log "ss-server running (PID $SS_SERVER_PID)"

# --- phase 6: boot QEMU ----------------------------------------------------

log "Booting QEMU"

KVM_FLAG=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    log "KVM acceleration available"
else
    log "KVM not available, using TCG (slower)"
fi

SERIAL_LOG="$WORK_DIR/serial.log"

qemu-system-x86_64 \
    $KVM_FLAG \
    -m 512 \
    -kernel "$WORK_DIR/vmlinuz" \
    -initrd "$WORK_DIR/initramfs.gz" \
    -append "console=ttyS0 init=/init panic=1" \
    -nographic \
    -serial "file:$SERIAL_LOG" \
    -monitor none \
    -net nic,model=virtio \
    -net user \
    -no-reboot &
QEMU_PID=$!

log "QEMU running (PID $QEMU_PID)"

# --- phase 7: monitor serial log -------------------------------------------

log "Waiting for test result (timeout: ${TIMEOUT}s)"

ELAPSED=0
POLL_INTERVAL=2
RESULT=""

while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ -f "$SERIAL_LOG" ]; then
        if grep -q "REDIR_TEST_PASS" "$SERIAL_LOG" 2>/dev/null; then
            RESULT="PASS"
            break
        fi
        if grep -q "REDIR_TEST_FAIL" "$SERIAL_LOG" 2>/dev/null; then
            RESULT="FAIL"
            break
        fi
    fi

    # Check if QEMU is still running
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        RESULT="QEMU_DIED"
        break
    fi

    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

# --- phase 8: report -------------------------------------------------------

echo ""
echo "============================================================"
echo "Serial console output:"
echo "============================================================"
if [ -f "$SERIAL_LOG" ]; then
    cat "$SERIAL_LOG"
else
    echo "(no serial log file)"
fi
echo "============================================================"
echo ""

case "$RESULT" in
    PASS)
        log "TEST PASSED"
        exit 0
        ;;
    FAIL)
        FAIL_MSG=$(grep "REDIR_TEST_FAIL" "$SERIAL_LOG" 2>/dev/null || echo "unknown")
        log "TEST FAILED: $FAIL_MSG"
        exit 1
        ;;
    QEMU_DIED)
        log "TEST FAILED: QEMU exited unexpectedly"
        exit 1
        ;;
    *)
        log "TEST FAILED: timeout after ${TIMEOUT}s"
        # Kill QEMU if still running
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            kill "$QEMU_PID" 2>/dev/null || true
        fi
        exit 1
        ;;
esac
