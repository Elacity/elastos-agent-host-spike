#!/usr/bin/env bash
# Cross-build C9 linux-confine for aarch64, pack an Alpine initramfs, and
# boot qemu-system-aarch64 TCG with Alpine virt kernel 6.18.58.
#
# Label: aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
# Never native aarch64. Never Jetson.
#
# Usage:
#   lab/linux-confine/run-aarch64-guest.sh           # full C9 + plants
#   lab/linux-confine/run-aarch64-guest.sh smoke     # ABI probe only
set -euo pipefail

MODE="${1:-full}"
LABEL='aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)'
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$REPO/lab/linux-confine"
EVIDENCE="$LAB/evidence/aarch64-qemu-system-6.18"
WORK="${LC_GUEST_WORK:-/tmp/linux-confine-aarch64}"
CC=aarch64-linux-gnu-gcc
TARGET=aarch64-unknown-linux-gnu
ALPINE_VER=3.23.5
KERNEL_APK_VER=6.18.58-r0
KERNEL_REL=6.18.58-0-virt
ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/v3.23}"

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$CC"
export CC_aarch64_unknown_linux_gnu="$CC"
unset TARGET_CC || true
# A leftover host CC_<target> would hide the real cross compiler.
for key in $(env | awk -F= '/^CC_/ {print $1}'); do
    if [ "$key" != "CC_aarch64_unknown_linux_gnu" ]; then
        unset "$key" || true
    fi
done

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing $1" >&2
        exit 1
    }
}

need qemu-system-aarch64
need "$CC"
need cargo
need rustc
need curl
need cpio
need gzip
need python3

mkdir -p "$WORK/dl" "$EVIDENCE"
echo "$LABEL" > "$EVIDENCE/LABEL.txt"
{
    echo "label=$LABEL"
    echo "native=0"
    echo "jetson=0"
    echo "emulated_cpu=1"
    echo "qemu_accel=tcg"
    echo "host_uname=$(uname -srm)"
    echo "qemu=$(qemu-system-aarch64 --version | head -1)"
    echo "cross_cc=$($CC --version | head -1)"
    echo "rustc=$(rustc --version)"
    echo "mode=$MODE"
    echo "repo=$REPO"
    echo "head=$(git -C "$REPO" rev-parse HEAD)"
} | tee "$EVIDENCE/host-context.txt"

echo "=== rust targets ==="
rustup target add aarch64-unknown-linux-gnu >/dev/null

echo "=== download Alpine kernel $KERNEL_REL and minirootfs $ALPINE_VER ==="
cd "$WORK/dl"
if [ ! -s "linux-virt-${KERNEL_APK_VER}.apk" ]; then
    curl -fL --retry 4 --retry-delay 4 -o "linux-virt-${KERNEL_APK_VER}.apk" \
        "$ALPINE_MIRROR/main/aarch64/linux-virt-${KERNEL_APK_VER}.apk"
fi
if [ ! -s "alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz" ]; then
    curl -fL --retry 4 --retry-delay 4 -o "alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz" \
        "$ALPINE_MIRROR/releases/aarch64/alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz"
fi
rm -rf "$WORK/kernel"
mkdir -p "$WORK/kernel"
tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk" \
    --warning=no-unknown-keyword 2>/dev/null \
    || tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk"
test -f "$WORK/kernel/boot/vmlinuz-virt"
echo "kernel=$WORK/kernel/boot/vmlinuz-virt" | tee -a "$EVIDENCE/host-context.txt"
sha256sum "$WORK/kernel/boot/vmlinuz-virt" | tee "$EVIDENCE/vmlinuz-virt.sha256"

echo "=== cross-build linux-confine tests ==="
(cd "$REPO" && cargo test --no-run --target "$TARGET" \
    --manifest-path lab/linux-confine/Cargo.toml)

echo "=== cross-build shipping provider binaries ==="
for name in did-provider wallet-provider model-provider; do
    (cd "$REPO" && cargo build --manifest-path "capsules/$name/Cargo.toml" \
        --bin "$name" --target "$TARGET")
done

echo "=== compile guest helpers ==="
"$CC" -static -O2 -Wall -Wextra -Werror \
    -o "$WORK/guest-landlock-probe" \
    "$LAB/helper/guest-landlock-probe.c"
"$CC" -static -O2 -Wall -Wextra -Werror \
    -o "$WORK/run-as-tester" \
    "$LAB/helper/run-as-tester.c"

echo "=== snapshot standing test binaries ==="
DEPS="$REPO/target-build/aarch64-unknown-linux-gnu/debug/deps"
BINS="$LAB/guest-bins"
rm -rf "$BINS"
mkdir -p "$BINS"
copy_latest() {
    prefix=$1
    dest=$2
    src=$(ls -t "$DEPS"/${prefix}-* 2>/dev/null | grep -v '\.d$' | head -1)
    test -n "$src" && test -x "$src"
    cp -a "$src" "$dest"
    chmod 755 "$dest"
    python3 - "$dest" <<'PY'
import struct, sys
p = sys.argv[1]
b = open(p, "rb").read(20)
mach = struct.unpack_from("<H", b, 18)[0]
assert mach == 183, (p, mach)
print(p, "EM_AARCH64=183")
PY
}
copy_latest confine "$BINS/confine"
copy_latest providers "$BINS/providers"
copy_latest elf "$BINS/elf"
copy_latest aarch64 "$BINS/aarch64"

HELPER_DIR=$(ls -d "$REPO"/target-build/aarch64-unknown-linux-gnu/debug/build/linux-confine-*/out | head -1)
test -d "$HELPER_DIR"
rm -rf "$WORK/standing-helpers"
mkdir -p "$WORK/standing-helpers"
cp -a "$HELPER_DIR/." "$WORK/standing-helpers/"
for h in lc-setup lc-setup-test lc-probe lc-witness.so; do
    python3 - "$HELPER_DIR/$h" <<'PY'
import struct, sys
p = sys.argv[1]
b = open(p, "rb").read(20)
mach = struct.unpack_from("<H", b, 18)[0]
assert mach == 183, (p, mach)
print(p, "EM_AARCH64=183")
PY
done
echo "helper_dir=$HELPER_DIR" | tee -a "$EVIDENCE/host-context.txt"

if [ "$MODE" = "full" ]; then
    echo "=== build falsify.py-equivalent plants ==="
    python3 "$LAB/guest/build-plants.py"
    # Cargo plant rebuilds can rewrite OUT_DIR. Put the standing helpers back.
    mkdir -p "$HELPER_DIR"
    cp -a "$WORK/standing-helpers/." "$HELPER_DIR/"
fi

echo "=== assemble initramfs ==="
ROOT="$WORK/rootfs"
rm -rf "$ROOT"
mkdir -p "$ROOT"
tar -C "$ROOT" -xzf "$WORK/dl/alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz"

# glibc loader + libs for the gnu-target Rust and C binaries.
mkdir -p "$ROOT/lib/aarch64-linux-gnu" "$ROOT/usr/local/bin"
cp -a /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 "$ROOT/lib/ld-linux-aarch64.so.1"
for lib in libc.so.6 libm.so.6 libgcc_s.so.1 libdl.so.2 libpthread.so.0 \
           librt.so.1 libutil.so.1; do
    if [ -e "/usr/aarch64-linux-gnu/lib/$lib" ]; then
        cp -a "/usr/aarch64-linux-gnu/lib/$lib" "$ROOT/lib/aarch64-linux-gnu/"
    fi
done

# 9p modules so the guest can write evidence without a second disk.
MODDST="$ROOT/lib/modules/$KERNEL_REL"
mkdir -p "$MODDST/kernel/fs/netfs" "$MODDST/kernel/net/9p" "$MODDST/kernel/fs/9p"
for rel in \
    kernel/fs/netfs/netfs.ko.gz \
    kernel/net/9p/9pnet.ko.gz \
    kernel/net/9p/9pnet_virtio.ko.gz \
    kernel/fs/9p/9p.ko.gz; do
    src="$WORK/kernel/lib/modules/$KERNEL_REL/$rel"
    if [ -f "$src" ]; then
        dest="$MODDST/${rel%.gz}"
        mkdir -p "$(dirname "$dest")"
        gzip -dc "$src" > "$dest"
    fi
done

# Recreate the baked host paths inside the guest tmpfs.
install_tree() {
    src=$1
    dest=$2
    mkdir -p "$(dirname "$dest")"
    if [ -d "$src" ]; then
        mkdir -p "$dest"
        cp -a "$src/." "$dest/"
    else
        cp -a "$src" "$dest"
    fi
}

# Profiles the suites read via CARGO_MANIFEST_DIR/../..
for name in did-provider wallet-provider model-provider; do
    install_tree "$REPO/capsules/$name/confine.sb" \
        "$ROOT/workspace/capsules/$name/confine.sb"
    install_tree "$REPO/capsules/$name/tests/fixtures/confine/declared-rights.json" \
        "$ROOT/workspace/capsules/$name/tests/fixtures/confine/declared-rights.json"
    # providers.rs looks at capsules/<name>/target/debug/<name>
    src="$REPO/capsules/$name/target/aarch64-unknown-linux-gnu/debug/$name"
    install_tree "$src" "$ROOT/workspace/capsules/$name/target/debug/$name"
    chmod 755 "$ROOT/workspace/capsules/$name/target/debug/$name"
done

# Standing test binaries live at a stable path. Do not glob deps/ after
# the plant rebuilds — those hashes may be planted copies.
mkdir -p "$ROOT/workspace/lab/linux-confine/guest-bins"
cp -a "$BINS/." "$ROOT/workspace/lab/linux-confine/guest-bins/"

# Baked helper paths from env!("LC_*").
guest_helper="$ROOT${HELPER_DIR}"
mkdir -p "$guest_helper"
cp -a "$WORK/standing-helpers/." "$guest_helper/"

# Lab sources needed for plants listing / docs inside the guest tree.
mkdir -p "$ROOT/workspace/lab/linux-confine"
cp -a "$LAB/guest/run-c9.sh" "$ROOT/usr/local/bin/run-c9.sh"
chmod 755 "$ROOT/usr/local/bin/run-c9.sh"
if [ -d "$LAB/guest-plants" ]; then
    cp -a "$LAB/guest-plants" "$ROOT/workspace/lab/linux-confine/guest-plants"
fi

cp -a "$WORK/guest-landlock-probe" "$ROOT/usr/local/bin/guest-landlock-probe"
cp -a "$WORK/run-as-tester" "$ROOT/usr/local/bin/run-as-tester"
chmod 755 "$ROOT/usr/local/bin/guest-landlock-probe" "$ROOT/usr/local/bin/run-as-tester"
install_tree "$LAB/guest/init.sh" "$ROOT/init"
chmod 755 "$ROOT/init"

# Smoke mode: replace run-c9.sh with a no-op so we only prove the kernel.
if [ "$MODE" = "smoke" ]; then
    cat > "$ROOT/usr/local/bin/run-c9.sh" <<'SMOKE'
#!/bin/sh
echo "SMOKE: skipped C9 suites"
echo "PASS" > /evidence/smoke.status 2>/dev/null || true
exit 0
SMOKE
    chmod 755 "$ROOT/usr/local/bin/run-c9.sh"
fi

echo "=== pack initramfs ==="
( cd "$ROOT" && find . -print0 | cpio --null -o -H newc ) | gzip -1 > "$WORK/guest.cpio.gz"
ls -lh "$WORK/guest.cpio.gz" | tee -a "$EVIDENCE/host-context.txt"

echo "=== boot qemu-system-aarch64 TCG ==="
# -accel tcg: emulated CPU. Do not use kvm. This is not Jetson.
QEMU_LOG="$EVIDENCE/qemu-console.txt"
set +e
qemu-system-aarch64 \
    -name linux-confine-c9-aarch64 \
    -M virt \
    -cpu max \
    -accel tcg \
    -smp 2 \
    -m 4096 \
    -nographic \
    -no-reboot \
    -kernel "$WORK/kernel/boot/vmlinuz-virt" \
    -initrd "$WORK/guest.cpio.gz" \
    -append "console=ttyAMA0 earlycon=pl011,0x09000000 panic=1" \
    -fsdev local,id=ev,path="$EVIDENCE",security_model=mapped-xattr \
    -device virtio-9p-pci,fsdev=ev,mount_tag=evidence \
    > "$QEMU_LOG" 2>&1
qemu_rc=$?
set -e
echo "qemu_exit=$qemu_rc" | tee -a "$EVIDENCE/host-context.txt"

# Console always stays; 9p files are a bonus.
echo "=== guest console tail ==="
tail -80 "$QEMU_LOG" || true

if ! grep -q "LABEL=$LABEL" "$QEMU_LOG" && ! grep -q "LABEL=$LABEL" "$EVIDENCE/summary.txt" 2>/dev/null; then
    echo "guest did not print the required TCG label" | tee -a "$EVIDENCE/host-context.txt"
    exit 1
fi
if grep -qi 'jetson' "$QEMU_LOG" && grep -qi 'jetson=1' "$QEMU_LOG"; then
    echo "guest claimed Jetson" >&2
    exit 1
fi

echo "wrote $EVIDENCE"
exit 0
