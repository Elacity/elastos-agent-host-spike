#!/usr/bin/env bash
# Cross-build fail-closed-linux for aarch64, pack an Alpine initramfs, and
# boot qemu-system-aarch64 TCG.
#
# Modes:
#   full   Alpine virt kernel 6.18 (default). Label: emulated CPU.
#   abi1   Alpine virt kernel 5.15. Label: emulated 5.15 kernel.
#
# Never native ARM. Never Jetson.
set -euo pipefail

MODE="${1:-full}"
REVIEW="$(cd "$(dirname "$0")" && pwd)"
CANDIDATE="${FCL_SRC:-/tmp/wt-307-r5/candidate/lab/fail-closed-linux}"
CANDIDATE_REPO="$(cd "$CANDIDATE/../.." && pwd)"
CC=aarch64-linux-gnu-gcc
TARGET=aarch64-unknown-linux-gnu
WORK="${FCL_GUEST_WORK:-/tmp/fcl-r5-aarch64}"
SRC_COPY="$WORK/crate"
NONCE="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"

if [ "$MODE" = "abi1" ]; then
    LABEL='emulated 5.15 kernel under qemu-system TCG (not Jetson)'
    EVIDENCE="$REVIEW/evidence/aarch64-qemu-5.15"
    ALPINE_VER=3.16.9
    ALPINE_MIRROR="${ALPINE_MIRROR_515:-https://dl-cdn.alpinelinux.org/alpine/v3.16}"
    KERNEL_APK_VER="${KERNEL_APK_VER_515:-}"
    KERNEL_REL=""
    APPEND_EXTRA="lsm=landlock,capability,yama"
else
    LABEL='aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)'
    EVIDENCE="$REVIEW/evidence/aarch64-qemu-system-6.18"
    ALPINE_VER=3.23.5
    ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/v3.23}"
    KERNEL_APK_VER=6.18.58-r0
    KERNEL_REL=6.18.58-0-virt
    APPEND_EXTRA=""
fi

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$CC"
export CC_aarch64_unknown_linux_gnu="$CC"
unset TARGET_CC || true
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
find "$EVIDENCE" -maxdepth 1 -type f \
    \( -name '*.status' -o -name '*.exit' -o -name '*.txt' -o -name 'LABEL.txt' \) \
    -delete
echo "$LABEL" > "$EVIDENCE/LABEL.txt"
echo "$NONCE" > "$EVIDENCE/nonce.txt"
{
    echo "label=$LABEL"
    echo "native=0"
    echo "jetson=0"
    echo "emulated_cpu=1"
    echo "qemu_accel=tcg"
    echo "mode=$MODE"
    echo "host_uname=$(uname -srm)"
    echo "qemu=$(qemu-system-aarch64 --version | head -1)"
    echo "cross_cc=$($CC --version | head -1)"
    echo "rustc=$(rustc --version)"
    echo "candidate=$CANDIDATE_REPO"
    echo "head=$(git -C "$CANDIDATE_REPO" rev-parse HEAD)"
    echo "nonce=$NONCE"
} | tee "$EVIDENCE/host-context.txt"

echo "=== rust target ==="
rustup target add aarch64-unknown-linux-gnu >/dev/null

echo "=== copy crate and allow cross probe build ==="
rm -rf "$SRC_COPY"
mkdir -p "$SRC_COPY"
python3 - "$CANDIDATE" "$SRC_COPY" <<'PY'
import shutil, sys
src, dest = sys.argv[1], sys.argv[2]
skip = {"target", "__pycache__", ".git"}
for item in __import__("pathlib").Path(src).iterdir():
    if item.name in skip:
        continue
    target = __import__("pathlib").Path(dest) / item.name
    if item.is_dir():
        shutil.copytree(item, target, ignore=shutil.ignore_patterns(*skip))
    else:
        shutil.copy2(item, target)
PY
# Cross-build the static probes for TARGET, even when TARGET != HOST.
python3 - "$SRC_COPY/build.rs" <<'PY'
from pathlib import Path
p = Path(__import__("sys").argv[1])
text = p.read_text()
old = """    if target != host {
        println!("cargo:rustc-env=FCL_PROBE=");
        println!("cargo:rustc-env=FCL_SILENT=");
        return;
    }
"""
new = """    let _ = host;
    // Review copy only: build probes for the cargo TARGET so aarch64
    // guest tests have FCL_PROBE. The #307 worktree is unchanged.
"""
if old not in text:
    raise SystemExit("build.rs host!=target skip not found")
p.write_text(text.replace(old, new, 1))
print("patched build.rs for cross probe")
PY

echo "=== download Alpine kernel and minirootfs ==="
cd "$WORK/dl"
if [ "$MODE" = "abi1" ]; then
    if [ -z "$KERNEL_APK_VER" ]; then
        echo "resolve 5.15 linux-virt apk"
        html=$(curl -fsSL "$ALPINE_MIRROR/main/aarch64/")
        KERNEL_APK_VER=$(python3 - <<PY
import re, sys
html = """$html"""
hits = re.findall(r'linux-virt-(5\.15\.[0-9]+-r[0-9]+)\.apk', html)
if not hits:
    raise SystemExit("no 5.15 linux-virt apk on Alpine 3.16")
# last listed is usually newest
print(hits[-1])
PY
)
    fi
    KERNEL_APK="linux-virt-${KERNEL_APK_VER}.apk"
    echo "kernel_apk=$KERNEL_APK" | tee -a "$EVIDENCE/host-context.txt"
    if [ ! -s "$KERNEL_APK" ]; then
        curl -fL --retry 4 --retry-delay 4 -o "$KERNEL_APK" \
            "$ALPINE_MIRROR/main/aarch64/$KERNEL_APK"
    fi
    ROOTFS="alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz"
    if [ ! -s "$ROOTFS" ]; then
        curl -fL --retry 4 --retry-delay 4 -o "$ROOTFS" \
            "$ALPINE_MIRROR/releases/aarch64/$ROOTFS"
    fi
else
    if [ ! -s "linux-virt-${KERNEL_APK_VER}.apk" ]; then
        curl -fL --retry 4 --retry-delay 4 -o "linux-virt-${KERNEL_APK_VER}.apk" \
            "$ALPINE_MIRROR/main/aarch64/linux-virt-${KERNEL_APK_VER}.apk"
    fi
    if [ ! -s "alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz" ]; then
        curl -fL --retry 4 --retry-delay 4 -o "alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz" \
            "$ALPINE_MIRROR/releases/aarch64/alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz"
    fi
fi

rm -rf "$WORK/kernel"
mkdir -p "$WORK/kernel"
if [ "$MODE" = "abi1" ]; then
    tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk" \
        --warning=no-unknown-keyword 2>/dev/null \
        || tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk"
    KERNEL_REL=$(basename "$(ls -d "$WORK/kernel/lib/modules/"* | head -1)")
    echo "kernel_rel=$KERNEL_REL" | tee -a "$EVIDENCE/host-context.txt"
else
    tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk" \
        --warning=no-unknown-keyword 2>/dev/null \
        || tar -C "$WORK/kernel" -xzf "$WORK/dl/linux-virt-${KERNEL_APK_VER}.apk"
fi
test -f "$WORK/kernel/boot/vmlinuz-virt"
echo "kernel=$WORK/kernel/boot/vmlinuz-virt" | tee -a "$EVIDENCE/host-context.txt"
sha256sum "$WORK/kernel/boot/vmlinuz-virt" | tee "$EVIDENCE/vmlinuz-virt.sha256"

echo "=== cross-build fail-closed-linux ==="
(
    cd "$SRC_COPY"
    export CARGO_TARGET_DIR="$SRC_COPY/target"
    export CARGO_BUILD_BUILD_DIR="$SRC_COPY/target/build"
    export RUST_TEST_THREADS=1
    export CARGO_INCREMENTAL=0
    cargo test --locked --no-run --target "$TARGET" --lib
    cargo test --locked --no-run --target "$TARGET" --test simulated
    cargo test --locked --no-run --target "$TARGET" --test real_kernel
    cargo build --locked --target "$TARGET" --bin fcl-launch
)

DEPS="$SRC_COPY/target/$TARGET/debug/deps"
BINS="$SRC_COPY/guest-bins"
rm -rf "$BINS"
mkdir -p "$BINS"
copy_latest() {
    prefix=$1
    dest=$2
    src=$(ls -t "$DEPS"/${prefix}-* 2>/dev/null | grep -v '\.d$' | grep -v '\.rlib$' | head -1)
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
copy_latest fail_closed_linux "$BINS/lib"
copy_latest simulated "$BINS/simulated"
copy_latest real_kernel "$BINS/real_kernel"
cp -a "$SRC_COPY/target/$TARGET/debug/fcl-launch" "$BINS/fcl-launch"
chmod 755 "$BINS/fcl-launch"
python3 - "$BINS/fcl-launch" <<'PY'
import struct, sys
p = sys.argv[1]
b = open(p, "rb").read(20)
mach = struct.unpack_from("<H", b, 18)[0]
assert mach == 183, (p, mach)
print(p, "EM_AARCH64=183")
PY
# Tiny static dummy for ABI-1 launch (exec never runs).
"$CC" -static -O1 -o "$BINS/dummy" -x c - <<'C'
int main(void) { return 0; }
C

echo "=== compile guest helpers ==="
"$CC" -static -O2 -Wall -Wextra -Werror \
    -o "$WORK/guest-landlock-probe" \
    "$REVIEW/guest/landlock-probe.c"
"$CC" -static -O2 -Wall -Wextra -Werror \
    -o "$WORK/run-as-tester" \
    "$REVIEW/guest/run-as-tester.c"

echo "=== assemble initramfs ==="
ROOT="$WORK/rootfs"
rm -rf "$ROOT"
mkdir -p "$ROOT"
tar -C "$ROOT" -xzf "$WORK/dl/alpine-minirootfs-${ALPINE_VER}-aarch64.tar.gz"

mkdir -p "$ROOT/lib/aarch64-linux-gnu" "$ROOT/usr/local/bin"
cp -a /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 "$ROOT/lib/ld-linux-aarch64.so.1"
for lib in libc.so.6 libm.so.6 libgcc_s.so.1 libdl.so.2 libpthread.so.0 \
           librt.so.1 libutil.so.1; do
    if [ -e "/usr/aarch64-linux-gnu/lib/$lib" ]; then
        cp -a "/usr/aarch64-linux-gnu/lib/$lib" "$ROOT/lib/aarch64-linux-gnu/"
    fi
done

if [ -n "$KERNEL_REL" ]; then
    MODDST="$ROOT/lib/modules/$KERNEL_REL"
    mkdir -p "$MODDST"
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
fi

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

# Recreate baked host paths (FCL_PROBE, CARGO_BIN_EXE, CARGO_TARGET_TMPDIR).
install_tree "$SRC_COPY" "$ROOT$SRC_COPY"

# Make target tmp writable.
mkdir -p "$ROOT$SRC_COPY/target/$TARGET/debug"
mkdir -p "$ROOT$SRC_COPY/target/$TARGET/tmp"
chmod 1777 "$ROOT$SRC_COPY/target/$TARGET/tmp" || true
chmod -R a+rX "$ROOT$SRC_COPY" || true

{
    printf "FCL_GUEST_SRC='%s'\n" "$SRC_COPY"
    printf "FCL_GUEST_NONCE='%s'\n" "$NONCE"
    printf "FCL_GUEST_LABEL='%s'\n" "$LABEL"
    printf "FCL_GUEST_MODE='%s'\n" "$MODE"
    printf "FCL_GUEST_TMPDIR='%s'\n" "$SRC_COPY/target/$TARGET/tmp"
} > "$ROOT/etc/fcl-guest.env"
echo "$NONCE" > "$ROOT/etc/fcl-nonce"
chmod 644 "$ROOT/etc/fcl-guest.env" "$ROOT/etc/fcl-nonce"

cp -a "$WORK/guest-landlock-probe" "$ROOT/usr/local/bin/guest-landlock-probe"
cp -a "$WORK/run-as-tester" "$ROOT/usr/local/bin/run-as-tester"
cp -a "$REVIEW/guest/run-fcl.sh" "$ROOT/usr/local/bin/run-fcl.sh"
cp -a "$REVIEW/guest/init.sh" "$ROOT/init"
chmod 755 "$ROOT/usr/local/bin/guest-landlock-probe" \
    "$ROOT/usr/local/bin/run-as-tester" \
    "$ROOT/usr/local/bin/run-fcl.sh" \
    "$ROOT/init"

echo "=== pack initramfs ==="
( cd "$ROOT" && find . -print0 | cpio --null -o -H newc ) | gzip -1 > "$WORK/guest.cpio.gz"
ls -lh "$WORK/guest.cpio.gz" | tee -a "$EVIDENCE/host-context.txt"

echo "=== boot qemu-system-aarch64 TCG ==="
QEMU_LOG="$EVIDENCE/qemu-console.txt"
set +e
qemu-system-aarch64 \
    -name "fcl-r5-aarch64-$MODE" \
    -M virt \
    -cpu max \
    -accel tcg \
    -smp 2 \
    -m 4096 \
    -nographic \
    -no-reboot \
    -kernel "$WORK/kernel/boot/vmlinuz-virt" \
    -initrd "$WORK/guest.cpio.gz" \
    -append "console=ttyAMA0 earlycon=pl011,0x09000000 panic=1 $APPEND_EXTRA" \
    -fsdev local,id=ev,path="$EVIDENCE",security_model=mapped-xattr \
    -device virtio-9p-pci,fsdev=ev,mount_tag=evidence \
    > "$QEMU_LOG" 2>&1
qemu_rc=$?
set -e
echo "qemu_exit=$qemu_rc" | tee -a "$EVIDENCE/host-context.txt"
echo "=== guest console tail ==="
tail -80 "$QEMU_LOG" || true

if ! grep -q "LABEL=$LABEL" "$QEMU_LOG" && ! grep -q "LABEL=$LABEL" "$EVIDENCE/summary.txt" 2>/dev/null; then
    echo "guest did not print the required TCG label" | tee -a "$EVIDENCE/host-context.txt"
    exit 1
fi
if grep -qi 'jetson=1' "$QEMU_LOG"; then
    echo "guest claimed Jetson" >&2
    exit 1
fi

python3 - "$EVIDENCE" "$MODE" "$NONCE" <<'PY'
import pathlib, sys
ev, mode, nonce = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
summary = (ev / "summary.txt").read_text() if (ev / "summary.txt").exists() else ""
console = (ev / "qemu-console.txt").read_text() if (ev / "qemu-console.txt").exists() else ""
text = summary + "\n" + console
if nonce not in text and f"nonce={nonce}" not in text:
    print("nonce missing from guest output")
    sys.exit(1)
if mode == "abi1":
    status = (ev / "abi1.status").read_text().strip() if (ev / "abi1.status").exists() else "MISSING"
    print(f"abi1.status={status}")
    sys.exit(0 if status == "PASS" else 1)
ok = True
for name, expected in (("lib", "9"), ("simulated", "21"), ("real_kernel", "28")):
    st = ev / f"{name}.status"
    status = st.read_text().strip() if st.exists() else "MISSING"
    print(f"{name}.status={status}")
    if status != "PASS":
        ok = False
sys.exit(0 if ok else 1)
PY
echo "wrote $EVIDENCE"
