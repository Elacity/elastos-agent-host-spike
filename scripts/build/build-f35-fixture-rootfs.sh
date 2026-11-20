#!/usr/bin/env bash
#
# test-support for the F3.5 KVM row; not a product script; not in release recipes
#
# Build the F3.5 fixture rootfs: a minimal busybox ext4 whose /init is the one
# guest program the F3.5 row needs. It sets the carrier console to raw, no-echo
# (the rule scripts/build/build-rootfs.sh:696-698 applies to the same console),
# announces itself on ttyS0, writes one line-delimited resource_invoke frame to
# /dev/hvc0, reads one reply line back, prints it and exits.
#
# The row asserts nothing about this output. The observable it reads is the
# audit record the resource bridge persists for the guest's frame.
#
# Usage:
#   scripts/build/build-f35-fixture-rootfs.sh --target x86_64 --output /tmp/f35-rootfs
#   scripts/build/build-f35-fixture-rootfs.sh --target x86_64 --output /tmp/f35-rootfs \
#       --busybox /tmp/busybox-static/usr/bin/busybox
#
# Output: <output>/rootfs.ext4
#
# Needs mke2fs (e2fsprogs), a static busybox with the sh, mount, echo and stty
# applets, and `file` to prove the busybox is static. Refuses by name otherwise.

set -euo pipefail
die() { echo "Error: $*" >&2; exit 1; }
info() { echo "  ▶ $*"; }

TARGET_ARCH="x86_64"
OUTPUT_DIR=""
BUSYBOX_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            [[ -z "${2:-}" ]] && die "Usage: --target <x86_64>"
            TARGET_ARCH="$2"
            shift 2
            ;;
        --output)
            [[ -z "${2:-}" ]] && die "Usage: --output <dir>"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --busybox)
            [[ -z "${2:-}" ]] && die "Usage: --busybox <path>"
            BUSYBOX_ARG="$2"
            shift 2
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[[ "$TARGET_ARCH" == "x86_64" ]] \
    || die "unsupported target arch: ${TARGET_ARCH} (this fixture builds for x86_64 only)"
[[ -n "$OUTPUT_DIR" ]] || die "Usage: --output <dir> is required"

command -v mke2fs >/dev/null 2>&1 || die "mke2fs not found. Install e2fsprogs."
command -v file >/dev/null 2>&1 \
    || die "file not found; it is needed to prove the busybox is static. Install file."

BUSYBOX="$BUSYBOX_ARG"
if [[ -z "$BUSYBOX" ]]; then
    for candidate in /bin/busybox /usr/bin/busybox "$(command -v busybox 2>/dev/null || true)"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            BUSYBOX="$candidate"
            break
        fi
    done
fi
[[ -n "$BUSYBOX" && -x "$BUSYBOX" ]] \
    || die "no static busybox found; pass --busybox <path> (install busybox-static)"
file "$BUSYBOX" | grep -Eq "statically linked|static-pie linked" \
    || die "busybox is not static: ${BUSYBOX}"

APPLETS="$("$BUSYBOX" --list 2>/dev/null || true)"
for applet in sh mount echo stty; do
    grep -qx "$applet" <<<"$APPLETS" \
        || die "busybox at ${BUSYBOX} is missing the '${applet}' applet"
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
STAGING_DIR="${WORK_DIR}/staging"
mkdir -p "${STAGING_DIR}"/{bin,dev,etc,proc,sys,tmp}

cp "$BUSYBOX" "${STAGING_DIR}/bin/busybox"
chmod 755 "${STAGING_DIR}/bin/busybox"
for applet in sh mount echo stty; do
    ln -sf busybox "${STAGING_DIR}/bin/${applet}"
done

cat > "${STAGING_DIR}/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true

# Carrier console: raw, no echo, no line discipline. The kernel echoes the
# frame back to the bridge and corrupts the next request otherwise
# (scripts/build/build-rootfs.sh:696-698 applies the same rule).
stty raw -echo -F /dev/hvc0 2>/dev/null || true

echo "f35-guest ready" >/dev/ttyS0 2>/dev/null || true
printf '%s\n' '{"id":1,"request":{"type":"resource_invoke","uri":"localhost://Users/self/f35.txt","operation":"read","body":{}}}' >/dev/hvc0 2>/dev/null || true

reply=""
IFS= read -r reply </dev/hvc0 2>/dev/null || true
echo "f35-guest reply: ${reply}" >/dev/ttyS0 2>/dev/null || true

exit 0
EOF
chmod 755 "${STAGING_DIR}/init"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
mke2fs -q -t ext4 -d "${STAGING_DIR}" -F "${OUTPUT_DIR}/rootfs.ext4" 64M \
    || die "mke2fs failed"

info "Built F3.5 fixture rootfs: ${OUTPUT_DIR}/rootfs.ext4"
