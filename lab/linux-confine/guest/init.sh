#!/bin/sh
# PID 1 inside the qemu-system aarch64 guest.
# Label: aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
# Never native aarch64. Never Jetson.
set -eu

LABEL='aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)'

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t tmpfs run /run
# DEVTMPFS_MOUNT=y usually mounts /dev; keep a fallback.
if [ ! -e /dev/null ]; then
    mount -t devtmpfs dev /dev
fi
mkdir -p /dev/pts /dev/shm
mount -t tmpfs shm /dev/shm 2>/dev/null || true

# Keep baked host worktree paths that live under /tmp. A tmpfs on /tmp
# would hide CARGO_MANIFEST_DIR / LC_* helpers from a /tmp worktree.
if [ -n "$(ls -A /tmp 2>/dev/null || true)" ]; then
    mkdir -p /mnt/initramfs-tmp
    mv /tmp /mnt/initramfs-tmp
    mkdir /tmp
    mount -t tmpfs tmp /tmp
    for ent in /mnt/initramfs-tmp/* /mnt/initramfs-tmp/.[!.]*; do
        [ -e "$ent" ] || continue
        base=$(basename "$ent")
        if [ -d "$ent" ]; then
            mkdir -p "/tmp/$base"
            mount --bind "$ent" "/tmp/$base"
        else
            cp -a "$ent" "/tmp/$base"
        fi
    done
    echo "tmp_mount=tmpfs+baked"
else
    mount -t tmpfs tmp /tmp
    echo "tmp_mount=tmpfs"
fi

# Sysrq halt is the reliable poweroff from PID 1.
if [ -w /proc/sys/kernel/sysrq ]; then
    echo 1 > /proc/sys/kernel/sysrq
fi

ip link set lo up 2>/dev/null || true

# Unprivileged user namespaces for the tester account.
if [ -w /proc/sys/kernel/unprivileged_userns_clone ]; then
    echo 1 > /proc/sys/kernel/unprivileged_userns_clone
fi
if [ -w /proc/sys/user/max_user_namespaces ]; then
    echo 10000 > /proc/sys/user/max_user_namespaces
fi

# Optional 9p evidence mount (modules are in the initramfs).
moddir=/lib/modules/6.18.58-0-virt
load_ko() {
    path="$moddir/$1"
    if [ -f "$path" ]; then
        insmod "$path" 2>/dev/null || true
    fi
}
load_ko kernel/fs/netfs/netfs.ko
load_ko kernel/net/9p/9pnet.ko
load_ko kernel/net/9p/9pnet_virtio.ko
load_ko kernel/fs/9p/9p.ko
# NIC so skip-netns is visible (lo-only qemu hid it).
load_ko kernel/drivers/net/dummy.ko
load_ko kernel/net/dummy.ko
load_ko kernel/drivers/net/virtio_net.ko

# Extra interface besides lo. dummy0 is enough; virtio-net is a bonus.
if ip link add dummy0 type dummy 2>/dev/null; then
    ip link set dummy0 up 2>/dev/null || true
    echo "guest_nic=dummy0"
else
    echo "guest_nic=dummy-missing"
fi
ip link set eth0 up 2>/dev/null && echo "guest_nic=eth0" || true

mkdir -p /evidence
if mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 evidence /evidence 2>/dev/null; then
    echo "evidence_mount=9p"
else
    echo "evidence_mount=console-only"
fi

# GNU ldd via the aarch64 glibc loader (Alpine's busybox ldd is musl).
mkdir -p /usr/local/bin
cat > /usr/local/bin/ldd <<'LDD'
#!/bin/sh
export LD_TRACE_LOADED_OBJECTS=1
exec /lib/ld-linux-aarch64.so.1 "$@"
LDD
chmod 755 /usr/local/bin/ldd
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Non-root tester so unconfined make-char/make-block stay EPERM (no CAP_MKNOD).
if ! grep -q '^tester:' /etc/passwd 2>/dev/null; then
    adduser -D -u 1000 tester 2>/dev/null || echo 'tester:x:1000:1000:tester:/home/tester:/bin/sh' >> /etc/passwd
    echo 'tester:x:1000:' >> /etc/group 2>/dev/null || true
    mkdir -p /home/tester
fi
chmod -R a+rX /workspace /lib /usr 2>/dev/null || true
# A /tmp worktree is the baked host path; tester must be able to read it.
chmod -R a+rX /tmp 2>/dev/null || true
# Test binaries and helpers must be executable.
find /workspace /tmp /lib -type f \( -name 'lc-*' -o -name 'confine' -o -name 'providers' -o -name 'elf' -o -name 'aarch64' -o -name 'did-provider' -o -name 'wallet-provider' -o -name 'model-provider' -o -name 'guest-landlock-probe' \) -exec chmod a+x {} \; 2>/dev/null || true

echo "============================================================"
echo "LABEL=$LABEL"
echo "native=0"
echo "jetson=0"
echo "emulated_cpu=1"
echo "qemu_accel=tcg"
echo "============================================================"
uname -a
echo "uid=$(id -u) gid=$(id -g)"
echo "--- landlock probe ---"
if [ -x /usr/local/bin/guest-landlock-probe ]; then
    if [ -w /evidence ]; then
        /usr/local/bin/guest-landlock-probe | tee /evidence/abi-probe.txt
    else
        /usr/local/bin/guest-landlock-probe
    fi
else
    echo "guest-landlock-probe missing"
fi

run_as_tester() {
    if command -v su >/dev/null 2>&1; then
        su tester -s /bin/sh -c "$1"
    else
        # busybox may lack su; drop privileges with a tiny helper if present
        if [ -x /usr/local/bin/run-as-tester ]; then
            /usr/local/bin/run-as-tester /bin/sh -c "$1"
        else
            echo "WARNING: running C9 suites as root; make-char/make-block controls may differ"
            /bin/sh -c "$1"
        fi
    fi
}

echo "--- C9 suites ---"
set +e
run_as_tester '/usr/local/bin/run-c9.sh'
status=$?
set -e

echo "--- guest finished status=$status ---"
sync
if [ -d /evidence ] && [ -w /evidence ]; then
    echo "guest_exit=$status" >> /evidence/guest-exit.txt
    if [ -f /etc/lc-guest.env ]; then
        # shellcheck disable=SC1091
        . /etc/lc-guest.env
        echo "LC_MARK nonce=${LC_GUEST_NONCE:-missing} suite=guest exit=$status passed=0 failed=0 ignored=0 status=DONE"
    fi
    sync
fi
# Prefer an orderly halt. sysrq-o stops qemu -nographic.
if [ -w /proc/sysrq-trigger ]; then
    echo o > /proc/sysrq-trigger
fi
poweroff -f 2>/dev/null || reboot -f 2>/dev/null || true
# Last resort: exit PID 1 (kernel panic, -no-reboot keeps qemu from looping).
exit "$status"
