#!/bin/sh
# PID 1 inside the qemu-system aarch64 guest.
# Label is set by /etc/fcl-guest.env. Never native. Never Jetson.
set -eu

. /etc/fcl-guest.env
LABEL="${FCL_GUEST_LABEL}"

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t tmpfs run /run
if [ ! -e /dev/null ]; then
    mount -t devtmpfs dev /dev
fi
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs shm /dev/shm 2>/dev/null || true

if [ -n "$(ls -A /tmp 2>/dev/null || true)" ]; then
    mkdir -p /mnt
    mv /tmp /mnt/baked-tmp
    mkdir /tmp
    mount -t tmpfs tmp /tmp
    for ent in /mnt/baked-tmp/* /mnt/baked-tmp/.[!.]*; do
        [ -e "$ent" ] || continue
        base=$(basename "$ent")
        if [ -d "$ent" ]; then
            mkdir -p "/tmp/$base"
            mount -o bind "$ent" "/tmp/$base"
        else
            cp -a "$ent" "/tmp/$base"
        fi
    done
    echo "tmp_mount=tmpfs+baked"
else
    mount -t tmpfs tmp /tmp
    echo "tmp_mount=tmpfs"
fi

if [ -w /proc/sys/kernel/sysrq ]; then
    echo 1 > /proc/sys/kernel/sysrq
fi

ip link set lo up 2>/dev/null || true

if [ -w /proc/sys/kernel/unprivileged_userns_clone ]; then
    echo 1 > /proc/sys/kernel/unprivileged_userns_clone
fi
if [ -w /proc/sys/user/max_user_namespaces ]; then
    echo 10000 > /proc/sys/user/max_user_namespaces
fi

# Load 9p if the kernel shipped modules.
moddir=$(ls -d /lib/modules/* 2>/dev/null | head -1 || true)
load_ko() {
    rel=$1
    if [ -n "$moddir" ] && [ -f "$moddir/$rel" ]; then
        insmod "$moddir/$rel" && echo "insmod_ok=$rel" || echo "insmod_fail=$rel"
    fi
}
load_ko kernel/fs/netfs/netfs.ko
load_ko kernel/net/9p/9pnet.ko
load_ko kernel/net/9p/9pnet_virtio.ko
load_ko kernel/fs/9p/9p.ko

mkdir -p /evidence
if mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 evidence /evidence 2>/dev/null; then
    echo "evidence_mount=9p"
else
    echo "evidence_mount=console-only"
fi

mkdir -p /usr/local/bin
cat > /usr/local/bin/ldd <<'LDD'
#!/bin/sh
export LD_TRACE_LOADED_OBJECTS=1
exec /lib/ld-linux-aarch64.so.1 "$@"
LDD
chmod 755 /usr/local/bin/ldd
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if ! grep -q '^tester:' /etc/passwd 2>/dev/null; then
    adduser -D -u 1000 tester 2>/dev/null || echo 'tester:x:1000:1000:tester:/home/tester:/bin/sh' >> /etc/passwd
    echo 'tester:x:1000:' >> /etc/group 2>/dev/null || true
    mkdir -p /home/tester
    chown -R 1000:1000 /home/tester 2>/dev/null || true
fi
chmod -R a+rX /tmp /lib /usr /home 2>/dev/null || true
# Writable tmp for CARGO_TARGET_TMPDIR fixtures.
if [ -n "${FCL_GUEST_TMPDIR:-}" ]; then
    mkdir -p "$FCL_GUEST_TMPDIR"
    chmod 1777 "$FCL_GUEST_TMPDIR" || true
fi
if [ -n "${FCL_GUEST_SRC:-}" ] && [ -d "$FCL_GUEST_SRC/target" ]; then
    chmod -R a+rwX "$FCL_GUEST_SRC/target" || true
fi
chmod 1777 /tmp || true

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
    elif [ -x /usr/local/bin/run-as-tester ]; then
        /usr/local/bin/run-as-tester /bin/sh -c "$1"
    else
        echo "WARNING: running as root"
        /bin/sh -c "$1"
    fi
}

echo "--- fail-closed-linux suites ---"
set +e
run_as_tester '/usr/local/bin/run-fcl.sh'
status=$?
set -e

echo "--- guest finished status=$status ---"
sync
if [ -d /evidence ] && [ -w /evidence ]; then
    echo "guest_exit=$status" >> /evidence/guest-exit.txt
    echo "FCL_MARK nonce=${FCL_GUEST_NONCE:-missing} suite=guest exit=$status"
    sync
fi
if [ -w /proc/sysrq-trigger ]; then
    echo o > /proc/sysrq-trigger
fi
poweroff -f 2>/dev/null || reboot -f 2>/dev/null || true
exit "$status"
