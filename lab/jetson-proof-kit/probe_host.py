# Host facts for the Jetson proof kit. Live mode calls
# landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) for the
# ABI, then creates one-right rulesets to see which rights this kernel
# accepts. It also records seccomp, unprivileged namespaces, the sysctls
# that gate them, and the capability bounding set.
# JPK_FACTS=file reprints a fixture and makes no system calls.
import ctypes
import errno
import os
import subprocess
import sys

SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1

FS_TRUNCATE = 1 << 14
FS_IOCTL_DEV = 1 << 15
NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX = 1 << 0
SCOPE_SIGNAL = 1 << 1

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000

SECCOMP_GET_ACTION_AVAIL = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SYS_SECCOMP = {"x86_64": 317, "aarch64": 277}
AUDIT_ARCH = {
    "x86_64": ("AUDIT_ARCH_X86_64", "0xc000003e"),
    "aarch64": ("AUDIT_ARCH_AARCH64", "0xc00000b7"),
}
# <linux/capability.h>. CAP_SYS_ADMIN is 21 and is not this check.
CAP_SETPCAP = 8

SYSCTL_PATHS = (
    ("sysctl.user.max_user_namespaces", "/proc/sys/user/max_user_namespaces"),
    ("sysctl.user.max_pid_namespaces", "/proc/sys/user/max_pid_namespaces"),
    ("sysctl.user.max_mnt_namespaces", "/proc/sys/user/max_mnt_namespaces"),
    (
        "sysctl.kernel.unprivileged_userns_clone",
        "/proc/sys/kernel/unprivileged_userns_clone",
    ),
)


class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    return lib


def _read_sysctl(path):
    try:
        with open(path, encoding="ascii") as handle:
            return handle.read().strip() or "empty"
    except FileNotFoundError:
        return "absent"
    except OSError as err:
        return f"error {errno.errorcode.get(err.errno, err.errno)}"


def _status_field(name):
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return ""
    return ""


def _probe_abi(libc):
    ctypes.set_errno(0)
    rc = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    err = ctypes.get_errno()
    if rc >= 0:
        return str(rc)
    if err == errno.ENOSYS:
        return "absent"
    if err == errno.EOPNOTSUPP:
        return "disabled"
    return "error"


def _probe_right(libc, fs=0, net=0, scoped=0, size=8):
    attr = RulesetAttr(fs, net, scoped)
    ctypes.set_errno(0)
    rc = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), size, 0)
    err = ctypes.get_errno()
    if rc >= 0:
        try:
            os.close(int(rc))
        except OSError:
            pass
        return "available"
    name = errno.errorcode.get(err, str(err))
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        return f"absent {name}"
    if err == errno.EINVAL:
        return f"absent {name}"
    return f"error {name}"


def _probe_seccomp(machine):
    nr = SYS_SECCOMP.get(machine)
    if nr is None:
        return "unavailable unknown-arch", "unknown", "unknown"
    libc = _libc()
    action = ctypes.c_uint32(SECCOMP_RET_ALLOW)
    ctypes.set_errno(0)
    rc = libc.syscall(nr, SECCOMP_GET_ACTION_AVAIL, 0, ctypes.byref(action))
    err = ctypes.get_errno()
    arch_name, arch_id = AUDIT_ARCH.get(machine, ("unknown", "unknown"))
    if rc >= 0:
        return "available", arch_name, arch_id
    name = errno.errorcode.get(err, str(err))
    if err == errno.ENOSYS:
        return f"unavailable {name}", arch_name, arch_id
    return f"error {name}", arch_name, arch_id


def _probe_unshare(flags):
    child = (
        "import ctypes, sys\n"
        "flags = int(sys.argv[1])\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "rc = libc.unshare(flags)\n"
        "err = ctypes.get_errno()\n"
        "sys.exit(0 if rc == 0 else (err or 1))\n"
    )
    ran = subprocess.run(
        [sys.executable, "-I", "-c", child, str(flags)],
        check=False,
        capture_output=True,
    )
    if ran.returncode == 0:
        return "available"
    name = errno.errorcode.get(ran.returncode, str(ran.returncode))
    return f"unavailable {name}"


def cap_setpcap_from_mask(mask):
    if mask == 0 or mask & (1 << CAP_SETPCAP):
        return "available"
    return "unavailable"


def _cap_bnd():
    raw = _status_field("CapBnd")
    if not raw:
        return "absent", "unavailable"
    try:
        mask = int(raw, 16)
    except ValueError:
        return raw, "unavailable"
    return raw, cap_setpcap_from_mask(mask)


def live_facts():
    uname = os.uname()
    lines = [
        f"uname_r {uname.release}",
        f"uname_m {uname.machine}",
    ]
    libc = _libc()
    abi = _probe_abi(libc)
    lines.append(f"landlock_abi {abi}")
    lines.append(f"right.truncate {_probe_right(libc, fs=FS_TRUNCATE, size=8)}")
    lines.append(f"right.ioctl_dev {_probe_right(libc, fs=FS_IOCTL_DEV, size=8)}")
    lines.append(
        f"right.net_bind_tcp {_probe_right(libc, net=NET_BIND_TCP, size=16)}"
    )
    lines.append(
        f"right.net_connect_tcp {_probe_right(libc, net=NET_CONNECT_TCP, size=16)}"
    )
    lines.append(
        f"right.scope_signal {_probe_right(libc, scoped=SCOPE_SIGNAL, size=24)}"
    )
    lines.append(
        f"right.scope_abstract_unix {_probe_right(libc, scoped=SCOPE_ABSTRACT_UNIX, size=24)}"
    )
    seccomp, arch_name, arch_id = _probe_seccomp(uname.machine)
    lines.append(f"seccomp {seccomp}")
    lines.append(f"seccomp_arch {arch_name}")
    lines.append(f"seccomp_arch_id {arch_id}")
    lines.append(f"userns {_probe_unshare(CLONE_NEWUSER)}")
    lines.append(f"pidns {_probe_unshare(CLONE_NEWUSER | CLONE_NEWPID)}")
    lines.append(f"mntns {_probe_unshare(CLONE_NEWUSER | CLONE_NEWNS)}")
    for key, path in SYSCTL_PATHS:
        lines.append(f"{key} {_read_sysctl(path)}")
    cap_bnd, cap_setpcap = _cap_bnd()
    lines.append(f"cap_bnd {cap_bnd}")
    lines.append(f"cap_setpcap {cap_setpcap}")
    return "\n".join(lines) + "\n"


def main():
    facts_path = os.environ.get("JPK_FACTS", "")
    if facts_path:
        with open(facts_path, encoding="utf-8") as handle:
            sys.stdout.write(handle.read())
        return
    sys.stdout.write(live_facts())


if __name__ == "__main__":
    main()
