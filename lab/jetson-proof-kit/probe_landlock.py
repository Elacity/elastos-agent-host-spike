# Landlock ABI probe from draft PR #314 (lab/landlock-abi-compat).
# aarch64 and x86_64 take the number from asm-generic: 444.
# uname -r alone is not the ABI.
import ctypes
import errno
import os

SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
rc = libc.syscall(
    SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION
)
err = ctypes.get_errno()
print("osrelease", os.uname().release)
print("machine", os.uname().machine)
print(
    "syscall",
    SYS_LANDLOCK_CREATE_RULESET,
    "ret",
    rc,
    "errno",
    err,
    errno.errorcode.get(err, ""),
)
if rc >= 0:
    print("landlock_abi", rc)
elif err == errno.ENOSYS:
    print("landlock_abi absent")
elif err == errno.EOPNOTSUPP:
    print("landlock_abi disabled")
else:
    print("landlock_abi error")
