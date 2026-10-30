#!/usr/bin/env python3
"""Static checks for the #307 / #320 review.

Reads the reviewed sources. Writes nothing into those trees.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
FCL = Path(
    os.environ.get(
        "FCL_SRC",
        "/tmp/review-c0-307-src/fail-closed-linux/lab/fail-closed-linux",
    )
)
JPK = Path(
    os.environ.get(
        "JPK_SRC",
        "/tmp/review-c0-307-src/jetson-proof-kit/lab/jetson-proof-kit",
    )
)

# Kernel 6.12 uapi (torvalds/linux v6.12 include/uapi/linux/landlock.h).
UAPI_612 = {
    "ACCESS_FS_EXECUTE": 1 << 0,
    "ACCESS_FS_WRITE_FILE": 1 << 1,
    "ACCESS_FS_READ_FILE": 1 << 2,
    "ACCESS_FS_READ_DIR": 1 << 3,
    "ACCESS_FS_REMOVE_DIR": 1 << 4,
    "ACCESS_FS_REMOVE_FILE": 1 << 5,
    "ACCESS_FS_MAKE_CHAR": 1 << 6,
    "ACCESS_FS_MAKE_DIR": 1 << 7,
    "ACCESS_FS_MAKE_REG": 1 << 8,
    "ACCESS_FS_MAKE_SOCK": 1 << 9,
    "ACCESS_FS_MAKE_FIFO": 1 << 10,
    "ACCESS_FS_MAKE_BLOCK": 1 << 11,
    "ACCESS_FS_MAKE_SYM": 1 << 12,
    "ACCESS_FS_REFER": 1 << 13,
    "ACCESS_FS_TRUNCATE": 1 << 14,
    "ACCESS_FS_IOCTL_DEV": 1 << 15,
    "ACCESS_NET_BIND_TCP": 1 << 0,
    "ACCESS_NET_CONNECT_TCP": 1 << 1,
    "SCOPE_ABSTRACT_UNIX_SOCKET": 1 << 0,
    "SCOPE_SIGNAL": 1 << 1,
    "CREATE_RULESET_VERSION": 1 << 0,
}

# First ABI that expresses the right. Docs: kernel.org 6.12 Landlock
# "Previous limitations" and the uapi comments.
FIRST_ABI = {
    "refer": 2,
    "truncate": 3,
    "net": 4,
    "ioctl_dev": 5,
    "scope": 6,
}
FIRST_KERNEL = {
    1: "5.13",
    2: "5.19",
    3: "6.2",
    4: "6.7",
    5: "6.10",
    6: "6.12",
}

CAP_SETPCAP_UAPI = 8
CAP_SYS_ADMIN_UAPI = 21
REVIEWED_307 = "2c70a0d845f9acc15144a2afec889370612cca66"
REVIEWED_320 = "34a89256e66037e97d52eb9d3e2c0da1267b56a7"
OLD_307_PIN = "129fdc98428c9029b328976511478c46ebe765a6"

pass_n = 0
fail_n = 0


def ok(name: str, cond: bool, detail: str = "") -> None:
    global pass_n, fail_n
    if cond:
        print(f"PASS {name}" + (f"  {detail}" if detail else ""))
        pass_n += 1
    else:
        print(f"FAIL {name}" + (f"  {detail}" if detail else ""))
        fail_n += 1


def rust_const(src: str, name: str) -> int:
    match = re.search(
        rf"pub const {re.escape(name)}: u\d+ = (.+?);", src
    )
    if not match:
        raise SystemExit(f"missing const {name}")
    expr = match.group(1).strip()
    if expr.startswith("1 <<"):
        return 1 << int(expr.split("<<")[1].strip())
    if re.fullmatch(r"\d+", expr):
        return int(expr)
    raise SystemExit(f"unparsed const {name} = {expr}")


def probe_abi() -> int:
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    rc = lib.syscall(444, None, 0, 1)
    if rc < 0:
        raise SystemExit(f"landlock probe failed errno={ctypes.get_errno()}")
    return int(rc)


def main() -> int:
    if not (FCL / "src/lib.rs").is_file():
        print(f"NOT RUN: FCL_SRC missing ({FCL})", file=sys.stderr)
        return 2
    if not (JPK / "decide.py").is_file():
        print(f"NOT RUN: JPK_SRC missing ({JPK})", file=sys.stderr)
        return 2

    lib = (FCL / "src/lib.rs").read_text()
    sim = (FCL / "src/sim.rs").read_text()
    real = (FCL / "src/real.rs").read_text()
    decide = (JPK / "decide.py").read_text()
    probe_host = (JPK / "probe_host.py").read_text()
    lib_sh = (JPK / "lib.sh").read_text()
    run_j = (JPK / "run-on-jetson.sh").read_text()
    decisions = (JPK / "tests/test_decisions.sh").read_text()
    evidence = (JPK / "evidence.txt").read_text()

    print(f"FCL_SRC {FCL}")
    print(f"JPK_SRC {JPK}")
    print(f"reviewed_307 {REVIEWED_307}")
    print(f"reviewed_320 {REVIEWED_320}")

    # ABI bits vs kernel 6.12 uapi.
    for name, value in UAPI_612.items():
        ok(f"uapi_{name}", rust_const(lib, name) == value, hex(value))

    ok("truncate_abi_3", rust_const(lib, "TRUNCATE_ABI") == FIRST_ABI["truncate"])
    ok("ioctl_dev_abi_5", rust_const(lib, "IOCTL_DEV_ABI") == FIRST_ABI["ioctl_dev"])
    ok("scope_signal_abi_6", rust_const(lib, "SCOPE_SIGNAL_ABI") == FIRST_ABI["scope"])
    ok("kernel_5.13_is_abi_1", FIRST_KERNEL[1] == "5.13")
    ok("kernel_5.15_class_is_abi_1", True, "5.15 < 5.19 so ABI 1 when LSM is on")

    needed = re.findall(r'name: "(\w+)"', lib.split("FILE_PROFILE_NEEDED_RIGHTS")[1].split("];")[0])
    ok("needed_rights_truncate_ioctl", needed == ["truncate", "ioctl_dev"], str(needed))
    ok("refer_not_a_needed_right", "refer" not in needed)

    # This VM's installed landlock.h is older than the running 6.12 kernel.
    host_h = Path("/usr/include/linux/landlock.h").read_text()
    ok(
        "host_uapi_header_lacks_ioctl_dev",
        "LANDLOCK_ACCESS_FS_IOCTL_DEV" not in host_h,
        "stale libc-dev header; 6.12 uapi is the oracle",
    )
    ok("host_uapi_header_lacks_scoped", "scoped" not in host_h)

    abi = probe_abi()
    ok("host_landlock_abi_6", abi == 6, str(abi))

    # Fail-closed shape in the unmutated guard.
    ok(
        "confine_checks_missing_mask",
        "if let Some(mask) = missing_required_mask(abi)" in lib,
    )
    ok(
        "require_abi_cannot_skip_a_right",
        "cannot skip a needed right" in lib,
    )
    ok(
        "empty_pipe_is_reported_as_start",
        "if got == 0 && read_error.is_none()" in real
        and "return Ok(pid as u32)" in real,
    )
    ok(
        "simkernel_ignores_access_mask",
        "_access: u64" in sim and "allowed_access" not in sim,
        "SimKernel add_path_rule does not EINVAL on unknown bits",
    )

    # #307 tests do not skip.
    test_src = ""
    for path in (FCL / "tests").rglob("*.rs"):
        test_src += path.read_text()
    ok("no_ignore_attr_in_307_tests", "#[ignore]" not in test_src)
    ok("no_not_run_in_307_tests", "NOT RUN" not in test_src)

    # Kit decision table is a copy, not the guard.
    ok("decide_py_has_no_guard_import", "fail_closed" not in decide)
    ok("decide_py_has_no_fcl_launch", "fcl-launch" not in decide)
    ok("test_decisions_calls_decide_py", "decide.py" in decisions)
    ok("test_decisions_never_calls_fcl_launch", "fcl-launch" not in decisions)
    ok(
        "kit_reasons_are_not_307_reasons",
        '"missing " + ", ".join(missing)' in decide
        and "cannot deny" not in decide
        and "needs ABI" not in decide,
    )
    ok(
        "default_c0_pin_is_old_abi5_floor",
        OLD_307_PIN in lib_sh and REVIEWED_307 not in lib_sh,
        OLD_307_PIN,
    )
    ok(
        "c0_guard_row_is_one_dummy_did",
        "--provider did-provider" in run_j and "wallet-provider" not in run_j,
    )
    ok(
        "c0_guard_dummy_exe_is_empty",
        ': >"$exe"' in run_j and "chmod +x" in run_j,
    )

    # CAP_SETPCAP mis-numbered as SYS_ADMIN.
    ok(
        "probe_host_cap_setpcap_is_21",
        "CAP_SETPCAP = 21" in probe_host,
    )
    ok(
        "uapi_cap_setpcap_is_8",
        CAP_SETPCAP_UAPI == 8 and CAP_SYS_ADMIN_UAPI == 21,
    )
    cap_h = Path("/usr/include/linux/capability.h").read_text()
    ok("host_capability_h_setpcap_8", "#define CAP_SETPCAP          8" in cap_h)
    ok("decide_fallback_uses_bit_21", "(1 << 21)" in decide)

    # Evidence rows stay NOT RUN. Recording a live right still stamps PASS.
    rows = [
        line
        for line in evidence.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    ok(
        "committed_evidence_all_not_run",
        all(line.split("\t")[1] == "NOT RUN" for line in rows),
        f"{len(rows)} rows",
    )
    ok(
        "live_right_rows_stamped_pass",
        'jpk_set_row "$evidence" host.right.truncate PASS' in run_j,
    )
    ok(
        "decision_launch_stamped_pass",
        'if [ "$decision" = LAUNCH ]; then' in run_j and "status=PASS" in run_j,
    )

    print(f"summary {pass_n} passed {fail_n} failed")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
