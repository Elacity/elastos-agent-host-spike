#!/usr/bin/env python3
"""Static checks for the #320 v2 review.

Reads the reviewed kit and the pinned #307 crate. Writes nothing
into those trees.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
JPK = Path(
    os.environ.get("JPK_SRC", "/tmp/jpk-320/lab/jetson-proof-kit")
)
FCL = Path(
    os.environ.get("FCL_SRC", "/tmp/c0-307/lab/fail-closed-linux")
)

REVIEWED_320 = "2bb0b5859bbf8582a43d958e3ddc1569eb77bf97"
REVIEWED_307 = "2c70a0d845f9acc15144a2afec889370612cca66"
OLD_PIN = "129fdc98428c9029b328976511478c46ebe765a6"
CAP_SETPCAP_UAPI = 8
CAP_SYS_ADMIN_UAPI = 21

# Same table as #307 FILE_PROFILE_NEEDED_RIGHTS.
FILE_PROFILE = (("truncate", 3, 1), ("ioctl_dev", 5, 2))

pass_n = 0
fail_n = 0
notes: list[str] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    global pass_n, fail_n
    if cond:
        print(f"PASS {name}" + (f"  {detail}" if detail else ""))
        pass_n += 1
    else:
        print(f"FAIL {name}" + (f"  {detail}" if detail else ""))
        fail_n += 1


def note(msg: str) -> None:
    notes.append(msg)
    print(f"NOTE {msg}")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_py(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rust_missing_required_mask(abi: int):
    mask = 0
    for _name, minimum_abi, bit in FILE_PROFILE:
        if abi < minimum_abi:
            mask |= bit
    return mask or None


def rust_missing_rights_reason(abi: int, mask: int) -> str:
    names = [
        f"{name} (needs ABI {minimum_abi})"
        for name, minimum_abi, bit in FILE_PROFILE
        if mask & bit
    ]
    return "this kernel's Landlock ABI {} cannot deny {}".format(
        abi, "; ".join(names)
    )


def rust_file_profile_launches(abi: int) -> bool:
    return rust_missing_required_mask(abi) is None


def kit_files() -> list[Path]:
    names = (
        "lib.sh",
        "run-on-jetson.sh",
        "probe_host.py",
        "probe_landlock.py",
        "decide.py",
        "standin.rs",
        "falsify.sh",
        "README.md",
        "tests/test_guards.sh",
        "tests/test_decisions.sh",
    )
    return [JPK / name for name in names]


def check_trees() -> None:
    ok("jpk_tree", (JPK / "decide.py").is_file(), str(JPK))
    ok("fcl_tree", (FCL / "src/lib.rs").is_file(), str(FCL))


def check_jpk1(decide_src: str, run_src: str) -> None:
    ok(
        "jpk1_labeled_oracle",
        "This file is not the guard" in decide_src
        and REVIEWED_307 in decide_src[:800],
    )
    for name in ("did", "wallet", "model"):
        ok(
            f"jpk1_script_launches_{name}",
            f'jpk_run_c0_provider "$bin" "$standin" {name}' in run_src,
        )
    ok(
        "jpk1_fcl_launch_argv",
        '"$bin" --provider "${name}-provider"' in run_src
        and '"$standin"' in run_src,
    )


def check_jpk2(lib_src: str, decide) -> None:
    ok(
        "jpk2_default_pin",
        f"JPK_C0_DEFAULT_SHA=$JPK_C0_PER_RIGHT_SHA" in lib_src
        and f"JPK_C0_PER_RIGHT_SHA={REVIEWED_307}" in lib_src,
    )
    ok("jpk2_old_pin_constant", f"JPK_C0_OLD_ABI5_FLOOR_SHA={OLD_PIN}" in lib_src)
    ok("jpk2_per_right_refuses_old_pin", decide.per_right_table_allowed(OLD_PIN) is False)
    ok("jpk2_per_right_allows_new_pin", decide.per_right_table_allowed(REVIEWED_307) is True)


def check_jpk3(lib_rs: str, decide) -> None:
    ok(
        "jpk3_rust_reason_format",
        "this kernel's Landlock ABI {abi} cannot deny {}" in lib_rs,
    )
    ok(
        "jpk3_rust_names_right_and_abi",
        '"{} (needs ABI {})"' in lib_rs or 'format!("{} (needs ABI {})"' in lib_rs,
    )
    for abi, mask in (
        (1, 3),
        (2, 3),
        (3, 2),
        (4, 2),
    ):
        rust = rust_missing_rights_reason(abi, mask)
        py = decide.missing_rights_reason(abi, mask)
        ok(f"jpk3_reason_abi{abi}", rust == py, py)
    facts = decide.parse_facts((JPK / "fixtures/abi-1-jetson.facts").read_text())
    _decision, reason = decide.decide_per_right(facts)
    ok(
        "jpk3_abi1_fixture_is_307_reason",
        reason == rust_missing_rights_reason(1, 3),
        reason,
    )
    # #307 wraps the OS error on AbiProbe. The oracle does not. Named gap.
    if 'return "Landlock is not available"' in read(JPK / "decide.py"):
        if "Landlock is not available: {}" in lib_rs:
            note(
                "jpk3_abi_probe: #307 prints 'Landlock is not available: {os error}'; "
                "decide.py prints 'Landlock is not available'"
            )


def check_jpk4(lib_rs: str, decide) -> None:
    confine = lib_rs[lib_rs.find("pub fn confine<") : lib_rs.find("pub fn confine_and_exec")]
    ok("jpk4_307_probes_abi_number", "kernel.landlock_abi()" in confine)
    ok("jpk4_307_mask_from_abi", "missing_required_mask(abi)" in confine)
    ok(
        "jpk4_307_mask_ignores_measured_rights",
        "right.truncate" not in confine and "ioctl_dev" not in confine.split("missing_required_mask")[0],
    )
    ok("jpk4_307_abi5_launches", rust_file_profile_launches(5) is True)
    ok("jpk4_307_abi1_refuses", rust_file_profile_launches(1) is False)
    lie = decide.parse_facts((JPK / "fixtures/abi-lie-5-rights-1.facts").read_text())
    decision, reason = decide.decide_per_right(lie)
    ok("jpk4_lie_launches", decision == "LAUNCH")
    ok("jpk4_lie_names_trust", "guard trusts the ABI number" in reason)
    ok("jpk4_lie_names_measured", "measured truncate, ioctl_dev absent" in reason)
    real_abi = read(FCL / "src/real.rs")
    ok(
        "jpk4_real_abi_is_version_query",
        "SYS_landlock_create_ruleset" in real_abi
        and "CREATE_RULESET_VERSION" in real_abi[real_abi.find("fn landlock_abi") :],
    )


def check_jpk5(decide, probe) -> None:
    header = Path("/usr/include/linux/capability.h")
    uapi = header.read_text(encoding="utf-8") if header.is_file() else ""
    ok("jpk5_uapi_setpcap_8", f"#define CAP_SETPCAP          {CAP_SETPCAP_UAPI}" in uapi)
    ok("jpk5_uapi_sysadmin_21", f"#define CAP_SYS_ADMIN        {CAP_SYS_ADMIN_UAPI}" in uapi)
    ok("jpk5_decide_bit", decide.CAP_SETPCAP == CAP_SETPCAP_UAPI)
    ok("jpk5_probe_bit", probe.CAP_SETPCAP == CAP_SETPCAP_UAPI)
    ok("jpk5_bit8_droppable", decide.cap_setpcap_from_mask(1 << 8) == "available")
    ok("jpk5_bit21_not_the_check", decide.cap_setpcap_from_mask(1 << 21) == "unavailable")


def check_jpk6(run_src: str, lib_src: str) -> None:
    ok("jpk6_no_empty_redirect", ': >"$exe"' not in run_src)
    ok("jpk6_standin_rs", (JPK / "standin.rs").is_file())
    ok("jpk6_standin_builder", "jpk_c0_standin" in run_src and "standin.rs" in run_src)
    ok(
        "jpk6_classify_enoexec",
        '*"Exec format error"* | *"os error 8"*' in lib_src
        or '"Exec format error"' in lib_src,
    )
    # Reproduce the classifier without sourcing bash: Exec format is NOT RUN.
    script = r"""
set -eu
. "$JPK/lib.sh"
printf '%s' "$(jpk_classify_c0_launch 71 "step execve: Exec format error (os error 8)")"
"""
    ran = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, "JPK": str(JPK)},
        text=True,
        capture_output=True,
        check=False,
    )
    ok("jpk6_classify_exec_format", ran.stdout.strip() == "NOT RUN", ran.stdout.strip())


def check_jpk7(lib_src: str) -> None:
    script = r"""
set -eu
. "$JPK/lib.sh"
printf '%s ' "$(jpk_availability_status "absent EINVAL")"
printf '%s ' "$(jpk_availability_status "available")"
printf '%s' "$(jpk_availability_status "unavailable ENOSPC")"
"""
    ran = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, "JPK": str(JPK)},
        text=True,
        capture_output=True,
        check=False,
    )
    got = ran.stdout.strip()
    ok("jpk7_absent_is_absent", got == "ABSENT PASS REFUSED", got)
    ok("jpk7_comment_never_pass", "Never stamps an absent right as PASS" in lib_src)
    evidence = read(JPK / "evidence.txt")
    rows = [
        line
        for line in evidence.splitlines()
        if line and not line.startswith("#")
    ]
    ok("jpk7_committed_rows_not_run", all(line.split("\t")[1] == "NOT RUN" for line in rows), str(len(rows)))


def check_safety(lib_src: str, run_src: str) -> None:
    ok("safety_root_name", "JPK_ROOT_NAME=flint-elastos-test" in lib_src)
    ok("safety_jobs_4", "JPK_BUILD_JOBS=4" in lib_src)
    ok("safety_cargo_uses_jobs", '"$JPK_BUILD_JOBS"' in run_src)
    ok("safety_mem_floor_1gib", "JPK_MEM_FLOOR_KB=1048576" in lib_src)
    ok(
        "safety_mem_guard_kills",
        "jpk_with_memory_guard" in lib_src and "kill \"$cmd\"" in lib_src,
    )
    operator = "\n".join(
        read(path)
        for path in (
            JPK / "lib.sh",
            JPK / "run-on-jetson.sh",
            JPK / "probe_host.py",
            JPK / "probe_landlock.py",
            JPK / "decide.py",
            JPK / "standin.rs",
        )
        if path.is_file()
    )
    blob = "\n".join(read(path) for path in kit_files() if path.is_file())
    ok("safety_no_pc2_net", "pc2.net" not in blob)
    ok(
        "safety_no_sudo_apt_pm2",
        re.search(r"(^|[\s\"'])(sudo|apt-get|apt|pm2|PM2)([\s\"']|$)", blob, re.M) is None,
    )
    ok(
        "safety_no_port_4200",
        re.search(r":4200\b|port 4200|localhost:4200", operator) is None,
    )
    ok(
        "safety_default_remote_is_github",
        "github.com/Elacity/elastos-agent-host-spike.git" in lib_src,
    )
    ok("safety_cargo_home_under_root", 'CARGO_HOME="$root/cargo-home"' in run_src)
    ok("safety_no_network_package_install", not re.search(r"\b(apt-get|pip3|npm install)\b", blob))

    if "TMPDIR=" not in lib_src and "TMPDIR=" not in run_src:
        note("safety_tmpdir: cargo/rustc/gcc may write compiler temps under /tmp")
    if not re.search(r"EUID|id -u|UID", run_src + lib_src):
        note("safety_root: kit does not refuse uid 0; HOME becomes /root/flint-elastos-test")
    if "kill -- -" not in lib_src and "kill -TERM -" not in lib_src:
        note("safety_mem_pgid: memory kill sends SIGTERM to cargo only, not the process group")
    gcc_lines = [line for line in run_src.splitlines() if re.search(r"\bgcc\b", line)]
    gcc_invokes = [line for line in gcc_lines if "jpk_with_memory_guard gcc" in line]
    if gcc_invokes and not any(" -j " in line for line in gcc_invokes):
        note("safety_gcc_jobs: README says gcc uses four jobs; gcc is invoked without -j")
    if '"$setup" 2>&1' in run_src and "policy" not in run_src[run_src.find("jpk_run_c9") :]:
        note("safety_c9: lc-setup is run with no policy path; C9 refuses and does not exec")


def check_standin_build() -> None:
    dest = Path("/tmp/jpk-review-standin")
    cmd = [
        "rustc",
        "--edition",
        "2021",
        "-C",
        "opt-level=1",
        "-C",
        "panic=abort",
        "-C",
        "target-feature=+crt-static",
        "-o",
        str(dest),
        str(JPK / "standin.rs"),
    ]
    ran = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if ran.returncode != 0:
        note(f"standin_build: rustc failed rc={ran.returncode}: {ran.stderr[-200:]}")
        ok("jpk6_standin_compiles", False, "rustc failed")
        return
    ok("jpk6_standin_compiles", dest.is_file())
    file_out = subprocess.run(["file", str(dest)], text=True, capture_output=True, check=False)
    ldd = subprocess.run(["ldd", str(dest)], text=True, capture_output=True, check=False)
    static = (
        "statically linked" in file_out.stdout
        or "static-pie linked" in file_out.stdout
        or "statically linked" in ldd.stdout
        or "not a dynamic executable" in ldd.stdout
    )
    ok("jpk6_standin_static", static, file_out.stdout.strip())
    if not static:
        note(f"standin_dynamic: {file_out.stdout.strip()} ldd={ldd.stdout.strip()[:120]}")


def main() -> int:
    check_trees()
    if fail_n:
        print(f"summary {pass_n} passed {fail_n} failed (trees missing)")
        return 1
    decide_src = read(JPK / "decide.py")
    run_src = read(JPK / "run-on-jetson.sh")
    lib_src = read(JPK / "lib.sh")
    lib_rs = read(FCL / "src/lib.rs")
    decide = load_py("decide", JPK / "decide.py")
    probe = load_py("probe_host", JPK / "probe_host.py")
    check_jpk1(decide_src, run_src)
    check_jpk2(lib_src, decide)
    check_jpk3(lib_rs, decide)
    check_jpk4(lib_rs, decide)
    check_jpk5(decide, probe)
    check_jpk6(run_src, lib_src)
    check_jpk7(lib_src)
    check_safety(lib_src, run_src)
    check_standin_build()
    print(f"summary {pass_n} passed {fail_n} failed")
    for item in notes:
        print(f"note: {item}")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
