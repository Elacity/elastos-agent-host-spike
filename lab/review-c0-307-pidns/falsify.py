#!/usr/bin/env python3
"""Lying-ABI falsifier for this review.

Shows that unpatched #307 at 637345ac launches a provider on a kernel
that reports ABI 5 but accepts only ABI 1 filesystem bits, and that
proposal.patch refuses that same kernel with a named EINVAL reason.

The plant is applied to a copy under /tmp. lab/fail-closed-linux is not
edited. PR #307 is not updated.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
FCL = Path(
    os.environ.get("FCL_SRC", "/tmp/fcl-637345ac/lab/fail-closed-linux")
)
PATCH = REVIEW / "proposal.patch"
TIMEOUT = 180

LYING_TEST = """
#[test]
fn sim_current_launches_when_abi_number_is_5() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(5);
        let started = launch(&mut kernel, &spec(provider)).expect("current code trusts ABI 5");
        assert_eq!(started.pid, SIM_PID);
        assert_eq!(kernel.execs.len(), 1, "{provider} {:?}", kernel.execs);
    }
}
"""


def run(cmd, cwd, env):
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=TIMEOUT,
    )


def writable_copy() -> Path:
    work = Path(tempfile.mkdtemp(prefix="rv-lying-"))
    crate = work / "crate"
    shutil.copytree(FCL, crate, ignore=shutil.ignore_patterns("target", "__pycache__"))
    for path in crate.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | 0o200)
        elif path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
    return work


def cargo_env(work: Path) -> dict:
    return dict(
        os.environ,
        CARGO_TARGET_DIR=str(work / "target"),
        CARGO_BUILD_BUILD_DIR=str(work / "build"),
        RUST_TEST_THREADS="2",
        CARGO_INCREMENTAL="0",
        RUSTUP_TOOLCHAIN=os.environ.get("RUSTUP_TOOLCHAIN", "1.91.0"),
    )


def add_current_test(crate: Path) -> None:
    path = crate / "tests/simulated.rs"
    path.write_text(path.read_text() + LYING_TEST)


def main() -> int:
    if not (FCL / "src/lib.rs").is_file():
        print("F-LYING NOT RUN  FCL_SRC missing")
        return 2
    if not PATCH.is_file():
        print("F-LYING NOT RUN  proposal.patch missing")
        return 2

    # --- current tree: reported ABI 5 launches ---
    current = writable_copy()
    add_current_test(current / "crate")
    env = cargo_env(current)
    ran = run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "simulated",
            "--",
            "--exact",
            "sim_current_launches_when_abi_number_is_5",
        ],
        current / "crate",
        env,
    )
    current_ok = (
        ran.returncode == 0
        and "test sim_current_launches_when_abi_number_is_5 ... ok" in ran.stdout
    )
    (REVIEW / "evidence" / "lying-current.txt").write_text(ran.stdout + ran.stderr)
    print(
        "F-LYING-CURRENT  "
        + (
            "CAUGHT  current code launched on reported ABI 5"
            if current_ok
            else f"ERROR  exit {ran.returncode}\n{ran.stdout}\n{ran.stderr}"
        )
    )
    shutil.rmtree(current, ignore_errors=True)
    if not current_ok:
        return 1

    # --- patched tree: same liar refuses ---
    patched = writable_copy()
    apply = run(
        ["patch", "-p1", "--forward", "--input", str(PATCH)],
        patched / "crate",
        os.environ.copy(),
    )
    (REVIEW / "evidence" / "lying-patch-apply.txt").write_text(apply.stdout + apply.stderr)
    if apply.returncode != 0:
        print(f"F-LYING-PATCHED ERROR  patch failed\n{apply.stdout}\n{apply.stderr}")
        shutil.rmtree(patched, ignore_errors=True)
        return 1
    env = cargo_env(patched)
    ran = run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "simulated",
            "--",
            "--exact",
            "sim_lying_abi_5_with_abi_1_rights_refuses",
        ],
        patched / "crate",
        env,
    )
    patched_ok = (
        ran.returncode == 0
        and "test sim_lying_abi_5_with_abi_1_rights_refuses ... ok" in ran.stdout
    )
    (REVIEW / "evidence" / "lying-patched.txt").write_text(ran.stdout + ran.stderr)
    print(
        "F-LYING-PATCHED  "
        + (
            "CAUGHT  patched code refused the lying ABI 5 kernel"
            if patched_ok
            else f"ERROR  exit {ran.returncode}\n{ran.stdout}\n{ran.stderr}"
        )
    )

    # --- drop the probe on the patched copy: the new test must fail ---
    lib = patched / "crate" / "src/lib.rs"
    text = lib.read_text()
    old = """    let mut probed = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        match kernel.landlock_can_handle_fs(right.access) {
            Ok(true) => {}
            Ok(false) => probed |= right.mask,
            Err(errno) => return Err(Fault::os(Step::RightProbe, errno)),
        }
    }
    if probed != 0 {
        return Err(Fault::right_probe(abi, probed));
    }
"""
    if text.count(old) != 1:
        print(f"F-LYING-DROP ERROR  probe block count {text.count(old)}")
        shutil.rmtree(patched, ignore_errors=True)
        return 1
    lib.write_text(text.replace(old, "    let _ = FILE_PROFILE_NEEDED_RIGHTS;\n", 1))
    ran = run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "simulated",
            "--",
            "--exact",
            "sim_lying_abi_5_with_abi_1_rights_refuses",
        ],
        patched / "crate",
        env,
    )
    dropped = (
        ran.returncode != 0
        and "test sim_lying_abi_5_with_abi_1_rights_refuses ... FAILED" in ran.stdout
    )
    (REVIEW / "evidence" / "lying-drop-probe.txt").write_text(ran.stdout + ran.stderr)
    print(
        "F-LYING-DROP     "
        + (
            "CAUGHT  removing the probe makes the liar launch again"
            if dropped
            else f"ERROR  exit {ran.returncode}\n{ran.stdout}\n{ran.stderr}"
        )
    )
    shutil.rmtree(patched, ignore_errors=True)

    ok = current_ok and patched_ok and dropped
    print(
        f"lying-abi falsifiers: {int(current_ok)+int(patched_ok)+int(dropped)}/3 caught"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
