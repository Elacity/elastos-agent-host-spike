#!/usr/bin/env python3
"""Re-plant F33, F34 and F35 on copies. The #307 worktree stays clean."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FCL_SRC = Path(os.environ.get("FCL_SRC", "/tmp/review-c0-307-r4-src/lab/fail-closed-linux"))
WORK = Path(os.environ.get("FCL_REPLANT", "/tmp/review-c0-307-r4-replant"))
EVIDENCE = HERE / "evidence"
NOT_COPIED = {"target", "__pycache__", ".git"}

PLANTS = {
    "F33-inherited-fds-left-open": {
        "file": "src/lib.rs",
        "harness": "real_kernel",
        "names": ["real_inherited_pty_ioctl_is_not_available"],
        "old": "    kernel.close_unneeded_fds().map_err(os(Step::CloseFds))?;\n",
        "new": "    let _ = Step::CloseFds;\n",
    },
    "F34-enforcement-self-test-skipped": {
        "file": "src/lib.rs",
        "jobs": [
            ("simulated", "sim_lying_kernel_enforcement_refuses"),
            ("real_kernel", "real_lying_enforcement_self_test_refuses"),
        ],
        "old": (
            "    kernel\n"
            "        .enforcement_self_test(plan)\n"
            "        .map_err(|errno| Fault::os(Step::EnforceSelf, errno))?;\n"
        ),
        "new": "    let _ = (plan, Step::EnforceSelf);\n",
    },
    "F35-close-pipe-reported-as-start": {
        "file": "src/real.rs",
        "harness": "real_kernel",
        "names": ["real_close_pipe_without_exec_is_not_a_start"],
        "old": (
            "                if !matched {\n"
            "                    unsafe { libc::kill(init as libc::pid_t, libc::SIGKILL) };\n"
            "                    reap(init as libc::pid_t);\n"
            "                    unsafe { libc::close(ack_write) };\n"
            "                    reap_if_exited(helper, 1);\n"
            "                    return Err(Fault::exec_identity());\n"
            "                }\n"
        ),
        "new": "                let _ = matched;\n",
    },
}


def copy_crate(dest: Path):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for item in FCL_SRC.iterdir():
        if item.name in NOT_COPIED:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=shutil.ignore_patterns(*NOT_COPIED))
        else:
            shutil.copy2(item, target)


def apply_plant(crate: Path, plant: dict):
    path = crate / plant["file"]
    text = path.read_text()
    if text.count(plant["old"]) != 1:
        raise SystemExit(f"{path}: plant old-text count is {text.count(plant['old'])}")
    path.write_text(text.replace(plant["old"], plant["new"], 1))


def run_tests(crate: Path, harness: str, name: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(crate / "target")
    env["CARGO_BUILD_BUILD_DIR"] = str(crate / "target" / "build")
    env["RUST_TEST_THREADS"] = "2"
    env["CARGO_INCREMENTAL"] = "0"
    return subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            harness,
            "--",
            "--exact",
            name,
            "--test-threads=2",
        ],
        cwd=crate,
        env=env,
        capture_output=True,
        text=True,
    )


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    lines = [
        f"source={FCL_SRC}",
        f"head={subprocess.check_output(['git', '-C', str(FCL_SRC), 'rev-parse', 'HEAD'], text=True).strip()}",
    ]
    all_caught = True
    for name, plant in PLANTS.items():
        crate = WORK / name / "crate"
        copy_crate(crate)
        apply_plant(crate, plant)
        # cargo test accepts one --test harness; run each named harness separately
        if "jobs" in plant:
            jobs = plant["jobs"]
        else:
            jobs = [(plant["harness"], n) for n in plant["names"]]
        for harness, test_name in jobs:
            run = run_tests(crate, harness, test_name)
            failed = run.returncode != 0 and "FAILED" in (run.stdout + run.stderr)
            caught = failed
            all_caught = all_caught and caught
            lines.append(f"==== {name} {harness}::{test_name} ====")
            lines.append(f"exit={run.returncode} caught={caught}")
            lines.append(run.stdout[-2000:])
            lines.append(run.stderr[-1500:])
        shutil.rmtree(crate.parent, ignore_errors=True)
    lines.append(f"ALL_CAUGHT={all_caught}")
    out = EVIDENCE / "replant.txt"
    out.write_text("\n".join(lines) + "\n")
    print(out.read_text())
    return 0 if all_caught else 1


if __name__ == "__main__":
    raise SystemExit(main())
