#!/usr/bin/env python3
"""Re-plant F36 and F37 on copies. The #307 worktree stays clean."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FCL_SRC = Path(os.environ.get("FCL_SRC", "/tmp/wt-307-r5/candidate/lab/fail-closed-linux"))
WORK = Path(os.environ.get("FCL_REPLANT", "/tmp/review-307-r5-replant"))
EVIDENCE = HERE / "evidence"
NOT_COPIED = {"target", "__pycache__", ".git"}

PLANTS = {
    "F36-memfd-execveat": {
        "file": "src/lib.rs",
        "harness": "real_kernel",
        "names": ["real_memfd_second_image_is_refused"],
        "old": (
            "    kernel\n"
            "        .install_no_exec_filter(plan)\n"
            "        .map_err(|errno| Fault::os(Step::InstallNoExec, errno))?;\n"
        ),
        "new": "    let _ = (plan, Step::InstallNoExec);\n",
    },
    "F37-stdio-pty": {
        "file": "src/lib.rs",
        "harness": "real_kernel",
        "names": ["real_stdin_pty_is_not_a_terminal"],
        "old": (
            "    kernel.sanitize_stdio().map_err(|errno| Fault {\n"
            "        step: Step::SanitizeStdio,\n"
            "        errno,\n"
            "        found: kernel.named_fault_found(),\n"
            "    })?;\n"
        ),
        "new": "    let _ = Step::SanitizeStdio;\n",
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
    count = text.count(plant["old"])
    if count != 1:
        raise SystemExit(f"{path}: plant old-text count is {count}")
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
        jobs = [(plant["harness"], n) for n in plant["names"]]
        for harness, test_name in jobs:
            run = run_tests(crate, harness, test_name)
            failed = run.returncode != 0 and "FAILED" in (run.stdout + run.stderr)
            caught = failed
            all_caught = all_caught and caught
            lines.append(f"==== {name} {harness}::{test_name} ====")
            lines.append(f"exit={run.returncode} caught={caught}")
            lines.append(run.stdout[-2500:])
            lines.append(run.stderr[-1500:])
        shutil.rmtree(crate.parent, ignore_errors=True)
    lines.append(f"ALL_CAUGHT={all_caught}")
    out = EVIDENCE / "replant.txt"
    out.write_text("\n".join(lines) + "\n")
    print(out.read_text())
    return 0 if all_caught else 1


if __name__ == "__main__":
    raise SystemExit(main())
