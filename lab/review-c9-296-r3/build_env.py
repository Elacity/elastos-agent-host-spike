#!/usr/bin/env python3
"""Try cargo check --target aarch64 under compiler env combinations.

A foreign TARGET must not silently compile the C helpers with host cc.
This script does not edit lab/linux-confine/.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296-r3")


def tree() -> pathlib.Path:
    env = os.environ.get("LC_REVIEW_TREE")
    if env:
        return pathlib.Path(env)
    if DEFAULT_TREE.is_dir():
        return DEFAULT_TREE
    raise SystemExit("set LC_REVIEW_TREE to the fetched #296 worktree")


def check(root: pathlib.Path, extra: dict[str, str], name: str) -> None:
    env = os.environ.copy()
    # Drop any inherited cross-cc hints so each case is explicit.
    for key in list(env):
        if key.startswith("CC_") or key in {"CC", "TARGET_CC", "HOST", "TARGET"}:
            env.pop(key, None)
    env.update(extra)
    proc = subprocess.run(
        [
            "cargo",
            "check",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--target",
            "aarch64-unknown-linux-gnu",
            "--all-targets",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=env,
    )
    out = HERE / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"build-{name}.txt").write_text(proc.stdout)
    text = proc.stdout
    host_used = "Host cc is not used" in text or "host cc is not used" in text.lower()
    cannot = "cannot run" in text or "no C compiler" in text
    finished = "Finished `dev` profile" in text
    print(f"## {name}")
    print(f"env {extra or '(cleared CC/TARGET_CC)'}")
    print(f"exit {proc.returncode}")
    print(f"finished {finished}")
    print(f"mentions_host_cc_not_used {host_used}")
    print(f"mentions_cannot_run {cannot}")
    for line in text.splitlines():
        low = line.lower()
        if any(
            key in low
            for key in (
                "linux-confine",
                "cannot run",
                "host cc",
                "aarch64-linux-gnu-gcc",
                "error: failed",
                "finished",
            )
        ):
            print(f"  {line}")
    print()


def main() -> int:
    root = tree()
    print(f"host cc {shutil.which('cc')}")
    print(f"aarch64-linux-gnu-gcc {shutil.which('aarch64-linux-gnu-gcc') or 'absent'}")
    print()
    check(root, {}, "default")
    check(root, {"CC": "cc"}, "CC-cc")
    check(root, {"TARGET_CC": "cc"}, "TARGET_CC-cc")
    check(root, {"CC_aarch64_unknown_linux_gnu": "cc"}, "CC_target-cc")
    check(root, {"CC_aarch64_unknown_linux_gnu": "", "TARGET_CC": ""}, "empty-cross-cc")
    return 0


if __name__ == "__main__":
    sys.exit(main())
