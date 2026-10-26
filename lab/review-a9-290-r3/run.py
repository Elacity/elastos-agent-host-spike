#!/usr/bin/env python3
"""Run #290's tests and this folder's probe. Write nothing into #290."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REVIEWED_SHA = "8d4d50104edcfd1eee03e4cd93816e7ed62b6088"
TESTED_CODE_SHA = "578e0959a374af726bbc8f113afdbb5e7723636d"
REVIEWED_BRANCH = "cursor/owned-storage-a9-9b7c"
DEFAULT_WORKTREE = Path("/tmp/pr-290-r3")
SHARED_TEMP = Path("/tmp/elastos/storage")

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run(
    cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_worktree(path: Path) -> Path:
    if path.exists():
        head = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
        if head != REVIEWED_SHA:
            sys.exit(f"worktree {path} is {head}, want {REVIEWED_SHA}")
        return path
    subprocess.check_call(["git", "-C", str(REPO), "fetch", "origin", REVIEWED_BRANCH])
    subprocess.check_call(
        [
            "git",
            "-C",
            str(REPO),
            "worktree",
            "add",
            "--detach",
            str(path),
            REVIEWED_SHA,
        ]
    )
    return path


def main() -> int:
    worktree = Path(os.environ.get("REVIEW_A9_290_R3_WORKTREE", DEFAULT_WORKTREE))
    worktree = ensure_worktree(worktree)
    crate = worktree / "lab" / "owned-storage"
    lib = crate / "src" / "lib.rs"
    walk = crate / "src" / "walk.rs"
    launch = crate / "src" / "launch.rs"
    before = {
        "lib.rs": sha256(lib),
        "walk.rs": sha256(walk),
        "launch.rs": sha256(launch),
    }
    shared_before = SHARED_TEMP.exists()

    env = {
        "RUST_TEST_THREADS": "2",
        "CARGO_INCREMENTAL": "0",
    }

    fmt = run(
        ["cargo", "fmt", "--manifest-path", str(crate / "Cargo.toml"), "--", "--check"],
        cwd=crate,
        env=env,
    )
    print(fmt.stdout[-2000:], flush=True)
    listed = run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "--manifest-path",
            str(crate / "Cargo.toml"),
            "--",
            "--list",
        ],
        cwd=crate,
        env=env,
    )
    tests = run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "--manifest-path",
            str(crate / "Cargo.toml"),
        ],
        cwd=crate,
        env=env,
    )
    print(tests.stdout[-4000:], flush=True)
    clippy = run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            str(crate / "Cargo.toml"),
            "--locked",
            "--offline",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        cwd=crate,
        env=env,
    )
    print(clippy.stdout[-2000:], flush=True)

    scratch = HERE / "scratch"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    (scratch / "src").mkdir()
    shutil.copy2(HERE / "probe.rs", scratch / "src" / "main.rs")
    (scratch / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "review-a9-290-r3-probe"',
                'version = "0.0.0"',
                'edition = "2021"',
                "publish = false",
                "",
                "[dependencies]",
                f'owned-storage = {{ path = "{crate}" }}',
                'rustix = { version = "1.1.4", default-features = false, features = ["fs", "std"] }',
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    probe = run(["cargo", "run", "--offline", "--quiet"], cwd=scratch, env=env)
    print(probe.stdout, flush=True)
    if probe.returncode != 0:
        print(probe.stdout[-4000:] if probe.stdout else "", flush=True)
        print("probe failed", flush=True)

    after = {
        "lib.rs": sha256(lib),
        "walk.rs": sha256(walk),
        "launch.rs": sha256(launch),
    }
    head = subprocess.check_output(
        ["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(worktree), "status", "--short"], text=True
    )
    record = {
        "reviewed_sha": REVIEWED_SHA,
        "tested_code_sha": TESTED_CODE_SHA,
        "worktree_head": head,
        "fmt_exit": fmt.returncode,
        "test_exit": tests.returncode,
        "clippy_exit": clippy.returncode,
        "probe_exit": probe.returncode,
        "test_list_tail": listed.stdout.splitlines()[-8:],
        "sha_before": before,
        "sha_after": after,
        "worktree_dirty": dirty,
        "shared_temp_before": shared_before,
        "shared_temp_after": SHARED_TEMP.exists(),
        "probe_findings": [
            line for line in probe.stdout.splitlines() if line.startswith("FINDING\t")
        ],
    }
    (HERE / "last-run.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("fmt_exit", "test_exit", "clippy_exit", "probe_exit", "shared_temp_after", "worktree_dirty")}, indent=2))
    if before != after or dirty.strip() or SHARED_TEMP.exists():
        return 2
    return 0 if fmt.returncode == 0 and tests.returncode == 0 and clippy.returncode == 0 and probe.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
