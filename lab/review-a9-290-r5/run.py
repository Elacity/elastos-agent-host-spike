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

REVIEWED_SHA = "78bc82bfb38047f9b8c367213bd06604e85a98cd"
REVIEWED_BRANCH = "cursor/owned-storage-a9-9b7c"
DEFAULT_WORKTREE = Path("/tmp/pr-290-r5")
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
    worktree = Path(os.environ.get("REVIEW_A9_290_R5_WORKTREE", DEFAULT_WORKTREE))
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
            "--",
            "--nocapture",
        ],
        cwd=crate,
        env=env,
    )
    print(tests.stdout[-8000:], flush=True)
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
                'name = "review-a9-290-r5-probe"',
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
    probe_env = dict(env)
    probe_env["OWNED_STORAGE_LIB_RS"] = str(lib)
    probe = run(["cargo", "run", "--offline", "--quiet"], cwd=scratch, env=probe_env)
    print(probe.stdout, flush=True)
    if probe.returncode != 0:
        print(probe.stdout[-8000:] if probe.stdout else "", flush=True)
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
    test_names = [
        line.strip()
        for line in listed.stdout.splitlines()
        if line.strip().endswith(": test")
    ]
    record = {
        "reviewed_sha": REVIEWED_SHA,
        "worktree_head": head,
        "fmt_exit": fmt.returncode,
        "test_exit": tests.returncode,
        "clippy_exit": clippy.returncode,
        "probe_exit": probe.returncode,
        "test_list_count": len(test_names),
        "test_names": test_names,
        "test_list_tail": listed.stdout.splitlines()[-12:],
        "test_summary": [
            line
            for line in tests.stdout.splitlines()
            if "test result:" in line
            or "bind-mount" in line
            or "race two-store" in line
            or "inode-reuse" in line
            or "NOT RUN" in line
        ],
        "sha_before": before,
        "sha_after": after,
        "worktree_dirty": dirty,
        "shared_temp_before": shared_before,
        "shared_temp_after": SHARED_TEMP.exists(),
        "probe_findings": [
            line for line in probe.stdout.splitlines() if line.startswith("FINDING\t")
        ],
    }
    (HERE / "last-run.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: record[k]
                for k in (
                    "fmt_exit",
                    "test_exit",
                    "clippy_exit",
                    "probe_exit",
                    "test_list_count",
                    "shared_temp_after",
                    "worktree_dirty",
                )
            },
            indent=2,
        )
    )
    if before != after or dirty.strip() or SHARED_TEMP.exists():
        return 2
    return (
        0
        if fmt.returncode == 0
        and tests.returncode == 0
        and clippy.returncode == 0
        and probe.returncode == 0
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
