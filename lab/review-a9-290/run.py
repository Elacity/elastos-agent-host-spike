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

REVIEWED_SHA = "c0b16491076c30366a3504066499c9f5ad831ef2"
REVIEWED_BRANCH = "cursor/owned-storage-a9-9b7c"
DEFAULT_WORKTREE = Path("/tmp/pr-290-readonly")
SHARED_TEMP = Path("/tmp/elastos/storage")

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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
        head = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        if head != REVIEWED_SHA:
            sys.exit(f"worktree {path} is {head}, want {REVIEWED_SHA}")
        return path
    subprocess.check_call(
        ["git", "-C", str(REPO), "fetch", "origin", REVIEWED_BRANCH],
    )
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
    worktree = Path(os.environ.get("REVIEW_A9_290_WORKTREE", DEFAULT_WORKTREE))
    worktree = ensure_worktree(worktree)
    crate = worktree / "lab" / "owned-storage"
    lib = crate / "src" / "lib.rs"
    launch = crate / "src" / "launch.rs"
    before = {"lib.rs": sha256(lib), "launch.rs": sha256(launch)}
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
    print(fmt.stdout)
    tests = run(
        ["cargo", "test", "--locked", "--offline", "--manifest-path", str(crate / "Cargo.toml")],
        cwd=crate,
        env=env,
    )
    print(tests.stdout)
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
    print(listed.stdout)

    after = {"lib.rs": sha256(lib), "launch.rs": sha256(launch)}
    dirty = subprocess.check_output(["git", "-C", str(worktree), "status", "--short"], text=True)
    shared_after = SHARED_TEMP.exists()

    scratch = Path("/tmp/review-a9-290-crate")
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    (scratch / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "review-a9-290-probe"',
                'version = "0.0.0"',
                'edition = "2021"',
                "publish = false",
                "",
                "[workspace]",
                "",
                "[dependencies]",
                f'owned-storage = {{ path = "{crate}" }}',
                "",
                "[[bin]]",
                'name = "probe"',
                f'path = "{HERE / "probe.rs"}"',
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    probe = run(
        ["cargo", "run", "--offline", "--manifest-path", str(scratch / "Cargo.toml"), "--bin", "probe"],
        cwd=scratch,
        env=env,
    )
    print(probe.stdout)

    findings = []
    for line in probe.stdout.splitlines():
        if line.startswith("FINDING\t"):
            parts = line.split("\t", 4)
            if len(parts) == 5:
                findings.append(
                    {
                        "id": parts[1],
                        "verdict": parts[2],
                        "title": parts[3],
                        "detail": parts[4],
                    }
                )

    ignored = [
        line.strip()
        for line in listed.stdout.splitlines()
        if "ignored" in line.lower() and "test" in line.lower()
    ]

    result = {
        "reviewed_sha": REVIEWED_SHA,
        "worktree": str(worktree),
        "shared_temp_before": shared_before,
        "shared_temp_after": shared_after,
        "hashes_before": before,
        "hashes_after": after,
        "worktree_dirty": dirty,
        "fmt_exit": fmt.returncode,
        "test_exit": tests.returncode,
        "probe_exit": probe.returncode,
        "ignored_list_lines": ignored,
        "findings": findings,
    }
    out = HERE / "last-run.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}", flush=True)

    if fmt.returncode != 0 or tests.returncode != 0 or probe.returncode != 0:
        return 1
    if before != after:
        print("ERROR: #290 sources changed", file=sys.stderr)
        return 1
    if dirty.strip():
        print("ERROR: #290 worktree dirty after plants", file=sys.stderr)
        return 1
    if shared_before != shared_after:
        print("ERROR: /tmp/elastos/storage existence changed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
