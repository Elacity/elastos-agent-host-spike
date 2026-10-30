#!/usr/bin/env python3
"""Revert each claimed #290 fix and extra guards. Restore #290 bytes after every run."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REVIEWED_SHA = "2e5c37293279996fcb98ee2623381264f2d92e3f"
DEFAULT_WORKTREE = Path("/tmp/pr-290-r2")
HERE = Path(__file__).resolve().parent

LIB_MUTANTS = [
    {
        "id": "M-root-swap",
        "claim": "1 Root swapped for a symlink",
        "old": "fn refuse_swapped_root() -> bool {\n    true\n}",
        "new": "fn refuse_swapped_root() -> bool {\n    false\n}",
        "tests": ["tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink"],
    },
    {
        "id": "M-hardlink-nlink",
        "claim": "2 Hard-linked inode",
        "old": "fn refuse_hard_link(meta: &fs::Metadata) -> Result<(), Refuse> {\n    if meta.is_file() && meta.nlink() > 1 {\n        return Err(Refuse::HardLink);\n    }\n    Ok(())\n}",
        "new": "fn refuse_hard_link(_meta: &fs::Metadata) -> Result<(), Refuse> {\n    Ok(())\n}",
        "tests": ["tests::agent_b_is_denied_a_hard_linked_inode"],
    },
    {
        "id": "M-list-no-resolve",
        "claim": "3 Store list and rename",
        "old": """        let dir = if path.is_empty() {
            root.clone()
        } else {
            self.resolve(grant, path)?
        };""",
        "new": """        let dir = if path.is_empty() {
            root.clone()
        } else if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            root.join(path)
        };""",
        "tests": ["tests::agent_a_is_denied_b_list_and_rename"],
    },
    {
        "id": "M-a5-users",
        "claim": "6 A5 UsersAI/<agent>/<rest>",
        "old": '    let name = format!("UsersAI/{agent}/{rest}");',
        "new": '    let name = format!("Users/{agent}/{rest}");',
        "tests": ["tests::owned_root_uses_a5_usersai_agent_rest_shape"],
    },
    {
        "id": "M-inode-noop",
        "claim": "inode_in_owner_tree extra guard",
        "old": """fn inode_in_owner_tree(root: &Path, path: &Path) -> Result<(), Refuse> {
    let meta = fs::symlink_metadata(path).map_err(|_| Refuse::NotFound)?;
    let owned = tree_inodes(root)?;
    if !owned.contains(&(meta.dev(), meta.ino())) {
        return Err(Refuse::HardLink);
    }
    Ok(())
}""",
        "new": """fn inode_in_owner_tree(_root: &Path, _path: &Path) -> Result<(), Refuse> {
    Ok(())
}""",
        "tests": ["tests::agent_b_is_denied_a_hard_linked_inode"],
    },
    {
        "id": "M-no-nofollow",
        "claim": "O_NOFOLLOW last-component flag",
        "old": "    opts.custom_flags(O_NOFOLLOW);\n    opts.open(path).map_err(|error| map_open_error(path, error))",
        "new": "    opts.open(path).map_err(|error| map_open_error(path, error))",
        "tests": ["--all"],
    },
]

LAUNCH_MUTANTS = [
    {
        "id": "M-share-count-zero",
        "claim": "4 Fourth /tmp site counted",
        "old": """        assert_eq!(
            share_count, 1,
            "share_cmd.rs:183 must stay a fourth shared-temp site"
        );""",
        "new": """        let share_count = 0;
        assert_eq!(
            share_count, 1,
            "share_cmd.rs:183 must stay a fourth shared-temp site"
        );""",
        "tests": ["launch::tests::real_runtime_rows_match_the_launcher"],
    },
    {
        "id": "M-fake-runtime-read",
        "claim": "5 Split lab / Runtime grades",
        "old": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Blocked\n}",
        "new": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Ready\n}",
        "tests": ["launch::tests::real_runtime_rows_match_the_launcher"],
    },
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cargo_test(crate: Path, test: str, env: dict[str, str]) -> tuple[int, str]:
    cmd = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        str(crate / "Cargo.toml"),
        "--lib",
    ]
    if test != "--all":
        cmd.append(test)
        cmd.extend(["--", "--exact"])
    else:
        cmd.extend(["--", "--test-threads=2"])
    merged = os.environ.copy()
    merged.update(env)
    merged["OWNED_STORAGE_PLANT_CHILD"] = "1"
    proc = subprocess.run(
        cmd,
        cwd=crate,
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, proc.stdout + (proc.stderr or "")


def apply_one(target: Path, old: str, new: str) -> None:
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{target} has {count} copies of old text, want 1")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    worktree = Path(os.environ.get("REVIEW_A9_290_R2_WORKTREE", DEFAULT_WORKTREE))
    head = subprocess.check_output(
        ["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != REVIEWED_SHA:
        sys.exit(f"worktree {worktree} is {head}, want {REVIEWED_SHA}")
    crate = worktree / "lab" / "owned-storage"
    lib = crate / "src" / "lib.rs"
    launch = crate / "src" / "launch.rs"
    before = {"lib.rs": sha256(lib), "launch.rs": sha256(launch)}
    env = {"RUST_TEST_THREADS": "2", "CARGO_INCREMENTAL": "0"}
    rows = []

    def run_mutant(mid: str, claim: str, target: Path, old: str, new: str, tests: list[str]) -> None:
        original = target.read_text(encoding="utf-8")
        apply_one(target, old, new)
        try:
            if tests == ["--all"]:
                code, out = cargo_test(crate, "--all", env)
                failed = [
                    line.strip()
                    for line in out.splitlines()
                    if line.startswith("test ") and line.strip().endswith("FAILED")
                ]
                passed = code == 0
                rows.append(
                    {
                        "id": mid,
                        "claim": claim,
                        "tests": ["all 14"],
                        "exit": code,
                        "caught": not passed,
                        "failed_lines": failed,
                        "excerpt": [
                            line
                            for line in out.splitlines()
                            if any(
                                token in line
                                for token in (
                                    "FAILED",
                                    "ok. ",
                                    "assertion",
                                    "left:",
                                    "right:",
                                    "ready without",
                                    "must stay",
                                )
                            )
                        ][-20:],
                    }
                )
                print(f"{mid}: all-tests exit={code} caught={not passed}", flush=True)
                return
            for test in tests:
                code, out = cargo_test(crate, test, env)
                failed_line = any(
                    line.startswith("test ") and test.split("::")[-1] in line and line.endswith("FAILED")
                    for line in (ln.strip() for ln in out.splitlines())
                )
                rows.append(
                    {
                        "id": mid,
                        "claim": claim,
                        "test": test,
                        "exit": code,
                        "caught": failed_line or code != 0,
                        "excerpt": [
                            line
                            for line in out.splitlines()
                            if any(
                                token in line
                                for token in (
                                    "FAILED",
                                    "ok",
                                    "assertion",
                                    "left:",
                                    "right:",
                                    "ready without",
                                    "must stay",
                                    "panic",
                                )
                            )
                        ][-30:],
                    }
                )
                print(f"{mid} / {test}: exit={code} caught={failed_line or code != 0}", flush=True)
        finally:
            target.write_text(original, encoding="utf-8")

    for mutant in LIB_MUTANTS:
        run_mutant(mutant["id"], mutant["claim"], lib, mutant["old"], mutant["new"], mutant["tests"])
    for mutant in LAUNCH_MUTANTS:
        run_mutant(
            mutant["id"], mutant["claim"], launch, mutant["old"], mutant["new"], mutant["tests"]
        )

    after = {"lib.rs": sha256(lib), "launch.rs": sha256(launch)}
    dirty = subprocess.check_output(["git", "-C", str(worktree), "status", "--short"], text=True)
    surviving = [row for row in rows if not row["caught"]]
    result = {
        "reviewed_sha": REVIEWED_SHA,
        "hashes_before": before,
        "hashes_after": after,
        "worktree_dirty": dirty,
        "rows": rows,
        "surviving": surviving,
    }
    out = HERE / "mutants-run.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}", flush=True)
    print(f"surviving={len(surviving)}", flush=True)
    if before != after or dirty.strip():
        print("ERROR: #290 sources not restored", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
