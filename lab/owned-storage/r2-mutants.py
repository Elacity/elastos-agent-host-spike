#!/usr/bin/env python3
"""Replay the r2/r3 mutants against this crate. Every mutant must be caught."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

LIB_MUTANTS = [
    {
        "id": "M-root-swap",
        "old": "fn refuse_swapped_root() -> bool {\n    true\n}",
        "new": "fn refuse_swapped_root() -> bool {\n    false\n}",
        "tests": ["tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink"],
    },
    {
        "id": "M-hardlink-nlink",
        "old": "fn refuse_hard_link(meta: &fs::Metadata) -> Result<(), Refuse> {\n    if meta.is_file() && meta.nlink() > 1 {\n        return Err(Refuse::HardLink);\n    }\n    Ok(())\n}",
        "new": "fn refuse_hard_link(_meta: &fs::Metadata) -> Result<(), Refuse> {\n    Ok(())\n}",
        "tests": ["tests::agent_b_is_denied_a_hard_linked_inode"],
    },
    {
        "id": "M-list-no-resolve",
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
        "old": '    let name = format!("UsersAI/{agent}/{rest}");',
        "new": '    let name = format!("Users/{agent}/{rest}");',
        "tests": ["tests::owned_root_uses_a5_usersai_agent_rest_shape"],
    },
    {
        "id": "M-inode-noop",
        "old": """fn require_owned(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    refuse_hard_link(meta)?;
    require_in_agent_record(agent_root, meta)
}""",
        "new": """fn require_owned(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    refuse_hard_link(meta)?;
    let _ = (agent_root, meta);
    Ok(())
}""",
        "tests": ["tests::agent_b_is_denied_a_hard_linked_inode"],
    },
    {
        "id": "M-unowned-allow",
        "old": "fn require_positive_ownership() -> bool {\n    true\n}",
        "new": "fn require_positive_ownership() -> bool {\n    false\n}",
        "tests": ["tests::host_rename_into_b_is_refused"],
    },
]

WALK_MUTANTS = [
    {
        "id": "M-no-nofollow",
        "old": "pub(crate) fn nofollow_flag() -> OFlags {\n    OFlags::NOFOLLOW\n}",
        "new": "pub(crate) fn nofollow_flag() -> OFlags {\n    OFlags::empty()\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-no-symlinks",
        "old": """    let mut flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);""",
        "new": """    let mut flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_MAGICLINKS);""",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-force-openat",
        "old": "pub(crate) fn openat2_first() -> bool {\n    true\n}",
        "new": "pub(crate) fn openat2_first() -> bool {\n    false\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-no-xdev",
        "old": "pub(crate) fn resolve_no_xdev() -> bool {\n    true\n}",
        "new": "pub(crate) fn resolve_no_xdev() -> bool {\n    false\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
]

LAUNCH_MUTANTS = [
    {
        "id": "M-share-count-zero",
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
        "old": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Blocked\n}",
        "new": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Ready\n}",
        "tests": ["launch::tests::real_runtime_rows_match_the_launcher"],
    },
]


def cargo_test(test: str) -> tuple[int, str]:
    cmd = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        str(HERE / "Cargo.toml"),
        "--lib",
        test,
        "--",
        "--exact",
        "--test-threads=2",
    ]
    env = os.environ.copy()
    env["OWNED_STORAGE_PLANT_CHILD"] = "1"
    env["RUST_TEST_THREADS"] = "2"
    proc = subprocess.run(
        cmd,
        cwd=HERE,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, proc.stdout


def apply_one(target: Path, old: str, new: str) -> None:
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{target} has {count} copies of mutant old text, want 1:\n{old}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    lib = HERE / "src" / "lib.rs"
    walk = HERE / "src" / "walk.rs"
    launch = HERE / "src" / "launch.rs"
    rows = []
    failed = 0

    def run(mid: str, target: Path, old: str, new: str, tests: list[str]) -> None:
        nonlocal failed
        original = target.read_text(encoding="utf-8")
        apply_one(target, old, new)
        try:
            for test in tests:
                code, out = cargo_test(test)
                caught = code != 0
                rows.append((mid, test, code, caught))
                print(f"{mid} / {test}: exit={code} caught={caught}", flush=True)
                if not caught:
                    print(out[-2000:], flush=True)
                    failed += 1
        finally:
            target.write_text(original, encoding="utf-8")

    for mutant in LIB_MUTANTS:
        run(mutant["id"], lib, mutant["old"], mutant["new"], mutant["tests"])
    for mutant in WALK_MUTANTS:
        run(mutant["id"], walk, mutant["old"], mutant["new"], mutant["tests"])
    for mutant in LAUNCH_MUTANTS:
        run(mutant["id"], launch, mutant["old"], mutant["new"], mutant["tests"])

    print(f"mutants={len(rows)} caught={sum(1 for r in rows if r[3])} surviving={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
