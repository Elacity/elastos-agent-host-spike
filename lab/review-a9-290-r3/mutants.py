#!/usr/bin/env python3
"""Replay #290's eight r2 mutants, then two extra walk mutants. Restore bytes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = Path(os.environ.get("REVIEW_A9_290_R3_WORKTREE", "/tmp/pr-290-r3"))
CRATE = WORKTREE / "lab" / "owned-storage"

# Same old/new strings as lab/owned-storage/r2-mutants.py on 8d4d5010.
LIB_MUTANTS = [
    {
        "id": "M-root-swap",
        "file": "src/lib.rs",
        "old": "fn refuse_swapped_root() -> bool {\n    true\n}",
        "new": "fn refuse_swapped_root() -> bool {\n    false\n}",
        "tests": ["tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink"],
    },
    {
        "id": "M-hardlink-nlink",
        "file": "src/lib.rs",
        "old": "fn refuse_hard_link(meta: &fs::Metadata) -> Result<(), Refuse> {\n    if meta.is_file() && meta.nlink() > 1 {\n        return Err(Refuse::HardLink);\n    }\n    Ok(())\n}",
        "new": "fn refuse_hard_link(_meta: &fs::Metadata) -> Result<(), Refuse> {\n    Ok(())\n}",
        "tests": ["tests::agent_b_is_denied_a_hard_linked_inode"],
    },
    {
        "id": "M-list-no-resolve",
        "file": "src/lib.rs",
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
        "file": "src/lib.rs",
        "old": '    let name = format!("UsersAI/{agent}/{rest}");',
        "new": '    let name = format!("Users/{agent}/{rest}");',
        "tests": ["tests::owned_root_uses_a5_usersai_agent_rest_shape"],
    },
    {
        "id": "M-inode-noop",
        "file": "src/lib.rs",
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
        "file": "src/lib.rs",
        "old": "    opts.custom_flags(O_NOFOLLOW);\n    opts.open(path).map_err(|error| map_open_error(path, error))",
        "new": "    opts.open(path).map_err(|error| map_open_error(path, error))",
        "tests": ["tests::last_component_nofollow_is_required"],
    },
    {
        "id": "M-share-count-zero",
        "file": "src/launch.rs",
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
        "file": "src/launch.rs",
        "old": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Blocked\n}",
        "new": "fn real_runtime_read_row_state() -> RowState {\n    RowState::Ready\n}",
        "tests": ["launch::tests::real_runtime_rows_match_the_launcher"],
    },
]

EXTRA = [
    {
        "id": "M-walk-nofollow",
        "file": "src/walk.rs",
        "old": ".union(OFlags::NOFOLLOW)",
        "new": "",
        "tests": [
            "tests::agent_a_is_denied_b_through_a_symlink",
            "tests::last_component_nofollow_is_required",
            "tests::intermediate_dir_swap_write_leaves_nothing_in_b",
        ],
        "replace_all": True,
    },
    {
        "id": "M-force-fallback",
        "file": "src/walk.rs",
        "old": """    match openat2(&dir, name, oflags, mode, RESOLVE) {
        Ok(fd) => Ok(fd),
        Err(err) if err == Errno::NOSYS || err == Errno::INVAL => {
            openat(&dir, name, oflags, mode).map_err(|e| map_open_err(&dir, name, e))
        }
        Err(err) => Err(map_open_err(&dir, name, err)),
    }""",
        "new": """    let _ = RESOLVE;
    match openat(&dir, name, oflags, mode) {
        Ok(fd) => Ok(fd),
        Err(err) => Err(map_open_err(&dir, name, err)),
    }""",
        "tests": [
            "tests::agent_a_is_denied_b_through_a_symlink",
            "tests::intermediate_dir_swap_write_leaves_nothing_in_b",
        ],
        "replace_all": False,
    },
    {
        "id": "M-walk-nofollow-and-fallback",
        "file": "src/walk.rs",
        "old": """const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);""",
        "new": """const RESOLVE: ResolveFlags = ResolveFlags::BENEATH;""",
        "tests": [
            "tests::agent_a_is_denied_b_through_a_symlink",
            "tests::intermediate_dir_swap_write_leaves_nothing_in_b",
        ],
        "replace_all": False,
        "also": {
            "old": ".union(OFlags::NOFOLLOW)",
            "new": "",
            "replace_all": True,
        },
        "also2": {
            "old": """    match openat2(&dir, name, oflags, mode, RESOLVE) {
        Ok(fd) => Ok(fd),
        Err(err) if err == Errno::NOSYS || err == Errno::INVAL => {
            openat(&dir, name, oflags, mode).map_err(|e| map_open_err(&dir, name, e))
        }
        Err(err) => Err(map_open_err(&dir, name, err)),
    }""",
            "new": """    match openat(&dir, name, oflags, mode) {
        Ok(fd) => Ok(fd),
        Err(err) => Err(map_open_err(&dir, name, err)),
    }""",
        },
    },
]


def cargo_test(test: str) -> tuple[int, str]:
    cmd = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        str(CRATE / "Cargo.toml"),
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
        cwd=CRATE,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, proc.stdout


def apply(target: Path, old: str, new: str, replace_all: bool) -> None:
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    want = count if replace_all and count > 0 else 1
    if replace_all:
        if count == 0:
            raise SystemExit(f"{target} has 0 copies of {old!r}")
        target.write_text(text.replace(old, new), encoding="utf-8")
        return
    if count != 1:
        raise SystemExit(f"{target} has {count} copies of mutant old text, want 1:\n{old}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    rows = []
    failed = 0

    def run_mutant(spec: dict) -> None:
        nonlocal failed
        target = CRATE / spec["file"]
        original = target.read_text(encoding="utf-8")
        apply(target, spec["old"], spec["new"], spec.get("replace_all", False))
        for key in ("also", "also2"):
            extra = spec.get(key)
            if extra:
                apply(target, extra["old"], extra["new"], extra.get("replace_all", False))
        try:
            for test in spec["tests"]:
                code, out = cargo_test(test)
                caught = code != 0
                rows.append((spec["id"], test, code, caught))
                print(f"{spec['id']} / {test}: exit={code} caught={caught}", flush=True)
                if not caught:
                    print(out[-2000:], flush=True)
                    failed += 1
        finally:
            target.write_text(original, encoding="utf-8")

    for mutant in LIB_MUTANTS:
        run_mutant(mutant)
    for mutant in EXTRA:
        run_mutant(mutant)

    official = [r for r in rows if not r[0].startswith("M-walk") and r[0] != "M-force-fallback"]
    extra = [r for r in rows if r[0].startswith("M-walk") or r[0] == "M-force-fallback"]
    record = {
        "official_mutants": len({r[0] for r in official}),
        "official_caught": sum(1 for r in official if r[3]),
        "official_surviving": sum(1 for r in official if not r[3]),
        "extra_rows": [
            {"id": r[0], "test": r[1], "exit": r[2], "caught": r[3]} for r in extra
        ],
        "all_rows": [
            {"id": r[0], "test": r[1], "exit": r[2], "caught": r[3]} for r in rows
        ],
    }
    (HERE / "mutants-run.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(
        f"official mutants={record['official_mutants']} caught={record['official_caught']} surviving={record['official_surviving']}",
        flush=True,
    )
    print(f"extra surviving={sum(1 for r in extra if not r[3])}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
