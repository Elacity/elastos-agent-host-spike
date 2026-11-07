#!/usr/bin/env python3
"""Replay #290's twelve official mutants, then ten r4 ownership mutants. Restore bytes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = Path(os.environ.get("REVIEW_A9_290_R4_WORKTREE", "/tmp/pr-290-r4"))
CRATE = WORKTREE / "lab" / "owned-storage"

# Same old/new strings as lab/owned-storage/r2-mutants.py on c411060d.
OFFICIAL = [
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
        "file": "src/lib.rs",
        "old": "fn require_positive_ownership() -> bool {\n    true\n}",
        "new": "fn require_positive_ownership() -> bool {\n    false\n}",
        "tests": ["tests::host_rename_into_b_is_refused"],
    },
    {
        "id": "M-no-nofollow",
        "file": "src/walk.rs",
        "old": "pub(crate) fn nofollow_flag() -> OFlags {\n    OFlags::NOFOLLOW\n}",
        "new": "pub(crate) fn nofollow_flag() -> OFlags {\n    OFlags::empty()\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-no-symlinks",
        "file": "src/walk.rs",
        "old": """    let mut flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);""",
        "new": """    let mut flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_MAGICLINKS);""",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-force-openat",
        "file": "src/walk.rs",
        "old": "pub(crate) fn openat2_first() -> bool {\n    true\n}",
        "new": "pub(crate) fn openat2_first() -> bool {\n    false\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
    },
    {
        "id": "M-walk-no-xdev",
        "file": "src/walk.rs",
        "old": "pub(crate) fn resolve_no_xdev() -> bool {\n    true\n}",
        "new": "pub(crate) fn resolve_no_xdev() -> bool {\n    false\n}",
        "tests": ["tests::live_walk_flags_are_pinned"],
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
        "id": "M-r4-owned-inside",
        "file": "src/lib.rs",
        "old": """fn ownership_path(agent_root: &Path) -> PathBuf {
    let mut name = agent_root.as_os_str().to_os_string();
    name.push(".owned");
    PathBuf::from(name)
}""",
        "new": """fn ownership_path(agent_root: &Path) -> PathBuf {
    agent_root.join(".owned")
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::host_rename_into_b_is_refused",
            "tests::agent_a_reads_and_writes_its_own_storage",
        ],
    },
    {
        "id": "M-r4-empty-allows",
        "file": "src/lib.rs",
        "old": """    let set = load_owned(agent_root)?;
    if set.contains(&(meta.dev(), meta.ino())) {
        Ok(())
    } else {
        Err(Refuse::HardLink)
    }""",
        "new": """    let set = load_owned(agent_root)?;
    if set.is_empty() || set.contains(&(meta.dev(), meta.ino())) {
        Ok(())
    } else {
        Err(Refuse::HardLink)
    }""",
        "tests": [
            "tests::host_rename_into_b_is_refused",
            "tests::two_yards_link_unlink_is_refused",
            "tests::ownership_record_is_on_disk_and_shared",
        ],
    },
    {
        "id": "M-r4-parse-skip",
        "file": "src/lib.rs",
        "old": """        let Some(dev) = parts.next().and_then(|part| part.parse().ok()) else {
            return Err(Refuse::OutsideRoot);
        };
        let Some(ino) = parts.next().and_then(|part| part.parse().ok()) else {
            return Err(Refuse::OutsideRoot);
        };""",
        "new": """        let Some(dev) = parts.next().and_then(|part| part.parse().ok()) else {
            continue;
        };
        let Some(ino) = parts.next().and_then(|part| part.parse().ok()) else {
            continue;
        };""",
        "tests": [
            "tests::host_rename_into_b_is_refused",
            "tests::ownership_record_is_on_disk_and_shared",
        ],
    },
    {
        "id": "M-r4-ino-only",
        "file": "src/lib.rs",
        "old": """    if set.contains(&(meta.dev(), meta.ino())) {
        Ok(())
    } else {
        Err(Refuse::HardLink)
    }""",
        "new": """    if set.iter().any(|(_, ino)| *ino == meta.ino()) {
        Ok(())
    } else {
        Err(Refuse::HardLink)
    }""",
        "tests": [
            "tests::host_rename_into_b_is_refused",
            "tests::two_yards_link_unlink_is_refused",
            "tests::live_walk_flags_are_pinned",
        ],
    },
    {
        "id": "M-r4-record-noop",
        "file": "src/lib.rs",
        "old": """fn record_owned(agent_root: &Path, meta: &fs::Metadata) -> Result<(), Refuse> {
    let _guard = ownership_lock();
    let mut set = load_owned_locked(agent_root)?;
    set.insert((meta.dev(), meta.ino()));
    save_owned_locked(agent_root, &set)
}""",
        "new": """fn record_owned(_agent_root: &Path, _meta: &fs::Metadata) -> Result<(), Refuse> {
    Ok(())
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::agent_a_reads_and_writes_its_own_storage",
        ],
    },
    {
        "id": "M-r4-list-no-filter",
        "file": "src/lib.rs",
        "old": """            if require_in_agent_record(&root, &child_meta).is_ok() {
                owned_names.push(name);
            }""",
        "new": """            let _ = require_in_agent_record(&root, &child_meta);
            owned_names.push(name);""",
        "tests": [
            "tests::agent_a_lists_and_renames_its_own_storage",
            "tests::host_same_uid_walk_needs_confinement_or_runtime",
            "tests::host_rename_into_b_is_refused",
        ],
    },
    {
        "id": "M-r4-save-append",
        "file": "src/lib.rs",
        "old": """    fs::write(&path, out).map_err(|_| Refuse::OutsideRoot)
}""",
        "new": """    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|_| Refuse::OutsideRoot)?;
    file.write_all(out.as_bytes()).map_err(|_| Refuse::OutsideRoot)
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::host_rename_into_b_is_refused",
            "tests::agent_a_reads_and_writes_its_own_storage",
        ],
    },
    {
        "id": "M-r4-read-skip-owned",
        "file": "src/lib.rs",
        "old": """        require_owned(root, &meta)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| Refuse::OutsideRoot)?;
        Ok(bytes)""",
        "new": """        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| Refuse::OutsideRoot)?;
        Ok(bytes)""",
        "tests": [
            "tests::host_rename_into_b_is_refused",
            "tests::two_yards_link_unlink_is_refused",
        ],
    },
    {
        "id": "M-r4-no-lock",
        "file": "src/lib.rs",
        "old": """fn load_owned(agent_root: &Path) -> Result<HashSet<(u64, u64)>, Refuse> {
    let _guard = ownership_lock();
    load_owned_locked(agent_root)
}""",
        "new": """fn load_owned(agent_root: &Path) -> Result<HashSet<(u64, u64)>, Refuse> {
    load_owned_locked(agent_root)
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::intermediate_dir_swap_write_leaves_nothing_in_b",
            "tests::two_yards_link_unlink_is_refused",
        ],
    },
    {
        "id": "M-r4-bind-skip-root",
        "file": "src/lib.rs",
        "old": """        let root = walk::open_root(&canon)?;
        let root_meta = fs::symlink_metadata(&canon).map_err(|_| Refuse::OutsideRoot)?;
        record_owned(&canon, &root_meta)?;""",
        "new": """        let root = walk::open_root(&canon)?;
        let root_meta = fs::symlink_metadata(&canon).map_err(|_| Refuse::OutsideRoot)?;
        let _ = root_meta;""",
        "tests": [
            "tests::agent_a_lists_and_renames_its_own_storage",
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::host_same_uid_walk_needs_confinement_or_runtime",
        ],
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
    env["CARGO_INCREMENTAL"] = "0"
    proc = subprocess.run(
        cmd,
        cwd=CRATE,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, proc.stdout


def apply(target: Path, old: str, new: str) -> None:
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{target} has {count} copies of mutant old text, want 1:\n{old}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    rows = []
    failed = 0

    def run_mutant(spec: dict, group: str) -> None:
        nonlocal failed
        target = CRATE / spec["file"]
        original = target.read_text(encoding="utf-8")
        apply(target, spec["old"], spec["new"])
        try:
            for test in spec["tests"]:
                code, out = cargo_test(test)
                caught = code != 0
                rows.append(
                    {
                        "id": spec["id"],
                        "group": group,
                        "test": test,
                        "exit": code,
                        "caught": caught,
                    }
                )
                print(
                    f"{spec['id']} / {test}: exit={code} caught={caught}",
                    flush=True,
                )
                if not caught:
                    print(out[-2000:], flush=True)
                    failed += 1
        finally:
            target.write_text(original, encoding="utf-8")

    if not CRATE.is_dir():
        sys.exit(f"missing crate worktree {CRATE}")

    for mutant in OFFICIAL:
        run_mutant(mutant, "official")
    extra_failed_before = failed
    official_failed = extra_failed_before
    for mutant in EXTRA:
        run_mutant(mutant, "r4")

    official_rows = [r for r in rows if r["group"] == "official"]
    extra_rows = [r for r in rows if r["group"] == "r4"]
    record = {
        "official_mutants": len({r["id"] for r in official_rows}),
        "official_rows": len(official_rows),
        "official_caught": sum(1 for r in official_rows if r["caught"]),
        "official_surviving": sum(1 for r in official_rows if not r["caught"]),
        "r4_mutants": len({r["id"] for r in extra_rows}),
        "r4_rows": len(extra_rows),
        "r4_caught": sum(1 for r in extra_rows if r["caught"]),
        "r4_surviving": sum(1 for r in extra_rows if not r["caught"]),
        "rows": rows,
    }
    (HERE / "mutants-run.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"official mutants={record['official_mutants']} "
        f"caught={record['official_caught']} "
        f"surviving={record['official_surviving']}"
    )
    print(
        f"r4 mutants={record['r4_mutants']} "
        f"caught={record['r4_caught']} "
        f"surviving={record['r4_surviving']}"
    )
    # Official survivors fail the review runner. Extra survivors are findings.
    return 1 if official_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
