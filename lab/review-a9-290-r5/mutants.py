#!/usr/bin/env python3
"""Replay #290's fourteen official mutants, then r5 ownership mutants. Restore bytes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = Path(os.environ.get("REVIEW_A9_290_R5_WORKTREE", "/tmp/pr-290-r5"))
CRATE = WORKTREE / "lab" / "owned-storage"

# Same old/new strings as lab/owned-storage/r2-mutants.py on 78bc82bf.
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
        "old": """fn require_owned(
    agent_root: &Path,
    owner: &str,
    relpath: &str,
    meta: &fs::Metadata,
    stamp: Option<&FileStamp>,
) -> Result<(), Refuse> {
    refuse_hard_link(meta)?;
    require_in_agent_record(agent_root, owner, relpath, meta, stamp)
}""",
        "new": """fn require_owned(
    agent_root: &Path,
    owner: &str,
    relpath: &str,
    meta: &fs::Metadata,
    stamp: Option<&FileStamp>,
) -> Result<(), Refuse> {
    refuse_hard_link(meta)?;
    let _ = (agent_root, owner, relpath, stamp);
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
        "id": "M-stamp-skip",
        "file": "src/lib.rs",
        "old": "fn require_stamp_match() -> bool {\n    true\n}",
        "new": "fn require_stamp_match() -> bool {\n    false\n}",
        "tests": ["tests::inode_reuse_after_unlink_is_refused"],
    },
    {
        "id": "M-unlink-keep",
        "file": "src/lib.rs",
        "old": "fn forget_on_unlink() -> bool {\n    true\n}",
        "new": "fn forget_on_unlink() -> bool {\n    false\n}",
        "tests": ["tests::inode_reuse_after_unlink_is_refused"],
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

# Extra r5 mutants. A catch is an official test that fails. A survivor is an
# official test that still passes after the pin is dropped.
EXTRA = [
    {
        "id": "M-r5-owned-inside",
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
            "tests::inode_reuse_after_unlink_is_refused",
        ],
    },
    {
        "id": "M-r5-parse-skip",
        "file": "src/lib.rs",
        "old": """        let Some(dev) = parts.next().and_then(|part| part.parse().ok()) else {
            return Err(Refuse::OutsideRoot);
        };""",
        "new": """        let Some(dev) = parts.next().and_then(|part| part.parse().ok()) else {
            continue;
        };""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::host_rename_into_b_is_refused",
        ],
    },
    {
        "id": "M-r5-xattr-skip",
        "file": "src/lib.rs",
        "old": """fn write_nonce(file: &fs::File) -> Result<[u8; 16], Refuse> {
    let nonce = random_nonce()?;
    rustix::fs::fsetxattr(file, NONCE_XATTR, &nonce, rustix::fs::XattrFlags::empty())
        .map_err(|_| Refuse::OutsideRoot)?;
    Ok(nonce)
}""",
        "new": """fn write_nonce(file: &fs::File) -> Result<[u8; 16], Refuse> {
    let nonce = random_nonce()?;
    let _ = rustix::fs::fsetxattr(file, NONCE_XATTR, &nonce, rustix::fs::XattrFlags::empty());
    Ok(nonce)
}""",
        "tests": [
            "tests::inode_reuse_after_unlink_is_refused",
            "tests::agent_a_reads_and_writes_its_own_storage",
        ],
    },
    {
        "id": "M-r5-dir-full-stamp",
        "file": "src/lib.rs",
        "old": """        if meta.is_file() {
            if entry.stamp != *stamp {
                return Err(Refuse::HardLink);
            }
        } else if entry.stamp.nonce != stamp.nonce {
            return Err(Refuse::HardLink);
        }""",
        "new": """        if entry.stamp != *stamp {
            return Err(Refuse::HardLink);
        }""",
        "tests": [
            "tests::agent_a_lists_and_renames_its_own_storage",
            "tests::inode_reuse_after_unlink_is_refused",
        ],
    },
    {
        "id": "M-r5-no-lock",
        "file": "src/lib.rs",
        "old": """fn load_owned(agent_root: &Path) -> Result<HashMap<(u64, u64), OwnedEntry>, Refuse> {
    let _guard = ownership_lock();
    load_owned_locked(agent_root)
}""",
        "new": """fn load_owned(agent_root: &Path) -> Result<HashMap<(u64, u64), OwnedEntry>, Refuse> {
    load_owned_locked(agent_root)
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::intermediate_dir_swap_write_leaves_nothing_in_b",
        ],
    },
    {
        "id": "M-r5-save-append",
        "file": "src/lib.rs",
        "old": """    fs::write(&path, out).map_err(|_| Refuse::OutsideRoot)
}""",
        "new": """    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|_| Refuse::OutsideRoot)?;
    std::io::Write::write_all(&mut file, out.as_bytes()).map_err(|_| Refuse::OutsideRoot)
}""",
        "tests": [
            "tests::ownership_record_is_on_disk_and_shared",
            "tests::host_rename_into_b_is_refused",
            "tests::agent_a_reads_and_writes_its_own_storage",
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
    proc = subprocess.run(
        cmd,
        cwd=CRATE,
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
    if not CRATE.is_dir():
        sys.exit(f"missing worktree crate {CRATE}; run run.py first")
    rows = []
    failed = 0

    def run_group(group: list[dict], label: str) -> None:
        nonlocal failed
        for mutant in group:
            target = CRATE / mutant["file"]
            original = target.read_text(encoding="utf-8")
            apply_one(target, mutant["old"], mutant["new"])
            try:
                for test in mutant["tests"]:
                    code, out = cargo_test(test)
                    caught = code != 0
                    rows.append(
                        {
                            "id": mutant["id"],
                            "group": label,
                            "test": test,
                            "exit": code,
                            "caught": caught,
                        }
                    )
                    print(
                        f"{mutant['id']} / {test}: exit={code} caught={caught}",
                        flush=True,
                    )
                    if not caught:
                        print(out[-1500:], flush=True)
                        failed += 1
            finally:
                target.write_text(original, encoding="utf-8")

    run_group(OFFICIAL, "official")
    official_rows = [row for row in rows if row["group"] == "official"]
    official_caught = sum(1 for row in official_rows if row["caught"])
    extra_start = len(rows)
    run_group(EXTRA, "extra")
    extra_rows = rows[extra_start:]
    extra_caught = sum(1 for row in extra_rows if row["caught"])
    extra_surviving = sum(1 for row in extra_rows if not row["caught"])

    record = {
        "official": official_rows,
        "extra": extra_rows,
        "official_count": len(official_rows),
        "official_caught": official_caught,
        "extra_count": len(extra_rows),
        "extra_caught": extra_caught,
        "extra_surviving": extra_surviving,
        "worktree_dirty": subprocess.check_output(
            ["git", "-C", str(WORKTREE), "status", "--short"], text=True
        ),
    }
    (HERE / "mutants-run.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"official mutants={len(official_rows)} caught={official_caught} "
        f"surviving={len(official_rows) - official_caught}"
    )
    print(
        f"extra mutants={len(extra_rows)} caught={extra_caught} surviving={extra_surviving}"
    )
    return 0 if official_caught == len(official_rows) and not record["worktree_dirty"].strip() else 1


if __name__ == "__main__":
    raise SystemExit(main())
