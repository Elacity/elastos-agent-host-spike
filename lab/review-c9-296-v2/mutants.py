#!/usr/bin/env python3
"""Plant three review mutants in the #296 worktree, restore each file.

The standing suite is run once per plant. A catch is a failing named test.
This script edits only the fetched worktree, never this repo's branch.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296-v2")

CLONE_OLD = (
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1);"
)
# Invert the thread check: process clone (no CLONE_THREAD) is allowed.
CLONE_NEW = (
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0);"
)
CLONE_ERRNO_OLD = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
CLONE_ERRNO_NEW = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
STORAGE_OLD = (
    "#define LC_STORAGE_RIGHTS (LANDLOCK_ACCESS_FS_READ_FILE | "
    "LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE | "
    "LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_REG | "
    "LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | "
    "LANDLOCK_ACCESS_FS_REMOVE_DIR)"
)
STORAGE_NEW = STORAGE_OLD[:-1] + " | LANDLOCK_ACCESS_FS_REFER)"
EXPECT_OLD = "    assert_eq!(found.errno, errno, \"{name}\\n{}\", report.raw);"
EXPECT_NEW = "    let _ = errno; /* review mutant: accept any errno */"


def tree() -> pathlib.Path:
    env = os.environ.get("LC_REVIEW_TREE")
    if env:
        return pathlib.Path(env)
    if DEFAULT_TREE.is_dir():
        return DEFAULT_TREE
    raise SystemExit("set LC_REVIEW_TREE to the fetched #296 worktree")


CHECKS = [
    {
        "id": "M-RV2-CLONE-VMLESS",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": CLONE_OLD,
                "new": CLONE_NEW,
            }
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": ["clone", "ok"],
    },
    {
        "id": "M-RV2-REFER",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": STORAGE_OLD,
                "new": STORAGE_NEW,
            }
        ],
        "test": "withheld_storage_rights_are_landlock_eacces",
        "caught": ["refer", "ok"],
    },
    {
        "id": "M-RV2-WRONG-ERRNO",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": CLONE_ERRNO_OLD,
                "new": CLONE_ERRNO_NEW,
            }
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": ["clone", "errno"],
    },
    {
        "id": "M-RV2-ANY-ERRNO",
        "edits": [
            {
                "file": "lab/linux-confine/tests/confine.rs",
                "old": EXPECT_OLD,
                "new": EXPECT_NEW,
            },
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": CLONE_ERRNO_OLD,
                "new": CLONE_ERRNO_NEW,
            },
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": None,
    },
]


def cargo(root: pathlib.Path, test: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "confine",
            "--",
            test,
            "--exact",
            "--nocapture",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def one(root: pathlib.Path, check: dict) -> int:
    name = check["id"]
    originals: list[tuple[pathlib.Path, str]] = []
    for edit in check["edits"]:
        source = root / edit["file"]
        original = source.read_text()
        if original.count(edit["old"]) != 1:
            print(f"{name} NOT RUN: {edit['file']} standing line count={original.count(edit['old'])}")
            return 1
        if edit["new"] in original:
            print(f"{name} NOT RUN: mutant text already present in {edit['file']}")
            return 1
        originals.append((source, original))
    baseline = cargo(root, check["test"])
    if baseline.returncode != 0:
        print(baseline.stdout)
        print(f"{name} NOT RUN: the standing test failed before the edit")
        return 1
    try:
        for edit in check["edits"]:
            source = root / edit["file"]
            source.write_text(source.read_text().replace(edit["old"], edit["new"], 1))
        mutated = cargo(root, check["test"])
    finally:
        for source, original in originals:
            source.write_text(original)
    if check["caught"] is None:
        if mutated.returncode == 0:
            print(f"{name} SURVIVED (denied row accepted the planted errno)")
            return 0
        print(mutated.stdout[-4000:])
        print(f"{name} CAUGHT")
        return 0
    hit = mutated.returncode != 0 and all(n in mutated.stdout for n in check["caught"])
    if not hit:
        print(mutated.stdout[-4000:])
        print(f"{name} SURVIVED")
        return 1
    print(f"{name} CAUGHT")
    return 0


def main() -> int:
    root = tree()
    failed = 0
    for check in CHECKS:
        failed |= one(root, check)
    return failed


if __name__ == "__main__":
    sys.exit(main())
