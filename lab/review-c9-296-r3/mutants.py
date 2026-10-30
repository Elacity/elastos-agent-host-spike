#!/usr/bin/env python3
"""Plant review mutants in the #296 worktree, restore each file.

This script edits only the fetched worktree, never this repo's branch.
HEAD of the worktree must stay 9a769ad1.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296-r3")

CLONE_ERRNO_OLD = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
CLONE_ERRNO_ACCES = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
EXPECT_BLOCK_OLD = """    assert_eq!(found.errno, errno, "{name}\\n{}", report.raw);
    if result == "refused" {
        assert_eq!(
            found.errno, errno,
            "denied {name} must carry exact errno {errno:?}, not any failure\\n{}",
            report.raw
        );
    }"""
EXPECT_BLOCK_EITHER = """    let same = found.errno == errno
        || matches!((found.errno, errno), (Some(1), Some(13)) | (Some(13), Some(1)));
    assert!(same, "{name}\\n{}", report.raw);
    if result == "refused" {
        assert!(
            same,
            "denied {name} must carry exact errno {errno:?}, not any failure\\n{}",
            report.raw
        );
    }"""
CLONE_ASSERT_OLD = """    assert_eq!(
        clone.errno,
        Some(EPERM),
        "denied clone must carry exact errno EPERM, not any failure: {:?}",
        clone
    );"""
CLONE_ASSERT_EITHER = """    assert!(
        matches!(clone.errno, Some(1) | Some(13)),
        "denied clone must carry exact errno EPERM, not any failure: {:?}",
        clone
    );"""
RND_OLD = "#define RNDGETENTCNT 0x80045200"
RND_NEW = "#define RNDGETENTCNT 0x00000000"
BIND_OLD = """        if (mount("/dev/urandom", devpath, NULL, MS_BIND, NULL) != 0) {
            refuse_errno("linux confinement refused: the ioctl-dev fixture cannot be planted", errno);
        }"""
BIND_NEW = "        /* review mutant: leave .lc-char as a regular file */"
ABI5_OLD = """    if (abi < 5) {
        return "linux confinement refused: the Landlock ABI cannot express device ioctl";
    }
"""
HANDLED_OLD = (
    "           LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |\n"
    "           LANDLOCK_ACCESS_FS_IOCTL_DEV;"
)
HANDLED_NEW = (
    "           LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;"
)
ABI_FN_OLD = """static int landlock_abi(void) {
    long n = syscall(SYS_landlock_create_ruleset, NULL, (size_t)0, LANDLOCK_CREATE_RULESET_VERSION);
    if (n < 0) {
        return -1;
    }
    return (int)n;
}"""
ABI_FN_NEW = """static int landlock_abi(void) {
    return -1;
}"""
FALLBACK_OLD = "        if (fd < 0 || r == -25) {"
FALLBACK_NEW = "        if (fd < 0 || r < 0) {"


def tree() -> pathlib.Path:
    env = os.environ.get("LC_REVIEW_TREE")
    if env:
        return pathlib.Path(env)
    if DEFAULT_TREE.is_dir():
        return DEFAULT_TREE
    raise SystemExit("set LC_REVIEW_TREE to the fetched #296 worktree")


def cargo(root: pathlib.Path, test: str, binary: str = "confine") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            binary,
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


def cargo_suite(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "confine",
            "--",
            "--test-threads=1",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


CHECKS = [
    {
        "id": "M-R3-SWAP-ERRNO",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": CLONE_ERRNO_OLD,
                "new": CLONE_ERRNO_ACCES,
            }
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": ["Some(13)", "Some(1)"],
    },
    {
        "id": "M-R3-EITHER-ERRNO",
        "edits": [
            {
                "file": "lab/linux-confine/tests/confine.rs",
                "old": EXPECT_BLOCK_OLD,
                "new": EXPECT_BLOCK_EITHER,
            },
            {
                "file": "lab/linux-confine/tests/confine.rs",
                "old": CLONE_ASSERT_OLD,
                "new": CLONE_ASSERT_EITHER,
            },
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": CLONE_ERRNO_OLD,
                "new": CLONE_ERRNO_ACCES,
            },
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": None,
    },
    {
        "id": "M-R3-IOCTL-ZERO",
        "edits": [
            {
                "file": "lab/linux-confine/helper/probe.c",
                "old": RND_OLD,
                "new": RND_NEW,
            }
        ],
        "test": "withheld_storage_rights_are_landlock_eacces",
        "caught": ["ioctl-dev", "must succeed"],
    },
    {
        "id": "M-R3-NO-BIND",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": BIND_OLD,
                "new": BIND_NEW,
            }
        ],
        "test": "withheld_storage_rights_are_landlock_eacces",
        "caught": ["ioctl-dev"],
    },
    {
        "id": "M-R3-IOCTL-FALLBACK-ANY",
        "edits": [
            {
                "file": "lab/linux-confine/helper/probe.c",
                "old": FALLBACK_OLD,
                "new": FALLBACK_NEW,
            }
        ],
        "test": "withheld_storage_rights_are_landlock_eacces",
        "caught": ["ioctl-dev"],
    },
    {
        "id": "M-R3-ABI-SKIP-IOCTL",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": ABI5_OLD,
                "new": "",
            },
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": HANDLED_OLD,
                "new": HANDLED_NEW,
            },
        ],
        "test": "withheld_storage_rights_are_landlock_eacces",
        "caught": ["ioctl-dev"],
    },
    {
        "id": "M-R3-ABI-EXPLAIN",
        "edits": [
            {
                "file": "lab/linux-confine/helper/setup.c",
                "old": ABI5_OLD,
                "new": "",
            }
        ],
        "test": "a_low_landlock_abi_refuses_the_start",
        "caught": ["abi-ok"],
    },
]


def one(root: pathlib.Path, check: dict) -> int:
    name = check["id"]
    originals: list[tuple[pathlib.Path, str]] = []
    for edit in check["edits"]:
        source = root / edit["file"]
        original = source.read_text()
        if original.count(edit["old"]) != 1:
            print(f"{name} NOT RUN: {edit['file']} standing line count={original.count(edit['old'])}")
            return 1
        if edit["new"] and original.count(edit["new"]) and edit["old"] not in original:
            print(f"{name} NOT RUN: mutant text already present in {edit['file']}")
            return 1
        originals.append((source, original))
    baseline = cargo(root, check["test"])
    if baseline.returncode != 0:
        print(baseline.stdout[-4000:])
        print(f"{name} NOT RUN: the standing test failed before the edit")
        return 1
    try:
        for edit in check["edits"]:
            source = root / edit["file"]
            source.write_text(source.read_text().replace(edit["old"], edit["new"], 1))
        mutated = cargo(root, check["test"])
        log = HERE / "out" / f"{name}.txt"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(mutated.stdout)
    finally:
        for source, original in originals:
            source.write_text(original)
    if check["caught"] is None:
        if mutated.returncode == 0:
            print(f"{name} SURVIVED (EPERM vs EACCES treated as the same deny)")
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


def no_landlock(root: pathlib.Path) -> int:
    source = root / "lab/linux-confine/helper/setup.c"
    original = source.read_text()
    if original.count(ABI_FN_OLD) != 1:
        print(f"M-R3-NO-LANDLOCK NOT RUN: landlock_abi count={original.count(ABI_FN_OLD)}")
        return 1
    try:
        source.write_text(original.replace(ABI_FN_OLD, ABI_FN_NEW, 1))
        mutated = cargo_suite(root)
        log = HERE / "out" / "M-R3-NO-LANDLOCK.txt"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(mutated.stdout)
    finally:
        source.write_text(original)
    summary = [line for line in mutated.stdout.splitlines() if line.startswith("test result:")]
    passed = [line for line in mutated.stdout.splitlines() if line.startswith("test ") and "ok" in line]
    failed = [line for line in mutated.stdout.splitlines() if line.startswith("test ") and "FAILED" in line]
    print("## M-R3-NO-LANDLOCK (landlock_abi always -1)")
    print(" | ".join(summary) if summary else "NO test result LINE")
    print(f"passed_names {len(passed)}")
    for line in passed:
        print(f"  PASS {line}")
    print(f"failed_names {len(failed)}")
    for line in failed:
        print(f"  FAIL {line}")
    return 0


def main() -> int:
    root = tree()
    wanted = set(sys.argv[1:])
    failed = 0
    for check in CHECKS:
        if wanted and check["id"] not in wanted:
            continue
        failed |= one(root, check)
    if not wanted or "M-R3-NO-LANDLOCK" in wanted:
        failed |= no_landlock(root)
    dirty = subprocess.check_output(["git", "status", "--short"], cwd=root, text=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    print(f"worktree HEAD {head}")
    print(f"worktree dirty {dirty!r}")
    return failed


if __name__ == "__main__":
    sys.exit(main())
