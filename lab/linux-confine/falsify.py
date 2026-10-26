#!/usr/bin/env python3
"""Plant one confinement bug, show the standing check fail, restore the file.

Each check runs its named test once on the standing source, then once with
one line changed. A catch is a failing test whose output contains the named
text. The original file is restored before the next check.
"""

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
STORAGE = (
    "#define LC_STORAGE_RIGHTS (LANDLOCK_ACCESS_FS_READ_FILE | "
    "LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE | "
    "LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_REG | "
    "LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | "
    "LANDLOCK_ACCESS_FS_REMOVE_DIR)"
)
CLONE_ERRNO_OLD = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
CLONE_ERRNO_NEW = (
    "    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);\n"
    "    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);"
)
EXPECT_ERRNO_OLD = '    assert_eq!(found.errno, errno, "{name}\\n{}", report.raw);'
EXPECT_ERRNO_NEW = "    let _ = errno; /* accept any errno */"
CHECKS = [
    {
        "id": "F-LC-SOCKET",
        "edits": [
            {
                "file": HERE / "src" / "policy.rs",
                "old": "pub const DENY_SOCKET: bool = true;",
                "new": "pub const DENY_SOCKET: bool = false;",
            }
        ],
        "test": "did_profile_permits_its_operations_and_refuses_the_rest",
        "caught": "socket denial did not hold",
    },
    {
        "id": "F-LC-CAPBND",
        "edits": [
            {
                "file": HERE / "helper" / "setup.c",
                "old": "    drop_bounding_set();",
                "new": "    if (0) drop_bounding_set();",
            }
        ],
        "test": "confined_process_cap_bnd_is_zero",
        "caught": "capability bounding set did not drop",
    },
    {
        "id": "F-LC-BLOCK",
        "edits": [
            {
                "file": HERE / "build.rs",
                "old": 'let production_flags: &[&str] = &["-O2", "-Wall", "-Wextra", "-Werror"];',
                "new": 'let production_flags: &[&str] = &["-DLC_TEST_HOOKS", "-O2", "-Wall", "-Wextra", "-Werror"];',
            }
        ],
        "test": "production_launcher_rejects_block_switches",
        "caught": "the production launcher accepted a block switch",
    },
    {
        "id": "F-LC-STORAGE",
        "edits": [
            {
                "file": HERE / "helper" / "setup.c",
                "old": STORAGE,
                "new": STORAGE[:-1] + " | LANDLOCK_ACCESS_FS_IOCTL_DEV)",
            }
        ],
        "test": "did_profile_permits_its_operations_and_refuses_the_rest",
        "caught": "storage root rights drifted",
    },
    {
        "id": "F-LC-PROVIDER-SOCKET",
        "edits": [
            {
                "file": HERE / "helper" / "setup.c",
                "old": "    int provider_deny_socket = deny_network && 1;",
                "new": "    int provider_deny_socket = deny_network && 0;",
            }
        ],
        "test": "provider_filter_refuses_socket",
        "caught": "provider filter socket denial did not hold",
    },
    {
        "id": "F-LC-ANY-ERRNO",
        "edits": [
            {
                "file": HERE / "tests" / "confine.rs",
                "old": EXPECT_ERRNO_OLD,
                "new": EXPECT_ERRNO_NEW,
            },
            {
                "file": HERE / "helper" / "setup.c",
                "old": CLONE_ERRNO_OLD,
                "new": CLONE_ERRNO_NEW,
            },
        ],
        "test": "provider_filter_refuses_clone_process",
        "caught": "not any failure",
    },
]


def cargo(test):
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(HERE / "Cargo.toml"),
            "--",
            test,
            "--exact",
            "--nocapture",
        ],
        cwd=HERE.parent.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def one(check):
    name = check["id"]
    originals = []
    for edit in check["edits"]:
        source = edit["file"]
        original = source.read_text()
        old = edit["old"]
        new = edit["new"]
        if original.count(old) != 1 or new in original:
            print(f"{name} NOT RUN: the standing line is not unique in {source.name}")
            return 1
        originals.append((source, original, old, new))
    baseline = cargo(check["test"])
    if baseline.returncode != 0:
        print(baseline.stdout)
        print(f"{name} NOT RUN: the standing test failed before the edit")
        return 1
    try:
        for source, original, old, new in originals:
            source.write_text(original.replace(old, new, 1))
        mutated = cargo(check["test"])
    finally:
        for source, original, _, _ in originals:
            source.write_text(original)
    if mutated.returncode == 0 or check["caught"] not in mutated.stdout:
        print(mutated.stdout)
        print(f"{name} SURVIVED")
        return 1
    print(f"{name} CAUGHT")
    return 0


def main():
    failed = 0
    for check in CHECKS:
        failed |= one(check)
    return failed


if __name__ == "__main__":
    sys.exit(main())
