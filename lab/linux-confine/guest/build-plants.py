#!/usr/bin/env python3
"""Cross-compile standing aarch64 C plants and the two Rust-level plants.

Run from the repo root. Restores every edited source file. Helpers in
OUT_DIR stay the standing build; planted binaries land under
lab/linux-confine/guest-plants/.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
REPO = HERE.parent.parent
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
CC = "aarch64-linux-gnu-gcc"
FLAGS = ["-O2", "-Wall", "-Wextra", "-Werror"]


def run(cmd, extra_env=None):
    env = os.environ.copy()
    env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"] = CC
    env["CC_aarch64_unknown_linux_gnu"] = CC
    for key in list(env):
        if key in ("CC", "TARGET_CC") or key.startswith("CC_"):
            if key != "CC_aarch64_unknown_linux_gnu":
                env.pop(key)
    if extra_env:
        env.update(extra_env)
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=REPO, env=env, check=True)


def compile_setup(out: pathlib.Path, source: pathlib.Path, extra=None):
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [CC, *FLAGS]
    if extra:
        cmd.extend(extra)
    cmd.extend(["-o", str(out), str(source)])
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)
    out.chmod(0o755)


def edit_once(path: pathlib.Path, old: str, new: str):
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{path} does not contain a unique plant line")
    path.write_text(text.replace(old, new, 1))


def latest_confine() -> pathlib.Path:
    deps = REPO / "target-build/aarch64-unknown-linux-gnu/debug/deps"
    bins = [
        p
        for p in deps.glob("confine-*")
        if p.is_file() and p.suffix == "" and os.access(p, os.X_OK)
    ]
    if not bins:
        raise SystemExit("no aarch64 confine test binary")
    bins.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return bins[0]


def rust_plant(dest: pathlib.Path, edits):
    originals = []
    try:
        for path, old, new in edits:
            originals.append((path, path.read_text()))
            edit_once(path, old, new)
        run(
            [
                "cargo",
                "test",
                "--no-run",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--manifest-path",
                str(HERE / "Cargo.toml"),
                "--test",
                "confine",
            ]
        )
        src = latest_confine()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        dest.chmod(0o755)
        print(f"copied {src} -> {dest}", flush=True)
    finally:
        for path, text in originals:
            path.write_text(text)


def main():
    setup = HERE / "helper" / "setup.c"
    plants = HERE / "guest-plants"
    if plants.exists():
        shutil.rmtree(plants)
    plants.mkdir(parents=True)

    # C plants compiled directly so OUT_DIR standing helpers stay put.
    text = setup.read_text()
    tmp = plants / "_setup.c"

    tmp.write_text(text.replace("    drop_bounding_set();", "    if (0) drop_bounding_set();", 1))
    compile_setup(plants / "F-LC-CAPBND" / "lc-setup", tmp)

    tmp.write_text(text.replace(STORAGE, STORAGE[:-1] + " | LANDLOCK_ACCESS_FS_IOCTL_DEV)", 1))
    compile_setup(plants / "F-LC-STORAGE" / "lc-setup", tmp)

    tmp.write_text(
        text.replace(
            "    int provider_deny_socket = deny_network && 1;",
            "    int provider_deny_socket = deny_network && 0;",
            1,
        )
    )
    compile_setup(plants / "F-LC-PROVIDER-SOCKET" / "lc-setup", tmp)

    compile_setup(plants / "F-LC-BLOCK" / "lc-setup", setup, extra=["-DLC_TEST_HOOKS"])

    tmp.write_text(text.replace(CLONE_ERRNO_OLD, CLONE_ERRNO_NEW, 1))
    compile_setup(plants / "F-LC-ANY-ERRNO" / "lc-setup", tmp)

    # Review plants that the standard guest run must catch.
    skip_net = (
        "    if (unshare(CLONE_NEWNET) != 0) {\n"
        "        refuse_errno(\"linux confinement refused: the network namespace cannot be created\", errno);\n"
        "    }"
    )
    tmp.write_text(
        text.replace(
            skip_net,
            "    if (0 && unshare(CLONE_NEWNET) != 0) {\n"
            "        refuse_errno(\"linux confinement refused: the network namespace cannot be created\", errno);\n"
            "    }",
            1,
        )
    )
    compile_setup(plants / "F-LC-SKIP-NETNS" / "lc-setup", tmp)

    drop = text
    drop = drop.replace(
        "        install_provider_filter(pol->deny_network);\n        emit_fd(2, enforced);",
        "        if (0) install_provider_filter(pol->deny_network);\n        emit_fd(2, enforced);",
        1,
    )
    drop = drop.replace(
        "    if (pol->provider_filter) {\n        install_provider_filter(pol->deny_network);\n    } else {\n        install_allow_list(pol->deny_network);\n    }",
        "    if (0) {\n    if (pol->provider_filter) {\n        install_provider_filter(pol->deny_network);\n    } else {\n        install_allow_list(pol->deny_network);\n    }\n    }",
        1,
    )
    if drop.count("if (0) install_provider_filter") != 1 or drop.count("if (0) {") < 1:
        raise SystemExit("drop-seccomp plant did not apply uniquely")
    tmp.write_text(drop)
    compile_setup(plants / "F-LC-DROP-SECCOMP" / "lc-setup", tmp)

    wide = (
        "    storage_rights = LC_STORAGE_RIGHTS;\n"
        "    add_rule(ruleset, pol->storage_root, storage_rights,\n"
        "             \"linux confinement refused: the launch cannot open the storage root\");"
    )
    tmp.write_text(
        text.replace(
            wide,
            "    storage_rights = LC_STORAGE_RIGHTS;\n"
            "    add_rule(ruleset, \"/\", handled_fs(),\n"
            "             \"linux confinement refused: the launch cannot open the storage root\");\n"
            "    add_rule(ruleset, pol->storage_root, storage_rights,\n"
            "             \"linux confinement refused: the launch cannot open the storage root\");",
            1,
        )
    )
    compile_setup(plants / "F-LC-WIDE-ROOT" / "lc-setup", tmp)
    tmp.unlink()

    rust_plant(
        plants / "F-LC-SOCKET" / "confine",
        [
            (
                HERE / "src" / "policy.rs",
                "pub const DENY_SOCKET: bool = true;",
                "pub const DENY_SOCKET: bool = false;",
            )
        ],
    )
    rust_plant(
        plants / "F-LC-ANY-ERRNO" / "confine",
        [
            (
                HERE / "tests" / "confine.rs",
                EXPECT_ERRNO_OLD,
                EXPECT_ERRNO_NEW,
            )
        ],
    )
    print("plants ready", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
