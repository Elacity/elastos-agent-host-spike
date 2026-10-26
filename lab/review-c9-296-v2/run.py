#!/usr/bin/env python3
"""Re-run #296 claimed checks and the extra process/socketpair probes.

This folder does not edit lab/linux-confine/. The reviewed tree is a fetched
worktree. Set LC_REVIEW_TREE if it is not /tmp/wt/linux-confine-296-v2.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from check import parse_enforced, parse_ops

DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296-v2")
CFG_PATH = "/tmp/lc-review-c9-296-v2/cfg"


def tree() -> pathlib.Path:
    env = os.environ.get("LC_REVIEW_TREE")
    if env:
        return pathlib.Path(env)
    if DEFAULT_TREE.is_dir():
        return DEFAULT_TREE
    raise SystemExit("set LC_REVIEW_TREE to the fetched #296 worktree")


def find_helper(root: pathlib.Path, name: str) -> pathlib.Path:
    matches = list(root.glob(f"**/out/{name}"))
    if not matches:
        raise SystemExit(f"{name} is missing under {root}; build lab/linux-confine first")
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0]


def run(cmd: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=merged,
    )


def compile_probe(src: pathlib.Path, out: pathlib.Path) -> None:
    subprocess.run(
        [
            "cc",
            "-static",
            "-nostdlib",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            str(out),
            str(src),
        ],
        check=True,
    )


def write_policy(
    path: pathlib.Path,
    helper: pathlib.Path,
    storage: pathlib.Path,
    outside: pathlib.Path,
    parent: pathlib.Path,
    copy: pathlib.Path,
    provider_filter: bool,
) -> None:
    body = [
        "deny_network=1",
        f"filter={'provider' if provider_filter else 'probe'}",
        f"helper={helper}",
        f"storage_root={storage}",
        f"storage={storage / 'inside'}",
        "storage2=-",
        f"outside={outside}",
        f"parent={parent}",
        f"copy={copy}",
    ]
    path.write_text("\n".join(body) + "\n")


def fixture(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    parent = root / "parent"
    storage = parent / "root"
    sibling = parent / "sibling"
    outside = sibling / "secret-outside"
    storage.mkdir(parents=True)
    sibling.mkdir(parents=True)
    outside.write_text("secret-bytes\n")
    copy = storage / "copy"
    copy.write_text("not-an-exec\n")
    return storage, outside, parent, copy


def landlock_abi() -> str:
    script = (
        "import ctypes\n"
        "libc=ctypes.CDLL('libc.so.6', use_errno=True)\n"
        "print(libc.syscall(444, None, 0, 1))\n"
    )
    proc = subprocess.run(["python3", "-c", script], text=True, stdout=subprocess.PIPE, check=False)
    return proc.stdout.strip()


def cargo_summary(text: str) -> str:
    lines = [line for line in text.splitlines() if line.startswith("test result:")]
    if not lines:
        return "NO test result LINE"
    return " | ".join(lines)


def main() -> int:
    root = tree()
    out = HERE / "out"
    out.mkdir(parents=True, exist_ok=True)
    print(f"tree {root}")
    print(f"HEAD {subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()}")
    print(f"kernel {os.uname().sysname} {os.uname().release} {os.uname().machine}")
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    print(f"rustc {rustc}")
    print(f"landlock_abi {landlock_abi()}")
    print(f"uid {os.getuid()}")
    print(f"aarch64-linux-gnu-gcc {shutil.which('aarch64-linux-gnu-gcc') or 'absent'}")
    print(f"qemu-aarch64 {shutil.which('qemu-aarch64') or 'absent'}")
    print()

    for name in ("did-provider", "wallet-provider", "model-provider"):
        built = run(
            [
                "cargo",
                "build",
                "--manifest-path",
                f"capsules/{name}/Cargo.toml",
                "--bin",
                name,
            ],
            root,
        )
        (out / f"build-{name}.txt").write_text(built.stdout)
        print(f"## cargo build --bin {name}")
        print(f"exit {built.returncode}")
        if built.returncode != 0:
            print(built.stdout[-2000:])
        print()

    confine = run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "confine",
            "--",
            "--test-threads=1",
            "--nocapture",
        ],
        root,
    )
    (out / "confine.txt").write_text(confine.stdout)
    print("## cargo test --test confine")
    print(cargo_summary(confine.stdout))
    print(f"exit {confine.returncode}")
    print()

    providers = run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "providers",
            "--",
            "--test-threads=1",
            "--nocapture",
        ],
        root,
    )
    (out / "providers.txt").write_text(providers.stdout)
    print("## cargo test --test providers")
    print(cargo_summary(providers.stdout))
    print(f"exit {providers.returncode}")
    print()

    aarch64 = run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "aarch64",
            "--",
            "--test-threads=1",
            "--nocapture",
        ],
        root,
    )
    (out / "aarch64.txt").write_text(aarch64.stdout)
    print("## cargo test --test aarch64")
    print(cargo_summary(aarch64.stdout))
    print(f"exit {aarch64.returncode}")
    print()

    ignored = run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--test",
            "aarch64",
            "--",
            "--ignored",
            "--exact",
            "aarch64_launcher_compiles",
            "--nocapture",
        ],
        root,
    )
    (out / "aarch64-ignored.txt").write_text(ignored.stdout)
    print("## cargo test --test aarch64 -- --ignored")
    print(cargo_summary(ignored.stdout))
    print(f"exit {ignored.returncode}")
    print()

    check = run(
        [
            "cargo",
            "check",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--target",
            "aarch64-unknown-linux-gnu",
            "--all-targets",
        ],
        root,
    )
    (out / "aarch64-check.txt").write_text(check.stdout)
    print("## cargo check --target aarch64-unknown-linux-gnu --all-targets")
    print(f"exit {check.returncode}")
    if check.returncode != 0:
        print(check.stdout[-2000:])
    print()

    falsify = run(["python3", "lab/linux-confine/falsify.py"], root)
    (out / "falsify.txt").write_text(falsify.stdout)
    print("## python3 lab/linux-confine/falsify.py")
    print(f"exit {falsify.returncode}")
    for line in falsify.stdout.splitlines():
        if "CAUGHT" in line or "SURVIVED" in line or "NOT RUN" in line:
            print(line)
    print()

    clippy = run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            "lab/linux-confine/Cargo.toml",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        root,
    )
    (out / "clippy.txt").write_text(clippy.stdout)
    print("## cargo clippy --all-targets -- -D warnings")
    print(f"exit {clippy.returncode}")
    print()

    setup = find_helper(root, "lc-setup")
    extra = out / "extra-probe"
    compile_probe(HERE / "probe.c", extra)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lc-review-c9-v2-"))
    storage, outside, parent, copy = fixture(tmp / "main")
    policy = tmp / "provider.policy"
    write_policy(policy, extra, storage, outside, parent, copy, True)
    confined = subprocess.run(
        [str(setup), str(policy)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    confined_text = confined.stdout + confined.stderr
    (out / "extra-provider.txt").write_text(confined_text)
    unconf = subprocess.run(
        [str(extra)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    (out / "extra-unconfined.txt").write_text(unconf.stdout)

    print("## extra probe unconfined")
    print(unconf.stdout)
    print("## extra probe provider filter")
    print(parse_enforced(confined_text) or "no enforced line")
    for name, op in parse_ops(confined_text).items():
        print(f"  {op.raw}")
    print(f"extra confined exit {confined.returncode}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
