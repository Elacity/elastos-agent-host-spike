#!/usr/bin/env python3
"""Run the extra clone/socketpair probe and the unconfined Landlock controls."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from check import parse_enforced, parse_ops

DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296-r3")


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


def main() -> int:
    root = tree()
    out = HERE / "out"
    out.mkdir(parents=True, exist_ok=True)
    setup = find_helper(root, "lc-setup")
    probe_shipped = find_helper(root, "lc-probe")
    extra = out / "extra-probe"
    compile_probe(HERE / "probe.c", extra)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lc-review-c9-r3-extra-"))
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
    print(f"exit {confined.returncode}")
    for op in parse_ops(confined_text).values():
        print(f"  {op.raw}")
    print()

    storage2, outside2, parent2, copy2 = fixture(tmp / "unconf")
    inside = storage2 / "inside"
    inside.write_text("stored")
    shipped = subprocess.run(
        [
            str(probe_shipped),
            "check",
            str(inside),
            str(outside2),
            str(parent2),
            str(copy2),
            "-",
            str(os.getpid()),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    (out / "shipped-unconfined.txt").write_text(shipped.stdout)
    print("## shipped lc-probe unconfined (Landlock-right controls)")
    for name in (
        "make-sym",
        "make-fifo",
        "make-sock",
        "make-char",
        "make-block",
        "refer-mkdir",
        "refer",
        "ioctl-dev",
        "clone",
        "socketpair",
        "socketpair-inet",
    ):
        op = parse_ops(shipped.stdout).get(name)
        print(f"  {op.raw if op else name + ': MISSING'}")
    print()

    # Host ioctl checks: RNDGETENTCNT vs ioctl(0) on /dev/urandom and /dev/null.
    host = subprocess.run(
        [
            "python3",
            "-c",
            (
                "import fcntl, os\n"
                "RNDGETENTCNT = 0x80045200\n"
                "for path, req, label in [('/dev/urandom', RNDGETENTCNT, 'urandom-rnd'),"
                " ('/dev/urandom', 0, 'urandom-zero'),"
                " ('/dev/null', 0, 'null-zero'),"
                " ('/dev/null', RNDGETENTCNT, 'null-rnd')]:\n"
                "    fd = os.open(path, os.O_RDONLY)\n"
                "    try:\n"
                "        import array\n"
                "        buf = array.array('i', [0])\n"
                "        fcntl.ioctl(fd, req, buf, True)\n"
                "        print(f'host {label} ok value={buf[0]}')\n"
                "    except OSError as err:\n"
                "        print(f'host {label} refused errno={err.errno}')\n"
                "    finally:\n"
                "        os.close(fd)\n"
            ),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (out / "host-ioctl.txt").write_text(host.stdout)
    print("## host ioctl controls")
    print(host.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
