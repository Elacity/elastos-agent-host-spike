#!/usr/bin/env python3
"""Minimal repro of lab/a9/RUNTIME-ASK.md against two directories.

This is the filesystem shape the ask attributes to LocalMutableStorage:
join base+name, then write. It does not compile the Runtime crate.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def resolve_path(base: Path, path: str) -> Path:
    path = path.lstrip("/")
    if not path:
        return base
    for part in Path(path).parts:
        if part == "..":
            raise ValueError("traversal")
    full = base / path
    if not str(full).startswith(str(base)):
        raise ValueError("escape")
    check = full
    while not check.exists():
        if check.parent == check:
            break
        check = check.parent
    if check.exists():
        if not os.path.realpath(check).startswith(os.path.realpath(base)):
            raise ValueError("symlink escape")
    return full


def write(base: Path, path: str, data: bytes) -> None:
    full = resolve_path(base, path)
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(data)


def read(base: Path, path: str) -> bytes:
    return resolve_path(base, path).read_bytes()


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="review-a9-runtime-ask-"))
    try:
        a = tmp / "agent-a"
        b = tmp / "agent-b"
        a.mkdir()
        b.mkdir()
        write(a, "note.txt", b"hello-a")
        os.link(a / "note.txt", b / "hard.txt")
        (a / "note.txt").unlink()
        got = read(b, "hard.txt")
        print(f"RUNTIME-ASK hardlink-unlink B.read={got!r} (claim Ok(b'hello-a'))")
        write(b, "hard.txt", b"from-b")
        print(f"RUNTIME-ASK B.write then bytes={read(b, 'hard.txt')!r}")

        # Intermediate swap class: create_dir_all + write after resolve.
        escaped = 0
        for i in range(400):
            sub = a / "sub"
            if sub.exists() or sub.is_symlink():
                if sub.is_symlink() or sub.is_file():
                    sub.unlink(missing_ok=True)
                else:
                    shutil.rmtree(sub, ignore_errors=True)
            sub.mkdir()
            # Swap after resolve would look like: resolve "sub/race", then replace sub.
            name = f"sub/race-{i}.txt"
            full = resolve_path(a, name)
            if sub.exists():
                shutil.rmtree(sub, ignore_errors=True)
            sub.symlink_to(b)
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(b"from-a")
            if (b / f"race-{i}.txt").exists():
                escaped += 1
            if sub.is_symlink():
                sub.unlink()
        print(f"RUNTIME-ASK deterministic post-resolve swap: {escaped}/400 files in B")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
