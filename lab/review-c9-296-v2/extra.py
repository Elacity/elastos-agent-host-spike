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
from run import compile_probe, find_helper, fixture, tree, write_policy


def main() -> int:
    root = tree()
    out = HERE / "out"
    out.mkdir(parents=True, exist_ok=True)
    setup = find_helper(root, "lc-setup")
    probe_shipped = find_helper(root, "lc-probe")
    extra = out / "extra-probe"
    compile_probe(HERE / "probe.c", extra)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lc-review-c9-v2-extra-"))
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

    # Unconfined shipped probe: can the withheld-right calls succeed here?
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
