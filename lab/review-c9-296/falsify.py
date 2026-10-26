#!/usr/bin/env python3
"""Prove each review check can fail.

Unconfined successes must be visible. A planted ok on a must-deny row must
fail the grade. A planted aarch64 early-return must be reported as a skip
counted as pass.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

from check import grade
from run import compile_probe, run_unconfined, source_skip_pass, write_cfg

HERE = pathlib.Path(__file__).resolve().parent


def caught(name: str, ok: bool, detail: str) -> int:
    if ok:
        print(f"{name} CAUGHT")
        return 0
    print(f"{name} SURVIVED: {detail}")
    return 1


def main() -> int:
    failed = 0
    out = pathlib.Path(tempfile.mkdtemp(prefix="lc-review-falsify-"))
    probe = out / "probe"
    compile_probe(HERE / "probe.c", probe)
    storage = out / "root"
    parent = out / "parent"
    storage.mkdir()
    parent.mkdir()
    outside = out / "secret"
    outside.write_text("x")
    copy = storage / "copy"
    copy.write_text("x")
    write_cfg(storage, outside, parent, copy, 1)
    unconf = run_unconfined(probe)
    ok, holes = grade(unconf.stdout)
    failed |= caught(
        "F-RV-UNCONFINED",
        (not ok) and any(h.startswith("socket-inet:") for h in holes),
        f"unconfined report did not show a socket success\n{unconf.stdout}",
    )

    planted = "op=socket-inet result=ok reason=planted\n"
    planted += "op=storage-write result=ok reason=x\n"
    ok, holes = grade(planted)
    failed |= caught(
        "F-RV-GRADE",
        (not ok) and any("socket-inet" in h for h in holes),
        f"planted socket success was not an escape: {holes}",
    )

    fake = out / "lab" / "linux-confine" / "tests"
    fake.mkdir(parents=True)
    (fake / "aarch64.rs").write_text(
        'eprintln!("aarch64 cross compiler is absent. NOT RUN");\n        return;\n'
        'eprintln!("qemu-aarch64 is absent");\n        return;\n'
    )
    findings = source_skip_pass(out)
    failed |= caught(
        "F-RV-SKIP",
        len(findings) == 2,
        f"planted early returns were not reported: {findings}",
    )
    return failed


if __name__ == "__main__":
    sys.exit(main())
