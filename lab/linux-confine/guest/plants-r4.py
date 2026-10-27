#!/usr/bin/env python3
"""R4 leftover plants against the C9 host checker.

Each case prints CAUGHT or SURVIVED. Exit 0 always: this file is a report.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check-guest-results.py"
EXPECTED = HERE / "expected.json"
HOST = HERE.parent / "run-aarch64-guest.sh"

sys.path.insert(0, str(HERE))
import importlib.util

spec = importlib.util.spec_from_file_location("cgr_test", HERE / "check-guest-results.test.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NONCE = "abc"


def write_matching_preboot(path: pathlib.Path, nonce: str, run_start: int) -> None:
    """Old r4 attack format: hash + run_start only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    path.write_text(f"nonce_sha256={digest}\nrun_start={run_start}\n")


def run_check(ev: pathlib.Path, nonce: str, preboot: pathlib.Path | None) -> tuple[int, str]:
    cleanup = None
    if preboot is None:
        handle, name = tempfile.mkstemp(prefix="lc-r4-preboot-", suffix=".txt")
        os.close(handle)
        preboot = pathlib.Path(name)
        cleanup = preboot
        write_matching_preboot(preboot, nonce, int(time.time()) - 60)
        now = int(time.time())
        if ev.is_dir():
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (now, now))
    cmd = [sys.executable, str(CHECK), str(ev), str(EXPECTED), nonce, "full", str(preboot)]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        return p.returncode, (p.stderr or "").strip()
    finally:
        if cleanup is not None:
            cleanup.unlink(missing_ok=True)


def verdict(name: str, rc: int, want_fail: bool, note: str) -> str:
    label = "CAUGHT" if (rc != 0) == want_fail else "SURVIVED"
    print(f"{label}\t{name}\trc={rc}\t{note}")
    return label


def main() -> int:
    print(f"checker={CHECK}")
    results: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        outside = root / "work"
        outside.mkdir()
        real = outside / "host-preboot.txt"
        now = int(time.time())
        write_matching_preboot(real, NONCE, now - 60)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        link = ev / "host-preboot.txt"
        link.symlink_to(real)
        rc, err = run_check(ev, NONCE, link)
        results.append(verdict("R4-1b", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        work = root / "work"
        work.mkdir()
        now = int(time.time())
        write_matching_preboot(work / "host-preboot.txt", NONCE, now - 60)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        escape = ev / ".." / "work" / "host-preboot.txt"
        rc, err = run_check(ev, NONCE, escape)
        results.append(verdict("R4-1d", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        now = int(time.time())
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        preboot = root / "work2" / "host-preboot.txt"
        write_matching_preboot(preboot, NONCE, now - 5)
        rc, err = run_check(ev, NONCE, preboot)
        results.append(verdict("R4-2", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        now = int(time.time())
        future = now + 86400
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (future, future))
        preboot = root / "host-preboot.txt"
        write_matching_preboot(preboot, NONCE, now - 60)
        rc, err = run_check(ev, NONCE, preboot)
        results.append(verdict("R4-3", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "empty-suite", 0, 0, 0, status="PASS", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(verdict("R4-4a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(verdict("R4-5a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        mod.write_suite(ev, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "confine2.status").write_text("FAIL\n")
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "qemu-console.txt").write_text(console + "\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(verdict("R4-7a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        work_a = root / "work-a"
        work_b = root / "work-b"
        now = int(time.time())
        write_matching_preboot(work_a / "host-preboot.txt", NONCE, now - 60)
        write_matching_preboot(work_b / "host-preboot.txt", NONCE, now - 60)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        rc, err = run_check(ev, NONCE, work_b / "host-preboot.txt")
        results.append(verdict("R4-8a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        now = int(time.time())
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        preboot = root / "host-preboot.txt"
        write_matching_preboot(preboot, NONCE, 0)
        rc, err = run_check(ev, NONCE, preboot)
        results.append(verdict("R4-9b", rc, True, err.replace("\n", " | ")))

    host_text = HOST.read_text() if HOST.is_file() else ""
    work_outside = (
        'WORK="${LC_GUEST_WORK:-/tmp/linux-confine-aarch64}"' in host_text
        and 'path="$EVIDENCE"' in host_text
        and "security_model=mapped-xattr" in host_text
        and '"$WORK/host-preboot.txt"' in host_text
        and "run_id=" in host_text
        and "work=" in host_text
    )
    print(
        f"{'CAUGHT' if work_outside else 'SURVIVED'}\t"
        f"R4-1e-wrapper-preboot-off-9p\trc={0 if work_outside else 1}\t"
        "script keeps host-preboot in $WORK bound to run_id and work="
    )
    results.append("CAUGHT" if work_outside else "SURVIVED")

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"summary: {caught} CAUGHT, {survived} SURVIVED, {len(results)} plants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
