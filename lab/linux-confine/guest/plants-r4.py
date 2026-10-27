#!/usr/bin/env python3
"""R4 leftover plants against the C9 host checker.

Each case uses the live four-line preboot (nonce_sha256, run_start,
run_id, work=) so a CAUGHT row fails on its named leftover, not on a
missing run_id or work= line. Exit 0 always: this file is a report.
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


def write_live_preboot(
    path: pathlib.Path,
    nonce: str,
    work: pathlib.Path,
    run_start: int | None = None,
    run_id: str | None = None,
) -> str:
    """Mint the same four-line record the live wrapper writes."""
    if run_start is None:
        run_start = int(time.time()) - 60
    if run_id is None:
        run_id = hashlib.sha256(f"{nonce}:{path}:{work}".encode()).hexdigest()[:16]
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    path.write_text(
        f"nonce_sha256={digest}\n"
        f"run_start={run_start}\n"
        f"run_id={run_id}\n"
        f"work={pathlib.Path(work).resolve()}\n"
    )
    return run_id


def append_host_last(ev: pathlib.Path, work: pathlib.Path, run_id: str) -> None:
    hc = ev / "host-context.txt"
    with hc.open("a") as handle:
        handle.write(f"work={pathlib.Path(work).resolve()}\n")
        handle.write(f"run_id={run_id}\n")


def touch_now(ev: pathlib.Path, when: int | None = None) -> None:
    now = int(time.time()) if when is None else when
    for child in ev.iterdir():
        if child.is_file() and child.name != "RESULTS.txt":
            os.utime(child, (now, now))


def run_check(
    ev: pathlib.Path,
    nonce: str,
    preboot: pathlib.Path,
    ledger: pathlib.Path,
) -> tuple[int, str]:
    env = os.environ.copy()
    env["LC_USED_NONCES"] = str(ledger)
    p = subprocess.run(
        [
            sys.executable,
            str(CHECK),
            str(ev),
            str(EXPECTED),
            nonce,
            "full",
            str(preboot),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=env,
    )
    return p.returncode, (p.stderr or "").strip()


def honest_tree(
    root: pathlib.Path, nonce: str = NONCE, *, work_name: str = "work"
) -> tuple[pathlib.Path, pathlib.Path, str]:
    ev = root / "ev"
    work = root / work_name
    ev.mkdir()
    work.mkdir()
    mod.populate(ev, nonce)
    run_id = write_live_preboot(work / "host-preboot.txt", nonce, work)
    append_host_last(ev, work, run_id)
    touch_now(ev)
    return ev, work, run_id


def verdict(name: str, rc: int, want_fail: bool, note: str) -> str:
    label = "CAUGHT" if (rc != 0) == want_fail else "SURVIVED"
    print(f"{label}\t{name}\trc={rc}\t{note}")
    return label


def main() -> int:
    print(f"checker={CHECK}")
    results: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        link = ev / "host-preboot.txt"
        link.symlink_to(work / "host-preboot.txt")
        rc, err = run_check(ev, NONCE, link, ledger)
        results.append(verdict("R4-1b", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        escape = ev / ".." / work.name / "host-preboot.txt"
        rc, err = run_check(ev, NONCE, escape, ledger)
        results.append(verdict("R4-1d", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        touch_now(ev)
        write_live_preboot(work / "host-preboot.txt", NONCE, work, run_id="b" * 16)
        append_host_last(ev, work, "b" * 16)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        results.append(
            verdict(
                "R4-2",
                rc,
                True,
                f"same nonce, new run_id, first_rc={rc1}. " + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        touch_now(ev, int(time.time()) + 86400)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        results.append(verdict("R4-3", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "empty-suite", 0, 0, 0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        results.append(verdict("R4-4a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        ledger = root / "host-used-nonces.txt"
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work)
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        results.append(verdict("R4-5a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        mod.write_suite(ev, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "confine2.status").write_text("FAIL\n")
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
        results.append(verdict("R4-7a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work_a, run_id = honest_tree(root, work_name="work-a")
        work_b = root / "work-b"
        work_b.mkdir()
        ledger = root / "host-used-nonces.txt"
        write_live_preboot(work_b / "host-preboot.txt", NONCE, work_b, run_id=run_id)
        rc, err = run_check(ev, NONCE, work_b / "host-preboot.txt", ledger)
        results.append(verdict("R4-8a", rc, True, err.replace("\n", " | ")))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        ledger = root / "host-used-nonces.txt"
        mod.populate(ev, NONCE)
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work, run_start=0)
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger)
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
