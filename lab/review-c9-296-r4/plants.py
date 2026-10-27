#!/usr/bin/env python3
"""New r4 plants against the C9 host checker at c7c07e3b.

These are not the author's M1-M11. Each case prints CAUGHT or SURVIVED.
Exit 0 always: this file is a report, not a gate.
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
SRC = pathlib.Path("/tmp/review-c9-296-r4-src/lab/linux-confine/guest")
if not (SRC / "check-guest-results.py").is_file():
    SRC = pathlib.Path("/workspace/lab/linux-confine/guest")
CHECK = SRC / "check-guest-results.py"
EXPECTED = SRC / "expected.json"
HOST = SRC.parent / "run-aarch64-guest.sh"

sys.path.insert(0, str(SRC))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "cgr_test", SRC / "check-guest-results.test.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NONCE = "abc"


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
    if want_fail:
        label = "CAUGHT" if rc != 0 else "SURVIVED"
    else:
        label = "CAUGHT" if rc == 0 else "SURVIVED"
    print(f"{label}\t{name}\trc={rc}\t{note}")
    return label


def write_matching_preboot(path: pathlib.Path, nonce: str, run_start: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    path.write_text(f"nonce_sha256={digest}\nrun_start={run_start}\n")


def main() -> int:
    print(f"checker={CHECK}")
    print(f"head_src={SRC}")
    results: list[str] = []

    # R3 leftovers the author claims closed — rerun as plants.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "elf", 6, 0, 0) + "\n"
        (ev / "qemu-console.txt").write_text(console)
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R3-dup-lc-mark",
                rc,
                want_fail=True,
                note="duplicate LC_MARK last matches 9p. " + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=01\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R3-guest-exit-01",
                rc,
                want_fail=True,
                note="guest_exit=01 substring. " + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        yesterday = int(time.time()) - 86400
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (yesterday, yesterday))
        preboot = root / "host-preboot.txt"
        write_matching_preboot(preboot, NONCE, int(time.time()))
        rc, err = run_check(ev, NONCE, preboot)
        results.append(
            verdict(
                "R3-replay-old-mtime",
                rc,
                want_fail=True,
                note="old tree, matching nonce, mtimes before run_start. "
                + err.replace("\n", " | "),
            )
        )

    # R4-1: guest-writable preboot via path inside 9p, symlink, or escape.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        now = int(time.time())
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        inside = ev / "host-preboot.txt"
        write_matching_preboot(inside, NONCE, now - 60)
        rc, err = run_check(ev, NONCE, inside)
        results.append(
            verdict(
                "R4-1a-preboot-inside-evidence",
                rc,
                want_fail=True,
                note="PREBOOT path is a regular file inside evidence. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        outside = root / "work"
        outside.mkdir()
        real = outside / "host-preboot.txt"
        now = int(time.time())
        write_matching_preboot(real, NONCE, now - 60)
        ev.mkdir(exist_ok=True)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        link = ev / "host-preboot.txt"
        link.symlink_to(real)
        rc, err = run_check(ev, NONCE, link)
        results.append(
            verdict(
                "R4-1b-preboot-symlink-inside-to-outside",
                rc,
                want_fail=True,
                note="PREBOOT is a symlink in evidence that resolves outside. "
                "resolve() may hide the 9p path. " + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        work = root / "work"
        work.mkdir()
        now = int(time.time())
        forged = ev / "forged-preboot.txt"
        write_matching_preboot(forged, NONCE, now - 60)
        link = work / "host-preboot.txt"
        link.symlink_to(forged)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        rc, err = run_check(ev, NONCE, link)
        results.append(
            verdict(
                "R4-1c-work-preboot-symlink-into-evidence",
                rc,
                want_fail=True,
                note="WORK/host-preboot.txt is a symlink into evidence. "
                + err.replace("\n", " | "),
            )
        )

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
        # Guest-style relative escape path the host might accidentally pass.
        escape = ev / ".." / "work" / "host-preboot.txt"
        rc, err = run_check(ev, NONCE, escape)
        results.append(
            verdict(
                "R4-1d-preboot-dotdot-path",
                rc,
                want_fail=True,
                note="PREBOOT is evidence/../work/host-preboot.txt (resolves outside). "
                + err.replace("\n", " | "),
            )
        )

    # R4-2: same nonce reused across two runs, files touched fresh.
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
        results.append(
            verdict(
                "R4-2-nonce-reuse-fresh-mtime",
                rc,
                want_fail=True,
                note="complete tree + same nonce + new preboot run_start + touch. "
                "want fail if a nonce cannot be reused. " + err.replace("\n", " | "),
            )
        )

    # R4-3: evidence mtime forged into the future.
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
        results.append(
            verdict(
                "R4-3-future-mtime",
                rc,
                want_fail=True,
                note="honest counts, mtimes one day in the future. "
                "want fail if mtime must sit in [run_start, now]. "
                + err.replace("\n", " | "),
            )
        )

    # R4-4: LC_MARK for a suite with zero tests.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "empty-suite", 0, 0, 0, status="PASS", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-4a-extra-zero-test-suite-mark",
                rc,
                want_fail=True,
                note="extra LC_MARK suite=empty-suite passed=0. "
                "want fail if unknown suites are refused. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        mod.write_suite(ev, "elf", 0, 0, 0, status="PASS", rc=0)
        console = (ev / "qemu-console.txt").read_text().splitlines()
        console = [ln for ln in console if "suite=elf " not in ln]
        console.append(mod.mark_line(NONCE, "elf", 0, 0, 0))
        (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-4b-standing-suite-zero-tests",
                rc,
                want_fail=True,
                note="elf 9p+mark say 0 passed vs expected 6. "
                + err.replace("\n", " | "),
            )
        )

    # R4-5: guest_exit trailing NUL or CRLF.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-5a-guest-exit-crlf",
                rc,
                want_fail=True,
                note="guest_exit=0 CRLF. want fail if only LF is canonical. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\x00\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-5b-guest-exit-trailing-nul",
                rc,
                want_fail=True,
                note="guest_exit=0 + NUL + LF. " + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\n\x00")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-5c-guest-exit-nul-second-line",
                rc,
                want_fail=True,
                note="guest_exit=0 LF then NUL. " + err.replace("\n", " | "),
            )
        )

    # R4-6: qemu killed mid-run, stale complete evidence still present.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE, qemu_exit=137)
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-6a-qemu-137-with-complete-tree",
                rc,
                want_fail=True,
                note="complete PASS tree + qemu_exit=137. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        (ev / "host-context.txt").write_text(
            "label=" + mod.EXPECTED["label"] + "\n"
        )
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-6b-qemu-killed-before-exit-line",
                rc,
                want_fail=True,
                note="complete tree, qemu_exit missing. "
                + err.replace("\n", " | "),
            )
        )

    # R4-7: suite name collision confine vs confine2.
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
        results.append(
            verdict(
                "R4-7a-extra-confine2-fail-ignored",
                rc,
                want_fail=True,
                note="honest confine plus failing confine2 mark+files. "
                "want fail if unknown colliding names are refused. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp) / "ev"
        ev.mkdir()
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().splitlines()
        console = [ln for ln in console if "suite=confine " not in ln]
        console.append(mod.mark_line(NONCE, "confine2", 25, 0, 0))
        (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
        rc, err = run_check(ev, NONCE, None)
        results.append(
            verdict(
                "R4-7b-only-confine2-mark",
                rc,
                want_fail=True,
                note="standing confine mark replaced by confine2. "
                + err.replace("\n", " | "),
            )
        )

    # R4-8: checker invoked with a different $WORK preboot.
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
        results.append(
            verdict(
                "R4-8a-other-work-matching-hash",
                rc,
                want_fail=True,
                note="PREBOOT is work-b, not the run's work-a. same hash. "
                "want fail if path must be the minting WORK. "
                + err.replace("\n", " | "),
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        ev.mkdir()
        now = int(time.time())
        write_matching_preboot(root / "work-b" / "host-preboot.txt", "other-nonce", now - 60)
        mod.populate(ev, NONCE)
        for child in ev.iterdir():
            if child.is_file():
                os.utime(child, (now, now))
        rc, err = run_check(ev, NONCE, root / "work-b" / "host-preboot.txt")
        results.append(
            verdict(
                "R4-8b-other-work-other-nonce",
                rc,
                want_fail=True,
                note="PREBOOT hash is for a different nonce. "
                + err.replace("\n", " | "),
            )
        )

    # R4-9: clock skew / run_start boundary.
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
        write_matching_preboot(preboot, NONCE, now + 30)
        rc, err = run_check(ev, NONCE, preboot)
        results.append(
            verdict(
                "R4-9a-host-clock-ahead-of-files",
                rc,
                want_fail=True,
                note="run_start 30s after file mtimes (host clock ahead / guest behind). "
                + err.replace("\n", " | "),
            )
        )

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
        results.append(
            verdict(
                "R4-9b-run-start-zero",
                rc,
                want_fail=True,
                note="run_start=0 disables the age check. "
                + err.replace("\n", " | "),
            )
        )

    # Wrapper source: 9p share is EVIDENCE, preboot is $WORK, mapped-xattr.
    host_text = HOST.read_text() if HOST.is_file() else ""
    work_outside = (
        'WORK="${LC_GUEST_WORK:-/tmp/linux-confine-aarch64}"' in host_text
        and 'path="$EVIDENCE"' in host_text
        and 'security_model=mapped-xattr' in host_text
        and '"$WORK/host-preboot.txt"' in host_text
    )
    print(
        f"{'CAUGHT' if work_outside else 'SURVIVED'}\t"
        f"R4-1e-wrapper-preboot-off-9p\trc={0 if work_outside else 1}\t"
        f"script keeps host-preboot in $WORK and 9p on $EVIDENCE mapped-xattr"
    )
    results.append("CAUGHT" if work_outside else "SURVIVED")

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"summary: {caught} CAUGHT, {survived} SURVIVED, {len(results)} plants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
