#!/usr/bin/env python3
"""R6 leftover plants against the C9 host checker at 862f4c88 / 4396d77e.

Hunt NEW ways to turn a failed or replayed boot into checker rc=0
(HOST_EXIT=0), and false-FAIL / hang cases on a first-ever or crashed
ledger. Does not edit lab/linux-confine/.

Exit 0 always: this file is a report, not a gate.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
SRC = pathlib.Path("/tmp/review-c9-442-r6-src/lab/linux-confine/guest")
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


def write_live_preboot(
    path: pathlib.Path,
    nonce: str,
    work: pathlib.Path,
    run_start: int | None = None,
    run_id: str | None = None,
) -> str:
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
    *,
    ledger: pathlib.Path | None = None,
    xdg: pathlib.Path | None = None,
    home: pathlib.Path | None = None,
    extra_env: dict[str, str] | None = None,
    drop_lc: bool = False,
) -> tuple[int, str]:
    env = os.environ.copy()
    if drop_lc:
        env.pop("LC_USED_NONCES", None)
    if ledger is not None:
        env["LC_USED_NONCES"] = str(ledger)
    elif drop_lc or xdg is not None:
        env.pop("LC_USED_NONCES", None)
    if xdg is not None:
        env["XDG_RUNTIME_DIR"] = str(xdg)
    if home is not None:
        env["HOME"] = str(home)
    if extra_env:
        env.update(extra_env)
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
    err = (p.stderr or "").strip()
    return p.returncode, err


def honest_tree(
    root: pathlib.Path,
    nonce: str = NONCE,
    *,
    work_name: str = "work",
    ev_name: str = "ev",
) -> tuple[pathlib.Path, pathlib.Path, str]:
    ev = root / ev_name
    work = root / work_name
    ev.mkdir()
    work.mkdir()
    mod.populate(ev, nonce)
    run_id = write_live_preboot(work / "host-preboot.txt", nonce, work)
    append_host_last(ev, work, run_id)
    touch_now(ev)
    return ev, work, run_id


def verdict(name: str, rc: int, want_fail: bool, note: str) -> str:
    if want_fail:
        label = "CAUGHT" if rc != 0 else "SURVIVED"
    else:
        label = "CAUGHT" if rc == 0 else "SURVIVED"
    one = note.replace("\n", " | ")
    if len(one) > 280:
        one = one[:277] + "..."
    print(f"{label}\t{name}\trc={rc}\t{one}")
    return label


def wrapper_text() -> str:
    return HOST.read_text() if HOST.is_file() else ""


def main() -> int:
    print(f"checker={CHECK}")
    print(f"head_src={SRC}")
    results: list[str] = []
    host = wrapper_text()

    # Control: honest live-format fixture must PASS.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-honest-pass",
                rc,
                want_fail=False,
                note="complete live-format fixture. " + err,
            )
        )

    # First-ever run: ledger file missing. Must not false-FAIL.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "never-created-ledger.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-missing-ledger-first-run",
                rc,
                want_fail=False,
                note="LC_USED_NONCES path does not exist yet. " + err,
            )
        )

    # First-ever via default XDG path (no LC_USED_NONCES), empty runtime dir.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        xdg = pathlib.Path(tmp) / "xdg-empty"
        xdg.mkdir()
        rc, err = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        results.append(
            verdict(
                "R6-missing-xdg-ledger-first-run",
                rc,
                want_fail=False,
                note="fresh XDG_RUNTIME_DIR, no ledger file. " + err,
            )
        )

    # Stale lock file left next to the ledger. There is no flock today.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        xdg = pathlib.Path(tmp) / "xdg-lock"
        lockdir = xdg / "linux-confine"
        lockdir.mkdir(parents=True)
        (lockdir / "used-nonces.lock").write_text("stale pid 1\n")
        t0 = time.time()
        rc, err = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        dt = time.time() - t0
        hung = dt > 5
        results.append(
            verdict(
                "R6-stale-lock-no-hang",
                1 if hung else rc,
                want_fail=False,
                note=f"stale lock file present, elapsed={dt:.3f}s hung={hung}. " + err,
            )
        )

    # --- R5 leftovers claimed closed: replay with pinned ledger ---

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev1, work1, run_id = honest_tree(root, work_name="work1")
        ledger = root / "host-used-nonces.txt"
        rc1, _ = run_check(ev1, NONCE, work1 / "host-preboot.txt", ledger=ledger)
        ev2 = root / "ev2"
        work2 = root / "work2"
        shutil.copytree(ev1, ev2)
        work2.mkdir()
        write_live_preboot(work2 / "host-preboot.txt", NONCE, work2, run_id=run_id)
        append_host_last(ev2, work2, run_id)
        touch_now(ev2)
        rc2, err2 = run_check(ev2, NONCE, work2 / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-r5-1-nonce-new-work-pinned",
                rc2,
                want_fail=True,
                note=f"new $WORK, pinned LC_USED_NONCES, first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        used = work / "used-nonces.txt"
        if used.is_file():
            used.unlink()
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-r5-1-wipe-work-used-nonces",
                rc2,
                want_fail=True,
                note=f"unlink $WORK/used-nonces.txt, first_rc={rc1}. {err2}",
            )
        )

    # --- NEW: ledger identity is XDG/LC, not HOME or $WORK ---

    # Fresh XDG_RUNTIME_DIR after a PASS: default ledger path moves.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        xdg1 = root / "xdg1"
        xdg2 = root / "xdg2"
        xdg1.mkdir()
        xdg2.mkdir()
        rc1, _ = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg1, drop_lc=True
        )
        touch_now(ev)
        rc2, err2 = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg2, drop_lc=True
        )
        results.append(
            verdict(
                "R6-fresh-xdg-resets-ledger",
                rc2,
                want_fail=True,
                note=f"same nonce after new XDG_RUNTIME_DIR, first_rc={rc1}. {err2}",
            )
        )

    # Fresh HOME does not move the default ledger (XDG or /var/tmp).
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        xdg = root / "xdg-home"
        home1 = root / "home1"
        home2 = root / "home2"
        xdg.mkdir()
        home1.mkdir()
        home2.mkdir()
        rc1, _ = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, home=home1, drop_lc=True
        )
        touch_now(ev)
        rc2, err2 = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, home=home2, drop_lc=True
        )
        results.append(
            verdict(
                "R6-fresh-home-same-xdg",
                rc2,
                want_fail=True,
                note=f"new HOME, same XDG, first_rc={rc1}. {err2}",
            )
        )

    # Delete the host-side ledger file between two checks.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        xdg = root / "xdg-del"
        xdg.mkdir()
        rc1, _ = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        ledgers = list((xdg / "linux-confine").glob("used-nonces-*.txt"))
        for path in ledgers:
            path.unlink()
        touch_now(ev)
        rc2, err2 = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        results.append(
            verdict(
                "R6-delete-host-ledger",
                rc2,
                want_fail=True,
                note=(
                    f"unlinked {len(ledgers)} host ledger file(s), "
                    f"first_rc={rc1}. {err2}"
                ),
            )
        )

    # Ledger path inside evidence (guest 9p / same uid). Guest can unlink it.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = ev / "used-nonces-guest.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        if ledger.is_file():
            ledger.unlink()
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-ledger-inside-evidence",
                rc2,
                want_fail=True,
                note=f"LC_USED_NONCES under 9p evidence, unlinked, first_rc={rc1}. {err2}",
            )
        )

    # World-writable ledger created before the check. Checker chmod 0600
    # after write; a later chmod 0666 + truncate is a host/guest-uid wipe.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "wide-ledger.txt"
        ledger.write_text("")
        ledger.chmod(0o666)
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        try:
            mode_after = oct(ledger.stat().st_mode & 0o777)
        except OSError:
            mode_after = "missing"
        ledger.chmod(0o666)
        ledger.write_text("")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-world-writable-ledger-wipe",
                rc2,
                want_fail=True,
                note=(
                    f"pre-created 0666 ledger, mode_after_check={mode_after}, "
                    f"truncated, first_rc={rc1}. {err2}"
                ),
            )
        )

    # Parent dir of the default ledger is a symlink into evidence.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        xdg = root / "xdg-sym"
        real = ev / "guest-ledger-dir"
        real.mkdir()
        xdg.mkdir()
        os.symlink(real, xdg / "linux-confine")
        rc1, _ = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        for child in real.iterdir():
            if child.is_file():
                child.unlink()
        touch_now(ev)
        rc2, err2 = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg, drop_lc=True
        )
        results.append(
            verdict(
                "R6-symlinked-ledger-dir",
                rc2,
                want_fail=True,
                note=f"XDG linux-confine -> evidence, wiped via guest path, first_rc={rc1}. {err2}",
            )
        )

    # Parallel same-nonce checks against one empty ledger (TOCTOU / lost update).
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev_a, work_a, _ = honest_tree(root, ev_name="ev-a", work_name="work-a")
        ev_b, work_b, _ = honest_tree(
            root, nonce=NONCE, ev_name="ev-b", work_name="work-b"
        )
        ledger = root / "host-used-nonces.txt"
        box: dict[str, tuple[int, str]] = {}

        def _one(tag: str, ev: pathlib.Path, work: pathlib.Path) -> None:
            box[tag] = run_check(
                ev, NONCE, work / "host-preboot.txt", ledger=ledger
            )

        t1 = threading.Thread(target=_one, args=("a", ev_a, work_a))
        t2 = threading.Thread(target=_one, args=("b", ev_b, work_b))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        rc_a, err_a = box.get("a", (1, "missing"))
        rc_b, err_b = box.get("b", (1, "missing"))
        both_pass = rc_a == 0 and rc_b == 0
        results.append(
            verdict(
                "R6-parallel-same-nonce",
                0 if both_pass else 1,
                want_fail=True,
                note=(
                    f"two concurrent checks rc=({rc_a},{rc_b}) "
                    f"err_a={err_a!s} err_b={err_b!s}"
                )[:280],
            )
        )

    # Crash mid-write: truncate the ledger to a partial digest, replay.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        raw = ledger.read_text() if ledger.is_file() else ""
        if raw:
            ledger.write_text(raw[:17])
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-partial-ledger-write",
                rc2,
                want_fail=True,
                note=f"ledger truncated to 17 bytes after first_rc={rc1}. {err2}",
            )
        )

    # Crash after open-truncates: empty ledger, replay.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        ledger.write_text("")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-empty-ledger-after-crash",
                rc2,
                want_fail=True,
                note=f"ledger emptied after first_rc={rc1}. {err2}",
            )
        )

    # Lost-update: two sequential records with a planted mid-write snapshot.
    # The live code is read-modify-write (not O_APPEND). Replay the lost digest.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev1, work1, _ = honest_tree(root, nonce="aaa", ev_name="ev1", work_name="w1")
        ev2, work2, _ = honest_tree(root, nonce="bbb", ev_name="ev2", work_name="w2")
        ev3, work3, _ = honest_tree(root, nonce="aaa", ev_name="ev3", work_name="w3")
        ledger = root / "host-used-nonces.txt"
        rc_a, _ = run_check(ev1, "aaa", work1 / "host-preboot.txt", ledger=ledger)
        rc_b, _ = run_check(ev2, "bbb", work2 / "host-preboot.txt", ledger=ledger)
        # Simulate B's write_text losing A's line (classic RMW race):
        # B read empty, then overwrote the file with only bbb.
        digest_b = hashlib.sha256(b"bbb").hexdigest()
        ledger.write_text(f"{digest_b} - unknown\n")
        touch_now(ev3)
        rc_replay, err = run_check(
            ev3, "aaa", work3 / "host-preboot.txt", ledger=ledger
        )
        results.append(
            verdict(
                "R6-rmw-lost-update",
                rc_replay,
                want_fail=True,
                note=(
                    f"RMW lost nonce aaa after rc_a={rc_a} rc_b={rc_b}. {err}"
                ),
            )
        )

    # Source: record_used_nonce uses write_text, not O_APPEND + flock.
    src = CHECK.read_text()
    rmw = (
        "used.write_text(" in src
        and "O_APPEND" not in src
        and "flock" not in src
        and "fcntl" not in src
    )
    results.append(
        verdict(
            "R6-ledger-not-oappend-locked",
            0 if rmw else 1,
            want_fail=False,
            note="checker record_used_nonce is read-modify-write with write_text; no flock/O_APPEND",
        )
    )

    # Clock backwards: run_start in the past still PASSes (not a future).
    # A true clock step-back that makes run_start > now is a false FAIL.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        write_live_preboot(
            work / "host-preboot.txt",
            NONCE,
            work,
            run_start=int(time.time()) - 3600,
            run_id=run_id,
        )
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-clock-run-start-one-hour-past",
                rc,
                want_fail=False,
                note="run_start = now-3600, files now. " + err,
            )
        )

    # Simulate clock step-back: run_start is 30s ahead of checker's now.
    # That is how a backwards step looks. Honest tree then false-FAILs.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        write_live_preboot(
            work / "host-preboot.txt",
            NONCE,
            work,
            run_start=int(time.time()) + 30,
            run_id=run_id,
        )
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-clock-step-back-false-fail",
                rc,
                want_fail=True,
                note="run_start=now+30 models a clock step-back. " + err,
            )
        )

    # Preboot TOCTOU: nlink==1 at check, then rename a hardlinked inode over it.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        pb = work / "host-preboot.txt"
        other = pathlib.Path(tmp) / "other-preboot"
        shutil.copy2(pb, other)
        stop = threading.Event()
        swapped = {"n": 0}

        def _swap() -> None:
            for _ in range(4000):
                try:
                    if pb.exists() and pb.stat().st_nlink == 1:
                        os.link(other, pathlib.Path(tmp) / "hl")
                        os.replace(other, pb)
                        swapped["n"] += 1
                        return
                except OSError:
                    pass
                if stop.is_set():
                    return
                time.sleep(0.0005)

        thr = threading.Thread(target=_swap, daemon=True)
        thr.start()
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc, err = run_check(ev, NONCE, pb, ledger=ledger)
        stop.set()
        thr.join(timeout=2)
        nlink_after = pb.stat().st_nlink if pb.exists() else -1
        # A PASS while nlink>1 after the swap is a nlink TOCTOU bypass.
        bypass = rc == 0 and nlink_after > 1
        results.append(
            verdict(
                "R6-preboot-rename-toctou",
                0 if bypass else 1,
                want_fail=True,
                note=(
                    f"swaps={swapped['n']} nlink_after={nlink_after} rc={rc}. {err}"
                ),
            )
        )

    # Guest exit forged only on the serial console. File stays guest_exit=1.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=1\n")
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work)
        append_host_last(ev, work, run_id)
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\nguest_exit=0\n"
        console += "\n" + mod.mark_line(NONCE, "guest", 0, 0, 0, status="DONE", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        ledger = root / "host-used-nonces.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-serial-forged-guest-exit",
                rc,
                want_fail=True,
                note="guest-exit.txt is 1; console has guest_exit=0 + guest mark. " + err,
            )
        )

    # QEMU killed (137) then host-context rewritten to 0. Same ledger.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        hc = ev / "host-context.txt"
        text = hc.read_text()
        hc.write_text(text.replace("qemu_exit=0", "qemu_exit=137"))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, err1 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        hc.write_text(hc.read_text().replace("qemu_exit=137", "qemu_exit=0"))
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-qemu137-rewrite-same-ledger",
                rc2,
                want_fail=True,
                note=f"rewrite 137->0, same ledger, first_rc={rc1}. {err2}",
            )
        )

    # Same rewrite, but a fresh XDG so the recorded nonce is gone.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_id = honest_tree(root)
        hc = ev / "host-context.txt"
        hc.write_text(hc.read_text().replace("qemu_exit=0", "qemu_exit=137"))
        xdg1 = root / "xdg-kill-1"
        xdg2 = root / "xdg-kill-2"
        xdg1.mkdir()
        xdg2.mkdir()
        rc1, _ = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg1, drop_lc=True
        )
        hc.write_text(hc.read_text().replace("qemu_exit=137", "qemu_exit=0"))
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc2, err2 = run_check(
            ev, NONCE, work / "host-preboot.txt", xdg=xdg2, drop_lc=True
        )
        results.append(
            verdict(
                "R6-qemu137-rewrite-fresh-xdg",
                rc2,
                want_fail=True,
                note=f"rewrite 137->0 after new XDG, first_rc={rc1}. {err2}",
            )
        )

    # Timeout path never calls the checker (no LABEL). Nonce never recorded.
    # A later checker-only call on a forged PASS tree reuses that preboot.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        # Simulate wrapper early-exit: do not call the checker.
        # Then present a complete PASS tree with the unused nonce.
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-timeout-skip-then-forged-pass",
                rc,
                want_fail=True,
                note=(
                    "wrapper timeout exits before checker, so this first "
                    "checker-only call on a forged PASS tree is rc=0. "
                    + err
                ),
            )
        )

    wrapper_early = (
        'echo "guest did not print the required TCG label"' in host
        and "python3 \"$LAB/guest/check-guest-results.py\"" in host
        and host.find('echo "guest did not print the required TCG label"')
        < host.find("=== host check of guest results ===")
    )
    results.append(
        verdict(
            "R6-wrapper-timeout-skips-checker",
            0 if wrapper_early else 1,
            want_fail=False,
            note="run-aarch64-guest.sh exits 1 on missing LABEL before the checker, so the nonce is never recorded",
        )
    )

    wrapper_no_pin = "LC_USED_NONCES" not in host
    results.append(
        verdict(
            "R6-wrapper-does-not-pin-ledger",
            0 if wrapper_no_pin else 1,
            want_fail=False,
            note="live wrapper never sets LC_USED_NONCES; ledger follows XDG_RUNTIME_DIR or /var/tmp",
        )
    )

    # Stale symlink at the ledger path: honest first run false-FAILs.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        xdg = pathlib.Path(tmp) / "xdg-stale"
        (xdg / "linux-confine").mkdir(parents=True)
        target = pathlib.Path(tmp) / "gone"
        link = xdg / "linux-confine" / "used-nonces-stale.txt"
        # Name must match used-nonces-{boot_id}.txt. Use LC override instead.
        ledger = pathlib.Path(tmp) / "stale-link"
        os.symlink(target, ledger)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-stale-symlink-ledger-false-fail",
                rc,
                want_fail=True,
                note="honest tree, ledger path is a dangling symlink. " + err,
            )
        )

    # path_is_alias does not check the parent directory.
    src_alias = "def path_is_alias" in src and "used.parent" not in src.split("def path_is_alias")[1][:400]
    results.append(
        verdict(
            "R6-alias-ignores-parent-dir",
            0 if src_alias else 1,
            want_fail=False,
            note="path_is_alias checks the ledger file only, not a symlinked parent",
        )
    )

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"summary: {caught} CAUGHT, {survived} SURVIVED, {len(results)} plants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
