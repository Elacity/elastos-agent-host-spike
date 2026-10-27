#!/usr/bin/env python3
"""R6 leftover plants against the C9 host checker.

Hunt the r6 survivors (unused timeout nonce, XDG reset, unlinked or
emptied ledger, parent symlink into evidence, RMW/crash) and the two
false-FAIL cases (leftover ledger symlink, clock step-back). Each
survivor must be CAUGHT. False-FAIL rows must name their reason.

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
SRC = HERE
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

cgr_spec = importlib.util.spec_from_file_location("cgr", CHECK)
cgr = importlib.util.module_from_spec(cgr_spec)
cgr_spec.loader.exec_module(cgr)

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
    drop_lc: bool = False,
) -> tuple[int, str]:
    env = os.environ.copy()
    if drop_lc:
        env.pop("LC_USED_NONCES", None)
    if ledger is not None:
        env["LC_USED_NONCES"] = str(ledger)
    if xdg is not None:
        env["XDG_RUNTIME_DIR"] = str(xdg)
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


def mint_nonce(ledger: pathlib.Path, nonce: str, run_id: str) -> int:
    p = subprocess.run(
        [
            sys.executable,
            str(CHECK),
            "--mint-nonce",
            str(ledger),
            nonce,
            run_id,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    return p.returncode


def consume_run(ledger: pathlib.Path, run_id: str) -> int:
    p = subprocess.run(
        [
            sys.executable,
            str(CHECK),
            "--consume-run",
            str(ledger),
            run_id,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    return p.returncode


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
    src = CHECK.read_text()

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

    # Default ledger ignores XDG_RUNTIME_DIR.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        xdg1 = root / "xdg1"
        xdg2 = root / "xdg2"
        xdg1.mkdir()
        xdg2.mkdir()
        env_save = os.environ.pop("LC_USED_NONCES", None)
        try:
            os.environ["XDG_RUNTIME_DIR"] = str(xdg1)
            p1 = str(cgr.used_nonce_path(root))
            os.environ["XDG_RUNTIME_DIR"] = str(xdg2)
            p2 = str(cgr.used_nonce_path(root))
        finally:
            os.environ.pop("XDG_RUNTIME_DIR", None)
            if env_save is not None:
                os.environ["LC_USED_NONCES"] = env_save
        pinned = p1.startswith("/var/tmp/linux-confine/used-nonces-") and p1 == p2
        results.append(
            verdict(
                "R6-fresh-xdg-resets-ledger",
                0 if pinned else 1,
                want_fail=False,
                note=f"used_nonce_path ignores XDG ({p1} vs {p2})",
            )
        )

    # Same nonce after a new XDG still hits the pinned ledger.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_id = honest_tree(root)
        ledger = root / "host-used-nonces.txt"
        mint_nonce(ledger, NONCE, run_id)
        consume_run(ledger, run_id)
        xdg = root / "xdg-fresh"
        xdg.mkdir()
        rc, err = run_check(
            ev, NONCE, work / "host-preboot.txt", ledger=ledger, xdg=xdg
        )
        results.append(
            verdict(
                "R6-qemu137-rewrite-fresh-xdg",
                rc,
                want_fail=True,
                note="minted nonce then new XDG still uses pinned ledger. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        if ledger.is_file():
            ledger.unlink()
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-delete-host-ledger",
                rc2,
                want_fail=True,
                note=f"unlink host ledger after first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        ledger = ev / "used-nonces-in-evidence.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-ledger-inside-evidence",
                rc,
                want_fail=True,
                note="LC_USED_NONCES under 9p evidence. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        ledger.write_text("")
        ledger.chmod(0o666)
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        ledger.chmod(0o666)
        ledger.write_text("")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-world-writable-ledger-wipe",
                rc2,
                want_fail=True,
                note=f"chmod 0666 then truncate after first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        alias_parent = root / "alias-parent"
        os.symlink(ev, alias_parent)
        ledger = alias_parent / "used-nonces.txt"
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-symlinked-ledger-dir",
                rc,
                want_fail=True,
                note="ledger parent is a symlink into evidence. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        if ledger.is_file():
            ledger.write_bytes(ledger.read_bytes()[:17])
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-partial-ledger-write",
                rc2,
                want_fail=True,
                note=f"truncate ledger to 17 bytes after first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        if ledger.is_file():
            ledger.write_text("")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-empty-ledger-after-crash",
                rc2,
                want_fail=True,
                note=f"empty ledger after first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        snapshot = ledger.read_text() if ledger.is_file() else ""
        # Replay the first-line-only snapshot (lost later appends).
        stale = "\n".join(snapshot.splitlines()[:1])
        if stale:
            ledger.write_text(stale + "\n")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        locked = "O_APPEND" in src and "flock" in src and "fcntl" in src
        results.append(
            verdict(
                "R6-rmw-lost-update",
                rc2 if locked else 0,
                want_fail=True,
                note=f"stale RMW snapshot after first_rc={rc1} locked={locked}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        mint_nonce(ledger, NONCE, run_id)
        consume_run(ledger, run_id)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "R6-timeout-skip-then-forged-pass",
                rc,
                want_fail=True,
                note="wrapper mint+consume before checker, then forged PASS. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        mint_nonce(ledger, NONCE, run_id)
        consume_run(ledger, run_id)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        results.append(
            verdict(
                "LIVE-timeout-nonce-forged-pass-default-ledger",
                rc,
                want_fail=True,
                note="minted timeout nonce then forged PASS tree. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "host-used-nonces.txt"
        mint_nonce(ledger, NONCE, run_id)
        consume_run(ledger, run_id)
        xdg = pathlib.Path(tmp) / "xdg-fail-closed"
        xdg.mkdir()
        rc, err = run_check(
            ev, NONCE, work / "host-preboot.txt", ledger=ledger, xdg=xdg
        )
        results.append(
            verdict(
                "LIVE-fail-closed-nonce-fresh-xdg-pass",
                rc,
                want_fail=True,
                note="fail-closed mint then new XDG + PASS tree. " + err,
            )
        )

    wrapper_pins = (
        'export LC_USED_NONCES="/var/tmp/linux-confine/used-nonces-' in host
        and "--mint-nonce" in host
        and "trap consume_minted_run EXIT" in host
        and "$XDG_RUNTIME_DIR" not in host
    )
    results.append(
        verdict(
            "R6-wrapper-pins-ledger",
            0 if wrapper_pins else 1,
            want_fail=False,
            note="live wrapper pins LC_USED_NONCES to /var/tmp and mints before qemu",
        )
    )

    mint_before = host.find("--mint-nonce") < host.find("=== boot qemu-system-aarch64 TCG ===")
    results.append(
        verdict(
            "R6-wrapper-mints-before-qemu",
            0 if mint_before else 1,
            want_fail=False,
            note="--mint-nonce is recorded before qemu starts",
        )
    )

    locked = (
        "O_APPEND" in src
        and "flock" in src
        and "fcntl" in src
        and "write_text(" not in src.split("def record_used_nonce")[1][:400]
    )
    results.append(
        verdict(
            "R6-ledger-oappend-locked",
            0 if locked else 1,
            want_fail=False,
            note="record path uses flock and O_APPEND",
        )
    )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        ledger = pathlib.Path(tmp) / "stale-link"
        os.symlink(pathlib.Path(tmp) / "gone", ledger)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
        named = "leftover symlink" in err
        results.append(
            verdict(
                "R6-stale-symlink-ledger-false-fail",
                0 if (rc != 0 and named) else 1,
                want_fail=False,
                note="honest tree, leftover symlink, named reason. " + err,
            )
        )

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
        named = "ahead of the host clock" in err or "implausible" in err
        results.append(
            verdict(
                "R6-clock-step-back-false-fail",
                0 if (rc != 0 and named) else 1,
                want_fail=False,
                note="run_start=now+30 names the clock reason. " + err,
            )
        )

    # Parallel same nonce: one must lose. flock keeps this from flipping to 0,0.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev1, work1, _ = honest_tree(root, work_name="work1", ev_name="ev1")
        ev2 = root / "ev2"
        work2 = root / "work2"
        shutil.copytree(ev1, ev2)
        work2.mkdir()
        write_live_preboot(work2 / "host-preboot.txt", NONCE, work2)
        append_host_last(ev2, work2, (work2 / "host-preboot.txt").read_text().split("run_id=")[1].splitlines()[0])
        touch_now(ev2)
        ledger = root / "host-used-nonces.txt"
        rcs: list[int] = []

        def _one(ev: pathlib.Path, work: pathlib.Path) -> None:
            rc, _ = run_check(ev, NONCE, work / "host-preboot.txt", ledger=ledger)
            rcs.append(rc)

        t1 = threading.Thread(target=_one, args=(ev1, work1))
        t2 = threading.Thread(target=_one, args=(ev2, work2))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        pair_ok = sorted(rcs) in ([0, 1], [1, 1])
        results.append(
            verdict(
                "R6-parallel-same-nonce",
                0 if pair_ok else 1,
                want_fail=False,
                note=f"concurrent checks rcs={rcs}",
            )
        )

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"summary: {caught} CAUGHT, {survived} SURVIVED, {len(results)} plants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
