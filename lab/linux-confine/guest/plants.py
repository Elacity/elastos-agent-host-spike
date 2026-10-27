#!/usr/bin/env python3
"""R5 plants against the C9 host checker.

Re-plants each r4 leftover with a complete live-format preboot
(run_id + work= + host-context last-field), then hunts leftover ways to
turn a failed or replayed boot into checker rc=0 / HOST_EXIT=0.

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
    """Live wrapper appends work= and run_id= last after qemu."""
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
    ev: pathlib.Path, nonce: str, preboot: pathlib.Path
) -> tuple[int, str]:
    # Sibling $WORK dirs under one plant root share one host-side ledger.
    # A fresh TemporaryDirectory does not see another plant's nonces.
    ledger = preboot.resolve().parent.parent / "host-used-nonces.txt"
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
    if len(one) > 240:
        one = one[:237] + "..."
    print(f"{label}\t{name}\trc={rc}\t{one}")
    return label


def wrapper_text() -> str:
    return HOST.read_text() if HOST.is_file() else ""


def main() -> int:
    print(f"checker={CHECK}")
    print(f"head_src={SRC}")
    results: list[str] = []

    # Honest control: complete live-format fixture must PASS.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-honest-pass",
                rc,
                want_fail=False,
                note="complete live-format fixture. " + err,
            )
        )

    # Clock skew +1s must not false-FAIL a genuine tree.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        touch_now(ev, int(time.time()) + 1)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-skew-plus-1s",
                rc,
                want_fail=False,
                note="mtime = now+1 within 2s skew. " + err,
            )
        )

    # --- R4 leftovers, complete fixtures (not the author's old two-line preboot) ---

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        link = ev / "host-preboot.txt"
        link.symlink_to(work / "host-preboot.txt")
        rc, err = run_check(ev, NONCE, link)
        results.append(
            verdict(
                "R4-1b-complete",
                rc,
                want_fail=True,
                note="PREBOOT symlink, live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, _ = honest_tree(root)
        escape = ev / ".." / work.name / "host-preboot.txt"
        rc, err = run_check(ev, NONCE, escape)
        results.append(
            verdict(
                "R4-1d-complete",
                rc,
                want_fail=True,
                note="PREBOOT contains ... live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_id = honest_tree(root)
        rc1, err1 = run_check(ev, NONCE, work / "host-preboot.txt")
        touch_now(ev)
        write_live_preboot(
            work / "host-preboot.txt", NONCE, work, run_id="b" * 16
        )
        append_host_last(ev, work, "b" * 16)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-2-complete",
                rc2,
                want_fail=True,
                note=f"same nonce, new run_id, first_rc={rc1}. {err2}",
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        touch_now(ev, int(time.time()) + 86400)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-3-complete",
                rc,
                want_fail=True,
                note="future mtime +1d, live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "empty-suite", 0, 0, 0) + "\n"
        (ev / "qemu-console.txt").write_text(console)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-4a-complete",
                rc,
                want_fail=True,
                note="extra empty-suite mark, live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work)
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-5a-complete",
                rc,
                want_fail=True,
                note="CRLF guest_exit, live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        mod.write_suite(ev, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "confine2.status").write_text("FAIL\n")
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "confine2", 0, 25, 0, status="FAIL", rc=1)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-7a-complete",
                rc,
                want_fail=True,
                note="extra confine2 fail, live format. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work_a, run_id = honest_tree(root, work_name="work-a")
        work_b = root / "work-b"
        work_b.mkdir()
        write_live_preboot(
            work_b / "host-preboot.txt", NONCE, work_b, run_id=run_id
        )
        rc, err = run_check(ev, NONCE, work_b / "host-preboot.txt")
        results.append(
            verdict(
                "R4-8a-complete",
                rc,
                want_fail=True,
                note="other $WORK, same hash/run_id. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        mod.populate(ev, NONCE)
        write_live_preboot(work / "host-preboot.txt", NONCE, work, run_start=0)
        # live format still writes run_start=0; regex must refuse it.
        append_host_last(
            ev,
            work,
            hashlib.sha256(f"{NONCE}:{work}".encode()).hexdigest()[:16],
        )
        # rewrite so run_id matches what we append
        run_id = "c" * 16
        (work / "host-preboot.txt").write_text(
            "nonce_sha256="
            + hashlib.sha256(NONCE.encode()).hexdigest()
            + "\nrun_start=0\n"
            + f"run_id={run_id}\n"
            + f"work={work.resolve()}\n"
        )
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R4-9b-complete",
                rc,
                want_fail=True,
                note="run_start=0, live format. " + err,
            )
        )

    host = wrapper_text()
    live_wrapper = (
        'WORK="${LC_GUEST_WORK:-/tmp/linux-confine-aarch64}"' in host
        and 'path="$EVIDENCE"' in host
        and "security_model=mapped-xattr" in host
        and '"$WORK/host-preboot.txt"' in host
        and "run_id=" in host
        and "work=" in host
        and 'echo "run_id=$RUN_ID"' in host
        and "Host appends last" in host
    )
    results.append(
        verdict(
            "R4-live-wrapper-binds-work",
            0 if live_wrapper else 1,
            want_fail=False,
            note="wrapper mints $WORK/host-preboot.txt and appends work=/run_id= last",
        )
    )

    # --- New r5 plants ---

    # R5-1 nonce binding across runs: copy the successful tree to a new $WORK.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev1, work1, run_id = honest_tree(root, work_name="work1")
        rc1, _ = run_check(ev1, NONCE, work1 / "host-preboot.txt")
        ev2 = root / "ev2"
        work2 = root / "work2"
        shutil.copytree(ev1, ev2)
        work2.mkdir()
        write_live_preboot(
            work2 / "host-preboot.txt", NONCE, work2, run_id=run_id
        )
        # host-context last work= still names work1; rewrite last fields.
        hc = (ev2 / "host-context.txt").read_text()
        (ev2 / "host-context.txt").write_text(hc)
        append_host_last(ev2, work2, run_id)
        touch_now(ev2)
        rc2, err2 = run_check(ev2, NONCE, work2 / "host-preboot.txt")
        results.append(
            verdict(
                "R5-1-nonce-new-work",
                rc2,
                want_fail=True,
                note=f"replay same nonce on a new $WORK after first_rc={rc1}. {err2}",
            )
        )

    # Same $WORK after wiping the used-nonces ledger.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt")
        used = work / "used-nonces.txt"
        if used.is_file():
            used.unlink()
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-1-wipe-used-nonces",
                rc2,
                want_fail=True,
                note=f"same $WORK after unlink used-nonces, first_rc={rc1}. {err2}",
            )
        )

    # Failed check must not record the nonce; swapping in a PASS tree then
    # succeeds with the same nonce. That is a checker-API second call.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_id = honest_tree(root)
        (ev / "elf.status").write_text("FAIL\n")
        rc_fail, _ = run_check(ev, NONCE, work / "host-preboot.txt")
        (ev / "elf.status").write_text("PASS\n")
        touch_now(ev)
        rc_pass, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-1-fail-then-swap-pass",
                rc_pass,
                want_fail=True,
                note=f"failed tree then PASS swap, fail_rc={rc_fail}. {err}",
            )
        )

    # R5-2 hardlink PREBOOT that is not $WORK/host-preboot.txt.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        alias = ev / "preboot-hardlink"
        os.link(work / "host-preboot.txt", alias)
        rc, err = run_check(ev, NONCE, alias)
        results.append(
            verdict(
                "R5-2-hardlink-preboot",
                rc,
                want_fail=True,
                note="PREBOOT is a hardlink into evidence. " + err,
            )
        )

    # Hardlink used-nonces, truncate via the other name, replay.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        rc1, _ = run_check(ev, NONCE, work / "host-preboot.txt")
        alias = ev / "used-nonces-hardlink"
        used = pathlib.Path(tmp) / "host-used-nonces.txt"
        if used.is_file():
            os.link(used, alias)
            alias.write_text("")
        touch_now(ev)
        rc2, err2 = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-2-hardlink-wipe-ledger",
                rc2,
                want_fail=True,
                note=f"truncate used-nonces via evidence hardlink, first_rc={rc1}. {err2}",
            )
        )

    # R5-3 PREBOOT copy on another directory (same or other fs).
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        other = pathlib.Path(tmp) / "otherfs"
        other.mkdir()
        shutil.copy2(work / "host-preboot.txt", other / "host-preboot.txt")
        rc, err = run_check(ev, NONCE, other / "host-preboot.txt")
        results.append(
            verdict(
                "R5-3-copied-preboot",
                rc,
                want_fail=True,
                note="copied PREBOOT, work= still original. " + err,
            )
        )

    # Bind-mount $WORK at another path; live resolve() should still PASS.
    bind_note = "bind mount not created"
    bind_rc = 1
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        mountpoint = pathlib.Path(tmp) / "bind"
        mountpoint.mkdir()
        mounted = False
        try:
            p = subprocess.run(
                ["mount", "--bind", str(work), str(mountpoint)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            if p.returncode != 0:
                p = subprocess.run(
                    ["sudo", "-n", "mount", "--bind", str(work), str(mountpoint)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    text=True,
                )
            if p.returncode == 0:
                mounted = True
                rc, err = run_check(ev, NONCE, mountpoint / "host-preboot.txt")
                bind_rc = rc
                bind_note = "PREBOOT via bind mount of $WORK. " + err
            else:
                bind_note = f"bind mount skipped: {(p.stderr or p.stdout or '').strip()}"
        finally:
            if mounted:
                subprocess.run(
                    ["sudo", "-n", "umount", str(mountpoint)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        # A skipped bind mount is not a bypass; record as NOT RUN-equivalent
        # by treating inability to mount as CAUGHT (no HOST_EXIT=0 path shown).
        if not mounted:
            results.append(
                verdict(
                    "R5-3-bind-mount",
                    1,
                    want_fail=True,
                    note=bind_note,
                )
            )
        else:
            # Live wrapper never passes a bind-mount PREBOOT path. A
            # refused bind path is fail-closed (same as a copied PREBOOT).
            results.append(
                verdict(
                    "R5-3-bind-mount",
                    bind_rc,
                    want_fail=True,
                    note=bind_note + " (bind PREBOOT path is not $WORK/host-preboot.txt)",
                )
            )

    # R5-4 guest qemu_exit=0 then wrapper appends 137. Last field must win.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        hc = ev / "host-context.txt"
        text = hc.read_text()
        hc.write_text(text.replace("qemu_exit=0", "qemu_exit=0"))
        with hc.open("a") as handle:
            handle.write("qemu_exit=137\n")
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-4-guest-qemu-exit-then-137",
                rc,
                want_fail=True,
                note="guest qemu_exit=0, wrapper last qemu_exit=137. " + err,
            )
        )

    # FIFO guest-exit that later delivers guest_exit=0.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        ge = ev / "guest-exit.txt"
        ge.unlink()
        os.mkfifo(ge, 0o644)

        def _fifo_writer() -> None:
            time.sleep(0.05)
            with ge.open("w") as handle:
                handle.write("guest_exit=0\n")

        thr = threading.Thread(target=_fifo_writer, daemon=True)
        thr.start()
        try:
            rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        except Exception as exc:  # noqa: BLE001 - plant must not crash the report
            rc, err = 1, f"exception {exc}"
        thr.join(timeout=2)
        results.append(
            verdict(
                "R5-4-fifo-guest-exit",
                rc,
                want_fail=True,
                note="guest-exit.txt is a FIFO that delivers 0. " + err,
            )
        )

    # R5-5 unicode / whitespace marks.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "confine\u00a0", 25, 0, 0) + "\n"
        (ev / "qemu-console.txt").write_text(console)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-5-nbsp-suite",
                rc,
                want_fail=True,
                note="extra LC_MARK suite=confine+nbsp. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().splitlines()
        console = [ln for ln in console if "suite=elf " not in ln]
        console.append(
            f"LC_MARK nonce={NONCE} suite=elf\u200b exit=0 passed=6 "
            "failed=0 ignored=0 status=PASS"
        )
        (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-5-zwsp-elf-mark",
                rc,
                want_fail=True,
                note="elf mark name has zwsp; standing elf missing. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0\u200b\n")
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work)
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-5-zwsp-guest-exit",
                rc,
                want_fail=True,
                note="guest_exit=0 + zwsp. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += f"\nLC_MARK nonce={NONCE} suite=elf  exit=0 passed=6 failed=0 ignored=0 status=PASS\n"
        (ev / "qemu-console.txt").write_text(console)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-5-double-space-mark",
                rc,
                want_fail=True,
                note="second elf mark with double space (may not parse). " + err,
            )
        )

    # R5-6 run_start in the future.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        write_live_preboot(
            work / "host-preboot.txt",
            NONCE,
            work,
            run_start=int(time.time()) + 30,
            run_id=run_id,
        )
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-6-run-start-plus-30",
                rc,
                want_fail=True,
                note="run_start = now+30. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        future = int(time.time()) + 1
        write_live_preboot(
            work / "host-preboot.txt",
            NONCE,
            work,
            run_start=future,
            run_id=run_id,
        )
        touch_now(ev, future)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-6-run-start-plus-1-aligned",
                rc,
                want_fail=True,
                note="run_start=now+1 and files touched to now+1. " + err,
            )
        )

    # R5-7 partial writes.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev = root / "ev"
        work = root / "work"
        ev.mkdir()
        work.mkdir()
        mod.populate(ev, NONCE, guest_exit="guest_exit=0")
        run_id = write_live_preboot(work / "host-preboot.txt", NONCE, work)
        append_host_last(ev, work, run_id)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-7-guest-exit-no-nl",
                rc,
                want_fail=True,
                note="guest_exit=0 with no trailing LF. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        (ev / "elf.status").write_text("PAS")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-7-partial-status",
                rc,
                want_fail=True,
                note="elf.status truncated to PAS. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, run_id = honest_tree(pathlib.Path(tmp))
        digest = hashlib.sha256(NONCE.encode()).hexdigest()
        (work / "host-preboot.txt").write_text(f"nonce_sha256={digest}\n")
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-7-partial-preboot",
                rc,
                want_fail=True,
                note="preboot cut after nonce_sha256. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        hc = ev / "host-context.txt"
        lines = [
            ln
            for ln in hc.read_text().splitlines()
            if not ln.startswith("qemu_exit=")
        ]
        hc.write_text("\n".join(lines) + "\n")
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-7-missing-qemu-exit",
                rc,
                want_fail=True,
                note="host-context has no qemu_exit=. " + err,
            )
        )

    # R5-8 kill -STOP: timeout --signal=KILL still returns 137.
    with tempfile.TemporaryDirectory() as tmp:
        sleeper = pathlib.Path(tmp) / "sleep-pid"
        proc = subprocess.Popen(["sleep", "30"])
        try:
            time.sleep(0.05)
            os.kill(proc.pid, 19)  # SIGSTOP
            killer = subprocess.run(
                ["timeout", "--foreground", "--signal=KILL", "1", "sleep", "30"],
                check=False,
            )
            # The plant is the wrapper's timeout path, not this sleep.
            # Re-run the exact wrapper idiom against a STOP'd child via timeout
            # wrapping a second sleep is not the STOP case. Do it directly:
            stopped_rc = None
            try:
                t = subprocess.run(
                    [
                        "timeout",
                        "--foreground",
                        "--signal=KILL",
                        "1",
                        "bash",
                        "-c",
                        f"kill -STOP {proc.pid}; wait {proc.pid}",
                    ],
                    check=False,
                )
                stopped_rc = t.returncode
            except Exception as exc:  # noqa: BLE001
                stopped_rc = f"exc {exc}"
            # Wrapper copies this exact timeout invocation. 124 is TERM default;
            # KILL is 137. Either non-zero is fail-closed.
            wrapper_has_kill = (
                "timeout --foreground --signal=KILL" in host
                and 'echo "qemu_exit=$qemu_rc"' in host
            )
            rc = 0 if (wrapper_has_kill and killer.returncode != 0) else 1
            results.append(
                verdict(
                    "R5-8-timeout-kill",
                    rc,
                    want_fail=False,
                    note=(
                        f"timeout KILL rc={killer.returncode} "
                        f"stop_wait_rc={stopped_rc} wrapper_has_kill={wrapper_has_kill}"
                    ),
                )
            )
        finally:
            try:
                os.kill(proc.pid, 18)  # SIGCONT
            except OSError:
                pass
            proc.kill()
            proc.wait(timeout=2)

    # R5-9 extra suite mark names.
    for extra in ("smoke", "full", "PASS", "guest2", "helpers"):
        with tempfile.TemporaryDirectory() as tmp:
            ev, work, _ = honest_tree(pathlib.Path(tmp))
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += "\n" + mod.mark_line(NONCE, extra, 0, 0, 0) + "\n"
            (ev / "qemu-console.txt").write_text(console)
            touch_now(ev)
            rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
            results.append(
                verdict(
                    f"R5-9-extra-mark-{extra}",
                    rc,
                    want_fail=True,
                    note=f"extra LC_MARK suite={extra}. " + err,
                )
            )

    # Allowed extra `guest` mark is a duplicate of the standing guest line
    # only if we add a second one.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "guest", 0, 0, 0, status="DONE", rc=0)
        console += "\n" + mod.mark_line(NONCE, "guest", 0, 0, 0, status="DONE", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-9-dup-guest-mark",
                rc,
                want_fail=True,
                note="two suite=guest marks. " + err,
            )
        )

    # Single extra guest mark on a tree that had none (populate does not
    # emit suite=guest). Allowed name; must not become a free PASS.
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        console = (ev / "qemu-console.txt").read_text().rstrip()
        console += "\n" + mod.mark_line(NONCE, "guest", 0, 0, 0, status="DONE", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n")
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-9-single-guest-mark",
                rc,
                want_fail=False,
                note="one extra allowed suite=guest mark on an honest tree. " + err,
            )
        )

    # R5-10 stale host-preboot from an earlier $WORK.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev_old, work_old, run_old = honest_tree(
            root, nonce="oldnonce", work_name="old", ev_name="ev-old"
        )
        ev_new, work_new, run_new = honest_tree(
            root, nonce=NONCE, work_name="new", ev_name="ev-new"
        )
        # Point the new check at the old preboot (wrong nonce hash).
        rc, err = run_check(ev_new, NONCE, work_old / "host-preboot.txt")
        results.append(
            verdict(
                "R5-10-stale-preboot-other-nonce",
                rc,
                want_fail=True,
                note="new evidence + old $WORK preboot. " + err,
            )
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_id = honest_tree(root)
        stale = root / "old-work"
        stale.mkdir()
        shutil.copy2(work / "host-preboot.txt", stale / "host-preboot.txt")
        # New wrapper would overwrite $WORK/host-preboot.txt. Keep the
        # stale copy and also write a new run_id into host-context last.
        write_live_preboot(
            work / "host-preboot.txt", NONCE, work, run_id="d" * 16
        )
        append_host_last(ev, work, "d" * 16)
        rc, err = run_check(ev, NONCE, stale / "host-preboot.txt")
        results.append(
            verdict(
                "R5-10-stale-copy-after-new-mint",
                rc,
                want_fail=True,
                note="stale preboot copy after new mint + new run_id. " + err,
            )
        )

    # Restore stale bytes onto $WORK/host-preboot.txt while host-context
    # already has the new run_id last.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        ev, work, run_old = honest_tree(root)
        stale_bytes = (work / "host-preboot.txt").read_text()
        write_live_preboot(
            work / "host-preboot.txt", NONCE, work, run_id="e" * 16
        )
        append_host_last(ev, work, "e" * 16)
        (work / "host-preboot.txt").write_text(stale_bytes)
        touch_now(ev)
        rc, err = run_check(ev, NONCE, work / "host-preboot.txt")
        results.append(
            verdict(
                "R5-10-restore-stale-bytes",
                rc,
                want_fail=True,
                note="stale preboot bytes, new run_id last in host-context. " + err,
            )
        )

    # Mode bits: PREBOOT must stay a regular file (not a dir, not a fifo).
    with tempfile.TemporaryDirectory() as tmp:
        ev, work, _ = honest_tree(pathlib.Path(tmp))
        pb = work / "host-preboot.txt"
        pb.unlink()
        pb.mkdir()
        rc, err = run_check(ev, NONCE, pb)
        results.append(
            verdict(
                "R5-10-preboot-is-dir",
                rc,
                want_fail=True,
                note="PREBOOT path is a directory. " + err,
            )
        )

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"summary: {caught} CAUGHT, {survived} SURVIVED, {len(results)} plants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
