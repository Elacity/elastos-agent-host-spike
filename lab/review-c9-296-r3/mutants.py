#!/usr/bin/env python3
"""New r3 mutants and forgeries against check-guest-results.py.

These are not the author's M1-M8. Each case prints CAUGHT or SURVIVED.
Exit 0 always: this file is a report, not a gate.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
# Live checker from the detached review worktree when present.
SRC = pathlib.Path("/tmp/review-c9-296-r3-src/lab/linux-confine/guest")
if not (SRC / "check-guest-results.py").is_file():
    SRC = pathlib.Path("/workspace/lab/linux-confine/guest")
CHECK = SRC / "check-guest-results.py"
sys.path.insert(0, str(SRC))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "cgr_test", SRC / "check-guest-results.test.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NONCE = "abc"
OLD_NONCE = "eacadb6e483a5b755c3fa8fa2394b96c"
COMMITTED = pathlib.Path(
    "/tmp/review-c9-296-r3-src/lab/linux-confine/evidence/aarch64-qemu-system-6.18"
)


def run(ev: pathlib.Path, nonce: str) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(CHECK), str(ev), str(SRC / "expected.json"), nonce, "full"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    err = p.stderr.strip()
    return p.returncode, err


def verdict(name: str, rc: int, want_fail: bool, note: str) -> str:
    if want_fail:
        label = "CAUGHT" if rc != 0 else "SURVIVED"
    else:
        label = "CAUGHT" if rc == 0 else "SURVIVED"
    print(f"{label}\t{name}\trc={rc}\t{note}")
    return label


def main() -> int:
    print(f"checker={CHECK}")
    print(f"head_src={SRC}")
    results = []

    # N1: tester-forged LC_MARK before init's honest last-wins mark.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().splitlines()
        forged = [
            "REVIEW_FORGE_TRY",
            mod.mark_line(NONCE, "elf", 99, 0, 0, status="PASS", rc=0),
        ]
        # Keep honest last marks (init writes after tester).
        (ev / "qemu-console.txt").write_text("\n".join(forged + console) + "\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N1-early-forged-mark-last-wins-honest",
                rc,
                want_fail=False,
                note="forged elf 99 passed first; honest last mark kept. " + err.replace("\n", " | "),
            )
        )

    # N1b: tester-forged LC_MARK AFTER init (last-wins forged, matching 9p).
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().rstrip()
        forged = mod.mark_line(NONCE, "elf", 6, 0, 0, status="PASS", rc=0)
        (ev / "qemu-console.txt").write_text(console + "\n" + forged + "\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N1b-late-duplicate-mark-matching-9p",
                rc,
                want_fail=True,
                note="duplicate last mark same as 9p. want fail if duplicates rejected. "
                + err.replace("\n", " | "),
            )
        )

    # N1c: late forged mark that matches inflated 9p (both sides rewritten).
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, inflate_elf=True)
        console = (ev / "qemu-console.txt").read_text().splitlines()
        console = [ln for ln in console if "suite=elf " not in ln]
        console.append(mod.mark_line(NONCE, "elf", 7, 0, 0))
        (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N1c-late-forged-mark-and-inflated-9p",
                rc,
                want_fail=True,
                note="guest rewrites both serial and 9p to 7 passed. " + err.replace("\n", " | "),
            )
        )

    # N2: replay committed old run + its nonce against this checker.
    if COMMITTED.is_dir() and (COMMITTED / "qemu-console.txt").is_file():
        rc, err = run(COMMITTED, OLD_NONCE)
        results.append(
            verdict(
                "N2-replay-committed-evidence-old-nonce",
                rc,
                want_fail=True,
                note="old complete 9p+serial+nonce replayed as a new run. "
                + err.replace("\n", " | "),
            )
        )
        rc, err = run(COMMITTED, "ffffffffffffffffffffffffffffffff")
        results.append(
            verdict(
                "N2b-replay-old-files-new-nonce",
                rc,
                want_fail=True,
                note="old files with a fresh host nonce. " + err.replace("\n", " | "),
            )
        )
    else:
        print("SKIP\tN2-replay\tcommitted evidence missing")

    # N3: isolation proof missing env/9p lines (only tester_nonce_readable=0).
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, isolation=False, extra_console=("tester_nonce_readable=0",))
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N3-missing-env-and-9p-isolation-lines",
                rc,
                want_fail=True,
                note="only tester_nonce_readable=0 present. " + err.replace("\n", " | "),
            )
        )

    # N4: extra passes with matching marks.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, inflate_elf=True)
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N4-extra-passes-matching-marks",
                rc,
                want_fail=True,
                note="elf passed 7 vs expected 6, marks match inflation. "
                + err.replace("\n", " | "),
            )
        )

    # N5: two elf marks, last honest.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE)
        console = (ev / "qemu-console.txt").read_text().splitlines()
        # Insert a conflicting earlier elf mark; last remains honest.
        out = []
        for ln in console:
            if "suite=elf " in ln:
                out.append(mod.mark_line("other", "elf", 99, 0, 0))
            out.append(ln)
        (ev / "qemu-console.txt").write_text("\n".join(out) + "\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N5-duplicate-marks-last-honest",
                rc,
                want_fail=True,
                note="first mark nonce=other/99; last honest. want fail if dups rejected. "
                + err.replace("\n", " | "),
            )
        )

    # N6: qemu timeout=1 and qemu_exit=124.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, qemu_exit=124, qemu_timeout=True)
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N6-qemu-timeout-124",
                rc,
                want_fail=True,
                note=err.replace("\n", " | "),
            )
        )

    # N6b: timeout flag with qemu_exit=0 (wrapper wrote a lie / partial write).
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, qemu_exit=0, qemu_timeout=True)
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N6b-timeout-flag-qemu-exit-0",
                rc,
                want_fail=True,
                note="qemu_timeout=1 but qemu_exit=0. " + err.replace("\n", " | "),
            )
        )

    # N7: guest_exit=10 substring of guest_exit=0.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, guest_exit="guest_exit=10\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N7-guest-exit-10-substring",
                rc,
                want_fail=True,
                note='file is guest_exit=10; "guest_exit=0" in that string? '
                + err.replace("\n", " | "),
            )
        )

    # N8: guest_exit=1 plus a later comment containing guest_exit=0.
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, guest_exit="guest_exit=1\n# later guest_exit=0\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N8-guest-exit-comment-contains-zero",
                rc,
                want_fail=True,
                note="numeric rc is 1; file also contains guest_exit=0. "
                + err.replace("\n", " | "),
            )
        )

    # N9: guest_exit=01
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, guest_exit="guest_exit=01\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N9-guest-exit-01",
                rc,
                want_fail=True,
                note=err.replace("\n", " | "),
            )
        )

    # N10: qemu_exit=0 on first line, qemu_exit=137 later (last write?).
    with tempfile.TemporaryDirectory() as tmp:
        ev = pathlib.Path(tmp)
        mod.populate(ev, NONCE, qemu_exit=0)
        text = (ev / "host-context.txt").read_text()
        (ev / "host-context.txt").write_text(text + "qemu_exit=137\n")
        rc, err = run(ev, NONCE)
        results.append(
            verdict(
                "N10-last-qemu-exit-137-after-0",
                rc,
                want_fail=True,
                note="parse_host_context last assignment wins? " + err.replace("\n", " | "),
            )
        )

    caught = results.count("CAUGHT")
    survived = results.count("SURVIVED")
    print(f"SUMMARY\tCAUGHT={caught}\tSURVIVED={survived}\ttotal={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
