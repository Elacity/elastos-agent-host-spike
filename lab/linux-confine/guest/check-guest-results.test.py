#!/usr/bin/env python3
"""Falsifiers for the host guest-results checker.

Each named mutant is a one-site edit of a copy of check-guest-results.py.
The matching extra-probe fixture must fail the original checker and pass
that mutant. That is the catcher: if the live check is removed, this
file fails.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check-guest-results.py"
EXPECTED = json.loads((HERE / "expected.json").read_text())
NONCE = "abc"
HOST = HERE.parent / "run-aarch64-guest.sh"
INIT = HERE / "init.sh"


def write_suite(ev: pathlib.Path, name: str, passed: int, failed: int, ignored: int, status="PASS", rc=0, extra_result=""):
    (ev / f"{name}.status").write_text(status + "\n")
    (ev / f"{name}.exit").write_text(f"{rc}\n")
    body = extra_result
    body += (
        f"test foo ... ok\ntest result: ok. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; 0 filtered out\n"
    )
    (ev / f"{name}.txt").write_text(body)


def write_host_context(ev: pathlib.Path, qemu_exit=0, timeout=False):
    lines = [
        "label=" + EXPECTED["label"],
        f"qemu_exit={qemu_exit}",
    ]
    if timeout:
        lines.append("qemu_timeout=1")
    (ev / "host-context.txt").write_text("\n".join(lines) + "\n")


def mark_line(nonce, name, passed, failed, ignored, status="PASS", rc=0):
    return (
        f"LC_MARK nonce={nonce} suite={name} exit={rc} passed={passed} "
        f"failed={failed} ignored={ignored} status={status}"
    )


def populate(
    ev: pathlib.Path,
    nonce: str,
    *,
    short_elf=False,
    inflate_elf=False,
    miss_plant=False,
    marks=True,
    mark_nonce=None,
    guest_exit="guest_exit=0\n",
    qemu_exit=0,
    qemu_timeout=False,
    isolation=True,
    nonce_in_results=False,
    elf_status=None,
    elf_rc=None,
    elf_failed=None,
    elf_result_prefix="",
    extra_console=(),
):
    (ev / "LABEL.txt").write_text(EXPECTED["label"] + "\n")
    if guest_exit is not None:
        (ev / "guest-exit.txt").write_text(guest_exit)
    write_host_context(ev, qemu_exit=qemu_exit, timeout=qemu_timeout)
    results = []
    if nonce_in_results:
        results.append(f"nonce={nonce}")
    (ev / "guest-results.txt").write_text("\n".join(results) + ("\n" if results else ""))
    console = [f"LABEL={EXPECTED['label']}"]
    if isolation:
        console.extend(
            [
                "tester_nonce_readable=0",
                "env_has_nonce=0",
                "evidence_nonce_during_run=0",
            ]
        )
    console.extend(extra_console)
    used_mark_nonce = mark_nonce if mark_nonce is not None else nonce
    for name, want in EXPECTED["suites"].items():
        passed = want["passed"]
        failed = want["failed"] if elf_failed is None or name != "elf" else elf_failed
        ignored = want["ignored"]
        if short_elf and name == "elf":
            passed = want["passed"] - 1
        if inflate_elf and name == "elf":
            passed = want["passed"] + 1
        status = "PASS"
        rc = 0
        if name == "elf":
            if elf_status is not None:
                status = elf_status
            if elf_rc is not None:
                rc = elf_rc
        write_suite(
            ev,
            name,
            passed,
            failed,
            ignored,
            status=status,
            rc=rc,
            extra_result=elf_result_prefix if name == "elf" else "",
        )
        if marks:
            console.append(
                mark_line(used_mark_nonce, name, passed, failed, ignored, status=status, rc=rc)
            )
    for plant in EXPECTED["plants_caught"]:
        if miss_plant and plant == "F-LC-SKIP-NETNS":
            continue
        (ev / f"{plant}.status").write_text("CAUGHT\n")
    for plant in EXPECTED["plants_not_run"]:
        (ev / f"{plant}.status").write_text("NOT_RUN\n")
    (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
    (ev / "summary.txt").write_text("\n".join(console) + "\n")


def write_preboot(
    path: pathlib.Path,
    nonce: str,
    run_start: int | None = None,
    work: pathlib.Path | None = None,
    run_id: str | None = None,
) -> str:
    if run_start is None:
        run_start = int(time.time()) - 60
    if work is None:
        work = path.resolve().parent
    if run_id is None:
        run_id = hashlib.sha256(f"{nonce}:{path}".encode()).hexdigest()[:16]
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    path.write_text(
        f"nonce_sha256={digest}\n"
        f"run_start={run_start}\n"
        f"run_id={run_id}\n"
        f"work={pathlib.Path(work).resolve()}\n"
    )
    return run_id


def _sync_host_from_preboot(ev: pathlib.Path, preboot: pathlib.Path) -> None:
    target = preboot
    if preboot.is_symlink():
        try:
            target = preboot.resolve()
        except OSError:
            return
    if not target.is_file():
        return
    run_id = None
    work = None
    for raw in target.read_text().splitlines():
        if raw.startswith("run_id="):
            run_id = raw.split("=", 1)[1]
        elif raw.startswith("work="):
            work = raw.split("=", 1)[1]
    hc = ev / "host-context.txt"
    lines = hc.read_text() if hc.is_file() else ""
    extra = ""
    if work and last_field(lines, "work") != work:
        extra += f"work={work}\n"
    if run_id and last_field(lines, "run_id") != run_id:
        extra += f"run_id={run_id}\n"
    if extra:
        with hc.open("a") as handle:
            handle.write(extra)


def last_field(text: str, key: str) -> str | None:
    value = None
    prefix = f"{key}="
    for raw in text.splitlines():
        if raw.startswith(prefix):
            value = raw.split("=", 1)[1]
    return value


def run_check(
    ev: pathlib.Path,
    nonce: str,
    checker: pathlib.Path = CHECK,
    preboot: pathlib.Path | None = None,
    *,
    sync_host: bool = True,
    ledger: pathlib.Path | None = None,
) -> int:
    cleanup = None
    isolated = None
    env = os.environ.copy()
    if preboot is None:
        work = pathlib.Path(tempfile.mkdtemp(prefix="lc-host-work-"))
        cleanup = work
        preboot = work / "host-preboot.txt"
        write_preboot(preboot, nonce, work=work)
    if ledger is not None:
        env["LC_USED_NONCES"] = str(ledger)
    elif "LC_USED_NONCES" not in env:
        handle, name = tempfile.mkstemp(prefix="lc-used-nonces-")
        os.close(handle)
        isolated = name
        env["LC_USED_NONCES"] = name
    if sync_host:
        _sync_host_from_preboot(ev, preboot)
    try:
        return subprocess.run(
            [
                sys.executable,
                str(checker),
                str(ev),
                str(HERE / "expected.json"),
                nonce,
                "full",
                str(preboot),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        ).returncode
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
        if isolated is not None:
            pathlib.Path(isolated).unlink(missing_ok=True)


def apply_mutant(src: str, mutant_id: str) -> str:
    """One-site edit matching the r2 review mutants, updated for exact marks."""
    if mutant_id == "M1":
        old = '            if status != "CAUGHT":\n                problems.append(f"{plant}: status={status or \'MISSING\'} (want CAUGHT)")'
        new = "            if False:\n                problems.append(f\"{plant}: status={status or 'MISSING'} (want CAUGHT)\")"
    elif mutant_id == "M2":
        old = '        if counts["passed"] != want["passed"]:'
        new = '        if False and counts["passed"] != want["passed"]:'
    elif mutant_id == "M3":
        old = '        if status != "PASS" or exit_rc not in (0,):'
        new = "        if False:"
    elif mutant_id == "M4":
        old = "    problems.extend(collect_nonce_problems(nonce, guest_results, console, marks))"
        new = "    problems.extend([])"
    elif mutant_id == "M5":
        old = "    if mode == \"full\" and guest_exit_value != 0:"
        new = "    if False and mode == \"full\" and guest_exit_value != 0:"
    elif mutant_id == "M9":
        old = '        if name in marks:\n            problems.append(f"{name}: duplicate LC_MARK serial line")'
        new = '        if False and name in marks:\n            problems.append(f"{name}: duplicate LC_MARK serial line")'
    elif mutant_id == "M10":
        old = (
            "    if not text.endswith(\"\\n\") or text.count(\"\\n\") != 1:\n"
            "        return None\n"
            "    match = GUEST_EXIT_LINE.fullmatch(text[:-1])\n"
            "    if match is None:\n"
            "        return None\n"
            "    return int(match.group(1))"
        )
        new = '    if "guest_exit=0" in text:\n        return 0\n    return None'
    elif mutant_id == "M11":
        old = "    problems.extend(collect_preboot_problems(evidence, nonce, preboot, host_context))"
        new = "    problems.extend([])"
    elif mutant_id == "M12":
        old = '    if preboot.is_symlink():\n        problems.append("pre-boot path is a symlink")\n        return problems'
        new = '    if False and preboot.is_symlink():\n        problems.append("pre-boot path is a symlink")\n        return problems'
    elif mutant_id == "M13":
        old = '    if ".." in preboot.parts:\n        problems.append("pre-boot path contains ..")\n        return problems'
        new = '    if False and ".." in preboot.parts:\n        problems.append("pre-boot path contains ..")\n        return problems'
    elif mutant_id == "M14":
        old = "    if digest is not None and work_real is not None and not bind_problems:\n        used_problem = nonce_already_recorded(work_real, digest)\n        if used_problem:\n            problems.append(used_problem)"
        new = "    if False and digest is not None and work_real is not None and not bind_problems:\n        used_problem = nonce_already_recorded(work_real, digest)\n        if used_problem:\n            problems.append(used_problem)"
    elif mutant_id == "M15":
        old = "            elif mtime > now + MTIME_SKEW_SEC:\n                problems.append(f\"{child.name}: evidence file mtime is in the future\")"
        new = "            elif False and mtime > now + MTIME_SKEW_SEC:\n                problems.append(f\"{child.name}: evidence file mtime is in the future\")"
    elif mutant_id == "M16":
        old = "    problems.extend(collect_unexpected_mark_problems(marks, expected))"
        new = "    problems.extend([])"
    elif mutant_id == "M17":
        old = (
            '    if "\\r" in text or "\\0" in text:\n'
            "        return None\n"
            "    if not text.endswith(\"\\n\") or text.count(\"\\n\") != 1:\n"
            "        return None\n"
            "    match = GUEST_EXIT_LINE.fullmatch(text[:-1])"
        )
        new = (
            "    match = GUEST_EXIT_LINE.fullmatch("
            "text.splitlines()[0] if text.splitlines() else \"\")"
        )
    elif mutant_id == "M18":
        old = "    problems.extend(collect_unexpected_status_problems(evidence, expected))"
        new = "    problems.extend([])"
    elif mutant_id == "M19":
        old = "    problems.extend(bind_problems)"
        new = "    problems.extend([])"
    elif mutant_id == "M20":
        old = 'PREBOOT_START_LINE = re.compile(r"^run_start=([1-9][0-9]*)$")'
        new = 'PREBOOT_START_LINE = re.compile(r"^run_start=(0|[1-9][0-9]*)$")'
    elif mutant_id == "M21":
        old = (
            "        if match is None:\n"
            "            problems.append(f\"unparseable LC_MARK line: {raw!r}\")\n"
            "            continue"
        )
        new = "        if match is None:\n            continue"
    elif mutant_id == "M22":
        old = (
            "    if not text.endswith(\"\\n\") or text.count(\"\\n\") != 1:\n"
            "        return None\n"
            "    match = GUEST_EXIT_LINE.fullmatch(text[:-1])"
        )
        new = (
            "    lines = text.splitlines()\n"
            "    if len(lines) != 1:\n"
            "        return None\n"
            "    match = GUEST_EXIT_LINE.fullmatch(lines[0])"
        )
    elif mutant_id == "M23":
        old = "    return run_start > now"
        new = "    return run_start > now + MTIME_SKEW_SEC"
    elif mutant_id == "M24":
        old = (
            "    if preboot.stat().st_nlink > 1:\n"
            "        problems.append(\"pre-boot nonce record is a hardlink\")\n"
            "        return problems"
        )
        new = (
            "    if False and preboot.stat().st_nlink > 1:\n"
            "        problems.append(\"pre-boot nonce record is a hardlink\")\n"
            "        return problems"
        )
    elif mutant_id == "M25":
        old = (
            "    if path_is_alias(used):\n"
            "        return \"used-nonces path is a symlink or hardlink\""
        )
        new = (
            "    if False and path_is_alias(used):\n"
            "        return \"used-nonces path is a symlink or hardlink\""
        )
    elif mutant_id == "M6":
        old = "    passed, failed, ignored = (int(x) for x in matches[-1])"
        new = "    passed, failed, ignored = (int(x) for x in matches[0])"
    elif mutant_id == "M7":
        old = '        if counts["failed"] != want["failed"]:'
        new = '        if False and counts["failed"] != want["failed"]:'
    elif mutant_id == "M8":
        old = '        if not status:\n            problems.append(f"{name}: missing status file")'
        new = '        if not status:\n            status = "PASS"'
    else:
        raise AssertionError(mutant_id)
    if old not in src:
        raise AssertionError(f"{mutant_id}: mutant site missing from checker")
    if src.count(old) != 1:
        raise AssertionError(f"{mutant_id}: mutant site not unique")
    return src.replace(old, new, 1)


class CheckGuestResults(unittest.TestCase):
    def test_full_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            self.assertEqual(run_check(ev, NONCE), 0)
            text = (ev / "RESULTS.txt").read_text()
            self.assertIn("GENERATED from this guest run", text)
            self.assertIn("Host check PASSED", text)
            self.assertIn("qemu_exit=0", text)

    def test_m1_missing_plant_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, miss_plant=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m2_short_suite_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, short_elf=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m3_status_fail_exit_1_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, elf_status="FAIL", elf_rc=1)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m4_wrong_nonce_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, mark_nonce="other", marks=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m5_guest_exit_nonzero_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, guest_exit="guest_exit=1\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m6_first_ok_last_fail_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            prefix = "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            populate(ev, NONCE, elf_failed=1, elf_result_prefix=prefix)
            # Last line is 6 passed / 1 failed (write_suite appends the last result).
            # Reset elf log to first-ok then last-fail, and align marks with the first line
            # so a first-line mutant matches expected counts.
            write_suite(
                ev,
                "elf",
                0,
                1,
                0,
                extra_result="test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            )
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console = [ln for ln in console if "suite=elf " not in ln]
            console.append(mark_line(NONCE, "elf", 6, 0, 0))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m7_failed_count_nonzero_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, elf_failed=1)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_m8_missing_status_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            (ev / "elf.status").unlink()
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console = [ln for ln in console if "suite=elf " not in ln]
            console.append(mark_line(NONCE, "elf", 6, 0, 0, status="MISSING"))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_forged_9p_only_missing_marks_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, marks=False, nonce_in_results=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_count_inflation_no_marks_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, inflate_elf=True, marks=False, nonce_in_results=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_count_inflation_matching_marks_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, inflate_elf=True, marks=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_qemu_exit_137_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, qemu_exit=137)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_qemu_timeout_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, qemu_exit=124, qemu_timeout=True)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_missing_qemu_exit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            (ev / "host-context.txt").write_text("label=" + EXPECTED["label"] + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_serial_9p_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, inflate_elf=True, marks=False)
            console = (ev / "qemu-console.txt").read_text().splitlines()
            for name, want in EXPECTED["suites"].items():
                console.append(mark_line(NONCE, name, want["passed"], want["failed"], want["ignored"]))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_tester_can_read_nonce_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, isolation=False, extra_console=("tester_nonce_readable=1",))
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_missing_isolation_proof_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, isolation=False)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_duplicate_lc_mark_last_wins_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console.append(mark_line(NONCE, "elf", 6, 0, 0))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_guest_exit_must_be_one_canonical_line(self):
        cases = (
            "guest_exit=01\n",
            "guest_exit=1\n# later guest_exit=0\n",
            "guest_exit=0\nguest_exit=0\n",
            "status=ok guest_exit=0 extra\n",
        )
        for text in cases:
            with tempfile.TemporaryDirectory() as tmp:
                ev = pathlib.Path(tmp)
                populate(ev, NONCE, guest_exit=text)
                self.assertEqual(run_check(ev, NONCE), 1, msg=repr(text))

    def test_replay_old_tree_old_nonce_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            yesterday = int(time.time()) - 86400
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (yesterday, yesterday))
            preboot = root / "host-preboot.txt"
            write_preboot(preboot, NONCE, run_start=int(time.time()))
            self.assertEqual(run_check(ev, NONCE, preboot=preboot), 1)
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (now, now))
            write_preboot(preboot, "other-nonce", run_start=now - 60)
            self.assertEqual(run_check(ev, NONCE, preboot=preboot), 1)
            missing = subprocess.run(
                [
                    sys.executable,
                    str(CHECK),
                    str(ev),
                    str(HERE / "expected.json"),
                    NONCE,
                    "full",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(missing.returncode, 1)

    def test_r4_1b_preboot_symlink_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work)
            link = ev / "host-preboot.txt"
            link.symlink_to(work / "host-preboot.txt")
            self.assertEqual(run_check(ev, NONCE, preboot=link), 1)

    def test_r4_1d_preboot_dotdot_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work)
            escape = ev / ".." / "work" / "host-preboot.txt"
            self.assertEqual(run_check(ev, NONCE, preboot=escape), 1)

    def test_r4_2_nonce_reuse_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="a" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                0,
            )
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="b" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                1,
            )

    def test_r4_3_future_mtime_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            now = int(time.time())
            future = now + 86400
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (future, future))
            write_preboot(work / "host-preboot.txt", NONCE, now - 60, work=work)
            self.assertEqual(run_check(ev, NONCE, preboot=work / "host-preboot.txt"), 1)

    def test_r4_4a_unexpected_zero_suite_mark_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += "\n" + mark_line(NONCE, "empty-suite", 0, 0, 0)
            (ev / "qemu-console.txt").write_text(console + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_r4_5a_guest_exit_crlf_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_r4_7a_confine2_extra_fail_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            write_suite(ev, "confine2", 0, 25, 0, status="FAIL", rc=1)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += "\n" + mark_line(NONCE, "confine2", 0, 25, 0, status="FAIL", rc=1)
            (ev / "qemu-console.txt").write_text(console + "\n")
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_r4_8a_other_work_matching_hash_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work_a = root / "work-a"
            work_b = root / "work-b"
            work_a.mkdir()
            work_b.mkdir()
            populate(ev, NONCE)
            write_preboot(work_a / "host-preboot.txt", NONCE, work=work_a, run_id="c" * 16)
            write_preboot(work_b / "host-preboot.txt", NONCE, work=work_b, run_id="c" * 16)
            hc = ev / "host-context.txt"
            with hc.open("a") as handle:
                handle.write(f"work={work_a.resolve()}\nrun_id={'c' * 16}\n")
            self.assertEqual(
                run_check(ev, NONCE, preboot=work_b / "host-preboot.txt", sync_host=False),
                1,
            )

    def test_r4_9b_run_start_zero_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (now, now))
            write_preboot(work / "host-preboot.txt", NONCE, run_start=0, work=work)
            self.assertEqual(run_check(ev, NONCE, preboot=work / "host-preboot.txt"), 1)

    def test_r5_skew_plus_1s_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            now = int(time.time()) + 1
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (now, now))
            self.assertEqual(run_check(ev, NONCE), 0)

    def test_r5_1_nonce_new_work_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev1 = root / "ev1"
            ev2 = root / "ev2"
            work1 = root / "work1"
            work2 = root / "work2"
            ev1.mkdir()
            work1.mkdir()
            work2.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev1, NONCE)
            write_preboot(work1 / "host-preboot.txt", NONCE, work=work1, run_id="a" * 16)
            self.assertEqual(
                run_check(ev1, NONCE, preboot=work1 / "host-preboot.txt", ledger=ledger),
                0,
            )
            shutil.copytree(ev1, ev2)
            write_preboot(work2 / "host-preboot.txt", NONCE, work=work2, run_id="b" * 16)
            now = int(time.time())
            for child in ev2.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            self.assertEqual(
                run_check(ev2, NONCE, preboot=work2 / "host-preboot.txt", ledger=ledger),
                1,
            )

    def test_r5_1_wipe_used_nonces_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="a" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                0,
            )
            stale = work / "used-nonces.txt"
            if stale.is_file():
                stale.unlink()
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                1,
            )

    def test_r5_2_hardlink_wipe_ledger_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="a" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                0,
            )
            alias = ev / "used-nonces-hardlink"
            os.link(ledger, alias)
            alias.write_text("")
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                1,
            )

    def test_r5_5_nbsp_suite_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += "\n" + mark_line(NONCE, "confine\u00a0", 25, 0, 0) + "\n"
            (ev / "qemu-console.txt").write_text(console)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_r5_5_double_space_mark_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += (
                f"\nLC_MARK nonce={NONCE} suite=elf  exit=0 passed=6 "
                "failed=0 ignored=0 status=PASS\n"
            )
            (ev / "qemu-console.txt").write_text(console)
            self.assertEqual(run_check(ev, NONCE), 1)

    def test_r5_6_run_start_plus_1_aligned_fails(self):
        spec = importlib.util.spec_from_file_location("cgr", CHECK)
        cgr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cgr)
        now = 1_700_000_000
        self.assertTrue(cgr.run_start_is_implausible(now + 1, now))
        self.assertFalse(cgr.run_start_is_implausible(now, now))
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            populate(ev, NONCE)
            future = int(time.time()) + 1
            write_preboot(work / "host-preboot.txt", NONCE, run_start=future, work=work)
            _sync_host_from_preboot(ev, work / "host-preboot.txt")
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (future, future))
            rc = run_check(
                ev, NONCE, preboot=work / "host-preboot.txt", sync_host=False
            )
            if rc == 0:
                future = int(time.time()) + 1
                write_preboot(
                    work / "host-preboot.txt", NONCE, run_start=future, work=work
                )
                _sync_host_from_preboot(ev, work / "host-preboot.txt")
                for child in ev.iterdir():
                    if child.is_file():
                        os.utime(child, (future, future))
                rc = run_check(
                    ev, NONCE, preboot=work / "host-preboot.txt", sync_host=False
                )
            self.assertEqual(rc, 1)

    def test_r5_7_guest_exit_no_nl_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, NONCE, guest_exit="guest_exit=0")
            self.assertEqual(run_check(ev, NONCE), 1)


class MutantsAreCaught(unittest.TestCase):
    """Each r2 mutant lets one extra-probe fixture through. The live checker does not."""

    def _mutant_checker(self, tmp: pathlib.Path, mutant_id: str) -> pathlib.Path:
        path = tmp / f"check-{mutant_id}.py"
        path.write_text(apply_mutant(CHECK.read_text(), mutant_id))
        return path

    def test_m1_skip_plant_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, miss_plant=True)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M1")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m2_skip_passed_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, short_elf=True)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M2")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m3_skip_status_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, elf_status="FAIL", elf_rc=1)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M3")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m4_skip_nonce_presence(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, mark_nonce="other")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M4")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m5_skip_guest_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, guest_exit="guest_exit=1\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M5")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m6_first_result_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            write_suite(
                ev,
                "elf",
                0,
                1,
                0,
                extra_result="test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            )
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console = [ln for ln in console if "suite=elf " not in ln]
            console.append(mark_line(NONCE, "elf", 6, 0, 0))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M6")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m7_skip_failed_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, elf_failed=1)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M7")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m8_missing_status_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            (ev / "elf.status").unlink()
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console = [ln for ln in console if "suite=elf " not in ln]
            console.append(mark_line(NONCE, "elf", 6, 0, 0, status="PASS"))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M8")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m9_last_wins_duplicate_marks(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().splitlines()
            console.append(mark_line(NONCE, "elf", 6, 0, 0))
            (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M9")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m10_substring_guest_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, guest_exit="guest_exit=01\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M10")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m11_skip_preboot_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            yesterday = int(time.time()) - 86400
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (yesterday, yesterday))
            preboot = root / "host-preboot.txt"
            write_preboot(preboot, NONCE, run_start=int(time.time()))
            mutant = self._mutant_checker(root, "M11")
            self.assertEqual(run_check(ev, NONCE, preboot=preboot), 1)
            self.assertEqual(run_check(ev, NONCE, mutant, preboot=preboot), 0)

    def test_m12_skip_preboot_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work)
            link = ev / "host-preboot.txt"
            link.symlink_to(work / "host-preboot.txt")
            mutant = self._mutant_checker(root, "M12")
            self.assertEqual(run_check(ev, NONCE, preboot=link), 1)
            self.assertEqual(run_check(ev, NONCE, mutant, preboot=link), 0)

    def test_m13_skip_preboot_dotdot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work)
            escape = ev / ".." / "work" / "host-preboot.txt"
            mutant = self._mutant_checker(root, "M13")
            self.assertEqual(run_check(ev, NONCE, preboot=escape), 1)
            self.assertEqual(run_check(ev, NONCE, mutant, preboot=escape), 0)

    def test_m14_skip_used_nonce(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="a" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                0,
            )
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="b" * 16)
            mutant = self._mutant_checker(root, "M14")
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                1,
            )
            self.assertEqual(
                run_check(
                    ev, NONCE, mutant, preboot=work / "host-preboot.txt", ledger=ledger
                ),
                0,
            )

    def test_m15_skip_future_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            now = int(time.time())
            future = now + 86400
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (future, future))
            write_preboot(work / "host-preboot.txt", NONCE, now - 60, work=work)
            mutant = self._mutant_checker(root, "M15")
            self.assertEqual(run_check(ev, NONCE, preboot=work / "host-preboot.txt"), 1)
            self.assertEqual(run_check(ev, NONCE, mutant, preboot=work / "host-preboot.txt"), 0)

    def test_m16_skip_unexpected_mark(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += "\n" + mark_line(NONCE, "empty-suite", 0, 0, 0)
            (ev / "qemu-console.txt").write_text(console + "\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M16")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m17_skip_guest_exit_crlf(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, guest_exit="guest_exit=0\r\n")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M17")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m18_skip_unexpected_status_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            write_suite(ev, "confine2", 0, 25, 0, status="FAIL", rc=1)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M18")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m19_skip_work_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work_a = root / "work-a"
            work_b = root / "work-b"
            work_a.mkdir()
            work_b.mkdir()
            populate(ev, NONCE)
            write_preboot(work_a / "host-preboot.txt", NONCE, work=work_a, run_id="c" * 16)
            write_preboot(work_b / "host-preboot.txt", NONCE, work=work_b, run_id="c" * 16)
            hc = ev / "host-context.txt"
            with hc.open("a") as handle:
                handle.write(f"work={work_a.resolve()}\nrun_id={'c' * 16}\n")
            mutant = self._mutant_checker(root, "M19")
            self.assertEqual(
                run_check(ev, NONCE, preboot=work_b / "host-preboot.txt", sync_host=False),
                1,
            )
            self.assertEqual(
                run_check(
                    ev, NONCE, mutant, preboot=work_b / "host-preboot.txt", sync_host=False
                ),
                0,
            )

    def test_m20_allow_run_start_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            ev.mkdir()
            work = root / "work"
            work.mkdir()
            populate(ev, NONCE)
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file():
                    os.utime(child, (now, now))
            write_preboot(work / "host-preboot.txt", NONCE, run_start=0, work=work)
            mutant = self._mutant_checker(root, "M20")
            self.assertEqual(run_check(ev, NONCE, preboot=work / "host-preboot.txt"), 1)
            self.assertEqual(run_check(ev, NONCE, mutant, preboot=work / "host-preboot.txt"), 0)

    def test_m21_skip_unparseable_mark(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE)
            console = (ev / "qemu-console.txt").read_text().rstrip()
            console += (
                f"\nLC_MARK nonce={NONCE} suite=elf  exit=0 passed=6 "
                "failed=0 ignored=0 status=PASS\n"
            )
            (ev / "qemu-console.txt").write_text(console)
            mutant = self._mutant_checker(pathlib.Path(tmp), "M21")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m22_skip_guest_exit_lf(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp) / "ev"
            ev.mkdir()
            populate(ev, NONCE, guest_exit="guest_exit=0")
            mutant = self._mutant_checker(pathlib.Path(tmp), "M22")
            self.assertEqual(run_check(ev, NONCE), 1)
            self.assertEqual(run_check(ev, NONCE, mutant), 0)

    def test_m23_allow_run_start_plus_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            populate(ev, NONCE)
            mutant = self._mutant_checker(root, "M23")

            def _stamp_and_check(checker):
                stamp = int(time.time()) + 1
                write_preboot(
                    work / "host-preboot.txt", NONCE, run_start=stamp, work=work
                )
                _sync_host_from_preboot(ev, work / "host-preboot.txt")
                for child in ev.iterdir():
                    if child.is_file():
                        os.utime(child, (stamp, stamp))
                return run_check(
                    ev, NONCE, checker, preboot=work / "host-preboot.txt", sync_host=False
                )

            live_rc = _stamp_and_check(CHECK)
            if live_rc == 0:
                live_rc = _stamp_and_check(CHECK)
            self.assertEqual(live_rc, 1)
            self.assertEqual(_stamp_and_check(mutant), 0)

    def test_m24_skip_preboot_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work)
            alias = work / "host-preboot-alias.txt"
            os.link(work / "host-preboot.txt", alias)
            # Pass the original path; nlink is 2 on both names.
            mutant = self._mutant_checker(root, "M24")
            self.assertEqual(run_check(ev, NONCE, preboot=work / "host-preboot.txt"), 1)
            self.assertEqual(
                run_check(ev, NONCE, mutant, preboot=work / "host-preboot.txt"), 0
            )

    def test_m25_skip_ledger_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ev = root / "ev"
            work = root / "work"
            ev.mkdir()
            work.mkdir()
            ledger = root / "host-used-nonces.txt"
            populate(ev, NONCE)
            write_preboot(work / "host-preboot.txt", NONCE, work=work, run_id="a" * 16)
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                0,
            )
            alias = ev / "used-nonces-hardlink"
            os.link(ledger, alias)
            alias.write_text("")
            now = int(time.time())
            for child in ev.iterdir():
                if child.is_file() and child.name != "RESULTS.txt":
                    os.utime(child, (now, now))
            mutant = self._mutant_checker(root, "M25")
            self.assertEqual(
                run_check(ev, NONCE, preboot=work / "host-preboot.txt", ledger=ledger),
                1,
            )
            self.assertEqual(
                run_check(
                    ev, NONCE, mutant, preboot=work / "host-preboot.txt", ledger=ledger
                ),
                0,
            )


class HostScriptNonceIsolation(unittest.TestCase):
    def test_wrapper_keeps_nonce_off_guest_paths_until_after_qemu(self):
        text = HOST.read_text()
        self.assertNotIn("printf \"LC_GUEST_NONCE=", text)
        self.assertIn('chmod 400 "$ROOT/etc/lc-nonce"', text)
        self.assertIn("echo \"$NONCE\" > \"$ROOT/etc/lc-nonce\"", text)
        # nonce.txt and host-context nonce only after qemu returns.
        before, after = text.split("=== boot qemu-system-aarch64 TCG ===", 1)
        self.assertNotIn('echo "$NONCE" > "$EVIDENCE/nonce.txt"', before)
        self.assertIn('echo "$NONCE" > "$EVIDENCE/nonce.txt"', after)
        self.assertIn('"$WORK/host-preboot.txt"', before)
        self.assertIn("nonce_sha256=", before)
        self.assertIn("run_start=", before)
        self.assertIn("run_id=", before)
        self.assertIn("work=", before)
        self.assertNotIn('echo "$NONCE" > "$WORK/host-preboot.txt"', before)
        self.assertIn('"$WORK/host-preboot.txt"', after)
        self.assertIn('echo "run_id=$RUN_ID"', after)
        self.assertIn('echo "work=$(cd "$WORK" && pwd)"', after)
        self.assertIn("timeout --foreground --signal=KILL", after)
        self.assertIn("< /dev/null", after)
        self.assertIn('QEMU_LOG="$WORK/qemu-console.txt"', after)
        self.assertIn('cp "$QEMU_LOG" "$EVIDENCE/qemu-console.txt"', after)

    def test_init_reads_root_only_nonce_and_emits_marks(self):
        text = INIT.read_text()
        self.assertIn("chmod 400 /etc/lc-nonce", text)
        self.assertIn("emit_suite_marks", text)
        self.assertIn("tester_nonce_readable=", text)
        self.assertIn("probe_nonce_isolation", text)
        self.assertIn("guest_exit=$guest_rc", text)
        self.assertNotIn("echo \"guest_exit=$status\"", text)
        self.assertNotIn("${LC_GUEST_NONCE", text)
        self.assertNotIn("LC_GUEST_NONCE=", text)


if __name__ == "__main__":
    unittest.main()
