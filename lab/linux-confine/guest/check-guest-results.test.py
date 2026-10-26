#!/usr/bin/env python3
"""Falsifiers for the host guest-results checker.

Each named mutant is a one-site edit of a copy of check-guest-results.py.
The matching extra-probe fixture must fail the original checker and pass
that mutant. That is the catcher: if the live check is removed, this
file fails.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
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


def run_check(ev: pathlib.Path, nonce: str, checker: pathlib.Path = CHECK) -> int:
    return subprocess.run(
        [sys.executable, str(checker), str(ev), str(HERE / "expected.json"), nonce, "full"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).returncode


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
        old = '    if mode == "full" and "guest_exit=0" not in guest_exit:'
        new = '    if False and mode == "full" and "guest_exit=0" not in guest_exit:'
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
        self.assertNotIn("${LC_GUEST_NONCE", text)
        self.assertNotIn("LC_GUEST_NONCE=", text)


if __name__ == "__main__":
    unittest.main()
