#!/usr/bin/env python3
"""Falsifiers for the host guest-results checker."""

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


def write_suite(ev: pathlib.Path, name: str, passed: int, failed: int, ignored: int, status="PASS", rc=0):
    (ev / f"{name}.status").write_text(status + "\n")
    (ev / f"{name}.exit").write_text(f"{rc}\n")
    (ev / f"{name}.txt").write_text(
        f"test foo ... ok\ntest result: ok. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; 0 filtered out\n"
    )


def populate(ev: pathlib.Path, nonce: str, short_elf=False, miss_plant=False):
    (ev / "LABEL.txt").write_text(EXPECTED["label"] + "\n")
    (ev / "guest-exit.txt").write_text("guest_exit=0\n")
    (ev / "guest-results.txt").write_text(f"nonce={nonce}\n")
    console = [f"LABEL={EXPECTED['label']}", f"nonce={nonce}"]
    for name, want in EXPECTED["suites"].items():
        passed = want["passed"] - (1 if short_elf and name == "elf" else 0)
        write_suite(ev, name, passed, want["failed"], want["ignored"])
        console.append(
            f"LC_MARK nonce={nonce} suite={name} exit=0 passed={passed} "
            f"failed={want['failed']} ignored={want['ignored']} status=PASS"
        )
    for plant in EXPECTED["plants_caught"]:
        if miss_plant and plant == "F-LC-SKIP-NETNS":
            continue
        (ev / f"{plant}.status").write_text("CAUGHT\n")
    for plant in EXPECTED["plants_not_run"]:
        (ev / f"{plant}.status").write_text("NOT_RUN\n")
    (ev / "qemu-console.txt").write_text("\n".join(console) + "\n")
    (ev / "summary.txt").write_text("\n".join(console) + "\n")


def run_check(ev: pathlib.Path, nonce: str) -> int:
    return subprocess.run(
        [sys.executable, str(CHECK), str(ev), str(HERE / "expected.json"), nonce, "full"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).returncode


class CheckGuestResults(unittest.TestCase):
    def test_full_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, "abc")
            self.assertEqual(run_check(ev, "abc"), 0)
            text = (ev / "RESULTS.txt").read_text()
            self.assertIn("GENERATED from this guest run", text)
            self.assertIn("Host check PASSED", text)

    def test_short_suite_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, "abc", short_elf=True)
            self.assertEqual(run_check(ev, "abc"), 1)

    def test_missing_plant_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = pathlib.Path(tmp)
            populate(ev, "abc", miss_plant=True)
            self.assertEqual(run_check(ev, "abc"), 1)


if __name__ == "__main__":
    unittest.main()
