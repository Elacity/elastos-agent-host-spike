#!/usr/bin/env python3
"""Unit tests for this review's detectors. They read the reviewed heads."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REVIEW = Path(__file__).resolve().parent


class ReviewDetectors(unittest.TestCase):
    def test_check_py_exits_zero_on_these_heads(self):
        ran = subprocess.run(
            [sys.executable, str(REVIEW / "check.py")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("summary", ran.stdout)
        self.assertNotIn("FAIL ", ran.stdout)

    def test_abi1_fixture_never_names_the_guard_binary(self):
        kit = Path(
            os.environ.get(
                "JPK_SRC",
                "/tmp/review-c0-307-src/jetson-proof-kit/lab/jetson-proof-kit",
            )
        )
        fixture = (kit / "fixtures/abi-1-jetson.facts").read_text()
        self.assertIn("landlock_abi 1", fixture)
        self.assertNotIn("fcl-launch", fixture)
        decisions = (kit / "tests/test_decisions.sh").read_text()
        self.assertIn("decide.py", decisions)
        self.assertNotIn("fcl-launch", decisions)

    def test_307_reason_template_names_right_and_abi(self):
        src = Path(
            os.environ.get(
                "FCL_SRC",
                "/tmp/review-c0-307-src/fail-closed-linux/lab/fail-closed-linux",
            )
        )
        lib = (src / "src/lib.rs").read_text()
        self.assertIn('format!("{} (needs ABI {})", right.name, right.minimum_abi)', lib)
        self.assertIn("this kernel's Landlock ABI {abi} cannot deny", lib)


if __name__ == "__main__":
    unittest.main()
