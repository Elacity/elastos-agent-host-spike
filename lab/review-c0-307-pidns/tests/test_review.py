#!/usr/bin/env python3
"""Unit tests for this review's detectors."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REVIEW = Path(__file__).resolve().parent.parent


class ReviewDetectors(unittest.TestCase):
    def test_check_py_exits_zero(self):
        ran = subprocess.run(
            [sys.executable, str(REVIEW / "check.py")],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("summary", ran.stdout)
        self.assertNotIn("FAIL  ", ran.stdout)

    def test_proposal_patch_is_not_applied_to_307(self):
        src = Path(
            os.environ.get(
                "FCL_SRC", "/tmp/fcl-637345ac/lab/fail-closed-linux"
            )
        )
        lib = (src / "src/lib.rs").read_text()
        self.assertNotIn("landlock_can_handle_fs", lib)
        self.assertNotIn("Step::RightProbe", lib)
        patch = (REVIEW / "proposal.patch").read_text()
        self.assertIn("landlock_can_handle_fs", patch)
        self.assertIn("RightProbe", patch)

    def test_307_still_trusts_the_abi_number(self):
        src = Path(
            os.environ.get(
                "FCL_SRC", "/tmp/fcl-637345ac/lab/fail-closed-linux"
            )
        )
        lib = (src / "src/lib.rs").read_text()
        self.assertIn("if let Some(mask) = missing_required_mask(abi)", lib)
        self.assertIn("if abi < right.minimum_abi", lib)


if __name__ == "__main__":
    unittest.main()
