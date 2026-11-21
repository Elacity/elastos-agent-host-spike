"""An outer seatbelt block is a SKIP only after an independent stock canary."""

import subprocess
import unittest
from unittest.mock import patch

import sbx


class OuterSandboxClassification(unittest.TestCase):
    def test_stock_canary_confirms_outer_block(self):
        blocked = sbx.Result(71, "", sbx.SANDBOX_APPLY_REFUSAL + "\n")
        canary = subprocess.CompletedProcess([], 71, "", sbx.SANDBOX_APPLY_REFUSAL + "\n")
        with patch.object(sbx.subprocess, "run", return_value=canary) as run:
            reason = sbx.outer_sandbox_reason(blocked)
        self.assertIn("outer sandbox prevents", reason)
        self.assertEqual(run.call_args.args[0], [
            sbx.SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true",
        ])

    def test_profile_specific_failure_remains_an_error(self):
        blocked = sbx.Result(71, "", sbx.SANDBOX_APPLY_REFUSAL + "\n")
        canary = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(sbx.subprocess, "run", return_value=canary):
            self.assertIsNone(sbx.outer_sandbox_reason(blocked))
        with patch.object(sbx.subprocess, "run") as run:
            self.assertIsNone(sbx.outer_sandbox_reason(sbx.Result(71, "", "other failure")))
            run.assert_not_called()

    def test_runner_reports_confirmed_platform_skip(self):
        blocked = subprocess.CompletedProcess([], 71, "", sbx.SANDBOX_APPLY_REFUSAL + "\n")
        with patch.object(sbx.subprocess, "run", side_effect=[blocked, blocked]) as run:
            with self.assertRaisesRegex(unittest.SkipTest, "outer sandbox prevents"):
                sbx.run(
                    pinned_exe="/usr/bin/true", launch_exe="/usr/bin/true",
                    storage_root="/tmp/root", storage_parent="/tmp",
                )
        self.assertEqual(run.call_count, 2)
