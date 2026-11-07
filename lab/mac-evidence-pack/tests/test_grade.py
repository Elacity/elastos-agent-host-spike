import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
from common import PACK

from catalog import row_by_id
from grade import grade


class GradeTests(unittest.TestCase):
    def test_exit_zero_without_evidence_is_fail(self):
        verdict = grade(row_by_id("A8"), exit_code=0, evidence_path=None)
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("no evidence file", verdict.reason)

    def test_empty_evidence_with_exit_zero_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("", encoding="utf-8")
            verdict = grade(row_by_id("A8"), exit_code=0, evidence_path=path)
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("empty", verdict.reason)

    def test_exit_zero_without_named_test_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("ok\nall good\nexit 0\n", encoding="utf-8")
            verdict = grade(row_by_id("A8"), exit_code=0, evidence_path=path)
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("without evidence", verdict.reason)

    def test_ignored_named_test_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text(
                "test outside_write_denied ... ignored, NOT RUN: sandbox-exec is macOS only\n",
                encoding="utf-8",
            )
            verdict = grade(row_by_id("C3"), exit_code=0, evidence_path=path)
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("ignored", verdict.reason)

    def test_failed_named_test_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text(
                "test agent_host_host_key_read_is_refused ... FAILED\n",
                encoding="utf-8",
            )
            verdict = grade(row_by_id("A8"), exit_code=101, evidence_path=path)
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("FAILED", verdict.reason)

    def test_expected_a8_table_line_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text(
                "test agent_host_host_key_read_is_refused ... ok\n"
                "A8 | agent_host_host_key_read_is_refused | PASS\n",
                encoding="utf-8",
            )
            verdict = grade(row_by_id("A8"), exit_code=0, evidence_path=path)
        self.assertEqual(verdict.status, "PASS")

    def test_a14_preflight_ok_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("preflight: OK\n", encoding="utf-8")
            verdict = grade(row_by_id("A14"), exit_code=0, evidence_path=path)
        self.assertEqual(verdict.status, "PASS")

    def test_skipped_row_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("NOT RUN: --dry-run\n", encoding="utf-8")
            verdict = grade(
                row_by_id("A8"),
                exit_code=None,
                evidence_path=path,
                skipped="--dry-run; macOS row not executed",
            )
        self.assertEqual(verdict.status, "NOT RUN")

    def test_blocked_pin_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("FAIL: PIN_NEEDS_REPIN\n", encoding="utf-8")
            verdict = grade(
                row_by_id("C1"),
                exit_code=0,
                evidence_path=path,
                blocked="PIN_NEEDS_REPIN: #323 needs a new SHA",
            )
        self.assertEqual(verdict.status, "FAIL")
        self.assertTrue(verdict.reason.startswith("PIN_NEEDS_REPIN"))

    def test_crash_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            path.write_text("boom\n", encoding="utf-8")
            verdict = grade(
                row_by_id("C1"),
                exit_code=None,
                evidence_path=path,
                crashed="boom",
            )
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("crashed", verdict.reason)
