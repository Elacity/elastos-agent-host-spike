#!/usr/bin/env python3
"""The re-review date check names an advisory whose date has passed."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("audit-re-review.py")

FRESH = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0381",
]
"""

EXPIRED = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0381",
  # re-review by 2026-11-20 at the latest.
  "RUSTSEC-2026-0387",
]
"""

UNDATED = """\
[advisories]
ignore = [
  # reviewed, with no date.
  "RUSTSEC-2026-0001",
]
"""


class AuditReReviewTest(unittest.TestCase):
    def run_check(self, text, day):
        with tempfile.TemporaryDirectory(prefix="audit-re-review-") as directory:
            path = Path(directory) / "audit.toml"
            path.write_text(text, encoding="utf-8")
            env = {**os.environ, "AUDIT_RE_REVIEW_TODAY": day, "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
        return result.returncode, result.stderr

    def test_a_future_date_passes(self):
        status, errors = self.run_check(FRESH, "2026-11-25")
        self.assertEqual(status, 0, errors)
        self.assertEqual(errors, "")

    def test_an_expired_date_fails_and_names_that_advisory(self):
        status, errors = self.run_check(EXPIRED, "2026-11-25")
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0387: re-review date 2026-11-20 has passed", errors)
        self.assertNotIn("RUSTSEC-2026-0381", errors)

    def test_the_deadline_day_itself_still_passes(self):
        status, errors = self.run_check(EXPIRED, "2026-11-20")
        self.assertEqual(status, 0, errors)

    def test_a_missing_date_names_the_advisory(self):
        status, errors = self.run_check(UNDATED, "2026-11-25")
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is missing", errors)


if __name__ == "__main__":
    unittest.main()
