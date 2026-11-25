#!/usr/bin/env python3
"""The re-review date check names an advisory whose date has passed.

Today in these tests is the fixed day below. It is not the clock, and it is
not the re-review date written in elastos/.cargo/audit.toml.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("audit-re-review.py")
REAL = SCRIPT.resolve().parents[1] / "elastos/.cargo/audit.toml"
# A fixed day. The committed audit file's own deadline is later than this.
FIXED_TODAY = "2026-11-25"

FRESH = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0381",
]
"""

# 2026-11-20 is a fixture deadline. It is not the date in elastos/.cargo/audit.toml.
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
        status, errors = self.run_check(FRESH, FIXED_TODAY)
        self.assertEqual(status, 0, errors)
        self.assertEqual(errors, "")

    def test_an_expired_date_fails_and_names_that_advisory(self):
        # The expired deadline stays 2026-11-20. It is not copied from the audit file.
        self.assertNotIn("re-review by 2026-11-20", REAL.read_text(encoding="utf-8"))
        status, errors = self.run_check(EXPIRED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0387: re-review date 2026-11-20 has passed", errors)
        self.assertNotIn("RUSTSEC-2026-0381", errors)

    def test_todays_file_passes_on_a_fixed_today(self):
        text = REAL.read_text(encoding="utf-8")
        self.assertIn("Reviewed 2026-10-23 and 2026-11-25", text)
        self.assertIn("re-review by 2026-12-09 at the latest.", text)
        status, errors = self.run_check(text, FIXED_TODAY)
        self.assertEqual(status, 0, errors)
        self.assertEqual(errors, "")

    def test_the_deadline_day_itself_still_passes(self):
        status, errors = self.run_check(EXPIRED, "2026-11-20")
        self.assertEqual(status, 0, errors)

    def test_a_missing_date_names_the_advisory(self):
        status, errors = self.run_check(UNDATED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is missing", errors)


if __name__ == "__main__":
    unittest.main()
