#!/usr/bin/env python3
"""The re-review date check names an advisory whose date has passed.

Today in these tests is the fixed day below. It is not the clock, and it is
not the re-review date written in elastos/.cargo/audit.toml. Each ignored id
has to carry its own date: the comment block directly above it, or a date on
its own line. A date is not kept for the next id.
"""

import datetime
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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

SAME_LINE = """\
[advisories]
ignore = [
  "RUSTSEC-2026-0001", # re-review by 2026-12-09 at the latest.
]
"""

# The review's demonstrated line: the date sits in a trailing comment, so a
# scan that keeps the date and skips the id accepts an overdue advisory.
DEMONSTRATED = """\
[advisories]
ignore = [
  "RUSTSEC-2026-0001", # re-review by 2026-01-01 at the latest.
]
"""

DEMONSTRATED_FRAGMENT = '"RUSTSEC-2026-0001", # re-review by 2026-01-01 at the latest.\n'

NOT_KEPT = """\
[advisories]
ignore = [
  "RUSTSEC-2026-0001", # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0002",
]
"""

NOT_KEPT_ABOVE = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0001",
  "RUSTSEC-2026-0002",
]
"""

TWO_DATES = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0001", # re-review by 2026-12-31 at the latest.
]
"""

# 2026 is not a leap year, so 29 February is not a date.
UNREAL = """\
[advisories]
ignore = [
  # re-review by 2026-02-29 at the latest.
  "RUSTSEC-2026-0001",
]
"""

ONE_LINE = """\
[advisories]
ignore = [
  "RUSTSEC-2026-0001", "RUSTSEC-2026-0002", # re-review by 2026-12-09 at the latest.
]
"""

SINGLE_QUOTED = """\
[advisories]
ignore = [
  # re-review by 2026-11-20 at the latest.
  'RUSTSEC-2026-0001',
]
"""

TRAILING = """\
[advisories]
ignore = [
  # re-review by 2026-11-20 at the latest.
  "RUSTSEC-2026-0001", # still accepted
]
"""

COMMENTED_OUT = """\
[advisories]
ignore = [
  # "RUSTSEC-2026-0001",
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0381",
]
"""

OTHER_SECTION = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.
  "RUSTSEC-2026-0381",
]
note = "RUSTSEC-2026-0009"

[notes]
ignore = [
  "RUSTSEC-2026-0001", # re-review by 2020-01-01 at the latest.
]
also = 'RUSTSEC-2026-0002'
"""

BLANK = """\
[advisories]
ignore = [
  # re-review by 2026-12-09 at the latest.

  "RUSTSEC-2026-0001",
]
"""

DOTTED = """\
advisories.ignore = [
  # re-review by 2026-01-01 at the latest.
  "RUSTSEC-2026-0001",
]
"""

INLINE = """\
advisories = { note = "no", ignore = ["RUSTSEC-2026-0001"] }
"""


class AuditReReviewTest(unittest.TestCase):
    def run_check(self, text, day):
        with tempfile.TemporaryDirectory(prefix="audit-re-review-") as directory:
            path = Path(directory) / "audit.toml"
            path.write_text(text, encoding="utf-8")
            env = {**os.environ, "AUDIT_RE_REVIEW_TODAY": day, "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), str(path)],
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

    def test_todays_ids_keep_their_own_dates(self):
        found, items = load_checker().parse_document(REAL.read_text(encoding="utf-8"))
        self.assertTrue(found)
        self.assertEqual(
            [(advisory, dates) for advisory, dates, _own in items],
            [
                ("RUSTSEC-2026-0381", ["2026-12-09"]),
                ("RUSTSEC-2026-0387", ["2026-12-09"]),
            ],
        )

    def test_the_deadline_day_itself_still_passes(self):
        status, errors = self.run_check(EXPIRED, "2026-11-20")
        self.assertEqual(status, 0, errors)

    def test_a_missing_date_names_the_advisory(self):
        status, errors = self.run_check(UNDATED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is missing", errors)

    def test_a_date_on_the_same_line_is_that_ids_date(self):
        status, errors = self.run_check(SAME_LINE, FIXED_TODAY)
        self.assertEqual(status, 0, errors)
        self.assertEqual(errors, "")

    def test_the_demonstrated_same_line_date_names_the_advisory(self):
        status, errors = self.run_check(DEMONSTRATED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date 2026-01-01 has passed", errors)

    def test_the_demonstrated_fragment_does_not_pass(self):
        # The review's temp file was this line alone. It is not an ignore list.
        status, errors = self.run_check(DEMONSTRATED_FRAGMENT, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001", errors)

    def test_a_same_line_date_is_not_kept_for_the_next_id(self):
        status, errors = self.run_check(NOT_KEPT, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0002: re-review date is missing", errors)
        self.assertNotIn("RUSTSEC-2026-0001", errors)

    def test_a_date_above_is_not_kept_for_the_next_id(self):
        status, errors = self.run_check(NOT_KEPT_ABOVE, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0002: re-review date is missing", errors)
        self.assertNotIn("RUSTSEC-2026-0001", errors)

    def test_two_dates_name_the_advisory(self):
        status, errors = self.run_check(TWO_DATES, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn(
            "RUSTSEC-2026-0001: re-review dates 2026-12-09 and 2026-12-31 are not one date",
            errors,
        )

    def test_a_date_that_is_not_real_names_the_advisory(self):
        status, errors = self.run_check(UNREAL, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date 2026-02-29 is not a date", errors)

    def test_two_ids_on_one_line_are_both_named(self):
        status, errors = self.run_check(ONE_LINE, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is not its own", errors)
        self.assertIn("RUSTSEC-2026-0002: re-review date is not its own", errors)

    def test_a_single_quoted_id_is_checked(self):
        status, errors = self.run_check(SINGLE_QUOTED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date 2026-11-20 has passed", errors)

    def test_a_trailing_comment_does_not_hide_the_id(self):
        status, errors = self.run_check(TRAILING, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date 2026-11-20 has passed", errors)

    def test_a_commented_out_id_is_not_checked(self):
        status, errors = self.run_check(COMMENTED_OUT, FIXED_TODAY)
        self.assertEqual(status, 0, errors)
        self.assertNotIn("RUSTSEC-2026-0001", errors)

    def test_an_id_in_another_section_is_not_checked(self):
        status, errors = self.run_check(OTHER_SECTION, FIXED_TODAY)
        self.assertEqual(status, 0, errors)
        self.assertNotIn("RUSTSEC-2026-0001", errors)
        self.assertNotIn("RUSTSEC-2026-0002", errors)
        self.assertNotIn("RUSTSEC-2026-0009", errors)

    def test_a_blank_line_ends_the_comment_block(self):
        status, errors = self.run_check(BLANK, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is missing", errors)

    def test_a_dotted_ignore_key_is_checked(self):
        status, errors = self.run_check(DOTTED, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date 2026-01-01 has passed", errors)
        self.assertNotIn("ignore list is missing", errors)

    def test_an_inline_ignore_table_is_checked(self):
        status, errors = self.run_check(INLINE, FIXED_TODAY)
        self.assertEqual(status, 1)
        self.assertIn("RUSTSEC-2026-0001: re-review date is missing", errors)
        self.assertNotIn("ignore list is missing", errors)

    def test_the_clock_is_utc(self):
        # 2026-11-25 01:00 UTC is still 2026-11-24 in Los Angeles. The deadline
        # below has passed in UTC and has not passed on that local calendar.
        module = load_checker()
        seen = []

        class Clock(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                seen.append(tz)
                return datetime.datetime(2026, 11, 25, 1, 0, tzinfo=datetime.timezone.utc)

        previous = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/Los_Angeles"
            time.tzset()
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUDIT_RE_REVIEW_TODAY", None)
                with mock.patch.object(module.datetime, "datetime", Clock):
                    self.assertEqual(module.today(), datetime.date(2026, 11, 25))
                    text = """\
[advisories]
ignore = [
  # re-review by 2026-11-24 at the latest.
  "RUSTSEC-2026-0001",
]
"""
                    self.assertEqual(
                        module.failures(text, module.today()),
                        ["RUSTSEC-2026-0001: re-review date 2026-11-24 has passed"],
                    )
        finally:
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            time.tzset()
        self.assertEqual(seen, [datetime.timezone.utc, datetime.timezone.utc])

    def test_tomllib_disagreement_names_the_id(self):
        module = load_checker()

        class FakeToml:
            @staticmethod
            def loads(_text):
                return {"advisories": {"ignore": ["RUSTSEC-2026-9999"]}}

        module.tomllib = FakeToml()
        found = module.failures(FRESH, datetime.date(2026, 11, 25))
        self.assertEqual(len(found), 1)
        self.assertIn("RUSTSEC-2026-9999", found[0])
        self.assertIn("RUSTSEC-2026-0381", found[0])


def load_checker():
    name = "audit_re_review_loaded"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()
