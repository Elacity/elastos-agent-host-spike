import unittest

import common  # noqa: F401
from common import PACK

from catalog import ROWS, a14_runs_demo, unique_checkouts


class CatalogTests(unittest.TestCase):
    def test_expected_row_ids(self):
        self.assertEqual(
            [row.id for row in ROWS],
            ["A8", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "A6", "A12", "A14"],
        )

    def test_pins_are_full_commits(self):
        for row in ROWS:
            self.assertEqual(len(row.commit), 40, row.id)
            self.assertTrue(row.branch.startswith("cursor/"), row.id)
            self.assertTrue(row.pr > 0, row.id)

    def test_four_draft_checkouts(self):
        pins = unique_checkouts()
        self.assertEqual(len(pins), 4)
        prs = {pr for _, _, pr in pins}
        self.assertEqual(prs, {301, 323, 343, 289})

    def test_a14_does_not_run_the_demo(self):
        self.assertFalse(a14_runs_demo())
        a14 = next(row for row in ROWS if row.id == "A14")
        joined = " ".join(" ".join(cmd) for cmd in a14.commands)
        self.assertIn("lab/demo-a14/preflight.sh", joined)
        self.assertNotIn("install.sh", joined)
        self.assertNotIn("demo.py", joined)
        self.assertTrue(a14.demo_pointer)
        self.assertIn("NOT RUN", a14.demo_pointer)

    def test_c_series_uses_323(self):
        for row_id in ("C1", "C2", "C3", "C4", "C5", "C6", "C7"):
            row = next(item for item in ROWS if item.id == row_id)
            self.assertEqual(row.pr, 323)
            self.assertEqual(row.branch, "cursor/redteam-fix-4bfb")

    def test_readme_has_sash_commands(self):
        text = (PACK / "README.md").read_text(encoding="utf-8")
        for needle in (
            "git fetch origin cursor/mac-evidence-pack-be32",
            "git checkout cursor/mac-evidence-pack-be32",
            "sh lab/mac-evidence-pack/run.sh",
            "summary.txt",
        ):
            self.assertIn(needle, text)
