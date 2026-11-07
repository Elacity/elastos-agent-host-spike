import unittest

import common  # noqa: F401
from common import PACK

from catalog import PIN_BY_ID, ROWS, a14_runs_demo, unique_checkouts


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
            self.assertEqual(row.pin_status, "NEEDS_REPIN")
            self.assertEqual(PIN_BY_ID[row_id].status, "NEEDS_REPIN")

    def test_readme_has_sash_commands(self):
        text = (PACK / "README.md").read_text(encoding="utf-8")
        self.assertIn("sh lab/mac-evidence-pack/morning.sh", text)
        self.assertIn("pack-clone", text)
        self.assertIn("PACK_CLONE_FOREIGN", text)
        self.assertIn("summary.txt", text)
        self.assertNotIn("git checkout cursor/mac-evidence-pack-be32", text)
        self.assertNotIn("git fetch origin cursor/mac-evidence-pack-be32", text)

    def test_pins_file_is_the_only_row_map(self):
        pins_text = (PACK / "pins.ini").read_text(encoding="utf-8")
        self.assertIn("row -> branch + SHA", pins_text)
        self.assertIn("NEEDS_REPIN", pins_text)
        self.assertIn("[C1]", pins_text)
        self.assertIn("fa1841f35d32e7bea98e124fd406231d0088fd4e", pins_text)
