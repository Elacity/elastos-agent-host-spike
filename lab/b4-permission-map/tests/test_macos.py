"""Parse the three macOS oracles and the C8 declared-rights files."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.catalog import CONTRACT_RIGHT_IDS, PLATFORM_BASELINE_IDS, SHARED_RULES
from b4map.gitread import repo_root
from b4map.macos import MacosParseError, parse_declared_rights, parse_operations_table, parse_profile


class MacosTests(unittest.TestCase):
    def setUp(self):
        self.root = repo_root()

    def test_each_oracle_holds_the_shared_rules(self):
        for provider in ("did-provider", "wallet-provider", "model-provider"):
            rel = f"capsules/{provider}/confine.sb"
            profile = parse_profile((self.root / rel).read_text(), rel)
            forms = [allow["form"] for allow in profile["allows"]]
            self.assertEqual(profile["deny_default"]["form"], "(deny default)")
            self.assertEqual(profile["deny_network"]["form"], "(deny network*)")
            self.assertIn(SHARED_RULES["bound-executable"], forms)
            self.assertIn(SHARED_RULES["storage.root"], forms)
            self.assertIn(SHARED_RULES["storage.parent"], forms)

    def test_declared_rights_are_the_c8_template(self):
        for provider in ("did-provider", "wallet-provider", "model-provider"):
            rel = f"capsules/{provider}/tests/fixtures/confine/declared-rights.json"
            declared = parse_declared_rights((self.root / rel).read_text(), rel, provider)
            self.assertEqual(set(declared["rights"]), set(CONTRACT_RIGHT_IDS))
            self.assertEqual(set(declared["platform_baseline"]), set(PLATFORM_BASELINE_IDS))
            self.assertEqual(
                declared["rights"]["storage"],
                [SHARED_RULES["storage.parent"], SHARED_RULES["storage.root"]],
            )

    def test_second_template_id_is_refused(self):
        rel = "capsules/did-provider/tests/fixtures/confine/declared-rights.json"
        text = (self.root / rel).read_text().replace('"storage"', '"bridge-template"', 1)
        with self.assertRaises(MacosParseError) as caught:
            parse_declared_rights(text, rel, "did-provider")
        self.assertIn("not a C8 contract right", str(caught.exception))

    def test_operations_table_is_read(self):
        rel = "capsules/did-provider/CONFINEMENT.md"
        rows = parse_operations_table((self.root / rel).read_text(), rel)
        self.assertGreater(len(rows), 0)
        init = next(row for row in rows if row["operation"] == "init")
        self.assertEqual(init["right"], "`storage`")
        self.assertIn("designed, not enforced", init["linux"])

    def test_allow_default_is_refused(self):
        with self.assertRaises(MacosParseError):
            parse_profile("(version 1)\n(allow default)\n(deny network*)\n", "x.sb")


if __name__ == "__main__":
    unittest.main()
