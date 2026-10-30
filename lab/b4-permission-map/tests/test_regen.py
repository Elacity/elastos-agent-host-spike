"""Committed tables stay generated from the sources."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.catalog import PROVIDERS
from b4map.compare import build_report
from b4map.gitread import load_pins, repo_root
from b4map.render import render_baseline, render_mismatches


class RegenTests(unittest.TestCase):
    def test_committed_outputs_match_a_fresh_report(self):
        report = build_report(repo_root(), load_pins())
        for provider in PROVIDERS:
            path = LAB / "tables" / f"{provider}.json"
            self.assertTrue(path.is_file(), path)
            committed = json.loads(path.read_text())
            self.assertEqual(committed, report["providers"][provider])
        self.assertEqual((LAB / "MISMATCHES.md").read_text(), render_mismatches(report))
        self.assertEqual((LAB / "BASELINE.md").read_text(), render_baseline(report))


if __name__ == "__main__":
    unittest.main()
