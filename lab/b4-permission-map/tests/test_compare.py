"""The checker flags polarity, coverage, and Linux-split mismatches."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.compare import classify_mismatch, mismatch_ids
from b4map.gitread import load_pins, repo_root
from b4map.compare import build_report


def _side(verdict: str) -> dict:
    return {"verdict": verdict, "rule": verdict, "file": "x", "line": 1}


class CompareTests(unittest.TestCase):
    def test_same_polarity_is_not_a_mismatch(self):
        self.assertEqual(
            classify_mismatch(_side("deny"), _side("deny"), _side("deny")),
            [],
        )
        self.assertEqual(
            classify_mismatch(_side("allow"), _side("allow"), _side("allow")),
            [],
        )

    def test_allow_versus_deny_is_polarity(self):
        found = classify_mismatch(_side("allow"), _side("deny"), _side("deny"))
        kinds = {item["kind"] for item in found}
        self.assertIn("polarity", kinds)

    def test_enforced_versus_missing_is_coverage(self):
        found = classify_mismatch(_side("allow"), _side("missing"), _side("missing"))
        kinds = {item["kind"] for item in found}
        self.assertIn("coverage", kinds)

    def test_linux_sides_that_disagree_are_a_split(self):
        found = classify_mismatch(_side("deny"), _side("allow"), _side("deny"))
        kinds = {item["kind"] for item in found}
        self.assertIn("linux-split", kinds)
        self.assertIn("polarity", kinds)

    def test_real_sources_flag_the_known_gaps(self):
        report = build_report(repo_root(), load_pins())
        ids = set(mismatch_ids(report))
        self.assertIn(
            "did-provider/startup-root-directory/coverage/macos->linux-confine", ids
        )
        self.assertIn("did-provider/storage.parent/coverage/macos->linux-confine", ids)
        self.assertIn("did-provider/unix-socketpair/polarity/macos->linux-confine", ids)
        self.assertIn(
            "did-provider/unix-socketpair/linux-split/linux-confine->fail-closed-linux",
            ids,
        )
        self.assertIn("did-provider/signal.host/coverage/macos->fail-closed-linux", ids)
        self.assertIn(
            "did-provider/signal.host/linux-split/linux-confine->fail-closed-linux",
            ids,
        )
        self.assertTrue(all("did-provider/network/polarity" not in ident for ident in ids))
        self.assertTrue(all("did-provider/device.ioctl/" not in ident for ident in ids))
        self.assertTrue(
            all("did-provider/bound-executable/" not in ident for ident in ids)
        )
        self.assertTrue(report["providers"]["did-provider"]["rights"])
        network = next(
            row
            for row in report["providers"]["did-provider"]["rights"]
            if row["id"] == "network"
        )
        self.assertTrue(network["match"])
        self.assertEqual(report["status"]["linux_x86_64_execution"], "NOT RUN")
        self.assertEqual(report["status"]["jetson_aarch64_execution"], "NOT RUN")
        self.assertEqual(report["status"]["macos_execution"], "NOT RUN")


if __name__ == "__main__":
    unittest.main()
