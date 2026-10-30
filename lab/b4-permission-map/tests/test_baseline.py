"""The proposed baseline declares each right once and scores every platform."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.baseline import (
    BaselineError,
    apply_overlay,
    load_baseline,
    matches_proposal,
    planted_network_allow_caught,
    score_ids,
    validate_baseline,
)
from b4map.catalog import COMPARISON_RIGHTS, PROVIDERS
from b4map.compare import build_report
from b4map.gitread import load_pins, repo_root


class BaselineTests(unittest.TestCase):
    def test_committed_baseline_declares_each_right_once(self):
        baseline = load_baseline()
        ids = [entry["id"] for entry in baseline["rights"]]
        self.assertEqual(ids, [spec["id"] for spec in COMPARISON_RIGHTS])
        self.assertEqual(len(ids), len(set(ids)))
        parent = next(entry for entry in baseline["rights"] if entry["id"] == "storage.parent")
        self.assertEqual(parent["declared_as"], "STORAGE_PARENT")
        self.assertEqual(parent["proposed"], "deny")
        self.assertTrue(parent["open_decision"])
        slash = next(
            entry for entry in baseline["rights"] if entry["id"] == "startup-root-directory"
        )
        sysctl = next(entry for entry in baseline["rights"] if entry["id"] == "startup-sysctl")
        self.assertEqual(slash["proposed"], "deny")
        self.assertEqual(sysctl["proposed"], "deny")
        self.assertTrue(slash["open_decision"])
        self.assertTrue(sysctl["open_decision"])
        self.assertEqual(baseline["execution"]["linux_x86_64"], "NOT RUN")
        self.assertEqual(baseline["execution"]["jetson_aarch64"], "NOT RUN")
        self.assertEqual(baseline["execution"]["macos"], "NOT RUN")

    def test_missing_grant_matches_deny_and_partial_does_not(self):
        self.assertTrue(matches_proposal("deny", "deny"))
        self.assertTrue(matches_proposal("missing", "deny"))
        self.assertFalse(matches_proposal("partial", "deny"))
        self.assertFalse(matches_proposal("allow", "deny"))
        self.assertTrue(matches_proposal("allow", "allow"))
        self.assertFalse(matches_proposal("missing", "allow"))

    def test_real_sources_score_against_the_committed_baseline(self):
        report = build_report(repo_root(), load_pins())
        ids = set(score_ids(report))
        self.assertIn("did-provider/network/macos=CONFORMS", ids)
        self.assertIn("did-provider/unix-socketpair/linux-confine=MUST CHANGE", ids)
        self.assertIn("did-provider/unix-socketpair/macos=CONFORMS", ids)
        self.assertIn("did-provider/unix-socketpair/fail-closed-linux=CONFORMS", ids)
        self.assertIn("did-provider/signal.host/fail-closed-linux=MUST CHANGE", ids)
        self.assertIn("did-provider/signal.host/macos=CONFORMS", ids)
        self.assertIn("did-provider/storage.parent/macos=OPEN DECISION", ids)
        self.assertIn("did-provider/startup-root-directory/linux-confine=OPEN DECISION", ids)
        self.assertIn("did-provider/startup-sysctl/fail-closed-linux=OPEN DECISION", ids)
        self.assertEqual(report["baseline"]["counts"]["CONFORMS"], 75)
        self.assertEqual(report["baseline"]["counts"]["MUST CHANGE"], 6)
        self.assertEqual(report["baseline"]["counts"]["OPEN DECISION"], 27)
        self.assertEqual(report["status"]["linux_x86_64_execution"], "NOT RUN")
        for provider in PROVIDERS:
            network = next(
                row
                for row in report["providers"][provider]["rights"]
                if row["id"] == "network"
            )
            self.assertEqual(network["baseline"]["macos"], "CONFORMS")
            self.assertEqual(network["baseline"]["linux_confine"], "CONFORMS")
            self.assertEqual(network["baseline"]["fail_closed_linux"], "CONFORMS")

    def test_duplicate_right_is_refused(self):
        baseline = load_baseline()
        planted = copy.deepcopy(baseline)
        planted["rights"].append(planted["rights"][0])
        with self.assertRaises(BaselineError) as caught:
            validate_baseline(planted, rel="dup.json")
        self.assertIn("declared twice", str(caught.exception))

    def test_looser_network_overlay_is_caught(self):
        overlay = json.loads(
            (LAB / "plants" / "baseline-network-allow" / "overlay.json").read_text()
        )
        self.assertEqual(overlay["right"], "network")
        self.assertEqual(overlay["proposed"], "allow")
        planted = apply_overlay(load_baseline(), overlay)
        report = build_report(repo_root(), load_pins(), baseline=planted)
        self.assertTrue(planted_network_allow_caught(report))
        ids = set(score_ids(report))
        self.assertIn("did-provider/network/macos=MUST CHANGE", ids)
        self.assertIn("wallet-provider/network/linux-confine=MUST CHANGE", ids)
        self.assertIn("model-provider/network/fail-closed-linux=MUST CHANGE", ids)
        committed = build_report(repo_root(), load_pins())
        self.assertFalse(planted_network_allow_caught(committed))


if __name__ == "__main__":
    unittest.main()
