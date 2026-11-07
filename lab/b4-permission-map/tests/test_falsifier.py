"""Plant a network allow in a copied profile and require CATCH."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.baseline import planted_network_allow_caught
from b4map.compare import build_report, mismatch_ids
from b4map.gitread import load_pins, repo_root
from check import planted_network_caught


class FalsifierTests(unittest.TestCase):
    def test_copied_profile_with_network_allow_is_caught(self):
        root = repo_root()
        plant = LAB / "plants" / "macos-network-allow" / "confine.sb"
        self.assertTrue(plant.is_file())
        original = (root / "capsules/did-provider/confine.sb").read_text()
        planted = plant.read_text()
        self.assertIn("(allow network*)", planted)
        self.assertNotIn("(allow network*)", original)
        report = build_report(root, load_pins(), {"did-provider": plant})
        self.assertTrue(planted_network_caught(report, "did-provider"))
        self.assertTrue(
            any(ident.startswith("did-provider/network/polarity/") for ident in mismatch_ids(report))
        )

    def test_control_copy_without_the_plant_is_not_a_network_catch(self):
        root = repo_root()
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "confine.sb"
            copy.write_text((root / "capsules/did-provider/confine.sb").read_text())
            report = build_report(root, load_pins(), {"did-provider": copy})
            self.assertFalse(planted_network_caught(report, "did-provider"))

    def test_cli_prints_caught(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(LAB / "check.py"),
                "--plant",
                str(LAB / "plants" / "macos-network-allow"),
                "--provider",
                "did-provider",
            ],
            cwd=repo_root(),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("F-B4-MACOS-NETWORK-ALLOW CAUGHT", result.stdout)

    def test_cli_prints_baseline_network_allow_caught(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(LAB / "check.py"),
                "--plant-baseline",
                str(LAB / "plants" / "baseline-network-allow"),
            ],
            cwd=repo_root(),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("F-B4-BASELINE-NETWORK-ALLOW CAUGHT", result.stdout)

    def test_committed_baseline_is_not_a_network_catch(self):
        report = build_report(repo_root(), load_pins())
        self.assertFalse(planted_network_allow_caught(report))


if __name__ == "__main__":
    unittest.main()

