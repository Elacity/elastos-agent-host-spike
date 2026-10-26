import unittest

import common
from common import PACK

import preflight


def _load(name: str):
    return preflight.load_facts(PACK / "fixtures" / f"{name}.json")


class PreflightTests(unittest.TestCase):
    def test_darwin_arm64_fixture_is_clean(self):
        gaps = preflight.problems(_load("darwin-arm64"))
        self.assertEqual(gaps, [])

    def test_rosetta_fixture_is_refused(self):
        gaps = preflight.problems(_load("rosetta"))
        self.assertTrue(
            any("Rosetta" in gap for gap in gaps),
            gaps,
        )
        self.assertTrue(
            any("x86_64" in gap or "arm64" in gap for gap in gaps),
            gaps,
        )

    def test_root_fixture_is_refused(self):
        gaps = preflight.problems(_load("root"))
        self.assertIn("refuses to run as uid 0", gaps)

    def test_spaced_path_fixture_is_refused(self):
        gaps = preflight.problems(_load("spaced-path"))
        self.assertTrue(any("space" in gap for gap in gaps), gaps)

    def test_low_disk_fixture_is_refused(self):
        gaps = preflight.problems(_load("low-disk"))
        self.assertTrue(any("free disk" in gap for gap in gaps), gaps)

    def test_linux_fixture_is_refused(self):
        gaps = preflight.problems(_load("linux-x64"))
        self.assertTrue(any("live rows need macOS" in gap for gap in gaps), gaps)

    def test_sudo_env_is_refused(self):
        facts = _load("darwin-arm64")
        planted = preflight.facts_from_dict(
            {**facts.__dict__, "sudo_present": True}
        )
        gaps = preflight.problems(planted)
        self.assertTrue(any("SUDO_" in gap for gap in gaps), gaps)

    def test_missing_cargo_is_refused(self):
        facts = _load("darwin-arm64")
        planted = preflight.facts_from_dict({**facts.__dict__, "cargo_path": ""})
        gaps = preflight.problems(planted)
        self.assertIn("cargo is not on PATH", gaps)

    def test_host_facts_are_readable(self):
        from pathlib import Path

        facts = preflight.collect_facts(home=Path("/tmp"), work=Path("/tmp"))
        self.assertTrue(facts.os_name)
        self.assertTrue(facts.machine)
