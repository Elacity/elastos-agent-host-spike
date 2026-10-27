#!/usr/bin/env python3
"""Keep repro pins in the kit script; check and falsify without Cargo or Docker."""
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent.parent / "capsule-kit"
README = HERE / "README.md"
sys.path.insert(0, str(KIT / "falsify"))
import falsify_kit as kit  # noqa: E402

TEST = "PinsTests.test_the_repro_readme_does_not_repeat_the_kit_pins"
PIN_PATTERNS = (
    r'^IMAGE="[^"\n]*@sha256:([0-9a-f]{64})"$',
    r'^\s*apt-get [^\n]* install [^\n]* python3=([^\s]+)',
    r'https://snapshot\.debian\.org/archive/debian/(\d{8}T\d{6}Z)',
)
CASES = [
    (
        "the repro readme repeats the image digest",
        README, [], [TEST],
        [(README, "\n81c97592d519ba7397e8adccb0345fb5a91965c0a44b82af83bd1ef06c36cef5\n")],
    ),
    (
        "the repro readme repeats the python3 version",
        README, [], [TEST],
        [(README, "\n3.11.2-1+b1\n")],
    ),
    (
        "the repro readme repeats the Debian snapshot date",
        README, [], [TEST],
        [(README, "\n20261015T000000Z\n")],
    ),
]


class PinsTests(unittest.TestCase):
    def test_the_repro_readme_does_not_repeat_the_kit_pins(self):
        """the repro readme does not repeat the kit pins"""
        source = (KIT / "repro" / "build-in-container.sh").read_text()
        readme = README.read_text()
        self.assertEqual(len(CASES), len(PIN_PATTERNS))
        for pattern, case in zip(PIN_PATTERNS, CASES):
            name = case[0]
            values = re.findall(pattern, source, re.MULTILINE)
            self.assertEqual(len(values), 1, f"{name}: expected one kit pin")
            value = values[0]
            self.assertEqual(case[4][0][1], f"\n{value}\n",
                             f"{name}: update the stale falsifier from the kit script")
            self.assertNotIn(value, readme, f"{name}: refer to the kit script instead")


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the repro pin test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        kit.main([(CASES, None, test_fails, None, True)], args=[],
                 done="all 3 photo repro pin falsifiers caught")
    else:
        unittest.main(verbosity=2)
