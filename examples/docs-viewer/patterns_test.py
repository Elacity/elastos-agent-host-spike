#!/usr/bin/env python3
"""Pin the Bus v2 patterns and falsify them with the kit runner; Cargo stays idle."""
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

CONFLICT_RULE = "Bus v2 `bus-error` has `conflict`, which v1 does not."
FOLDER_RULE = (
    "`verify.sh` cds into the `bus2` directory before the `cargo` commands for that guest, "
    "because `rustup` reads the toolchain from the current folder, not from `--manifest-path`."
)
BUS2_CD = '    cd "${VIEWER_DIR}/bus2"\n'
CONFLICT_ARM = (
    '        BusError::Conflict(why) => format!("in conflict: {why}"),\n'
)
READ_FAILURE_ARM = (
    '        | BusError::Internal(why) => format!("could not be read: {why}"),\n'
)
GUEST = HERE / "bus2" / "guests" / "docs" / "src" / "lib.rs"
V2_WIT = HERE.parent / "bus2-proof" / "wit" / "bus2.wit"
V1_WIT = HERE.parent.parent / "elastos" / "wit" / "elastos-bus-v1.wit"


def bus_error_variant(path):
    variants = re.findall(r"variant bus-error \{([^}]*)\}", path.read_text())
    if len(variants) != 1:
        raise AssertionError(f"{path} does not declare one bus-error variant")
    return variants[0]


class PatternsTests(unittest.TestCase):
    def check_rule(self, rule):
        source = (HERE.parent / "capsule-kit" / "PATTERNS.md").read_text()
        heading = "\n## 6. Bus v2 slices and stop\n"
        self.assertEqual(source.count(heading), 1)
        section = source.split(heading, 1)[1].split("\n## ", 1)[0]
        self.assertEqual(" ".join(section.split()).count(rule), 1)
        self.assertEqual(" ".join(source.split()).count(rule), 1)

    def test_the_bus2_checks_run_from_the_bus2_folder(self):
        """the bus2 checks run from the bus2 folder"""
        self.check_rule(FOLDER_RULE)
        source = (HERE / "verify.sh").read_text()
        self.assertEqual(source.count(BUS2_CD), 1)
        fmt = "    cargo fmt --all -- --check\n"
        self.assertEqual(source.count(fmt), 1)
        self.assertIn(f"(\n{BUS2_CD}{fmt}", source)
        gate = 'python3 -I "${VIEWER_DIR}/verify_gate_test.py"'
        check = 'python3 -I "${VIEWER_DIR}/patterns_test.py"'
        self.assertIn(f"{gate}\n{gate} --falsify\n", source)
        self.assertIn(f"{check}\n{check} --falsify\n", source)
        self.assertLess(source.index(f"{gate} --falsify"), source.index(check))
        self.assertLess(source.index(f"{check} --falsify"), source.index(BUS2_CD))

    def test_bus_v2_conflict_is_named(self):
        """bus v2 conflict is named"""
        self.check_rule(CONFLICT_RULE)
        self.assertIn("conflict(string)", bus_error_variant(V2_WIT))
        self.assertNotIn("conflict", bus_error_variant(V1_WIT))
        source = GUEST.read_text()
        reasons = re.findall(r"^fn reason\(error: &BusError\) -> String \{\n.*?^\}",
                             source, re.M | re.S)
        self.assertEqual(len(reasons), 1)
        self.assertEqual(reasons[0].count(CONFLICT_ARM), 1)
        self.assertEqual(reasons[0].count(READ_FAILURE_ARM), 1)
        self.assertEqual(source.count(CONFLICT_ARM), 1)


def failing_tests(*names):
    result = kit.run([sys.executable, "-I", __file__, "-v", *names], HERE)
    output = result.stderr
    count = len(names) if names else 2
    if f"Ran {count} test" not in output or "ERROR:" in output:
        raise SystemExit(f"the pattern tests did not run cleanly:\n{output}")
    failed = set(re.findall(r"^FAIL: (\w+) \(__main__\.(\w+)(?:\.\w+)?\)$", output, re.M))
    if result.returncode != (1 if failed else 0):
        raise SystemExit(f"the pattern tests did not report their failures:\n{output}")
    return {f"{group}.{name}" for name, group in failed}


def test_fails(name):
    return failing_tests(name) == {name}


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [
            (
                "the bus2 checks omit the bus2 directory change",
                HERE / "verify.sh",
                [(BUS2_CD, "")],
                ["PatternsTests.test_the_bus2_checks_run_from_the_bus2_folder"],
            ),
            (
                "the bus2 reason makes conflict a plain read failure",
                GUEST,
                [(CONFLICT_ARM,
                  '        BusError::Conflict(why) => format!("could not be read: {why}"),\n')],
                ["PatternsTests.test_bus_v2_conflict_is_named"],
            ),
        ]
        kit.main([(cases, None, test_fails, None, True, failing_tests)], args=[],
                 done="all 2 docs pattern falsifiers caught")
    else:
        unittest.main(verbosity=2)
