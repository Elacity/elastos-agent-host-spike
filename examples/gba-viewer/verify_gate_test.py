#!/usr/bin/env python3
"""Check that the gba-viewer gate runs its rows and stops on a failed row."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

ROWS_CALL = 'python3 -I "${VIEWER_DIR}/rows_test.py"'
GATE_TEST = 'python3 -I "${VIEWER_DIR}/verify_gate_test.py"'
LAST_LINE = 'echo "gba-viewer: rows green, gate falsifier caught"'


def walk(script, tools):
    return subprocess.run(
        ["/bin/bash", str(script)], cwd=HERE,
        env={"PATH": f"{tools}{os.pathsep}{os.defpath}"},
        capture_output=True, text=True, timeout=60,
    )


def shim(root, rows_status):
    """A python3 that answers the gate's calls; the row call gets rows_status.

    Cargo is shimmed too: this test is the gate's control flow, not the core's
    rows, which the gate runs for real on its own.
    """
    tools = root / "bin"
    tools.mkdir(parents=True)
    python3 = tools / "python3"
    python3.write_text(
        "#!/bin/sh\n"
        'for argument in "$@"; do\n'
        '    case "$argument" in\n'
        f"        */rows_test.py) exit {rows_status} ;;\n"
        "    esac\n"
        "done\n"
        "exit 0\n"
    )
    python3.chmod(0o755)
    cargo = tools / "cargo"
    cargo.write_text("#!/bin/sh\nexit 0\n")
    cargo.chmod(0o755)
    return tools


class GateTests(unittest.TestCase):
    def test_the_gate_stops_on_a_failed_row(self):
        """the gate stops on a failed row"""
        with tempfile.TemporaryDirectory(prefix="gba-gate-") as temporary:
            root = pathlib.Path(temporary)
            failed = walk(HERE / "verify.sh", shim(root / "failing", 1))
            self.assertNotEqual(failed.returncode, 0, failed.stdout)
            self.assertNotIn("rows green", failed.stdout)

            passed = walk(HERE / "verify.sh", shim(root / "passing", 0))
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertIn("rows green", passed.stdout)

    def test_the_gate_runs_the_rows_before_its_last_line(self):
        """the gate runs the rows before its last line"""
        source = (HERE / "verify.sh").read_text()
        self.assertEqual(source.count(ROWS_CALL), 1)
        self.assertEqual(source.count(GATE_TEST + "\n"), 1)
        self.assertEqual(source.count(GATE_TEST + " --falsify\n"), 1)
        self.assertLess(source.index(ROWS_CALL + "\n"), source.index(GATE_TEST + "\n"))
        self.assertLess(
            source.index(GATE_TEST + " --falsify\n"), source.index(LAST_LINE),
        )
        self.assertIn("set -euo pipefail\n", source)
        self.assertEqual(source.count("rows_test.py"), 1)


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the gate test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "the gate keeps going after a failed row",
            HERE / "verify.sh",
            [("set -euo pipefail\n", "set -uo pipefail\n")],
            ["GateTests.test_the_gate_stops_on_a_failed_row"],
        )]
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done="all 1 gba gate falsifiers caught")
    else:
        unittest.main(verbosity=2)
