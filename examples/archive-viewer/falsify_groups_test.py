#!/usr/bin/env python3
"""Check the pass choice, and falsify it with the kit runner; Cargo stays idle."""
import inspect
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from falsify import guest_cases_on, kit, main  # noqa: E402


class GroupTests(unittest.TestCase):
    def test_guest_cases_run_on_the_plain_pass_only(self):
        """guest cases run on the plain pass only"""
        self.assertTrue(guest_cases_on([]))
        self.assertFalse(guest_cases_on(["--runtime"]))
        source = inspect.getsource(main)
        self.assertIn(
            "    if guest_cases_on(args):\n"
            "        groups.append((convert(CASES), build, test_fails, None, True))",
            source,
        )
        self.assertIn(
            "        if guest_cases_on(args):\n"
            "            check_isolation(CASES, args, every_test)",
            source,
        )


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the group test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "the guest group runs on the runtime pass too",
            HERE / "falsify.py",
            [(
                "    if guest_cases_on(args):\n"
                "        groups.append((convert(CASES), build, test_fails, None, True))",
                "    groups.append((convert(CASES), build, test_fails, None, True))",
            )],
            ["GroupTests.test_guest_cases_run_on_the_plain_pass_only"],
        )]
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done="all 1 archive group falsifiers caught")
    else:
        unittest.main(verbosity=2)
