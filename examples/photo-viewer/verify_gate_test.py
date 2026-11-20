#!/usr/bin/env python3
"""Check the kit guest gate and falsify it with the kit runner; Cargo stays idle."""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

KIT_CALL = 'bash "${VIEWER_DIR}/../capsule-kit/guest/verify.sh"'
GATE_CASE = '''GATE=0
case "${GATE_LIST:-}" in
    *gates-photo* | *photo-gates*) GATE=1 ;;
esac'''
GATED_CALL = f'''if [[ $GATE -eq 0 ]]; then
    {KIT_CALL}
else
    echo "photo-viewer: lane gate leaves kit guest checks to the kit verify"
fi'''


class GateTests(unittest.TestCase):
    def check_gate(self, source):
        self.assertEqual(source.count(KIT_CALL), 1)
        self.assertIn(GATED_CALL, source)
        self.assertIn(GATE_CASE, source)
        branch = source.index(GATED_CALL)
        self.assertLess(source.index(GATE_CASE), branch)
        check = 'python3 -I "${VIEWER_DIR}/verify_gate_test.py"\n'
        plant = 'python3 -I "${VIEWER_DIR}/verify_gate_test.py" --falsify\n'
        self.assertLess(source.index(check), source.index(plant))
        self.assertLess(source.index(plant), branch)

    def test_the_lane_gate_does_not_repeat_the_kit_guest_checks(self):
        """the lane gate does not repeat the kit guest checks"""
        self.check_gate((HERE / "verify.sh").read_text())
        with self.assertRaises(AssertionError):
            self.check_gate(KIT_CALL + "\n")


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the gate test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "the lane gate repeats the kit guest checks",
            HERE / "verify.sh",
            [(GATED_CALL, KIT_CALL)],
            ["GateTests.test_the_lane_gate_does_not_repeat_the_kit_guest_checks"],
        )]
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done="all 1 photo gate falsifiers caught")
    else:
        unittest.main(verbosity=2)
