"""Self-test of the mutation runner: a case is caught only when every named
test fails, and every named test runs.

Run: python3 -I examples/capsule-kit/falsify/test_falsify_kit.py
"""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import falsify_kit as kit  # noqa: E402


class Runner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.file = pathlib.Path(self.dir.name) / "check.rs"
        self.file.write_text("if size > cap {\n    refuse();\n}\n")
        self.ran = []

    def tearDown(self):
        self.dir.cleanup()

    def run_case(self, outcomes):
        """One case whose named tests fail or pass as `outcomes` says."""
        case = ("the cap is not checked", self.file, [("if size > cap {", "if false {")], list(outcomes))

        def test_fails(name):
            self.ran.append(name)
            # The mutant is in place while its tests run.
            self.assertIn("if false {", self.file.read_text())
            return outcomes[name]

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            missed = kit.falsify([case], None, test_fails)
        return missed, out.getvalue()

    def test_a_case_whose_second_test_passes_survives(self):
        missed, out = self.run_case({"first": True, "second": False})
        self.assertEqual(missed, ["the cap is not checked"])
        self.assertIn("SURVIVED: the cap is not checked", out)
        self.assertIn("still passing: second", out)
        self.assertEqual(self.ran, ["first", "second"], "every named test runs")

    def test_a_case_whose_first_test_passes_survives(self):
        missed, out = self.run_case({"first": False, "second": True})
        self.assertEqual(missed, ["the cap is not checked"])
        self.assertIn("still passing: first", out)
        self.assertEqual(self.ran, ["first", "second"])

    def test_a_case_is_caught_only_when_every_test_fails(self):
        missed, out = self.run_case({"first": True, "second": True})
        self.assertEqual(missed, [])
        self.assertIn("caught: the cap is not checked", out)
        self.assertEqual(self.ran, ["first", "second"])

    def test_a_case_with_no_named_test_survives(self):
        missed, _ = self.run_case({})
        self.assertEqual(missed, ["the cap is not checked"])

    def test_the_file_is_restored_after_each_case(self):
        before = self.file.read_bytes()
        self.run_case({"first": True, "second": False})
        self.assertEqual(self.file.read_bytes(), before)

    def test_main_stops_with_the_survivors(self):
        case = ("the cap is not checked", self.file, [("if size > cap {", "if false {")], ["a", "b"])
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                kit.main([([case], None, lambda name: name == "a", None, False)], args=[])
        self.assertIn("survived", str(stop.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
