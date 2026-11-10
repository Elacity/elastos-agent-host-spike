"""Self-test of the mutation runner: a case is caught only when every named
test fails, and every named test runs. With `failing_tests`, a case is caught
only when the whole file's failing set is exactly the declared set.

Run: python3 -I examples/capsule-kit/falsify/test_falsify_kit.py
"""
import contextlib
import io
import pathlib
import subprocess
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
        # The file's crate, as the runner finds it: the nearest [package] name.
        (pathlib.Path(self.dir.name) / "Cargo.toml").write_text(
            '[workspace]\nname = "not-this"\n\n[package]\nauthors = ["a"]\nname = "guest"\n\n[lib]\nname = "nor_this"\n'
        )
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

    def run_case_with_failures(self, outcomes, actual):
        """One case whose named tests fail as `outcomes` says, with the whole
        file's failures given as `actual`."""
        case = ("the cap is not checked", self.file, [("if size > cap {", "if false {")], list(outcomes))

        def test_fails(name):
            self.ran.append(name)
            self.assertIn("if false {", self.file.read_text())
            return outcomes[name]

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            missed = kit.falsify([case], None, test_fails, failing_tests=lambda: set(actual))
        return missed, out.getvalue()

    def test_a_case_with_an_undeclared_failure_survives(self):
        missed, out = self.run_case_with_failures({"first": True}, {"first", "extra"})
        self.assertEqual(missed, ["the cap is not checked"])
        self.assertIn("undeclared failures: extra", out)

    def test_a_case_is_caught_when_the_whole_failure_set_is_declared(self):
        missed, out = self.run_case_with_failures({"first": True, "second": True}, {"first", "second"})
        self.assertEqual(missed, [])
        self.assertIn("caught: the cap is not checked", out)

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

    CASE = [("if size > cap {", "if false {")]

    @contextlib.contextmanager
    def clock(self, wall, run=None):
        """The runner's clock reads `wall()` and no real time passes; `run`,
        if given, stands in for every command the runner starts."""
        real = kit.time.time, kit.time.monotonic, kit.subprocess.run
        kit.time.time, kit.time.monotonic = wall, lambda: 0.0
        kit._latest_seen, kit._started = 0.0, (0.0, 0.0)
        if run is not None:
            kit.subprocess.run = lambda cmd, cwd=None, **_: run(cmd, cwd)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                yield
        finally:
            kit.time.time, kit.time.monotonic, kit.subprocess.run = real
            kit._latest_seen, kit._started = 0.0, (real[0](), real[1]())

    def test_a_file_restored_after_the_clock_stepped_back_is_newer_than_the_build_before_it(self):
        # The mutant is built while the clock reads T + 30. The clock then
        # steps back 530 s. The restored file, and the next mutant, must still
        # be newer than that build, or Cargo would take them for unchanged.
        # T is far ahead of today, so a file left at its real time is older.
        T = 4_000_000_000.0
        now = [T]
        stamps = []

        def run(cmd, cwd):
            now[0] = T + 30 if len(stamps) == 0 else now[0]
            stamps.append(self.file.stat().st_mtime)
            return subprocess.CompletedProcess(cmd, 0, "", "   Compiling guest v0.1.0\n")

        def test_fails(name):
            now[0] = T - 500
            return True

        cases = [(name, self.file, self.CASE, ["a"]) for name in ("first", "second")]
        with self.clock(lambda: now[0], run):
            kit.falsify(cases, lambda: kit.cargo_compiles(self.dir.name, []), test_fails)
        self.assertGreater(stamps[0], T, "the first mutant is newer than anything built before it")
        self.assertGreater(stamps[1], T + 30, "the second mutant is newer than the first build")
        self.assertGreater(self.file.stat().st_mtime, stamps[1], "the last restore is newer still")

    def test_time_that_really_passed_counts_when_the_clock_stepped_back_during_a_command(self):
        # The clock read 1,000 at the start and reads 900 now, but 50 s have
        # really passed: a build in that time may have written at up to 1,050.
        real = kit.time.time, kit.time.monotonic
        kit.time.time, kit.time.monotonic = (lambda: 900.0), (lambda: 50.0)
        kit._latest_seen, kit._started = 0.0, (1_000.0, 0.0)
        try:
            kit.stamp([self.file])
        finally:
            kit.time.time, kit.time.monotonic = real
            kit._latest_seen, kit._started = 0.0, (real[0](), real[1]())
        self.assertEqual(self.file.stat().st_mtime, 1_051.0)

    def test_a_mutant_cargo_did_not_rebuild_is_stamped_ahead_and_built_again(self):
        builds = []

        def run(cmd, cwd):
            # The first build prints no "Compiling": Cargo took the mutant for unchanged.
            builds.append(self.file.stat().st_mtime)
            stderr = "    Finished `test` profile\n" if len(builds) == 1 else "   Compiling guest v0.1.0\n"
            return subprocess.CompletedProcess(cmd, 0, "", stderr)

        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        with self.clock(lambda: 2_000_000.0, run):
            missed = kit.falsify([case], lambda: kit.cargo_compiles(self.dir.name, []), lambda name: True)
        self.assertEqual(missed, [])
        self.assertEqual(len(builds), 2, "one more build after the one that rebuilt nothing")
        self.assertEqual(builds[1] - builds[0], 60.0, "the mutant was stamped 60 s ahead before it")

    def test_a_mutant_no_build_compiled_stops_the_run_and_is_not_scored(self):
        # Neither the build nor the one more try compiles anything: the test
        # binary is not the mutant's, so the run stops before any test is scored.
        before = self.file.read_bytes()
        scored = []
        quiet = lambda cmd, cwd: subprocess.CompletedProcess(cmd, 0, "", "    Finished `test` profile\n")  # noqa: E731
        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        for build in (
            lambda: kit.cargo_compiles(self.dir.name, []),
            lambda: kit.build(["./build.sh"], self.dir.name),
        ):
            with self.clock(lambda: 2_000_000.0, quiet):
                with self.assertRaises(SystemExit) as stop:
                    kit.falsify([case], build, lambda name: scored.append(name) or True)
            self.assertIn("did not compile guest with a mutant in", str(stop.exception))
            self.assertEqual(scored, [])
            self.assertEqual(self.file.read_bytes(), before)

    def test_a_build_that_compiled_only_another_crate_did_not_compile_the_mutant(self):
        # Cargo rebuilt something, but not the crate the mutant is in.
        other = lambda cmd, cwd: subprocess.CompletedProcess(cmd, 0, "", "   Compiling guest-host v0.1.0\n   Compiling other v0.1.0\n")  # noqa: E731
        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        with self.clock(lambda: 2_000_000.0, other):
            with self.assertRaises(SystemExit) as stop:
                kit.falsify([case], lambda: kit.cargo_compiles(self.dir.name, []), lambda name: True)
        self.assertIn("did not compile guest with a mutant in", str(stop.exception))

    def test_a_rust_file_in_no_cargo_package_cannot_be_scored(self):
        (pathlib.Path(self.dir.name) / "Cargo.toml").unlink()
        loud = lambda cmd, cwd: subprocess.CompletedProcess(cmd, 0, "", "   Compiling guest v0.1.0\n")  # noqa: E731
        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        with self.clock(lambda: 2_000_000.0, loud):
            with self.assertRaises(SystemExit) as stop:
                kit.falsify([case], lambda: kit.cargo_compiles(self.dir.name, []), lambda name: True)
        self.assertIn("is in no Cargo package", str(stop.exception))

    def test_a_named_test_is_not_run_before_a_build_compiled_the_mutant(self):
        # A group with no build step: the first named test makes the checked
        # build itself, and a second named test does not build again.
        commands = []

        def run(cmd, cwd):
            commands.append(cmd)
            return subprocess.CompletedProcess(cmd, 101, "test result: FAILED. 0 passed; 1 failed", "   Compiling guest v0.1.0\n")

        def build_then_pass(cmd, cwd):
            commands.append(cmd)
            code = 0 if "--no-run" in cmd else 101
            return subprocess.CompletedProcess(cmd, code, "test result: FAILED. 0 passed; 1 failed", "   Compiling guest v0.1.0\n")

        case = ("the cap is not checked", self.file, self.CASE, ["a", "b"])
        with self.clock(lambda: 2_000_000.0, build_then_pass):
            missed = kit.falsify([case], None, lambda name: kit.cargo_test_fails(self.dir.name, ["--lib"], name))
        self.assertEqual(missed, [])
        self.assertEqual([("--no-run" in cmd) for cmd in commands], [True, False, False])

    def test_a_named_test_stops_the_run_when_its_own_build_compiled_nothing(self):
        quiet = lambda cmd, cwd: subprocess.CompletedProcess(cmd, 0, "test result: ok. 1 passed", "    Finished\n")  # noqa: E731
        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        with self.clock(lambda: 2_000_000.0, quiet):
            with self.assertRaises(SystemExit) as stop:
                kit.falsify([case], None, lambda name: kit.cargo_test_fails(self.dir.name, ["--lib"], name))
        self.assertIn("did not compile guest with a mutant in", str(stop.exception))

    def test_a_mutant_cargo_rebuilt_is_built_once_and_cargo_is_not_told_to_be_quiet(self):
        builds = []
        run = lambda cmd, cwd: (builds.append(cmd), subprocess.CompletedProcess(cmd, 0, "", "   Compiling guest v0.1.0\n"))[1]  # noqa: E731
        case = ("the cap is not checked", self.file, self.CASE, ["a"])
        with self.clock(lambda: 2_000_000.0, run):
            kit.falsify([case], lambda: kit.cargo_compiles(self.dir.name, ["-q", "--lib"]), lambda name: True)
        self.assertEqual(builds, [["cargo", "test", "--locked", "--lib", "--no-run"]])

    def test_a_build_with_no_mutant_in_place_only_has_to_pass(self):
        quiet = lambda cmd, cwd: subprocess.CompletedProcess(cmd, 0, "", "    Finished\n")  # noqa: E731
        with self.clock(lambda: 2_000_000.0, quiet):
            kit.build(["./build.sh"], self.dir.name)

    def test_main_stops_with_the_survivors(self):
        case = ("the cap is not checked", self.file, [("if size > cap {", "if false {")], ["a", "b"])
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                kit.main([([case], None, lambda name: name == "a", None, False)], args=[])
        self.assertIn("survived", str(stop.exception))

    def node_file(self, source):
        path = pathlib.Path(self.dir.name) / "adapter.test.mjs"
        path.write_text(source)
        return path

    def test_node_test_fails_counts_only_a_named_test_that_ran_and_failed(self):
        tests = self.node_file(
            'import test from "node:test";\n'
            'test("fails", () => {\n    throw new Error("x");\n});\n'
            'test("passes", () => {});\n'
        )
        self.assertTrue(kit.node_test_fails(tests, "fails"))
        self.assertFalse(kit.node_test_fails(tests, "passes"))

    def test_node_test_failures_returns_every_failing_name(self):
        tests = self.node_file(
            'import test from "node:test";\n'
            'test("passes", () => {});\n'
            'test("fails", () => { throw new Error("x"); });\n'
        )
        self.assertEqual(kit.node_test_failures(tests), {"fails"})

    def test_node_test_fails_refuses_a_name_no_test_has(self):
        tests = self.node_file('import test from "node:test";\ntest("present", () => {});\n')
        with self.assertRaises(SystemExit) as stop:
            kit.node_test_fails(tests, "absent")
        self.assertIn("no test matches", str(stop.exception))

    def test_node_test_fails_refuses_a_missing_file(self):
        missing = pathlib.Path(self.dir.name) / "missing.test.mjs"
        with self.assertRaises(SystemExit) as stop:
            kit.node_test_fails(missing, "anything")
        self.assertIn("did not load", str(stop.exception))

    def test_node_test_fails_refuses_a_file_that_does_not_load(self):
        for source in ("const = ;\n", "use std::path::Path;\n"):
            broken = self.node_file(source)
            with self.assertRaises(SystemExit) as stop:
                kit.node_test_fails(broken, "anything")
            self.assertIn("did not load", str(stop.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
