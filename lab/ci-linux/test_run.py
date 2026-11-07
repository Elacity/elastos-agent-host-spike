"""Contract tests for the lab Linux evidence helper.

These tests are the standing falsifiers for the proof rule: a missing lane,
a one-sided row, a malformed row, or a failed command leaves B4 and C9
unproven.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "lab-linux-matrix.yml"


class HelperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rows = self.root / "rows"
        self.rows.mkdir()
        self.calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def facts(self, **overrides):
        facts = {
            "machine": "x86_64",
            "kernel": "Linux 6.8.0-1 x86_64",
            "landlock_abi": "5",
            "seccomp": "available (process mode 0)",
            "user_namespaces": "available",
            "user_namespace_sysctls": (
                "max_user_namespaces=1, unprivileged_userns_clone=absent, "
                "apparmor_restrict_unprivileged_userns=0"
            ),
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "runs_on": "ubuntu-24.04",
            "runner_arch": "X64",
            "github_sha": "",
        }
        facts.update(overrides)
        return facts

    def runner(self, result):
        def fake(argv, cwd, env, timeout):
            self.calls.append((argv, cwd, env, timeout))
            return result

        return fake

    def evaluate(self, facts=None, runner=None):
        if runner is None and hasattr(self, "_fake"):
            runner = self._fake
        return run.evaluate(
            self.root,
            "linux-x86-64",
            facts or self.facts(),
            runner or self.runner(run.CommandResult(0, "", "")),
            self.rows,
        )

    def test_missing_lanes_are_skips_and_do_not_prove_checks(self):
        report = self.evaluate()
        text = run.render(report)
        self.assertEqual(self.calls, [])
        self.assertEqual(report["lanes_result"], "skipped")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertEqual(
            report["claim"],
            "No confinement lane is on this branch. "
            "This run did not prove B4 or C9 on linux-x86-64.",
        )
        for name in run.LANES:
            self.assertIn(f"folder lab/{name} is absent on this branch", text)
        self.assertIn("landlock_abi: 5", text)
        self.assertIn("seccomp: available (process mode 0)", text)
        self.assertIn("user_namespaces: available", text)
        self.assertIn("kernel: Linux 6.8.0-1 x86_64", text)
        self.assertIn("confinement_proven: no", text)
        self.assertNotIn("are proven", text)

    def test_present_folder_without_a_runner_fails(self):
        lane = self.root / "lab" / "linux-confine"
        lane.mkdir(parents=True)
        report = self.evaluate()
        self.assertEqual(report["lanes_result"], "failed")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertIn("no run-ci-linux.sh", report["lanes"][0]["reason"])
        self.assertEqual(self.calls, [])

    def test_symlink_lane_is_a_failure(self):
        lab = self.root / "lab"
        lab.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (lab / "linux-confine").symlink_to(outside, target_is_directory=True)
        report = self.evaluate()
        self.assertEqual(report["lanes"][0]["status"], "failed")
        self.assertIn("symlink", report["lanes"][0]["reason"])
        self.assertEqual(report["confinement_proven"], "no")

    def test_unlocked_cargo_is_refused_before_a_command(self):
        lane = self.root / "lab" / "linux-confine"
        lane.mkdir(parents=True)
        (lane / "Cargo.toml").write_text("[package]\nname = 'x'\nversion = '0.0.0'\n", encoding="utf-8")
        report = self.evaluate()
        self.assertEqual(self.calls, [])
        self.assertEqual(report["lanes_result"], "failed")
        self.assertIn("no Cargo.lock", report["lanes"][0]["reason"])
        self.assertEqual(report["confinement_proven"], "no")

    def test_cargo_lane_uses_locked_and_nocapture(self):
        lane = self.root / "lab" / "owned-storage"
        lane.mkdir(parents=True)
        (lane / "Cargo.toml").write_text("[package]\nname = 'owned'\nversion = '0.0.0'\n", encoding="utf-8")
        (lane / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
        stdout = (
            "CI-LINUX-ROW B4 permitted read under STORAGE_ROOT returned the fixture\n"
            "CI-LINUX-ROW B4 refused outside read returned storage_error\n"
            "CI-LINUX-ROW C9 permitted the owned write stayed under the root\n"
            "CI-LINUX-ROW C9 refused the parent write returned storage_error\n"
            "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        report = self.evaluate(runner=self.runner(run.CommandResult(0, stdout, "")))
        argv, cwd, env, timeout = self.calls[0]
        self.assertEqual(cwd, lane)
        self.assertEqual(
            argv,
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                str(lane / "Cargo.toml"),
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(env["CI_LINUX_LANE"], "owned-storage")
        self.assertEqual(env["CI_LINUX_PLATFORM"], "linux-x86-64")
        self.assertTrue(env["CI_LINUX_ROWS"].endswith("owned-storage.rows"))
        self.assertGreaterEqual(timeout, 1)
        self.assertEqual(report["lanes_result"], "passed")
        self.assertEqual(report["confinement_proven"], "yes")
        self.assertEqual(report["checks"]["B4"]["status"], "proven")
        self.assertEqual(report["checks"]["C9"]["status"], "proven")
        self.assertIn("are proven", report["claim"])

    def test_script_is_the_only_command_when_it_is_present(self):
        lane = self.root / "lab" / "fail-closed-linux"
        lane.mkdir(parents=True)
        script = lane / "run-ci-linux.sh"
        script.write_text("echo ok\n", encoding="utf-8")
        (lane / "Cargo.toml").write_text("[package]\nname = 'x'\nversion = '0.0.0'\n", encoding="utf-8")
        (lane / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
        report = self.evaluate(runner=self.runner(run.CommandResult(0, "ok\n", "")))
        self.assertEqual(self.calls[0][0], ["bash", str(script)])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report["lanes_result"], "passed")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertIn("exited 0", report["claim"])

    def test_permitted_without_refusal_does_not_prove(self):
        self.write_script("linux-confine", "CI-LINUX-ROW B4 permitted the root read returned the fixture\n")
        report = self.evaluate()
        self.assertEqual(report["checks"]["B4"]["status"], "not proven")
        self.assertIn("no refused row", report["checks"]["B4"]["reason"])
        self.assertEqual(report["lanes_result"], "passed")
        self.assertEqual(report["confinement_proven"], "no")

    def test_refusal_without_permitted_does_not_prove(self):
        self.write_script("linux-confine", "CI-LINUX-ROW C9 refused the parent write returned storage_error\n")
        report = self.evaluate()
        self.assertEqual(report["checks"]["C9"]["status"], "not proven")
        self.assertIn("no permitted row", report["checks"]["C9"]["reason"])
        self.assertEqual(report["lanes_result"], "passed")
        self.assertEqual(report["confinement_proven"], "no")

    def test_rows_from_a_failing_lane_do_not_prove(self):
        text = (
            "CI-LINUX-ROW B4 permitted the root read returned the fixture\n"
            "CI-LINUX-ROW B4 refused the outside read returned storage_error\n"
            "CI-LINUX-ROW C9 permitted the owned write stayed under the root\n"
            "CI-LINUX-ROW C9 refused the parent write returned storage_error\n"
        )
        self.write_script("linux-confine", text)
        report = self.evaluate(runner=self.runner(run.CommandResult(1, text, "boom\n")))
        self.assertEqual(report["lanes_result"], "failed")
        self.assertEqual(report["checks"]["B4"]["status"], "not proven")
        self.assertEqual(report["checks"]["C9"]["status"], "not proven")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertTrue(any(not row["from_passing_lane"] for row in report["rows"]))
        self.assertIn("did not prove", report["claim"])

    def test_zero_cargo_tests_fail_the_lane(self):
        lane = self.root / "lab" / "linux-confine"
        lane.mkdir(parents=True)
        (lane / "Cargo.toml").write_text("[package]\nname = 'x'\nversion = '0.0.0'\n", encoding="utf-8")
        (lane / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
        stdout = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        report = self.evaluate(runner=self.runner(run.CommandResult(0, stdout, "")))
        self.assertEqual(report["lanes_result"], "failed")
        self.assertIn("0 passed", report["lanes"][0]["reason"])
        self.assertEqual(report["confinement_proven"], "no")

    def test_malformed_row_fails_the_lane(self):
        self.write_script("linux-confine", "CI-LINUX-ROW B4 allowed this is not a result\n")
        report = self.evaluate()
        self.assertEqual(report["lanes_result"], "failed")
        self.assertIn("malformed", report["lanes"][0]["reason"])
        self.assertEqual(report["confinement_proven"], "no")

    def test_rows_file_counts_when_stdout_is_quiet(self):
        self.write_script("linux-confine", "")

        def fake(argv, cwd, env, timeout):
            self.calls.append(argv)
            Path(env["CI_LINUX_ROWS"]).write_text(
                "CI-LINUX-ROW B4.storage permitted read under STORAGE_ROOT returned the fixture\n"
                "CI-LINUX-ROW B4.storage refused outside read returned storage_error\n"
                "CI-LINUX-ROW C9.owned permitted the owned write stayed under the root\n"
                "CI-LINUX-ROW C9.owned refused the parent write returned storage_error\n",
                encoding="utf-8",
            )
            return run.CommandResult(0, "", "")

        report = self.evaluate(runner=fake)
        self.assertEqual(report["confinement_proven"], "yes")
        self.assertEqual(report["checks"]["B4"]["reason"], "1 permitted, 1 refused")

    def test_machine_mismatch_does_not_claim_the_requested_platform(self):
        report = self.evaluate(facts=self.facts(machine="aarch64", runner_arch="ARM64"))
        text = run.render(report)
        self.assertEqual(self.calls, [])
        self.assertEqual(report["machine_matches"], "no")
        self.assertEqual(report["lanes_result"], "failed")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertIn("not the linux-x86-64 machine", report["claim"])
        self.assertIn("machine_matches: no", text)
        self.assertNotIn("are proven", text)

    def test_runner_arch_disagreement_is_a_mismatch(self):
        report = self.evaluate(facts=self.facts(runner_arch="ARM64"))
        self.assertEqual(report["machine_matches"], "no")
        self.assertEqual(self.calls, [])
        self.assertEqual(report["confinement_proven"], "no")

    def test_one_check_does_not_mark_confinement_proven(self):
        text = (
            "CI-LINUX-ROW B4 permitted the root read returned the fixture\n"
            "CI-LINUX-ROW B4 refused the outside read returned storage_error\n"
        )
        self.write_script("linux-confine", text)
        report = self.evaluate(runner=self.runner(run.CommandResult(0, text, "")))
        self.assertEqual(report["checks"]["B4"]["status"], "proven")
        self.assertEqual(report["checks"]["C9"]["status"], "not proven")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertIn("B4 is proven on linux-x86-64", report["claim"])
        self.assertIn("C9 is not proven", report["claim"])

    def test_a_later_lane_failure_voids_an_earlier_proof(self):
        self.write_script(
            "linux-confine",
            "CI-LINUX-ROW B4 permitted the root read returned the fixture\n"
            "CI-LINUX-ROW B4 refused the outside read returned storage_error\n"
            "CI-LINUX-ROW C9 permitted the owned write stayed under the root\n"
            "CI-LINUX-ROW C9 refused the parent write returned storage_error\n",
        )
        empty = self.root / "lab" / "owned-storage"
        empty.mkdir(parents=True)
        report = self.evaluate()
        self.assertEqual(report["lanes"][0]["status"], "passed")
        self.assertTrue(report["rows"])
        self.assertEqual(report["lanes_result"], "failed")
        self.assertEqual(report["checks"]["B4"]["status"], "not proven")
        self.assertEqual(report["checks"]["C9"]["status"], "not proven")
        self.assertEqual(report["confinement_proven"], "no")
        self.assertIn("did not prove", report["claim"])

    def test_render_refuses_a_false_yes(self):
        report = self.evaluate()
        report["confinement_proven"] = "yes"
        with self.assertRaises(RuntimeError):
            run.render(report)

    def test_parse_rows_ignores_ordinary_test_output(self):
        rows, errors = run.parse_rows("test storage ... ok\nCI-LINUX-ROW B4 permitted kept\n")
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["result"], "permitted")

    def test_a_real_python_lane_runs_its_tests(self):
        tests = self.root / "lab" / "linux-confine" / "tests"
        tests.mkdir(parents=True)
        (tests / "test_rows.py").write_text(
            "import os\n"
            "import unittest\n"
            "\n"
            "class Rows(unittest.TestCase):\n"
            "    def test_emit(self):\n"
            "        text = (\n"
            "            'CI-LINUX-ROW B4 permitted the root read returned the fixture\\n'\n"
            "            'CI-LINUX-ROW B4 refused the outside read returned storage_error\\n'\n"
            "            'CI-LINUX-ROW C9 permitted the owned write stayed under the root\\n'\n"
            "            'CI-LINUX-ROW C9 refused the parent write returned storage_error\\n'\n"
            "        )\n"
            "        with open(os.environ['CI_LINUX_ROWS'], 'a', encoding='utf-8') as handle:\n"
            "            handle.write(text)\n",
            encoding="utf-8",
        )
        report = run.evaluate(
            self.root,
            "linux-x86-64",
            self.facts(),
            run.default_runner,
            self.rows,
            timeout=60,
        )
        self.assertEqual(report["lanes"][0]["status"], "passed")
        self.assertGreaterEqual(report["lanes"][0]["tests_passed"], 1)
        self.assertEqual(report["confinement_proven"], "yes")
        self.assertIn("unittest", report["lanes"][0]["commands"][0])

    def write_script(self, name, stdout):
        lane = self.root / "lab" / name
        lane.mkdir(parents=True)
        (lane / "run-ci-linux.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        self._script_stdout = stdout

        def fake(argv, cwd, env, timeout):
            self.calls.append((argv, cwd, env, timeout))
            if stdout:
                Path(env["CI_LINUX_ROWS"]).write_text(stdout, encoding="utf-8")
            return run.CommandResult(0, stdout, "")

        self._fake = fake


class WorkflowTests(unittest.TestCase):
    def test_workflow_pins_and_permissions(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("pull-requests:", text)
        self.assertNotIn("id-token:", text)
        self.assertNotIn("actions:", text)
        self.assertIn("ubuntu-24.04-arm", text)
        self.assertIn("ubuntu-24.04", text)
        self.assertIn("linux-x86-64", text)
        self.assertIn("linux-aarch64", text)
        self.assertIn("fail-fast: false", text)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", text)
        self.assertIn("dtolnay/rust-toolchain@72504271e02fb719eb4eb3eaece3a8e3d06f57c0", text)
        self.assertIn("actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4", text)
        self.assertIn("persist-credentials: false", text)
        for lane in ("lab/linux-confine", "lab/fail-closed-linux", "lab/owned-storage"):
            self.assertIn(lane, text)
        self.assertIn("lab/ci-linux/run.py", text)
        self.assertIn("lab/ci-linux/test_run.py", text)
        self.assertNotIn("elastos/", text)
        self.assertNotIn("scripts/", text)
        self.assertIn("if: always()", text)


class LiveProbeTests(unittest.TestCase):
    def test_empty_tree_on_this_linux_skips_and_does_not_prove(self):
        if os.uname().sysname != "Linux":
            self.skipTest("kernel probes run on Linux")
        machine = platform.machine()
        chosen = {"x86_64": "linux-x86-64", "aarch64": "linux-aarch64"}.get(machine)
        if chosen is None:
            self.skipTest(f"no pinned platform for {machine}")
        with tempfile.TemporaryDirectory() as raw:
            evidence = Path(raw) / "out"
            code = run.main(
                ["--platform", chosen, "--root", raw, "--evidence-dir", str(evidence)]
            )
            text = (evidence / "evidence.txt").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("lanes_result: skipped", text)
        self.assertIn("confinement_proven: no", text)
        self.assertIn(f"kernel: Linux ", text)
        self.assertRegex(text, r"(?m)^landlock_abi: (?:[1-9][0-9]*|unavailable \(.+\))$")
        self.assertRegex(text, r"(?m)^seccomp: (?:available \(.+\)|unavailable \(.+\))$")
        self.assertRegex(text, r"(?m)^user_namespaces: (?:available|unavailable \(.+\))$")
        self.assertNotIn("are proven", text)
        self.assertNotIn("confinement_proven: yes", text)


class ProbeShapeTests(unittest.TestCase):
    def test_landlock_and_seccomp_shapes_on_linux(self):
        if os.uname().sysname != "Linux":
            self.skipTest("kernel probes run on Linux")
        landlock = run.probe_landlock()
        seccomp = run.probe_seccomp()
        self.assertRegex(landlock, r"^(?:[1-9][0-9]*|unavailable \(.+\))$")
        self.assertRegex(seccomp, r"^(?:available \(.+\)|unavailable \(.+\))$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
