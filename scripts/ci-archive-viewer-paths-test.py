#!/usr/bin/env python3
"""scripts/ci-archive-viewer-paths.py, and the CI step that loads it from the base."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("ci-archive-viewer-paths.py")
REPO = Path(__file__).resolve().parents[1]
WORKFLOW = (REPO / ".github/workflows/ci.yml").read_text()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


paths = load("ci_archive_viewer_paths", SCRIPT)
fixture_git = load("fixture_git_env", Path(__file__).with_name("fixture-git-env.py"))


class RuleTest(unittest.TestCase):
    def test_the_archive_viewer_runs(self):
        self.assertTrue(paths.must_run(["examples/archive-viewer/src/zip.rs"]))
        self.assertTrue(paths.must_run(["examples/archive-viewer"]))

    def test_a_check_file_runs(self):
        for name in paths.CHECK_FILES:
            with self.subTest(name=name):
                self.assertTrue(paths.must_run(["notes.md", name]))

    def test_an_unrelated_change_skips(self):
        self.assertFalse(paths.must_run([
            "examples/photo-viewer/src/lib.rs",
            "lab/grant-binding/src/lib.rs",
            "README.md",
        ]))

    def test_a_name_that_only_starts_like_the_folder_skips(self):
        self.assertFalse(paths.must_run(["examples/archive-viewer-extra/src/lib.rs"]))

    def test_an_empty_change_list_runs(self):
        self.assertTrue(paths.must_run([]))

    def test_one_archive_file_among_notes_runs(self):
        self.assertTrue(paths.must_run(["README.md", "examples/archive-viewer/verify.sh"]))


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.repo = Path(self.root.name) / "repo"
        self.repo.mkdir()
        self.env = fixture_git.fixture_git_env(Path(self.root.name), {key: "fixture" for key in fixture_git.IDENTITY})
        self.git("init", "-q", "-b", "main")
        self.write({"README.md": "note\n"})
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git("checkout", "-q", "-b", "work")

    def tearDown(self):
        self.root.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], env=self.env, check=True, capture_output=True, text=True)

    def write(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def decide(self, head, base="main"):
        return paths.decide({"BASE_REF": base, "HEAD_SHA": head}, self.repo)

    def test_a_pull_request_that_misses_the_viewer_skips(self):
        self.write({"examples/photo-viewer/src/lib.rs": "fn main() {}\n"})
        self.assertFalse(self.decide(self.commit("photo"))[0])

    def test_a_pull_request_that_touches_the_viewer_runs(self):
        self.write({"examples/archive-viewer/src/tar.rs": "fn tar() {}\n"})
        self.assertTrue(self.decide(self.commit("tar"))[0])

    def test_a_pull_request_that_changes_nothing_runs(self):
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertTrue(self.decide(head)[0])

    def test_a_git_failure_runs(self):
        self.write({"README.md": "changed\n"})
        head = self.commit("notes")
        self.assertFalse(self.decide(head)[0])
        self.assertTrue(self.decide("0" * 40)[0])
        self.assertTrue(self.decide(head, base="gone")[0])

    def test_the_script_writes_run_false_only_for_a_real_skip(self):
        self.write({"README.md": "changed\n"})
        notes = self.commit("notes")
        output = Path(self.root.name) / "output"
        output.write_text("")
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)], cwd=self.repo, capture_output=True, text=True,
            env={**self.env, "BASE_REF": "main", "HEAD_SHA": notes, "GITHUB_OUTPUT": str(output)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "run=false\n")


def decide_script():
    """The archive-viewer-paths decide step, the same shape as installed-app-paths."""
    marker = "          rule=\"$RUNNER_TEMP/archive-viewer-paths-rule.py\"\n"
    start = WORKFLOW.index(marker)
    end = WORKFLOW.index("          fi\n", start)
    return textwrap.dedent(WORKFLOW[start:end + len("          fi\n")])


class BaseRuleTest(unittest.TestCase):
    """A pull request is judged by the base commit's copy of the rule."""

    def run_decide(self, base_rule, changes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo, temp, output = root / "repo", root / "temp", root / "output"
            repo.mkdir()
            temp.mkdir()
            env = fixture_git.fixture_git_env(root, {key: "fixture" for key in fixture_git.IDENTITY})

            def commit(files):
                for name, text in files.items():
                    path = repo / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text)
                for args in (("add", "-A"), ("commit", "-q", "-m", "fixture")):
                    subprocess.run(["git", "-C", str(repo), *args], env=env, check=True, capture_output=True)

            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], env=env, check=True, capture_output=True)
            rule = "scripts/ci-archive-viewer-paths.py"
            commit({"README.md": "note\n", **({} if base_rule is None else {rule: base_rule})})
            base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=env, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-C", str(repo), "checkout", "-q", "-b", "work"], env=env, check=True, capture_output=True)
            commit(changes)
            head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=env, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "main"], env=env, check=True, capture_output=True)
            result = subprocess.run(
                ["bash", "-e", "-c", decide_script()], cwd=repo, capture_output=True, text=True, timeout=60,
                env={**env, "BASE_REF": "main", "BASE_SHA": base, "HEAD_SHA": head,
                     "RUNNER_TEMP": str(temp), "GITHUB_OUTPUT": str(output)})
            self.assertEqual(result.returncode, 0, result.stderr)
            return output.read_text()

    def test_the_workflow_loads_the_rule_from_the_base_commit(self):
        self.assertIn('git show "${BASE_SHA}:scripts/ci-archive-viewer-paths.py"', WORKFLOW)
        self.assertIn('python3 -I "$rule"', WORKFLOW)
        self.assertIn("needs.archive-viewer-paths.outputs.run == 'true'", WORKFLOW)
        honest = SCRIPT.read_text()
        notes = {"README.md": "changed\n"}
        always_skip = 'import os\nopen(os.environ["GITHUB_OUTPUT"], "a").write("run=false\\n")\n'
        self.assertEqual(self.run_decide(honest, notes), "run=false\n")
        self.assertEqual(self.run_decide(honest, {"examples/archive-viewer/src/lib.rs": "x\n"}), "run=true\n")
        # The pull request's copy of the rule never runs. The base copy sees the
        # rule's own path in the change list and runs the parser.
        self.assertEqual(self.run_decide(honest, {**notes, "scripts/ci-archive-viewer-paths.py": always_skip}), "run=true\n")
        self.assertEqual(self.run_decide(None, notes), "run=true\n")
        self.assertEqual(self.run_decide(always_skip + "raise SystemExit(1)\n", notes), "run=true\n")


if __name__ == "__main__":
    unittest.main()
