#!/usr/bin/env python3
"""scripts/fixture-git-env.py keeps the caller's repository and git config out of a fixture."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("fixture_git_env", Path(__file__).with_name("fixture-git-env.py"))
fixture_git = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_git)


class FixtureGitEnvTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name).resolve()
        self.root = self.scratch / "root"
        self.root.mkdir()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, env=fixture_git.fixture_git_env(self.root),
                              capture_output=True, text=True)

    def test_discovery_stops_at_the_temporary_root(self):
        subprocess.run(["git", "init", "-q", str(self.scratch)], check=True, capture_output=True,
                       env=fixture_git.fixture_git_env(self.scratch))
        found = self.git("rev-parse", "--absolute-git-dir")
        self.assertNotEqual(found.returncode, 0, f"discovery left the temporary root: {found.stdout}")

    def test_no_user_or_xdg_config_is_read(self):
        home = self.scratch / "home"
        (home / "xdg" / "git").mkdir(parents=True)
        (home / ".gitconfig").write_text("[user]\n\tname = leaked-home\n")
        (home / "xdg" / "git" / "config").write_text("[user]\n\temail = leaked-xdg@example.invalid\n")
        with mock.patch.dict(os.environ, {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg")}):
            seen = self.git("config", "--list", "--show-origin")
        self.assertEqual(seen.stdout, "", "the caller's git config reached the fixture")

    def test_only_the_named_git_variables_remain(self):
        leaked = {"GIT_DIR": "/elsewhere/.git", "GIT_WORK_TREE": "/elsewhere", "GIT_INDEX_FILE": "/elsewhere/index",
                  "GIT_COMMON_DIR": "/elsewhere/.git", "GIT_OBJECT_DIRECTORY": "/elsewhere/objects",
                  "GIT_CONFIG_PARAMETERS": "'user.name'='leaked'", "GIT_CEILING_DIRECTORIES": "/"}
        with mock.patch.dict(os.environ, leaked):
            env = fixture_git.fixture_git_env(self.root, {"GIT_AUTHOR_NAME": "fixture"})
        self.assertEqual({key: value for key, value in env.items() if key.startswith("GIT_")}, {
            "GIT_AUTHOR_NAME": "fixture", "GIT_CEILING_DIRECTORIES": str(self.scratch), "GIT_CONFIG_NOSYSTEM": "1"})
        self.assertEqual(env["HOME"], str(self.root))
        with self.assertRaisesRegex(ValueError, "GIT_DIR"):
            fixture_git.fixture_git_env(self.root, {"GIT_DIR": "/elsewhere/.git"})


if __name__ == "__main__":
    unittest.main()
