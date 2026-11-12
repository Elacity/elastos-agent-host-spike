#!/usr/bin/env python3
"""scripts/ci-installed-app-paths.py: its rule on plain path lists, its reading of a
pull request in throwaway git repositories, and the rule against this repository."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("ci-installed-app-paths.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


paths = load("ci_installed_app_paths", SCRIPT)
fixture_git = load("fixture_git_env", Path(__file__).with_name("fixture-git-env.py"))
REPO = Path(__file__).resolve().parents[1]
NOTES = ["lab/redteam/README.md", "docs/CARRIER.md", "PRINCIPLES.md"]


class RuleTest(unittest.TestCase):
    def test_a_change_list_of_lab_files_skips(self):
        self.assertFalse(paths.must_run(["lab/redteam/README.md", "lab/wasm-capsule/tools/src/run.rs",
                                         "lab/useful-task/Cargo.toml"]))

    def test_a_change_list_of_docs_files_skips(self):
        self.assertFalse(paths.must_run(["docs/CARRIER.md", "docs/system-map/viewer.html", "docs/audits/a.md"]))

    def test_markdown_at_the_repository_root_skips(self):
        self.assertFalse(paths.must_run(["README.md", "PRINCIPLES.md", "AGENTS.md"]))

    def test_one_rust_file_among_notes_runs(self):
        self.assertTrue(paths.must_run([*NOTES, "elastos/crates/elastos-runtime/src/lib.rs"]))
        self.assertTrue(paths.must_run(["capsules/home/src/main.rs", *NOTES]))

    def test_a_path_under_dot_github_runs(self):
        self.assertTrue(paths.must_run([".github/workflows/ci.yml"]))
        self.assertTrue(paths.must_run([*NOTES, ".github/CODEOWNERS"]))

    def test_an_empty_change_list_runs(self):
        self.assertTrue(paths.must_run([]))

    def test_names_that_only_look_like_notes_folders_or_markdown_run(self):
        for path in ("labs/x", "lab-extra/x", "lab", "docs", "docs.md.rs", "docs-old/x.md", "docs.md/x",
                     "Lab/x.md", "DOCS/x.md", "README.MD", "README.md.sh", "notes.mdx", ".md/x",
                     "capsules/lab/x.md", "elastos/docs/PEER_PROTOCOL.md", "scripts/docs/x", "x/lab/y"):
            with self.subTest(path=path):
                self.assertTrue(paths.must_run([path]))
                self.assertTrue(paths.must_run([*NOTES, path]))

    def test_a_readme_outside_the_notes_folders_runs(self):
        # setup-source-home.sh copies each capsule folder whole into the installed app.
        for path in ("capsules/home/README.md", "capsules/documents/browser/README.md", "elastos/README.md",
                     "scripts/README.md", "examples/photo-viewer/README.md", "elastos/CHANGELOG.md"):
            with self.subTest(path=path):
                self.assertTrue(paths.must_run([path]))

    def test_a_lab_crate_the_build_loads_skips_only_for_its_markdown(self):
        for crate in paths.LAB_CRATES_THE_BUILD_LOADS:
            for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs", "probe/Cargo.toml", "notes.txt", "x.md.rs"):
                with self.subTest(path=crate + name):
                    self.assertTrue(paths.must_run([crate + name]))
            self.assertFalse(paths.must_run([crate + "README.md", crate + "plants/LOG.md"]))
        # A lab crate no outside manifest names is skipped whole.
        self.assertFalse(paths.must_run(["lab/redteam/Cargo.toml", "lab/redteam/src/lib.rs"]))

    def test_a_file_the_runtime_serves_runs(self):
        for path in paths.SERVED_BY_THE_RUNTIME:
            with self.subTest(path=path):
                self.assertTrue(paths.must_run([path]))
                self.assertTrue(paths.must_run([*NOTES, path]))


class PullRequestTest(unittest.TestCase):
    """A base branch on origin and a pull request head, as the pr-substance job sees them."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="installed-app-paths-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.env = fixture_git.fixture_git_env(self.root, {key: "fixture" for key in fixture_git.IDENTITY})
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write({"lab/x.md": "lab note\n", "capsules/home/src/main.rs": "fn main() {}\n", "docs/a.md": "a\n"})
        self.commit("base")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git("checkout", "-q", "-b", "work")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, files):
        for name, text in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def decide(self, head, base="main", cwd=None):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return paths.decide({"BASE_REF": base, "HEAD_SHA": head}, cwd or self.repo)

    def changed(self, head):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return sorted(paths.changed_paths("origin/main", head, self.repo))

    def test_a_pull_request_of_notes_and_lab_files_skips(self):
        self.write({"lab/x.md": "changed\n", "docs/new/b.md": "b\n", "NOTES.md": "n\n"})
        head = self.commit("notes")
        self.assertEqual(self.changed(head), ["NOTES.md", "docs/new/b.md", "lab/x.md"])
        self.assertEqual(self.decide(head), (False, "all 3 changed paths are notes or lab files"))

    def test_a_pull_request_with_one_code_file_runs(self):
        self.write({"lab/x.md": "changed\n", "capsules/home/src/main.rs": "fn main() { }\n"})
        run, reason = self.decide(self.commit("code"))
        self.assertTrue(run)
        self.assertIn("1 of 2 changed paths are not notes or lab files, first 'capsules/home/src/main.rs'", reason)

    def test_a_pull_request_that_changes_nothing_runs(self):
        self.assertEqual(self.decide(self.commit("empty")), (True, "no changed path"))

    def test_a_rename_out_of_lab_runs(self):
        self.git("mv", "lab/x.md", "capsules/x.md")
        head = self.commit("move out")
        self.assertEqual(self.changed(head), ["capsules/x.md", "lab/x.md"])
        self.assertTrue(self.decide(head)[0])

    def test_a_rename_into_lab_runs(self):
        (self.repo / "lab/src").mkdir()
        self.git("mv", "capsules/home/src/main.rs", "lab/src/main.rs")
        head = self.commit("move in")
        self.assertEqual(self.changed(head), ["capsules/home/src/main.rs", "lab/src/main.rs"])
        self.assertTrue(self.decide(head)[0])

    def test_a_rename_inside_lab_skips(self):
        self.git("mv", "lab/x.md", "lab/y.md")
        head = self.commit("move inside")
        self.assertEqual(self.changed(head), ["lab/x.md", "lab/y.md"])
        self.assertFalse(self.decide(head)[0])

    def test_a_deleted_code_file_runs(self):
        self.git("rm", "-q", "capsules/home/src/main.rs")
        self.assertTrue(self.decide(self.commit("delete"))[0])

    def test_code_that_only_the_base_branch_gained_does_not_count(self):
        self.write({"lab/x.md": "changed\n"})
        head = self.commit("notes")
        self.git("checkout", "-q", "main")
        self.write({"capsules/home/src/main.rs": "fn main() { println!(); }\n"})
        self.git("update-ref", "refs/remotes/origin/main", self.commit("base moved"))
        self.assertEqual(self.changed(head), ["lab/x.md"])
        self.assertFalse(self.decide(head)[0])

    def test_a_git_failure_runs(self):
        self.write({"lab/x.md": "changed\n"})
        head = self.commit("notes")
        self.assertFalse(self.decide(head)[0])
        cases = {"an unknown head": self.decide("0" * 40), "an unknown base branch": self.decide(head, base="gone"),
                 "a folder that is no repository": self.decide(head, cwd=self.root),
                 "a folder that does not exist": self.decide(head, cwd=self.root / "absent")}
        for name, (run, reason) in cases.items():
            with self.subTest(name=name):
                self.assertTrue(run)
                self.assertIn("the changed paths could not be read", reason)
        with mock.patch.dict(os.environ, self.env, clear=True):
            for environ in ({}, {"BASE_REF": "main"}, {"HEAD_SHA": head}):
                self.assertEqual(paths.decide(environ, self.repo),
                                 (True, "the changed paths could not be read (KeyError)"))

    def run_script(self, head):
        output = self.root / "output"
        output.write_text("")
        result = subprocess.run([sys.executable, "-I", str(SCRIPT)], cwd=self.repo, capture_output=True, text=True,
                                env={**self.env, "BASE_REF": "main", "HEAD_SHA": head, "GITHUB_OUTPUT": str(output)})
        return result.returncode, output.read_text(), result.stdout

    def test_the_script_writes_its_answer_as_the_step_output(self):
        self.write({"docs/a.md": "changed\n"})
        notes = self.commit("notes")
        self.assertEqual(self.run_script(notes)[:2], (0, "run=false\n"))
        self.write({"scripts/x.sh": "true\n"})
        code = self.commit("code")
        self.assertEqual(self.run_script(code)[:2], (0, "run=true\n"))
        status, output, shown = self.run_script("0" * 40)
        self.assertEqual((status, output), (0, "run=true\n"))
        self.assertIn("installed-app jobs run: the changed paths could not be read", shown)


TRACKED = frozenset(subprocess.check_output(["git", "ls-files"], cwd=REPO, text=True).splitlines())


def lab_crates_named_from_outside_lab():
    """Every lab crate a manifest outside lab/ names by path, with the lab crates those name."""
    def named(manifest):
        folder = os.path.dirname(manifest)
        for value in re.findall(r"""["']([^"'\n]+)["']""", (REPO / manifest).read_text()):
            crate = os.path.normpath(os.path.join(folder, value))
            if crate.startswith("lab/") and crate + "/Cargo.toml" in TRACKED:
                yield crate + "/"

    found = set()
    queue = [name for name in TRACKED if name.endswith("Cargo.toml") and not name.startswith("lab/")]
    while queue:
        for crate in named(queue.pop()):
            if crate not in found:
                found.add(crate)
                queue.append(crate + "Cargo.toml")
    return found


INCLUDE = re.compile(r"\binclude(?:_str|_bytes)?!\s*\(")


def include_arguments(text):
    """The argument of each include!, include_str! and include_bytes! call, to its closing bracket."""
    for start in INCLUDE.finditer(text):
        depth, index, quoted = 1, start.end(), False
        while depth and index < len(text):
            char = text[index]
            if quoted:
                index += char == "\\"
                quoted = char != '"'
            elif char == '"':
                quoted = True
            else:
                depth += (char == "(") - (char == ")")
            index += 1
        yield " ".join(text[start.end():index - 1].split())


def included_notes(source_name, text):
    """Notes paths a Rust source includes: a literal path is resolved from the
    source file, and any other include argument must not name notes at all."""
    for argument in include_arguments(text):
        literal = re.fullmatch(r'"([^"]+)"', argument)
        if literal:
            target = os.path.normpath(os.path.join(os.path.dirname(source_name), literal[1]))
            if paths.is_notes_or_lab(target):
                yield target
        elif re.search(r"\.md\b|\bdocs/|\blab/", argument):
            yield argument


class RepositoryTest(unittest.TestCase):
    """The two exceptions in the rule are the ones this repository has."""

    def test_the_rule_lists_every_lab_crate_a_manifest_outside_lab_names(self):
        found = lab_crates_named_from_outside_lab()
        self.assertIn("lab/agent-conformance/", found)
        top = {crate for crate in found if not any(crate != other and crate.startswith(other) for other in found)}
        self.assertEqual(top, set(paths.LAB_CRATES_THE_BUILD_LOADS))

    def test_the_rule_lists_every_file_the_runtime_serves(self):
        handler = (REPO / "elastos/crates/elastos-server/src/api/handlers/docs.rs").read_text()
        table = handler.split("const ALLOWED_DOCS", 1)[1].split("];", 1)[0]
        served = {path for _, path in re.findall(r'\("([^"]+)",\s*"([^"]+)"\)', table)}
        self.assertEqual(served, set(paths.SERVED_BY_THE_RUNTIME))
        # The handler reads nothing outside that table.
        self.assertEqual(handler.count("docs_dir.join("), 2)
        self.assertEqual(handler.count("docs_dir.join(rel_path)"), 2)

    def test_no_rust_source_outside_lab_includes_a_notes_path(self):
        sources = [name for name in TRACKED if name.endswith(".rs") and not name.startswith("lab/")]
        self.assertGreater(len(sources), 500)
        seen = 0
        for name in sources:
            text = (REPO / name).read_text(encoding="utf-8", errors="replace")
            seen += len(list(include_arguments(text)))
            self.assertEqual(list(included_notes(name, text)), [], name)
        self.assertGreater(seen, 100)
        # The check sees a planted include of each kind.
        self.assertEqual(list(included_notes("elastos/crates/a/src/lib.rs", 'x = include_str!("../../../../docs/A.md");')),
                         ["docs/A.md"])
        self.assertEqual(list(included_notes("capsules/a/src/main.rs", 'include_bytes!(\n  "../../../README.md"\n);')),
                         ["README.md"])
        self.assertEqual(list(included_notes("capsules/a/src/main.rs", 'x = include_str!("../capsule.json");')), [])
        self.assertEqual(list(included_notes("a/b.rs", 'include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../lab/x"));')),
                         ['concat!(env!("CARGO_MANIFEST_DIR"), "/../lab/x")'])

    def test_no_tracked_link_outside_the_notes_folders_points_into_them(self):
        listing = subprocess.check_output(["git", "ls-files", "-s"], cwd=REPO, text=True).splitlines()
        self.assertGreater(len(listing), 1000)
        for line in listing:
            mode, name = line.split(" ", 1)[0], line.split("\t", 1)[1]
            self.assertNotEqual(mode, "160000", f"{name}: a submodule's changes do not show as its paths")
            if mode == "120000" and not paths.is_notes_or_lab(name):
                target = os.path.normpath(os.path.join(os.path.dirname(name), os.readlink(REPO / name)))
                self.assertFalse(paths.is_notes_or_lab(target) or target.rstrip("/") in ("lab", "docs"),
                                 f"{name} points into the notes folders")


if __name__ == "__main__":
    unittest.main()
