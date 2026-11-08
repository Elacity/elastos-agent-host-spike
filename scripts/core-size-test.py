#!/usr/bin/env python3
"""Line classes of scripts/core-size.py on small sources, and its budget check in throwaway git repos."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("core_size", Path(__file__).with_name("core-size.py"))
core_size = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core_size)

STRINGS_IN_TEST_MOD = '''fn kept() -> char {
    '{'
}

#[cfg(test)]
mod tests {
    #[test]
    fn braces_in_literals() {
        let plain = "}} // not a comment }";
        let raw = r#"}"} } "#;
        let bytes = br"}}";
        let open = '}';
        let lifetime: &'static str = "{";
    }
}
fn after() {}
'''

BLOCK_COMMENTS = '''/* one line */
/*
   } a closing brace inside a comment
   /* nested */ still inside
*/
fn code() {}
'''


def counts(source, path="src/lib.rs"):
    return core_size.count([(path, source)])


class CountTest(unittest.TestCase):
    def test_cfg_test_module_with_braces_in_strings_and_raw_strings(self):
        self.assertEqual(counts(STRINGS_IN_TEST_MOD),
                         {"total": 16, "tests": 11, "comments": 0, "blank": 1, "code": 4})

    def test_cfg_all_test_over_several_lines(self):
        source = "#[cfg(all(\n    test,\n    unix\n))]\nmod tests {\n}\nfn kept() {}\n"
        self.assertEqual(counts(source)["tests"], 6)
        self.assertEqual(counts(source.replace("test,", "feature = \"test\","))["tests"], 0)

    def test_block_comments(self):
        self.assertEqual(counts(BLOCK_COMMENTS),
                         {"total": 6, "tests": 0, "comments": 5, "blank": 0, "code": 1})

    def test_code_line_with_trailing_comment_is_code(self):
        source = "// leading comment\nlet x = 1; // trailing comment\nlet y = 2; /* trailing */\n"
        self.assertEqual(counts(source),
                         {"total": 3, "tests": 0, "comments": 1, "blank": 0, "code": 2})

    def test_code_after_a_leading_block_comment_is_code(self):
        self.assertEqual(counts("/* comment */ fn production() {}\n")["code"], 1)
        self.assertEqual(counts("/*\n*/ fn production() {}\n"),
                         {"total": 2, "tests": 0, "comments": 1, "blank": 0, "code": 1})
        self.assertEqual(counts("let x = f(\n    0\n);\n")["code"], 3)

    def test_test_files(self):
        for path in ("tests/integration.rs", "src/tests.rs", "src/io_test.rs"):
            self.assertEqual(counts("fn a() {}\n", path)["tests"], 1, path)
        self.assertEqual(counts("fn a() {}\n", "src/contests.rs")["code"], 1)


class CheckTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="core-size-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.git("init", "-q", "-b", "main")
        self.write(10, budget=10)
        self.commit("base")

    def git(self, *args):
        environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        *args], check=True, capture_output=True, env=environment)

    def write(self, lines, budget):
        source = self.root / core_size.CRATE / "src/lib.rs"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("// header\n" + "".join(f"fn f{n}() {{}}\n" for n in range(lines)))
        (self.root / core_size.BUDGET).write_text(f"# budget\n{budget}\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_check(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = core_size.main(["--check", "--root", str(self.root), *extra])
        return status, output.getvalue()

    def test_over_budget_fails_naming_both_numbers(self):
        self.write(12, budget=10)
        status, output = self.run_check()
        self.assertEqual(status, 1)
        self.assertIn("FAIL: core code is 12 lines, above the budget of 10", output)
        self.write(10, budget=10)
        self.assertEqual(self.run_check()[0], 0)

    def test_ratchet_reminder_when_more_than_50_below(self):
        self.write(10, budget=61)
        status, output = self.run_check()
        self.assertEqual(status, 0)
        self.assertIn("Reminder: core code is 51 lines below the budget of 61. Lower elastos/CORE-BUDGET to 10",
                      output)
        self.write(10, budget=60)
        self.assertNotIn("Reminder", self.run_check()[1])

    def test_base_change_reports_code_and_budget(self):
        self.git("checkout", "-q", "-b", "grow")
        self.write(13, budget=13)
        self.commit("grow the core")
        self.git("checkout", "-q", "main")
        self.write(4, budget=10)
        self.commit("main moves on")
        self.git("checkout", "-q", "grow")
        status, output = self.run_check("--base", "main")
        self.assertEqual(status, 0)
        self.assertIn("core code +3 lines (10 -> 13).", output)
        self.assertIn("elastos/CORE-BUDGET: changed 10 -> 13 (+3).", output)
        self.write(13, budget=10)
        status, output = self.run_check("--base", "main")
        self.assertEqual(status, 1)
        self.assertIn("elastos/CORE-BUDGET: unchanged.", output)


if __name__ == "__main__":
    unittest.main()
