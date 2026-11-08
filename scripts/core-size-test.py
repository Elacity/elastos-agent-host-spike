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


def extent(source):
    """(1-based line where the first item of source ends, its kind)."""
    tokens = [t for t in core_size.lex(source)[0] if t[1] != "comment"]
    vals = [t[2] for t in tokens] + [""] * 4
    last, kind, name, body = core_size.item_extent(vals, 0, len(tokens))
    return tokens[last][0] + 1, kind


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

    def test_every_cfg_spelling_that_holds_only_in_tests(self):
        for cfg in ("test,", "all(all(test), unix)", "any(test, all(test, unix),)", "not(not(test))",
                    "all(\n    unix,\n    test\n)"):
            source = f"#[cfg({cfg})]\nfn test_only() {{}}\nfn production() {{}}\n"
            self.assertEqual(counts(source)["code"], 1, cfg)
        for cfg in ("any(test, unix)", "not(test)", "all(unix, feature = \"test\")", "testing"):
            self.assertEqual(counts(f"#[cfg({cfg})]\nfn production() {{}}\n")["code"], 2, cfg)

    def test_unreadable_cfg_is_refused_with_its_line(self):
        for attribute in ("#[cfg(test test)]", "#[cfg_attr(unix, cfg(test))]", "#[cfg(not(test, unix))]"):
            with self.assertRaisesRegex(core_size.Refusal, r"^elastos/crates/elastos-runtime/src/lib.rs:2: "):
                counts(f"fn production() {{}}\n{attribute}\nfn other() {{}}\n")

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


class ItemExtentTest(unittest.TestCase):
    def test_items_end_at_their_own_end(self):
        cases = {
            "const T: usize = if true {\n    1\n} else {\n    2\n};\nfn production() {}\n": (5, "const"),
            "fn f() -> S<{ 1 }> {\n    S\n}\nfn production() {}\n": (3, "fn"),
            "impl<const N: usize> X for [u8; N] where S<{ N }>: Sized {\n}\nfn production() {}\n": (2, "impl"),
            'pub(crate) unsafe extern "C" fn f(g: fn() -> u8) -> u8 {\n    g()\n}\nfn production() {}\n': (3, "fn"),
            "struct T(u8);\nfn production() {}\n": (1, "struct"),
            "struct S<A, B> where A: Fn() -> B {\n    a: A,\n}\nfn production() {}\n": (3, "struct"),
            "macro_rules! m {\n    () => {};\n}\nfn production() {}\n": (3, "macro"),
            "thread_local!(static X: u8 = 1);\nfn production() {}\n": (1, "macro"),
            "use a::{\n    b,\n    c,\n};\nfn production() {}\n": (4, "use"),
            'extern "C" {\n    fn g();\n}\nfn production() {}\n': (3, "extern"),
            "mod outline;\nfn production() {}\n": (1, "mod"),
        }
        for source, expected in cases.items():
            self.assertEqual(extent(source), expected, source)

    def test_what_is_not_an_item_is_refused(self):
        for source in ("let x = 1;\n", "x.call();\n", "foo!(x)\nfn production() {}\n", "fn f()\n"):
            with self.assertRaises(core_size.Refusal, msg=source):
                extent(source)


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

    def test_refusal_exits_2_naming_file_and_line(self):
        source = self.root / core_size.CRATE / "src/lib.rs"
        source.write_text("fn production() {}\n#[cfg_attr(unix, cfg(test))]\nfn other() {}\n")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(self.run_check()[0], 2)
        self.assertIn("refused: elastos/crates/elastos-runtime/src/lib.rs:2: cfg_attr", errors.getvalue())

    def test_ratchet_fails_when_more_than_50_below(self):
        self.write(10, budget=61)
        status, output = self.run_check()
        self.assertEqual(status, 1)
        self.assertIn("FAIL: core code is 10 lines, 51 below the budget of 61: lower elastos/CORE-BUDGET to 10",
                      output)
        self.write(10, budget=60)
        status, output = self.run_check()
        self.assertEqual(status, 0)
        self.assertIn("OK: core code is 10 lines, within the budget of 60", output)

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
