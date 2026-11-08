#!/usr/bin/env python3
"""Line classes of scripts/core-size.py on small sources."""
import importlib.util
from pathlib import Path
import sys
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

    def test_test_files(self):
        for path in ("tests/integration.rs", "src/tests.rs", "src/io_test.rs"):
            self.assertEqual(counts("fn a() {}\n", path)["tests"], 1, path)
        self.assertEqual(counts("fn a() {}\n", "src/contests.rs")["code"], 1)


if __name__ == "__main__":
    unittest.main()
