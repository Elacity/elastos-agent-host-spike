#!/usr/bin/env python3
"""The per-file rule of scripts/trusted-code.py: #[cfg(test)] modules and statements, comments,
strings that hold //, and test files, each case pinned to its hand-counted number."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trusted_code = load("trusted_code", "trusted-code.py")
core_size = trusted_code.core_size

CFG_TEST_MODULE = """fn kept() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn one() {
        assert_eq!(super::kept(), 1);
    }
}
"""

CFG_TEST_STATEMENT = """fn f() -> u8 {
    #[cfg(test)]
    {
        let x = 1;
        let _ = x;
    }
    2
}
"""

COMMENTS = """/* head
 * two
 */
/// doc
fn f() {}

// tail
/* a /* nested */ b */
"""

URL_IN_STRING = """fn url() -> &'static str {
    "https://example.test/a//b"
}
"""

BLOCK_COMMENT_IN_RAW_STRING = """fn raw() -> &'static str {
    r#"/* not a comment */"#
}
"""


class CountFileTest(unittest.TestCase):
    def test_cfg_test_module_is_test_code(self):
        self.assertEqual(trusted_code.count_file(CFG_TEST_MODULE),
                         {"total": 11, "tests": 7, "comments": 0, "blank": 1, "code": 3})

    def test_cfg_test_statement_is_test_code(self):
        self.assertEqual(trusted_code.count_file(CFG_TEST_STATEMENT),
                         {"total": 8, "tests": 5, "comments": 0, "blank": 0, "code": 3})

    def test_comments_and_blank_lines_are_not_code(self):
        self.assertEqual(trusted_code.count_file(COMMENTS),
                         {"total": 8, "tests": 0, "comments": 6, "blank": 1, "code": 1})

    def test_slashes_inside_a_string_are_code(self):
        self.assertEqual(trusted_code.count_file(URL_IN_STRING),
                         {"total": 3, "tests": 0, "comments": 0, "blank": 0, "code": 3})

    def test_block_comment_markers_inside_a_raw_string_are_code(self):
        self.assertEqual(trusted_code.count_file(BLOCK_COMMENT_IN_RAW_STRING),
                         {"total": 3, "tests": 0, "comments": 0, "blank": 0, "code": 3})

    def test_a_test_file_counts_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root, path = Path(folder), "elastos/crates/x/tests/integration.rs"
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text("fn one() {\n}\n")
            rows = trusted_code.file_rows(root, {"files": [path]})
        self.assertEqual(rows[0]["counts"],
                         {"total": 2, "tests": 2, "comments": 0, "blank": 0, "code": 0})
        self.assertTrue(rows[0]["test_file"])

    def test_the_per_file_rule_agrees_with_the_core_counter(self):
        for source in (CFG_TEST_MODULE, COMMENTS, URL_IN_STRING, BLOCK_COMMENT_IN_RAW_STRING):
            one_file_crate = {"src/lib.rs": source}
            self.assertEqual(trusted_code.count_file(source), core_size.count(one_file_crate), source)


if __name__ == "__main__":
    unittest.main()
