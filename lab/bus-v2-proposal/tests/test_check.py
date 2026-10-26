"""Citation refusals for the core-calls draft.

The tests call ``check.problems``. They do not compile a citation expression.
"""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check


class CitationCheckTests(unittest.TestCase):
    def _draft(self, body, files=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        proposal = root / "lab" / "bus-v2-proposal"
        proposal.mkdir(parents=True)
        (proposal / "CORE-CALLS-PROPOSAL.md").write_text(body, encoding="utf-8")
        for rel, data in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def _assert_one(self, body, files, expected):
        got = check.problems(self._draft(body, files))
        assert got == [expected], expected

    def _caught(self, global_name, planted, named_test, prefix, label):
        named_test()
        original = getattr(check, global_name)
        try:
            setattr(check, global_name, planted)
            with self.assertRaises(AssertionError) as caught:
                named_test()
            self.assertIn(prefix, str(caught.exception))
        finally:
            setattr(check, global_name, original)
        print(label)

    def test_absent_draft_is_empty(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.assertEqual(check.problems(Path(tmp.name)), [])

    def test_supported_citations_pass(self):
        body = (
            "The principal is `Users/self`.\n"
            "Open `pkg/kept.rs:1`.\n"
            "Span `pkg/kept.rs:1-2`.\n"
            "Call `pkg/kept.rs::kept`.\n"
        )
        files = {"pkg/kept.rs": b"fn kept(\nsecond\nthird\n"}
        got = check.problems(self._draft(body, files))
        self.assertEqual(got, [])

    def test_missing_path_is_refused(self):
        expected = "refuse: path does not exist: missing/no-such.rs"
        self._assert_one("See `missing/no-such.rs:1`.\n", {}, expected)

    def test_past_end_line_is_refused(self):
        one = {"pkg/one.rs": b"only\n"}
        past = "refuse: line 2 is past the end of pkg/one.rs (1 lines)"
        self._assert_one("See `pkg/one.rs:2`.\n", one, past)
        reversed_range = "refuse: line range 2-1 is reversed in pkg/one.rs"
        self._assert_one("See `pkg/one.rs:2-1`.\n", one, reversed_range)
        empty = "refuse: line 1 is past the end of pkg/empty.rs (0 lines)"
        self._assert_one("See `pkg/empty.rs:1`.\n", {"pkg/empty.rs": b""}, empty)
        over = "refuse: line 4 is past the end of pkg/two.rs (2 lines)"
        self._assert_one(
            "See `pkg/two.rs:1-4`.\n",
            {"pkg/two.rs": b"a\nb\n"},
            over,
        )

    def test_reversed_range_is_refused(self):
        expected = "refuse: line range 2-1 is reversed in pkg/ord.rs"
        self._assert_one(
            "See `pkg/ord.rs:2-1`.\n",
            {"pkg/ord.rs": b"one\ntwo\n"},
            expected,
        )

    def test_missing_function_is_refused(self):
        expected = "refuse: function wanted is not in pkg/one.rs"
        self._assert_one(
            "See `pkg/one.rs::wanted`.\n",
            {"pkg/one.rs": b"fn other(\n"},
            expected,
        )

    def test_non_utf8_file_is_refused(self):
        expected = "refuse: path is not utf-8 text: pkg/bad.rs"
        self._assert_one(
            "See `pkg/bad.rs:1`.\n",
            {"pkg/bad.rs": b"\xff"},
            expected,
        )

    def test_refusals_follow_source_order(self):
        body = "`missing/z.rs:1` `pkg/one.rs:1` `missing/a.rs:1`\n"
        got = check.problems(self._draft(body, {"pkg/one.rs": b"only\n"}))
        self.assertEqual(
            got,
            [
                "refuse: path does not exist: missing/z.rs",
                "refuse: path does not exist: missing/a.rs",
            ],
        )

    def test_falsifier_missing_path_is_caught(self):
        self._caught(
            "read_file",
            lambda root, rel: b"fn x() {\n",
            self.test_missing_path_is_refused,
            "refuse: path does not exist:",
            "CAUGHT missing-path",
        )

    def test_falsifier_past_end_line_is_caught(self):
        self._caught(
            "line_count",
            lambda text: 10**9,
            self.test_past_end_line_is_refused,
            "refuse: line ",
            "CAUGHT past-end-line",
        )

    def test_falsifier_missing_function_is_caught(self):
        self._caught(
            "has_function",
            lambda text, name: True,
            self.test_missing_function_is_refused,
            "refuse: function ",
            "CAUGHT missing-function",
        )

    def test_falsifier_non_utf8_is_caught(self):
        self._caught(
            "decode_text",
            lambda data: "fn x() {\n",
            self.test_non_utf8_file_is_refused,
            "refuse: path is not utf-8 text:",
            "CAUGHT non-utf8",
        )

    def test_falsifier_reversed_range_is_caught(self):
        self._caught(
            "range_is_reversed",
            lambda start, end: False,
            self.test_reversed_range_is_refused,
            "refuse: line range ",
            "CAUGHT reversed-range",
        )

    def test_worktree_root_contains_checker(self):
        root = check.worktree_root()
        checker = root / "lab" / "bus-v2-proposal" / "check.py"
        self.assertTrue(checker.is_file())
        self.assertEqual(checker.resolve(), Path(check.__file__).resolve())

    def test_main_on_this_worktree(self):
        root = check.worktree_root()
        draft = root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = check.main()
        self.assertIsInstance(code, int)
        if not draft.is_file():
            self.assertEqual(code, 0)
            self.assertEqual(buf.getvalue(), "proposal: absent\n")
            self.assertFalse(draft.exists())
            return
        found = check.problems(root)
        if found:
            self.fail("draft refusals:\n" + "\n".join(found))
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue(), "")

    def _main_at(self, root):
        original = check.worktree_root
        buf = io.StringIO()
        try:
            check.worktree_root = lambda: root
            with contextlib.redirect_stdout(buf):
                code = check.main()
        finally:
            check.worktree_root = original
        return code, buf.getvalue()

    def test_main_absent_draft_prints_and_creates_nothing(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        draft = root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md"
        code, out = self._main_at(root)
        self.assertEqual(code, 0)
        self.assertEqual(out, "proposal: absent\n")
        self.assertFalse(draft.exists())

    def test_main_agrees_with_problems(self):
        clean = self._draft(
            "Open `pkg/kept.rs:1`.\n",
            {"pkg/kept.rs": b"fn kept(\n"},
        )
        code, out = self._main_at(clean)
        self.assertEqual(check.problems(clean), [])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        bad = self._draft("See `missing/no-such.rs:1`.\n", {})
        code, out = self._main_at(bad)
        found = check.problems(bad)
        self.assertEqual(found, ["refuse: path does not exist: missing/no-such.rs"])
        self.assertEqual(code, 1)
        self.assertEqual(out, found[0] + "\n")
