"""Citation refusals for the core-calls draft.

The tests call ``check.problems``. They do not compile a citation expression.
"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check

IDENTITY = {
    "GIT_AUTHOR_NAME": "citation-check",
    "GIT_AUTHOR_EMAIL": "citation-check@example.com",
    "GIT_COMMITTER_NAME": "citation-check",
    "GIT_COMMITTER_EMAIL": "citation-check@example.com",
}

OWNED_REL = "examples/agent-host/src/lib.rs"
OWNED_NUMBER = 3754
OWNED_SPAN = "examples/agent-host/src/lib.rs:3754"
OWNED_QUOTE = "/// The one place a task journal lives. The guest names only `Users/self`."
NEXT_NUMBER = 3755
NEXT_SPAN = "examples/agent-host/src/lib.rs:3755"
NEXT_QUOTE = "/// The Runtime scopes that to the launching person."


class CitationCheckTests(unittest.TestCase):
    def _temp_root(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "lab" / "bus-v2-proposal").mkdir(parents=True)
        return root

    def _write(self, root, body, files):
        (root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md").write_text(
            body, encoding="utf-8"
        )
        for rel, data in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def _git(self, root, *args):
        env = dict(os.environ)
        env.update(IDENTITY)
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _git_output(self, root, *args):
        env = dict(os.environ)
        env.update(IDENTITY)
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _commit_all(self, root):
        self._git(root, "init", "-q")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "fixture")
        return self._git_output(root, "rev-parse", "HEAD")

    def _draft(self, body, files=None):
        """A temp root whose draft pins the repository's committed HEAD."""
        root = self._temp_root()
        self._write(root, body, files or {})
        sha = self._commit_all(root)
        (root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md").write_text(
            "Pinned commit: " + sha + "\n" + body, encoding="utf-8"
        )
        return root

    def _raw_draft(self, body, files=None, commit=False):
        """A temp draft with the caller's pin text and no automatic pin."""
        root = self._temp_root()
        self._write(root, body, files or {})
        if commit:
            self._commit_all(root)
        return root

    def _assert_one(self, body, files, expected):
        got = check.problems(self._draft(body, files))
        assert got == [expected], expected

    def _source(self, quote, following=NEXT_QUOTE):
        """A committed file whose line 3754 is QUOTE and line 3755 is FOLLOWING."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [quote]
        if following is not None:
            rows.append(following)
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _quote_body(self, quote, following=None):
        """A draft that cites the owned span and indents QUOTE below it."""
        body = (
            "`" + OWNED_SPAN + "` states that the guest names only `Users/self`.\n"
            "\n"
            "    " + quote + "\n"
        )
        if following is not None:
            body += "    " + following + "\n"
        return body + "\n"

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

    def _pinned_reads(self, body, files):
        """Return the problems and the numbers read from the pinned commit."""
        reads = []
        original = check.pinned_line

        def record(root, sha, rel, number):
            reads.append(number)
            return original(root, sha, rel, number)

        try:
            check.pinned_line = record
            got = check.problems(self._draft(body, files))
        finally:
            check.pinned_line = original
        return got, reads

    def test_absent_draft_is_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.assertEqual(
            check.problems(Path(tmp.name)),
            ["refuse: proposal is absent"],
        )

    def test_missing_pin_is_refused(self):
        got = check.problems(self._raw_draft("No pin line here.\n"))
        self.assertEqual(got, ["refuse: draft has no pinned commit"])

    def test_pin_line_is_one_commit(self):
        sha = "a" * 40
        bodies = (
            "Pinned commit: HEAD\n",
            "Pinned commit: %s\nPinned commit: %s\n" % (sha, sha),
        )
        for body in bodies:
            got = check.problems(self._raw_draft(body))
            self.assertEqual(
                got,
                ["refuse: pinned commit is not one 40-hex commit"],
                body,
            )

    def test_unknown_pin_is_refused(self):
        sha = "f" * 40
        root = self._raw_draft("Pinned commit: " + sha + "\n", commit=True)
        got = check.problems(root)
        self.assertEqual(got, ["refuse: pinned commit is not a commit: " + sha])

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

    def test_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / OWNED_REL).write_bytes(self._source("// edited in the worktree"))
        self.assertEqual(check.problems(root), [expected])

    def test_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [])
        (root / OWNED_REL).write_bytes(self._source("// edited in the worktree"))
        self.assertEqual(check.problems(root), [])

    def test_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + OWNED_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._quote_body(OWNED_QUOTE), {OWNED_REL: short})
        (root / OWNED_REL).write_bytes(self._source(OWNED_QUOTE))
        self.assertEqual(check.problems(root), [expected])

    def test_next_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [])
        (root / OWNED_REL).write_bytes(
            self._source(OWNED_QUOTE, "// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_next_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / OWNED_REL).write_bytes(
            self._source(OWNED_QUOTE, "// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_next_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + NEXT_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE, following=None)},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_short_pinned_file_refuses_the_owned_line_only(self):
        expected = "refuse: quoted line is not in the pinned commit: " + OWNED_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE), {OWNED_REL: short}
        )
        (root / OWNED_REL).write_bytes(self._source(OWNED_QUOTE))
        self.assertEqual(check.problems(root), [expected])

    def test_owned_line_mismatch_adds_no_next_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE + "y"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_owned_line_refusal_skips_the_next_line_read(self):
        got, reads = self._pinned_reads(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + OWNED_SPAN])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_absent_next_quote_skips_the_next_line_read(self):
        got, reads = self._pinned_reads(
            self._quote_body(OWNED_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_quote_refusal_waits_for_a_known_pin(self):
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x")
        files = {OWNED_REL: self._source(OWNED_QUOTE)}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_two_quoted_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + OWNED_SPAN
        body = (
            "`" + OWNED_SPAN + "` states the journal root.\n"
            "\n"
            "    " + OWNED_QUOTE + "\n"
            "\n"
            "Again `" + OWNED_SPAN + "`.\n"
        )
        original = check.pinned_line
        try:
            check.pinned_line = lambda root, sha, rel, number: None
            got = check.problems(
                self._draft(body, {OWNED_REL: self._source(OWNED_QUOTE)})
            )
        finally:
            check.pinned_line = original
        self.assertEqual(got, [expected])

    def test_draft_without_the_owned_span_adds_no_quote_refusal(self):
        bodies = (
            "Open `pkg/kept.rs:1`.\n\n    /// Not the owned quote.\n",
            "`" + OWNED_SPAN + "` states the journal root.\n\n  /// Two-space indent.\n",
        )
        for body in bodies:
            root = self._draft(
                body,
                {
                    OWNED_REL: self._source(OWNED_QUOTE),
                    "pkg/kept.rs": b"fn kept(\n",
                },
            )
            self.assertEqual(check.problems(root), [], body)

    def test_quote_refusal_waits_for_a_known_pin(self):
        body = self._quote_body(OWNED_QUOTE + "x")
        files = {OWNED_REL: self._source(OWNED_QUOTE)}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_owned_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.owned_quote(text), OWNED_QUOTE)
        self.assertEqual(check.next_owned_quote(text), NEXT_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, OWNED_REL, OWNED_NUMBER),
            OWNED_QUOTE,
        )
        self.assertEqual(
            check.pinned_line(root, sha, OWNED_REL, NEXT_NUMBER),
            NEXT_QUOTE,
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

    def test_falsifier_absent_draft_is_caught(self):
        self._caught(
            "load_draft",
            lambda root: "Pinned commit: " + "a" * 40 + "\n",
            self.test_absent_draft_is_refused,
            "refuse: proposal is absent",
            "CAUGHT absent-draft",
        )

    def test_falsifier_missing_pin_is_caught(self):
        self._caught(
            "pin_refusal",
            lambda text: None,
            self.test_missing_pin_is_refused,
            "refuse: draft has no pinned commit",
            "CAUGHT missing-pin",
        )

    def test_falsifier_pin_line_is_caught(self):
        self._caught(
            "pin_refusal",
            lambda text: None,
            self.test_pin_line_is_one_commit,
            "refuse: pinned commit is not one 40-hex commit",
            "CAUGHT pin-line",
        )

    def test_falsifier_unknown_pin_is_caught(self):
        self._caught(
            "commit_exists",
            lambda root, sha: True,
            self.test_unknown_pin_is_refused,
            "refuse: pinned commit is not a commit:",
            "CAUGHT unknown-pin",
        )

    def test_falsifier_quoted_line_mismatch_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT quoted-line",
        )

    def test_falsifier_next_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_next_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT next-quoted-line",
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
            self.assertEqual(code, 1)
            self.assertEqual(buf.getvalue(), "refuse: proposal is absent\n")
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
        self.assertEqual(check.problems(root), ["refuse: proposal is absent"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "refuse: proposal is absent\n")
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
