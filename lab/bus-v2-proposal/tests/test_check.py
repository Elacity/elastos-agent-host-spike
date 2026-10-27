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

MARKER_NUMBER = 8162
MARKER_REL = OWNED_REL
MARKER_SPAN = "examples/agent-host/src/lib.rs:8162"
MARKER_HEAD = "/// The one marker a declared pattern may hold: the user-namespace root,"
MARKER_TAIL = "/// `Users/<one name>`. The declaration names no person and no host path."
MARKER_CFG = "#[cfg(test)]"
MARKER_CONST = 'const PRINCIPAL_MARKER: &str = "<principal>";'

LAUNCHING_NUMBER = 8168
LAUNCHING_SPAN = "examples/agent-host/src/lib.rs:8168"
LAUNCHING_HEAD = "/// The one principal a declared pattern may name. The guest names only"
LAUNCHING_SECOND = (
    "/// `Users/self`, which the Runtime scopes to the launching person, so the"
)
LAUNCHING_THIRD = "/// declaration covers that person and no other `Users/<name>`."
LAUNCHING_CFG = "#[cfg(test)]"
LAUNCHING_CONST = 'const LAUNCHING_PRINCIPAL: &str = "Users/self";'

ASKS_REL = OWNED_REL
ASKS_NUMBER = 8149
ASKS_SPAN = "examples/agent-host/src/lib.rs:8149"
ASKS_FIRST = "/// The declared per-step asks, compiled in from `asks.json` in this lane. The"
ASKS_SECOND = "/// file is an auditable declaration, not the policy check: the Runtime"
ASKS_THIRD = "/// enforces each grant (P4, P18). It is a lane-local stand-in for the Runtime"
ASKS_FOURTH = "/// manifest and retires into that one place when the Runtime defines per-step"
ASKS_FIFTH = "/// asks (P10). It is read by this module's tests only, so the shipped guest"
ASKS_SIXTH = "/// keeps no new production path."
ASKS_CFG = "#[cfg(test)]"
ASKS_CONST = 'const ASKS_JSON: &str = include_str!("../asks.json");'

DENY_REL = OWNED_REL
DENY_NUMBER = 3526
DENY_SPAN = "examples/agent-host/src/lib.rs:3526"
DENY_LINES = (
    "/// A missing grant denies the step. A grant id is recorded and does not run it.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn authorize(journal: &mut Journal, id: u64, grant: Option<&str>) -> bool {",
    "    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {",
    "        return false;",
    "    };",
    "    if step.state != StepState::Prepared {",
    "        return false;",
    "    }",
    "    match grant {",
    '        None | Some("") => {',
    "            step.state = StepState::Denied;",
    "            step.grant = None;",
    "            false",
    "        }",
    "        Some(grant_id) => {",
    "            step.grant = Some(grant_id.to_string());",
    "            true",
    "        }",
    "    }",
    "}",
)
DENY_QUOTE = DENY_LINES[0]
DENY_SECOND = DENY_LINES[1]
DENY_LAST = DENY_LINES[-1]

MINT_REL = OWNED_REL
MINT_NUMBER = 3549
MINT_SPAN = "examples/agent-host/src/lib.rs:3549"
MINT_FIRST = "/// An inbox answer. Allow once, allow for the session, and standing all fail"
MINT_SECOND = "/// closed when no grant id was sent. The guest does not mint one. Deny stores"
MINT_THIRD = "/// no grant. A second answer does not replace the first, and it does not"
MINT_FOURTH = "/// authorize another step. A child cannot be answered with the parent's"
MINT_LAST = "/// grant. The answer name is kept in the log. The grant string is not."


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

    def _marker_source(self, last=MARKER_CONST, head=MARKER_HEAD):
        """A committed file with the owned lines and the marker block at 8159-8162."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [head, MARKER_TAIL, MARKER_CFG, last]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _marker_body(self, last, head=MARKER_HEAD):
        """A draft that cites the marker span and indents four lines below it."""
        return (
            "`" + MARKER_SPAN + "` defines the marker a declared pattern may hold.\n"
            "\n"
            "    " + head + "\n"
            "    " + MARKER_TAIL + "\n"
            "    " + MARKER_CFG + "\n"
            "    " + last + "\n"
            "\n"
        )

    def _launching_source(self, last=LAUNCHING_CONST, head=LAUNCHING_HEAD):
        """A committed file with lines 3754-3755, 8162 and the block at 8164-8168."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [head, LAUNCHING_SECOND, LAUNCHING_THIRD, LAUNCHING_CFG, last]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _launching_body(self, last, head=LAUNCHING_HEAD):
        """A draft that cites the launching span and indents five lines below it."""
        return (
            "`" + LAUNCHING_SPAN + "` names the launching principal.\n"
            "\n"
            "    " + head + "\n"
            "    " + LAUNCHING_SECOND + "\n"
            "    " + LAUNCHING_THIRD + "\n"
            "    " + LAUNCHING_CFG + "\n"
            "    " + last + "\n"
            "\n"
        )

    def _asks_source(
        self,
        first=ASKS_FIRST,
        third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
    ):
        """A committed file with the owned lines, asks, marker and launching blocks."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            first,
            ASKS_SECOND,
            third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _asks_block(
        self,
        first=ASKS_FIRST,
        second=ASKS_SECOND,
        third=ASKS_THIRD,
        fourth=ASKS_FOURTH,
        last=ASKS_CONST,
        count=8,
    ):
        """A draft that cites the asks span and indents its quotation below it."""
        lines = [first, second, third, fourth, ASKS_FIFTH, ASKS_SIXTH, ASKS_CFG, last]
        body = "`" + ASKS_SPAN + "` states that the Runtime enforces each grant.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _deny_source(
        self,
        first=DENY_QUOTE,
        owned=OWNED_QUOTE,
        third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
    ):
        """A committed file with line 3526, the owned lines, asks, marker and launching."""
        rows = ["// filler"] * (DENY_NUMBER - 1) + [first]
        rows += ["// filler"] * (OWNED_NUMBER - 1 - len(rows)) + [owned, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _deny_block(self, first=DENY_QUOTE, second=DENY_SECOND, last=DENY_LAST):
        """A draft that cites the deny span and indents its 21 lines below it."""
        lines = [first, second] + list(DENY_LINES[2:-1]) + [last]
        body = "`" + DENY_SPAN + "` states that a missing grant denies the step.\n\n"
        body += "".join("    " + line + "\n" for line in lines)
        return body + "\n"

    def _mint_source(self, first=MINT_FIRST, second=MINT_SECOND):
        """A committed file with line 3526, line 3548, line 3549, then the other blocks."""
        rows = ["// filler"] * (DENY_NUMBER - 1) + [DENY_QUOTE]
        rows += ["// filler"] * (MINT_NUMBER - 2 - len(rows)) + [first, second]
        rows += ["// filler"] * (OWNED_NUMBER - 1 - len(rows)) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            ASKS_THIRD,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            LAUNCHING_CONST,
        ]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _mint_block(self, first=MINT_FIRST, second=MINT_SECOND, last=MINT_LAST, count=5):
        """A draft that cites the mint span and indents its five lines below it."""
        lines = [first, second, MINT_THIRD, MINT_FOURTH, last]
        body = "`" + MINT_SPAN + "` states that the guest does not mint one.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
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

    def test_marker_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        root = self._draft(
            self._marker_body(MARKER_CONST + "x"),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MARKER_REL).write_bytes(
            self._marker_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_marker_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])
        (root / MARKER_REL).write_bytes(
            self._marker_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_marker_first_line_does_not_stand_for_line_8162(self):
        root = self._draft(
            self._marker_body(MARKER_CONST, head=MARKER_HEAD + "x"),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_marker_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + MARKER_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._marker_body(MARKER_CONST), {MARKER_REL: short})
        (root / MARKER_REL).write_bytes(self._marker_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_marker_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + MARKER_SPAN
        body = (
            "`" + MARKER_SPAN + "` defines the marker.\n"
            "\n"
            "    " + MARKER_HEAD + "\n"
            "    " + MARKER_TAIL + "\n"
            "    " + MARKER_CFG + "\n"
            "    " + MARKER_CONST + "\n"
            "\n"
            "Again `" + MARKER_SPAN + "`.\n"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_marker_span_adds_no_marker_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_marker_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._marker_body(
            MARKER_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_marker_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._marker_body(
            MARKER_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_marker_quote_refusal_waits_for_a_known_pin(self):
        body = self._marker_body(MARKER_CONST + "x")
        files = {MARKER_REL: self._marker_source()}
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

    def test_launching_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + LAUNCHING_SPAN
        root = self._draft(
            self._launching_body(LAUNCHING_CONST + "x"),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MARKER_REL).write_bytes(
            self._launching_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_launching_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._launching_body(LAUNCHING_CONST),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])
        (root / MARKER_REL).write_bytes(
            self._launching_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_launching_first_line_does_not_stand_for_line_8168(self):
        root = self._draft(
            self._launching_body(LAUNCHING_CONST, head=LAUNCHING_HEAD + "x"),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_launching_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + LAUNCHING_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._launching_body(LAUNCHING_CONST), {MARKER_REL: short})
        (root / MARKER_REL).write_bytes(self._launching_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_launching_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + LAUNCHING_SPAN
        body = self._launching_body(LAUNCHING_CONST) + (
            "\nAgain `" + LAUNCHING_SPAN + "`.\n"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_launching_span_adds_no_launching_refusal(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_marker_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        body = self._marker_body(MARKER_CONST + "x") + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [MARKER_NUMBER])

    def test_launching_quote_refusal_waits_for_a_known_pin(self):
        body = self._launching_body(LAUNCHING_CONST + "x")
        files = {MARKER_REL: self._launching_source()}
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

    def test_live_draft_marker_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.marker_quote(text), MARKER_CONST)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MARKER_REL, MARKER_NUMBER),
            MARKER_CONST,
        )

    def test_live_draft_launching_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.launching_quote(text), LAUNCHING_CONST)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MARKER_REL, LAUNCHING_NUMBER),
            LAUNCHING_CONST,
        )

    def test_live_draft_asks_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.asks_quote(text), ASKS_THIRD)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, ASKS_REL, ASKS_NUMBER),
            ASKS_THIRD,
        )

    def test_asks_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        root = self._draft(
            self._asks_block(third=ASKS_THIRD + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / ASKS_REL).write_bytes(
            self._asks_source(third="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_asks_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._asks_block(), {ASKS_REL: self._asks_source()})
        self.assertEqual(check.problems(root), [])
        (root / ASKS_REL).write_bytes(
            self._asks_source(third="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_first_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(first=ASKS_FIRST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_second_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(second=ASKS_SECOND + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_fourth_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(fourth=ASKS_FOURTH + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_last_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(last=ASKS_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_two_asks_lines_are_not_read(self):
        got, reads = self._pinned_reads(
            self._asks_block(count=2), {ASKS_REL: self._asks_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_asks_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + ASKS_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._asks_block(), {ASKS_REL: short})
        (root / ASKS_REL).write_bytes(self._asks_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_asks_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + ASKS_SPAN
        body = self._asks_block() + "\nAgain `" + ASKS_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_asks_span_adds_no_asks_refusal(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._asks_block(
            third=ASKS_THIRD + "y"
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._asks_block(
            third=ASKS_THIRD + "y"
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_asks_line_mismatch_adds_no_marker_or_launching_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = (
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE)
            + self._asks_block(third=ASKS_THIRD + "x")
            + self._marker_body(MARKER_CONST + "y")
            + self._launching_body(LAUNCHING_CONST + "z")
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER, ASKS_NUMBER])

    def test_marker_line_mismatch_follows_the_asks_match(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        body = self._asks_block() + self._marker_body(MARKER_CONST + "x")
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [ASKS_NUMBER, MARKER_NUMBER])

    def test_draft_without_the_asks_span_still_refuses_a_marker_mismatch(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        root = self._draft(
            self._marker_body(MARKER_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_asks_span_still_refuses_a_launching_mismatch(self):
        expected = "refuse: quoted line does not match " + LAUNCHING_SPAN
        root = self._draft(
            self._launching_body(LAUNCHING_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_asks_quote_refusal_waits_for_a_known_pin(self):
        body = self._asks_block(third=ASKS_THIRD + "x")
        files = {ASKS_REL: self._asks_source()}
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

    def test_live_draft_deny_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.deny_quote(text), DENY_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, DENY_REL, DENY_NUMBER),
            DENY_QUOTE,
        )

    def test_deny_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        root = self._draft(
            self._deny_block(first=DENY_QUOTE + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / DENY_REL).write_bytes(
            self._deny_source(first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_deny_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._deny_block(), {DENY_REL: self._deny_source()})
        self.assertEqual(check.problems(root), [])
        (root / DENY_REL).write_bytes(
            self._deny_source(first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_second_line_does_not_stand_for_line_3526(self):
        root = self._draft(
            self._deny_block(second=DENY_SECOND + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_last_line_does_not_stand_for_line_3526(self):
        root = self._draft(
            self._deny_block(last=DENY_LAST + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_span_without_an_indented_line_adds_no_refusal(self):
        body = (
            "`"
            + DENY_SPAN
            + "` states that a missing grant denies the step.\n"
            "\n"
            "The block follows.\n"
        )
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_deny_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + DENY_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._deny_block(), {DENY_REL: short})
        (root / DENY_REL).write_bytes(self._deny_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_deny_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + DENY_SPAN
        body = self._deny_block() + "\nAgain `" + DENY_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_deny_span_adds_no_deny_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_line_mismatch_adds_no_owned_or_asks_refusal(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        body = (
            self._deny_block(first=DENY_QUOTE + "x")
            + self._quote_body(OWNED_QUOTE + "y", NEXT_QUOTE)
            + self._asks_block(third=ASKS_THIRD + "z")
        )
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER])

    def test_owned_line_mismatch_follows_the_deny_match(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._deny_block() + self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE)
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, OWNED_NUMBER])

    def test_draft_without_the_deny_span_still_refuses_an_owned_mismatch(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_deny_span_still_refuses_an_asks_mismatch(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        root = self._draft(
            self._asks_block(third=ASKS_THIRD + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_deny_quote_refusal_waits_for_a_known_pin(self):
        body = self._deny_block(first=DENY_QUOTE + "x")
        files = {DENY_REL: self._deny_source()}
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

    def test_live_draft_mint_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.mint_quote(text), MINT_SECOND)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MINT_REL, MINT_NUMBER),
            MINT_SECOND,
        )

    def test_mint_quote_is_absent_with_one_indented_line(self):
        body = self._mint_block(count=1)
        self.assertIsNone(check.mint_quote(body))
        self.assertIsNone(check.mint_quote("No mint span here.\n"))

    def test_mint_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        root = self._draft(
            self._mint_block(second=MINT_SECOND + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MINT_REL).write_bytes(self._mint_source(second="// edited in the worktree"))
        self.assertEqual(check.problems(root), [expected])

    def test_mint_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._mint_block(), {MINT_REL: self._mint_source()})
        self.assertEqual(check.problems(root), [])
        (root / MINT_REL).write_bytes(self._mint_source(second="// edited in the worktree"))
        self.assertEqual(check.problems(root), [])

    def test_mint_first_line_does_not_stand_for_line_3549(self):
        root = self._draft(
            self._mint_block(first=MINT_FIRST + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_mint_last_line_does_not_stand_for_line_3549(self):
        root = self._draft(
            self._mint_block(last=MINT_LAST + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_mint_span_without_two_indented_lines_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._mint_block(count=1), {MINT_REL: self._mint_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_mint_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + MINT_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._mint_block(), {MINT_REL: short})
        (root / MINT_REL).write_bytes(self._mint_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_mint_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + MINT_SPAN
        body = self._mint_block() + "\nAgain `" + MINT_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_mint_span_adds_no_mint_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_line_mismatch_adds_no_mint_refusal(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        body = self._deny_block(first=DENY_QUOTE + "x") + self._mint_block(
            second=MINT_SECOND + "y"
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER])

    def test_mint_line_mismatch_adds_no_owned_refusal(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        body = (
            self._deny_block()
            + self._mint_block(second=MINT_SECOND + "y")
            + self._quote_body(OWNED_QUOTE + "z", NEXT_QUOTE)
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, MINT_NUMBER])

    def test_mint_line_match_follows_to_the_owned_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = (
            self._deny_block()
            + self._mint_block()
            + self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE)
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, MINT_NUMBER, OWNED_NUMBER])

    def test_draft_without_the_mint_span_still_refuses_a_deny_mismatch(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        root = self._draft(
            self._deny_block(first=DENY_QUOTE + "x")
            + self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_deny_span_still_refuses_a_mint_mismatch(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        root = self._draft(
            self._mint_block(second=MINT_SECOND + "x")
            + self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_mint_quote_refusal_waits_for_a_known_pin(self):
        body = self._mint_block(second=MINT_SECOND + "x")
        files = {MINT_REL: self._mint_source()}
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

    def test_falsifier_marker_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_marker_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT marker-quoted-line",
        )

    def test_falsifier_launching_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_launching_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT launching-quoted-line",
        )

    def test_falsifier_asks_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_asks_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT asks-quoted-line",
        )

    def test_falsifier_deny_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_deny_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT deny-quoted-line",
        )

    def test_falsifier_mint_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_mint_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT mint-quoted-line",
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
