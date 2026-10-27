"""Row 10 rests on the model-provider anchors in falsifiers.json.

Grade row 10 (local model ops) counts the provider falsifiers as caught.
That count holds while each ``old`` anchor still occurs once, on the
updated text, the way ``falsify.py`` applies it. This probe judges the
entries whose command is ``provider`` (MP01–MP28). The selftest and PV
entries in the same file stay out of the checks; ``load_json`` still has
to accept the whole file. The ``about`` text is the runner's path rule
for every list, and this probe leaves it alone.

One snapshot. ``Snapshot.read`` is paths relative to ``examples/agent-host``,
which is ``Mutation.__enter__``'s base, and it collapses
``../../capsules/model-provider/...``. The model file itself is read with
``read_relative(snapshot.root, "capsules/model-provider/falsifiers.json")``.
Anchors go through ``anchor_problems``. The strict parse goes through
``falsifier_data.load_json``. This probe does not run cargo and does not
re-run the idle-release or context-window tests.

A clean run says the provider anchors hold on the snapshot commit.
A problem in the real provider entries is ``lab/redteam/findings/provider-001.md``.
The finding names the mismatches it records. A second mismatch still fails.

Run: python3 -I -m unittest discover -s lab/redteam/py
"""

import copy
import functools
import sys
import types
import unittest
from pathlib import Path

import falsifier_data
from test_agent_host_falsifier_honesty import (
    Problem,
    Snapshot,
    anchor_problems,
    caught_without_tests,
)

REPO = Path(__file__).resolve().parents[3]
MODEL_FILE = "capsules/model-provider/falsifiers.json"
# Measured on HEAD with
# `git log -1 --format='%H %s' HEAD -- capsules/model-provider/falsifiers.json`
# and `shasum -a 256` of that file. The merge is that change's first commit
# on HEAD's first-parent line.
RECORDED_SHA256 = "7861b3950da5029b36dd954098257538158c1b19e412b32d59a7bedfa3f126dd"
LAST_CHANGE = "13ed6ac5bfe85871fad37d647c47f9c9e34f8ff2"
RECORDED_PR = "PR #453"
MERGE_COMMIT = "717bc5c6cd1c2fccd2ca90700bdec6c66043e083"
FINDING_ID = "provider-001"
FINDING_NAME = "lab/redteam/findings/provider-001.md"
FINDING = REPO / FINDING_NAME
ROW_10_IDS = tuple(f"MP{number:02d}" for number in range(1, 29))


def load_provider_document(data):
    """The model-provider falsifier document, through the one strict reader."""
    return falsifier_data.load_json(data)


def anchors_of(entries, read):
    """Anchor problems for these entries. The count is ``anchor_problems``."""
    return anchor_problems(entries, read)


def provider_entries(document):
    """Entries whose command is ``provider``.

    Selftest and PV entries stay in the document so the strict reader has
    accepted the whole file, and they stay out of the row 10 checks.
    """
    if not isinstance(document, dict) or not isinstance(document.get("falsifiers"), list):
        raise AssertionError("the model file has no falsifiers list")
    return [entry for entry in document["falsifiers"]
            if isinstance(entry, dict) and entry.get("command") == "provider"]


@functools.lru_cache(maxsize=None)
def provider_base():
    """One snapshot, the model file's bytes, and its provider entries."""
    snapshot = Snapshot()
    data = snapshot.read_relative(snapshot.root, MODEL_FILE)
    document = load_provider_document(data)
    return snapshot, data, provider_entries(document)


def row_problems(entries):
    """Problems when the provider entries are not MP01–MP28, each caught."""
    problems = []
    ids = [entry["id"] for entry in entries]
    if ids != list(ROW_10_IDS):
        problems.append(Problem(
            "ids", "", MODEL_FILE,
            f"provider ids are {ids}, not MP01 through MP28"))
    for entry in entries:
        if entry["command"] != "provider":
            problems.append(Problem(
                "command", entry["id"], MODEL_FILE,
                f"command is {entry['command']!r}, not provider"))
        if entry["expect"] != "caught":
            problems.append(Problem(
                "expect", entry["id"], MODEL_FILE,
                f"expect is {entry['expect']!r}, not caught"))
    return problems


def provider_problems(entries, read):
    """Id, caught-without-a-test, and anchor problems for the provider entries."""
    return [*row_problems(entries), *caught_without_tests(entries), *anchors_of(entries, read)]


def require_digest(data, expected):
    """Refuse when the bytes' sha256 differs from ``expected`` (bare hex)."""
    actual = falsifier_data.digest(data)
    want = "sha256 " + expected
    if actual != want:
        raise AssertionError(f"{actual} != {want}")


def pull_request(described):
    """``PR #N`` from a snapshot description's merge subject, or None."""
    marker = "Merge pull request #"
    at = described.find(marker)
    if at < 0:
        return None
    digits = []
    for char in described[at + len(marker):]:
        if not char.isdigit():
            break
        digits.append(char)
    if not digits:
        return None
    return "PR #" + "".join(digits)


def finding_line(problem):
    """One recorded mismatch: entry id, file, and reason."""
    return f"{problem.entry} {problem.file}: {problem.reason}"


def finding_text(problems, commit, pull, digest):
    """The finding body. The first line carries the pin; each later line is one mismatch."""
    lines = [f"{FINDING_ID} {commit} {pull} sha256 {digest}"]
    lines.extend(finding_line(problem) for problem in problems)
    return "\n".join(lines) + "\n"


def parse_finding(text):
    """The mismatches named after the finding's first line."""
    found = []
    for line in text.splitlines()[1:]:
        if not line:
            continue
        entry, _space, rest = line.partition(" ")
        file, sep, reason = rest.partition(": ")
        if not sep:
            raise AssertionError(f"a finding line needs an entry id and a mismatch: {line}")
        found.append(Problem("recorded", entry, file, reason))
    return tuple(found)


def _identity(problem):
    return (problem.entry, problem.file, problem.reason)


def omit(problems, recorded):
    """Problems whose entry, file, and reason the finding does not name."""
    known = {_identity(item) for item in recorded}
    return [problem for problem in problems if _identity(problem) not in known]


def mark_recorded_check(method):
    """``expectedFailure`` for the one check whose docstring names the finding file."""
    if FINDING_NAME not in (method.__doc__ or ""):
        raise AssertionError(f"a recorded check names {FINDING_NAME}")
    return unittest.expectedFailure(method)


def report_text(commit, data, problems, described):
    """The record for one snapshot. The hold sentence is the clean result."""
    lines = []
    if commit and not problems:
        lines.append(f"the provider anchors hold on {commit}")
    elif not commit:
        lines.append(
            "HEAD cannot be resolved, so the provider anchors are bound to no commit")
    else:
        lines.append("provider entries differ from the row 10 anchors:")
        lines.extend(finding_line(problem) for problem in problems)
    pull = pull_request(described)
    if pull:
        lines.append(pull)
    lines.append(described)
    lines.append(falsifier_data.digest(data))
    return "\n".join(lines)


def report():
    """The run's record. It uses the snapshot's commit and does not resolve HEAD."""
    snapshot, data, entries = provider_base()
    problems = provider_problems(entries, snapshot.read)
    described = snapshot.describe({MODEL_FILE: data}, snapshot.commit)
    return report_text(snapshot.commit, data, problems, described)


def tearDownModule():
    print("\n" + report(), file=sys.stderr)


class ModelProviderFalsifierHonesty(unittest.TestCase):
    """The provider anchors on the snapshot, and the plants that break them."""

    def test_provider_file_is_strict_json(self):
        """``load_json`` accepts the model file and refuses ``"about": NaN``."""
        _snapshot, data, _entries = provider_base()
        document = load_provider_document(data)
        self.assertIsInstance(document, dict)
        self.assertIsInstance(document.get("falsifiers"), list)
        self.assertTrue(data.startswith(b"{"), "the model file is not a JSON object")
        planted = b'{"about": NaN, ' + data[1:]
        with self.assertRaises(falsifier_data.StrictJsonError) as caught:
            load_provider_document(planted)
        self.assertEqual(str(caught.exception), "NaN is not strict JSON")

    def test_provider_ids_are_the_row_10_list(self):
        """The provider entries are MP01–MP28, each caught, each naming a test."""
        _snapshot, _data, entries = provider_base()
        self.assertEqual(row_problems(entries), [])
        self.assertEqual([entry["id"] for entry in entries], list(ROW_10_IDS))
        self.assertEqual([entry["command"] for entry in entries], ["provider"] * len(entries))
        self.assertEqual([entry["expect"] for entry in entries], ["caught"] * len(entries))
        self.assertEqual(caught_without_tests(entries), [])

        planted = copy.deepcopy(entries)
        planted[0]["id"] = "MP00"
        self.assertEqual(row_problems(planted), [Problem(
            "ids", "", MODEL_FILE,
            f"provider ids are {[entry['id'] for entry in planted]}, not MP01 through MP28")])
        planted = copy.deepcopy(entries)
        planted[0]["command"] = "host"
        self.assertEqual(row_problems(planted), [Problem(
            "command", planted[0]["id"], MODEL_FILE,
            "command is 'host', not provider")])
        planted = copy.deepcopy(entries)
        planted[0]["expect"] = "survives"
        self.assertEqual(row_problems(planted), [Problem(
            "expect", planted[0]["id"], MODEL_FILE,
            "expect is 'survives', not caught")])

        planted = copy.deepcopy(entries)
        planted[0]["tests"] = []
        self.assertEqual(caught_without_tests(planted), [Problem(
            "caught", planted[0]["id"], "falsifiers.json",
            "caught, but names no test")])

    def test_provider_anchors_occur_once(self):
        """Each provider ``old`` is found once, in order, by ``anchor_problems``.

        Appending a line to one ``old`` is a stale anchor. A second entry's
        later ``old`` exists only after the earlier replace, so a count of
        the original text reports it found 0 times and ``anchor_problems``
        accepts the entry.
        """
        snapshot, _data, entries = provider_base()
        self.assertEqual(len(entries), len(ROW_10_IDS))
        self.assertEqual(anchors_of(entries, snapshot.read), [])

        planted = copy.deepcopy(entries)
        edit = planted[0]["edits"][0]
        edit["old"] = edit["old"] + "\n<redteam: planted stale anchor>"
        self.assertEqual(anchors_of(planted, snapshot.read), [Problem(
            "anchor", planted[0]["id"], edit["file"],
            "edits[0]: old is found 0 times, not once")])

        original = "alpha\n"
        entry = {
            "id": "SEQ",
            "edits": [
                {"file": "notes.txt", "old": "alpha", "new": "alpha beta"},
                {"file": "notes.txt", "old": "beta", "new": "gamma"},
            ],
        }
        self.assertEqual(original.count("alpha"), 1)
        self.assertEqual(original.count(entry["edits"][1]["old"]), 0)

        def read(name):
            if name != "notes.txt":
                raise LookupError("the file does not exist")
            return original.encode()

        self.assertEqual(anchors_of([entry], read), [])

    def test_pin_matches_the_recorded_file(self):
        """The model file's sha256 is the recorded digest, and the report names the pin."""
        snapshot, data, _entries = provider_base()
        self.assertEqual(snapshot.root, REPO)
        require_digest(data, RECORDED_SHA256)
        with self.assertRaises(AssertionError):
            require_digest(data, "0" * 64)
        text = report()
        commit = snapshot.commit
        self.assertTrue(commit)
        self.assertEqual(len(commit), 40)
        self.assertIn(f"the provider anchors hold on {commit}", text)
        self.assertIn(f"read at HEAD {commit}", text)
        self.assertIn(RECORDED_PR, text)
        self.assertIn(f"Merge pull request #{RECORDED_PR.removeprefix('PR #')}", text)
        self.assertIn(MERGE_COMMIT, text)
        self.assertIn(RECORDED_SHA256, text)
        self.assertIn(LAST_CHANGE, text)
        self.assertIn("first on HEAD's first-parent line", text)

    def test_a_second_problem_still_fails(self):
        """A finding covers the mismatch it names. A second mismatch fails the gate.

        With no problem in the real provider entries, the probe writes no
        finding and marks no check ``expectedFailure``.
        """
        commit = "a" * 40
        one = Problem(
            "anchor", "MP01", "src/a.rs", "edits[0]: old is found 0 times, not once")
        two = Problem(
            "anchor", "MP02", "src/a.rs", "edits[0]: old is found 2 times, not once")
        text = finding_text([one], commit, RECORDED_PR, RECORDED_SHA256)
        self.assertEqual(
            text.splitlines()[0],
            f"{FINDING_ID} {commit} {RECORDED_PR} sha256 {RECORDED_SHA256}")
        self.assertEqual(text.splitlines()[1], finding_line(one))
        self.assertIn(one.entry, text.splitlines()[1])
        self.assertIn(one.reason, text.splitlines()[1])
        recorded = parse_finding(text)
        self.assertEqual(omit([one], recorded), [])
        self.assertEqual(omit([one, two], recorded), [two])
        with self.assertRaises(AssertionError):
            self.assertEqual(omit([one, two], recorded), [])

        class Probe(unittest.TestCase):
            def test_named_only(self):
                self.assertEqual(omit([one], recorded), [])

            def test_live(self):
                self.assertEqual(omit([one, two], recorded), [])

            def test_recorded(self):
                """lab/redteam/findings/provider-001.md"""
                self.assertEqual([one], [])

        Probe.test_recorded = mark_recorded_check(Probe.test_recorded)

        def plain(self):
            """a check with no finding file in its docstring"""
            self.fail("plain")

        with self.assertRaises(AssertionError) as caught:
            mark_recorded_check(plain)
        self.assertIn(FINDING_NAME, str(caught.exception))
        self.assertFalse(getattr(plain, "__unittest_expecting_failure__", False))

        # The sample lives in its own module. A top-level suite tears the
        # caller's module down, and that would print this probe's report
        # from inside the test.
        sample = types.ModuleType("provider_finding_sample")
        Probe.__module__ = sample.__name__
        sys.modules[sample.__name__] = sample
        result = unittest.TestResult()
        try:
            unittest.defaultTestLoader.loadTestsFromTestCase(Probe).run(result)
        finally:
            sys.modules.pop(sample.__name__, None)
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(
            [case.id().rsplit(".", 1)[-1] for case, _err in result.expectedFailures],
            ["test_recorded"])
        self.assertEqual(
            [case.id().rsplit(".", 1)[-1] for case, _err in result.failures],
            ["test_live"])
        self.assertIn("MP02", result.failures[0][1])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])

        snapshot, data, entries = provider_base()
        live = provider_problems(entries, snapshot.read)
        self.assertEqual(live, [])
        self.assertEqual(omit(live, ()), [])
        self.assertFalse(FINDING.is_file())
        described = snapshot.describe({MODEL_FILE: data}, snapshot.commit)
        dirty = report_text(snapshot.commit, data, [two], described)
        self.assertNotIn("the provider anchors hold on ", dirty)
        self.assertIn("MP02", dirty)
        self.assertIn(RECORDED_PR, dirty)
        self.assertIn(snapshot.commit, dirty)
        self.assertIn(RECORDED_SHA256, dirty)

        marked = []
        pending = [unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])]
        while pending:
            item = pending.pop()
            if isinstance(item, unittest.TestSuite):
                pending.extend(item)
            elif getattr(getattr(item, item._testMethodName),
                         "__unittest_expecting_failure__", False):
                marked.append(item.id())
        self.assertEqual(marked, [])


if __name__ == "__main__":
    unittest.main()
