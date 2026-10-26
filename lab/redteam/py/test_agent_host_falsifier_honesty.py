"""Static honesty probe over the merged agent-host falsifiers and asks.

The agent-host re-score rests on examples/agent-host/falsifiers.json. This
probe reads that file, asks.json and the files the edits name. It does not
run cargo and it does not apply a mutation to the repository. It checks:

- falsifiers.json parses with the strict reader, each entry has its fields,
  and no id repeats;
- every ``caught`` entry names at least one test;
- every edit's old text is found exactly once, each file's edits applied in
  order on the updated text, the way falsify.py's Mutation applies them;
- asks.json has its schema, and every ask a known kind and a resource.

Whether a named test exists is task 004's check. This probe does not lex
Rust and does not walk falsify.py's AST.

Every file is read into one snapshot. The snapshot resolves HEAD once, to a
full SHA, and the pin, the history queries and the report all use that SHA.
Each file's pin is ``git log -1 --format='%H %s' <sha> -- <path>`` for that
same SHA. After the tests the run prints the record: the problems each rule
found, that commit, and for every file read its sha256, its last change, and
the commit that brought that change onto the first-parent line. A merge's
subject names the PR (guard a).

A clean run says that every merged anchor and the asks schema hold on that
commit. A reproduced defect becomes a finding under lab/redteam/findings,
listed in KNOWN_FINDINGS, and hides only the problems it records (guard b).
The probe writes no file.

Run: python3 -I -m unittest discover -s lab/redteam/py
"""

import collections
import copy
import functools
import json
import sys
import unittest
from pathlib import Path

import falsifier_data

REPO = Path(__file__).resolve().parents[3]
AGENT_HOST = REPO / "examples" / "agent-host"
FINDINGS = REPO / "lab" / "redteam" / "findings"

# The values falsifiers.json documents in its own `about` text.
COMMANDS = ("host", "e2e", "selftest")
EXPECTS = ("caught", "compile_error", "survives")
FIELDS = (("id", str), ("title", str), ("command", str), ("expect", str),
          ("edits", list), ("tests", list))
# The declaration's schema, and the kinds proposal_kind in src/lib.rs accepts.
ASKS_SCHEMA = "elastos.agent-host.asks/v1"
ASK_KINDS = ("read", "edit", "restore", "run", "child", "init", "hosted", "journal-append")

Problem = collections.namedtuple("Problem", "rule entry file reason")

# Guard (b): finding id -> the exact problems it records. Each id also has its
# file under lab/redteam/findings and an expected-failure test named
# test_finding_<id>. Empty: the probe found nothing on the merged base.
KNOWN_FINDINGS = {}

# Every test this module holds. A probe renamed out of discovery would stop
# running without a failure, so the roster is checked.
PROBES = (
    "test_falsifiers_json_parses_and_ids_are_unique",
    "test_every_caught_falsifier_lists_at_least_one_test",
    "test_every_edit_old_string_occurs_exactly_once",
    "test_asks_json_conforms_to_schema",
    "test_source_pin_matches_snapshot",
    "test_clean_report_pins_commit_and_merge",
    "test_probe_refusal_reasons",
    "test_edit_sequence_matches_runner",
    "test_new_finding_fails_gate",
    "test_discovery_contains_all_probes",
    "test_expected_failures_are_recorded_findings",
    "test_strict_json_refusals",
    "test_report_names_the_commit_it_read",
)


class Snapshot(falsifier_data.Snapshot):
    """The agent-host snapshot: names are relative to examples/agent-host."""

    def __init__(self, run=None):
        super().__init__(REPO, run=run)

    def read(self, name):
        """The bytes of examples/agent-host/<name>, or LookupError(reason)."""
        return self.read_relative(AGENT_HOST, name)


def nothing(_name):
    raise LookupError("the file does not exist")


def overlay(read, changed):
    """read, except that each name in changed reads its bytes there; None
    there means the file is absent."""
    def read_changed(name):
        if name not in changed:
            return read(name)
        if changed[name] is None:
            raise LookupError("the file does not exist")
        return changed[name]
    return read_changed


def _document(read, name):
    """(object, None) or (None, reason) from the one strict reader."""
    try:
        return falsifier_data.load_json(read(name)), None
    except LookupError as error:
        return None, str(error)
    except falsifier_data.StrictJsonError as error:
        return None, str(error)


def falsifier_entries(read):
    """(the well-formed entries, problems) for falsifiers.json: it parses into
    a non-empty falsifiers list, each entry has its fields and known values,
    and no id is used twice."""
    def problem(entry, reason):
        return Problem("parse", entry, "falsifiers.json", reason)

    document, reason = _document(read, "falsifiers.json")
    if reason is not None:
        return [], [problem("", reason)]
    if not isinstance(document, dict):
        return [], [problem("", "the document is not an object")]
    if "falsifiers" not in document:
        return [], [problem("", "the document has no falsifiers list")]
    listed = document["falsifiers"]
    if not isinstance(listed, list):
        return [], [problem("", "falsifiers is not a list")]
    if not listed:
        return [], [problem("", "falsifiers is empty")]
    entries, problems = [], []
    for at, entry in enumerate(listed):
        reason = entry_reason(entry)
        if reason is None:
            entries.append(entry)
            continue
        name = entry.get("id") if isinstance(entry, dict) else None
        problems.append(problem(name if isinstance(name, str) else f"entry {at}", reason))
    ids = collections.Counter(entry["id"] for entry in listed
                              if isinstance(entry, dict) and isinstance(entry.get("id"), str))
    problems += [problem(name, f"the id is used {count} times")
                 for name, count in ids.items() if count > 1]
    return entries, problems


def entry_reason(entry):
    """Why one entry is malformed, or None."""
    if not isinstance(entry, dict):
        return "the entry is not an object"
    for field, kind in FIELDS:
        if field not in entry:
            return f"{field} is missing"
        if not isinstance(entry[field], kind):
            return f"{field} is not a {kind.__name__}"
    if entry["command"] not in COMMANDS:
        return f"command {entry['command']!r} is not one of {', '.join(COMMANDS)}"
    if entry["expect"] not in EXPECTS:
        return f"expect {entry['expect']!r} is not one of {', '.join(EXPECTS)}"
    for at, name in enumerate(entry["tests"]):
        if not isinstance(name, str) or not name:
            return f"tests[{at}] is not a non-empty string"
    if not entry["edits"]:
        return "edits is empty"
    for at, edit in enumerate(entry["edits"]):
        if not (isinstance(edit, dict)
                and all(isinstance(edit.get(key), str) for key in ("file", "old", "new"))):
            return f"edits[{at}] is not an object with string file, old and new"
    return None


def caught_without_tests(entries):
    """Problems for caught entries that name no test: nothing could catch them."""
    return [Problem("caught", entry["id"], "falsifiers.json", "caught, but names no test")
            for entry in entries if entry["expect"] == "caught" and not entry["tests"]]


def anchor_problems(entries, read):
    """Problems for edits falsify.py could not apply.

    As in Mutation.__enter__, one file's edits apply in order, each to the
    text the earlier ones left, and each old text must be found exactly once
    at its turn. The count is ``apply_edits``; this function does not count
    for itself.
    """
    problems = []
    for entry in entries:
        by_file = {}
        for at, edit in enumerate(entry["edits"]):
            by_file.setdefault(edit["file"], []).append((at, edit))
        for name, edits in by_file.items():
            try:
                text = falsifier_data.text_of(read(name))
            except LookupError as error:
                problems.append(Problem("anchor", entry["id"], name, str(error)))
                continue
            _updated, failed = falsifier_data.apply_edits(text, edits)
            if failed:
                at, count = failed
                problems.append(Problem(
                    "anchor", entry["id"], name,
                    f"edits[{at}]: old is found {count} times, not once"))
    return problems


def asks_problems(read):
    """Problems for asks.json: its schema, and a known kind and a non-empty
    resource in every ask."""
    def problem(entry, reason):
        return Problem("asks", entry, "asks.json", reason)

    document, reason = _document(read, "asks.json")
    if reason is not None:
        return [problem("", reason)]
    if not isinstance(document, dict):
        return [problem("", "the document is not an object")]
    if "schema" not in document:
        return [problem("", "schema is missing")]
    if document["schema"] != ASKS_SCHEMA:
        return [problem("", f"schema is {document['schema']!r}, not {ASKS_SCHEMA!r}")]
    if "asks" not in document:
        return [problem("", "asks is missing")]
    asks = document["asks"]
    if not isinstance(asks, list):
        return [problem("", "asks is not a list")]
    if not asks:
        return [problem("", "asks is empty")]
    return [problem(f"ask {at}", reason)
            for at, reason in enumerate(map(ask_reason, asks)) if reason]


def ask_reason(ask):
    """Why one ask is malformed, or None."""
    if not isinstance(ask, dict):
        return "the ask is not an object"
    if "kind" not in ask:
        return "kind is missing"
    if ask["kind"] not in ASK_KINDS:
        return f"kind {ask['kind']!r} is not a known kind"
    if "resource" not in ask:
        return "resource is missing"
    if not isinstance(ask["resource"], str) or not ask["resource"]:
        return f"resource {ask['resource']!r} is not a non-empty string"
    return None


def probe(read):
    """Every rule over one tree: (the well-formed entries, {rule: problems})."""
    entries, parsed = falsifier_entries(read)
    return entries, {
        "parse": parsed,
        "caught": caught_without_tests(entries),
        "anchor": anchor_problems(entries, read),
        "asks": asks_problems(read),
    }


def git(*args):
    """One read-only git command in this repository, or None."""
    return falsifier_data.execute(REPO, args)


def digest(data):
    return falsifier_data.digest(data)


def committed_bytes(commit, paths, run=None):
    """{path: its bytes at commit, or None when the commit has no such file}."""
    if run is None:
        run = lambda *args: falsifier_data.execute(REPO, args)
    return {path: falsifier_data.blob_at(run, commit, path) for path in paths}


def pin_problems(files, commit, committed):
    """Problems binding the bytes read to one commit.

    Every file read must hold exactly the bytes ``committed(path)`` gives for
    that same commit, or None when the commit has no such file. ``commit`` is
    the snapshot's SHA. This function does not resolve HEAD.
    """
    if commit is None:
        return [Problem("pin", "", "HEAD",
                        "HEAD cannot be resolved, so the bytes read are bound to no commit")]
    problems = []
    for path, data in sorted(files.items()):
        want = committed(path)
        if data != want:
            problems.append(Problem(
                "pin", "", path,
                f"the bytes read ({digest(data)}) differ from {commit}:{path} ({digest(want)})"))
    return problems


def unexpected(problems, known=None):
    """The problems no recorded finding covers. A finding hides only the
    problems it records, so a second defect beside it still fails the gate."""
    known = KNOWN_FINDINGS if known is None else known
    recorded = {problem for found in known.values() for problem in found}
    return [problem for problem in problems if problem not in recorded]


def described(problems, files, snapshot):
    """The problems, as KNOWN_FINDINGS records them, then where they were read."""
    return "\n".join([repr(problem) for problem in problems]
                     + [snapshot.describe(files, snapshot.commit)])


@functools.lru_cache(maxsize=None)
def merged_base():
    """The rules over the checked-out base, run once: one snapshot, so every
    test judges the same bytes and the same commit."""
    snapshot = Snapshot()
    entries, problems = probe(snapshot.read)
    return snapshot, entries, problems


def report_text(snapshot, problems):
    """The record for one snapshot.

    The commit is the SHA the snapshot resolved. This function does not
    resolve HEAD. A second resolution here would let the record name a commit
    the bytes were not checked against.
    """
    commit = snapshot.commit
    blobs = {}
    if commit is not None:
        blobs = {path: falsifier_data.blob_at(snapshot.run, commit, path)
                 for path in snapshot.files}
    differ = pin_problems(snapshot.files, commit, blobs.get)
    counts = ", ".join(f"{rule} {len(found)}" for rule, found in problems.items())
    lines = []
    if commit is not None and not differ and not any(problems.values()):
        lines.append("every merged agent-host falsifier anchor and the asks schema "
                     f"hold on {commit}")
    lines.append(
        "agent-host honesty probe: problems by rule: "
        f"{counts}; recorded findings: {', '.join(KNOWN_FINDINGS) or 'none'}; "
        f"files read that differ from HEAD: {len(differ)} of {len(snapshot.files)}")
    lines.append(snapshot.describe(snapshot.files, commit))
    return "\n".join(lines)


def report():
    """The run's record (guard a), printed after the tests."""
    snapshot, _entries, problems = merged_base()
    return report_text(snapshot, problems)


def tearDownModule():
    print("\n" + report(), file=sys.stderr)


def merged_document(name):
    return falsifier_data.load_json(merged_base()[0].read(name))


def with_entries(entries):
    return {"falsifiers.json": json.dumps({"falsifiers": entries}).encode()}


def planted(changed):
    """The rules over a disposable copy of the merged base with some files
    replaced, judged by the same functions. Only the problems the merged base
    does not already have are returned."""
    snapshot = Snapshot()
    _entries, found = probe(overlay(snapshot.read, changed))
    base = merged_base()[2]
    return {rule: [problem for problem in found[rule] if problem not in base[rule]]
            for rule in found}


def discovered():
    """Every test case unittest discovers in this module."""
    pending = [unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])]
    cases = []
    while pending:
        item = pending.pop()
        if isinstance(item, unittest.TestSuite):
            pending.extend(item)
        else:
            cases.append(item)
    return cases


def method_name(case):
    return case.id().rsplit(".", 1)[-1]


def finding_tests():
    return tuple(f"test_finding_{finding.replace('-', '_')}" for finding in KNOWN_FINDINGS)


class AgentHostFalsifierHonesty(unittest.TestCase):
    """The rules on the merged base. Each test requires something to check,
    requires the merged data to be clean, then plants one defect in a copy of
    that data and requires the same rule to report exactly it."""

    def assert_clean(self, rule):
        snapshot, _entries, problems = merged_base()
        new = unexpected(problems[rule])
        if new:
            self.fail("\n" + described(new, snapshot.files, snapshot))

    def test_falsifiers_json_parses_and_ids_are_unique(self):
        self.assert_clean("parse")
        entries = merged_base()[1]
        self.assertTrue(entries, "falsifiers.json has no entry to check")
        twice = copy.deepcopy(entries) + [copy.deepcopy(entries[0])]
        self.assertEqual(planted(with_entries(twice))["parse"], [Problem(
            "parse", entries[0]["id"], "falsifiers.json", "the id is used 2 times")])

    def test_every_caught_falsifier_lists_at_least_one_test(self):
        entries = copy.deepcopy(merged_base()[1])
        caught = [entry for entry in entries if entry["expect"] == "caught"]
        self.assertTrue(caught, "no caught entry to check")
        self.assert_clean("caught")
        caught[0]["tests"] = []
        self.assertEqual(planted(with_entries(entries))["caught"], [Problem(
            "caught", caught[0]["id"], "falsifiers.json", "caught, but names no test")])

    def test_every_edit_old_string_occurs_exactly_once(self):
        entries = copy.deepcopy(merged_base()[1])
        self.assertTrue([edit for entry in entries for edit in entry["edits"]], "no edit to check")
        self.assert_clean("anchor")
        first = entries[0]
        edit = first["edits"][0]
        # An old text that is no longer in the file is a stale anchor.
        first["edits"] = [dict(edit, old=edit["old"] + "\n<redteam: planted stale anchor>")]
        self.assertEqual(planted(with_entries(entries))["anchor"], [Problem(
            "anchor", first["id"], edit["file"], "edits[0]: old is found 0 times, not once")])
        # A file outside the repository is refused before any read.
        outside = "../../../redteam-outside-the-repository.txt"
        first["edits"] = [dict(edit, file=outside)]
        self.assertEqual(planted(with_entries(entries))["anchor"], [Problem(
            "anchor", first["id"], outside, "the file is outside the repository")])

    def test_asks_json_conforms_to_schema(self):
        self.assert_clean("asks")
        document = merged_document("asks.json")
        document["asks"][0]["kind"] = "unspecified"
        self.assertEqual(planted({"asks.json": json.dumps(document).encode()})["asks"], [Problem(
            "asks", "ask 0", "asks.json", "kind 'unspecified' is not a known kind")])

    def test_source_pin_matches_snapshot(self):
        snapshot = merged_base()[0]
        for name in ("falsifiers.json", "asks.json"):
            self.assertIsNotNone(snapshot.files.get(f"examples/agent-host/{name}"),
                                 f"{name} was not read")
        commit = snapshot.commit
        self.assertIsNotNone(commit, "the snapshot resolved no commit")
        resolved = git("rev-parse", "--verify", "--quiet", "HEAD^{commit}")
        self.assertEqual(commit, resolved.decode("ascii").strip())
        committed = committed_bytes(commit, snapshot.files, snapshot.run)
        new = pin_problems(snapshot.files, commit, committed.get)
        if new:
            self.fail("\n" + described(new, snapshot.files, snapshot))
        # A changed source under the same pin is caught, and the report names
        # the commit and the sha256 of the changed bytes.
        path = "examples/agent-host/falsifiers.json"
        changed = dict(snapshot.files)
        changed[path] += b"\n"
        problems = pin_problems(changed, commit, committed.get)
        self.assertEqual(problems, [Problem("pin", "", path, (
            f"the bytes read ({digest(changed[path])}) differ from {commit}:{path} "
            f"({digest(snapshot.files[path])})"))])
        record = described(problems, changed, snapshot)
        self.assertIn(f"read at HEAD {commit}", record)
        self.assertIn(f"{path} {digest(changed[path])}, last changed in ", record)

    def test_clean_report_pins_commit_and_merge(self):
        """The record names the snapshot's commit, and for every file read its
        sha256, its last change, and the commit that brought that change onto
        that commit's first-parent line. git confirms each such commit is on
        that line and holds the change, and that its first parent does not,
        so it is the first one that does. Each pin is derived from the
        snapshot SHA, not from a second resolution of HEAD."""
        snapshot = merged_base()[0]
        record = report()
        commit = snapshot.commit
        self.assertIsNotNone(commit, "the snapshot resolved no commit")
        self.assertIn(f"every merged agent-host falsifier anchor and the asks schema "
                      f"hold on {commit}", record)
        self.assertIn(f"read at HEAD {commit}", record)
        self.assertIn("files read that differ from HEAD: 0 of ", record)
        listed = git("rev-list", "--first-parent", commit)
        self.assertIsNotNone(listed, "the snapshot commit has no first-parent line")
        line = listed.decode("ascii").split()
        self.assertEqual(snapshot.first_parent_line(commit), tuple(line))
        for path, data in sorted(snapshot.files.items()):
            with self.subTest(path):
                change_out = git("log", "-1", "--format=%H %s", commit, "--", path)
                self.assertIsNotNone(change_out, f"{path} has no commit at {commit}")
                change = change_out.decode("utf-8", "replace").strip()
                self.assertEqual(snapshot.last_change(path, commit), change)
                self.assertIn(f"  {path} {digest(data)}, last changed in {change}\n", record + "\n")
                changed_in = change.split()[0]
                entry = snapshot.entry_point(changed_in, commit)
                self.assertIn(entry, line)
                self.assertIsNotNone(git("merge-base", "--is-ancestor", changed_in, entry))
                self.assertIsNone(git("merge-base", "--is-ancestor", changed_in, entry + "^"))
                shown = git("log", "-1", "--format=%H %s", entry)
                self.assertIsNotNone(shown)
                self.assertIn("    first on HEAD's first-parent line in "
                              + shown.decode("utf-8", "replace").strip(), record)
                self.assertIn("Merge pull request #", record)


# One small tree every rule passes. Each control below breaks one thing in it.
GOOD_SOURCE = b"fn helper() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn a_test() {}\n}\n"
GOOD_RUNNER = b"return True\n"
GOOD_HOST = {"id": "ST1", "title": "host", "command": "host", "expect": "caught",
             "edits": [{"file": "src/lib.rs", "old": "fn helper() {}",
                        "new": "fn helper() { panic!() }"}],
             "tests": ["tests::a_test"]}
GOOD_SELFTEST = {"id": "ST2", "title": "selftest", "command": "selftest", "expect": "caught",
                 "edits": [{"file": "falsify.py", "old": "return True", "new": "return False"}],
                 "tests": ["a case"]}
GOOD_ASKS = {"schema": ASKS_SCHEMA, "asks": [{"kind": "read", "resource": "<principal>/"}]}


def tree(entries=(GOOD_HOST, GOOD_SELFTEST), **changed):
    """A fixture tree, name -> bytes (None: absent). A keyword changes one
    file: data, asks, source or runner."""
    files = {"falsifiers.json": json.dumps({"falsifiers": list(entries)}).encode(),
             "asks.json": json.dumps(GOOD_ASKS).encode(),
             "src/lib.rs": GOOD_SOURCE,
             "falsify.py": GOOD_RUNNER}
    names = {"data": "falsifiers.json", "asks": "asks.json",
             "source": "src/lib.rs", "runner": "falsify.py"}
    files.update((names[key], value) for key, value in changed.items())
    return files


def problems_in(files, rule=None):
    """The problems every rule finds in a fixture tree, or one rule's."""
    _entries, found = probe(overlay(nothing, files))
    return found[rule] if rule else [problem for problems in found.values() for problem in problems]


def document_with(extra):
    """A JSON object that is a valid falsifier list and a valid asks list,
    with ``extra`` source inserted after the opening brace.

    ``extra`` is raw JSON, so a caller can plant ``NaN`` or a repeated key,
    which ``json.dumps`` would not emit.
    """
    payload = {
        "schema": ASKS_SCHEMA,
        "asks": GOOD_ASKS["asks"],
        "falsifiers": [GOOD_HOST],
    }
    body = json.dumps(payload)
    return ("{" + extra + ", " + body[1:]).encode()


class ProbeControls(unittest.TestCase):
    """The rules on planted inputs, through the same functions the probes use."""

    def test_probe_refusal_reasons(self):
        """Each rule refuses each planted input with its own reason, and the
        good tree passes every rule."""

        def host(**change):
            return tree([dict(GOOD_HOST, **change), GOOD_SELFTEST])

        def edit(**change):
            return host(edits=[dict(GOOD_HOST["edits"][0], **change)])

        def data(text):
            return tree(data=text if text is None else text.encode())

        def asks(document):
            return tree(asks=json.dumps(document).encode())

        def parse(entry, reason):
            return [Problem("parse", entry, "falsifiers.json", reason)]

        def anchor(entry, file, reason):
            return [Problem("anchor", entry, file, reason)]

        def ask(entry, reason):
            return [Problem("asks", entry, "asks.json", reason)]

        untested = {key: value for key, value in GOOD_HOST.items() if key != "tests"}
        cases = (
            ("the good tree", tree(), []),
            ("a compile_error entry may name no test", host(expect="compile_error", tests=[]), []),
            ("falsifiers.json is missing", data(None), parse("", "the file does not exist")),
            ("falsifiers.json is not UTF-8", tree(data=b"\xff"),
             parse("", "the file is not UTF-8")),
            ("falsifiers.json is not JSON", data("{"), parse("", "the file is not JSON")),
            ("the document is a list", data("[]"), parse("", "the document is not an object")),
            ("no falsifiers list", data("{}"), parse("", "the document has no falsifiers list")),
            ("falsifiers is an object", data('{"falsifiers": {}}'),
             parse("", "falsifiers is not a list")),
            ("falsifiers is empty", data('{"falsifiers": []}'), parse("", "falsifiers is empty")),
            ("an entry is a number", tree([GOOD_HOST, 7]),
             parse("entry 1", "the entry is not an object")),
            ("an id is used twice", tree([GOOD_HOST, GOOD_HOST, GOOD_SELFTEST]),
             parse("ST1", "the id is used 2 times")),
            ("tests is missing", tree([untested, GOOD_SELFTEST]), parse("ST1", "tests is missing")),
            ("tests is a string", host(tests="tests::a_test"), parse("ST1", "tests is not a list")),
            ("an unknown command", host(command="cargo"),
             parse("ST1", "command 'cargo' is not one of host, e2e, selftest")),
            ("an unknown expect", host(expect="maybe"),
             parse("ST1", "expect 'maybe' is not one of caught, compile_error, survives")),
            ("an empty test name", host(tests=[""]),
             parse("ST1", "tests[0] is not a non-empty string")),
            ("no edit", host(edits=[]), parse("ST1", "edits is empty")),
            ("an edit without new", host(edits=[{"file": "src/lib.rs", "old": "fn helper() {}"}]),
             parse("ST1", "edits[0] is not an object with string file, old and new")),
            ("a caught entry names no test", host(tests=[]),
             [Problem("caught", "ST1", "falsifiers.json", "caught, but names no test")]),
            ("an old text found nowhere", edit(old="fn gone() {}"),
             anchor("ST1", "src/lib.rs", "edits[0]: old is found 0 times, not once")),
            ("an old text found twice", edit(old="fn "),
             anchor("ST1", "src/lib.rs", "edits[0]: old is found 2 times, not once")),
            ("an edit of a missing file", edit(file="src/gone.rs"),
             anchor("ST1", "src/gone.rs", "the file does not exist")),
            ("an edit of a file that is not UTF-8",
             dict(edit(file="blob.bin"), **{"blob.bin": b"\xff"}),
             anchor("ST1", "blob.bin", "the file is not UTF-8")),
            ("asks.json is missing", tree(asks=None), ask("", "the file does not exist")),
            ("asks.json is not JSON", tree(asks=b"{"), ask("", "the file is not JSON")),
            ("the declaration is a list", asks([]), ask("", "the document is not an object")),
            ("no schema", asks({"asks": GOOD_ASKS["asks"]}), ask("", "schema is missing")),
            ("another schema", asks(dict(GOOD_ASKS, schema="elastos.agent-host.asks/v0")),
             ask("", "schema is 'elastos.agent-host.asks/v0', not 'elastos.agent-host.asks/v1'")),
            ("no asks", asks({"schema": ASKS_SCHEMA}), ask("", "asks is missing")),
            ("asks is an object", asks(dict(GOOD_ASKS, asks={})), ask("", "asks is not a list")),
            ("asks is empty", asks(dict(GOOD_ASKS, asks=[])), ask("", "asks is empty")),
            ("an ask is a string", asks(dict(GOOD_ASKS, asks=["read"])),
             ask("ask 0", "the ask is not an object")),
            ("an ask with no kind", asks(dict(GOOD_ASKS, asks=[{"resource": "Models/"}])),
             ask("ask 0", "kind is missing")),
            ("an unknown kind",
             asks(dict(GOOD_ASKS, asks=[{"kind": "unspecified", "resource": "Models/"}])),
             ask("ask 0", "kind 'unspecified' is not a known kind")),
            ("an ask with no resource", asks(dict(GOOD_ASKS, asks=[{"kind": "read"}])),
             ask("ask 0", "resource is missing")),
            ("an empty resource", asks(dict(GOOD_ASKS, asks=[{"kind": "read", "resource": ""}])),
             ask("ask 0", "resource '' is not a non-empty string")),
            ("a resource that is not a string",
             asks(dict(GOOD_ASKS, asks=[{"kind": "read", "resource": 7}])),
             ask("ask 0", "resource 7 is not a non-empty string")),
        )
        for label, files, want in cases:
            with self.subTest(label):
                self.assertEqual(problems_in(files), want)
        commit = "c" * 40
        for label, files, committed, want in (
            ("the same bytes", {"a": b"x"}, {"a": b"x"}, []),
            ("changed bytes", {"a": b"y"}, {"a": b"x"},
             f"the bytes read ({digest(b'y')}) differ from {commit}:a ({digest(b'x')})"),
            ("a file the commit lacks", {"a": b"x"}, {},
             f"the bytes read ({digest(b'x')}) differ from {commit}:a (absent)"),
            ("a committed file that is gone", {"a": None}, {"a": b"x"},
             f"the bytes read (absent) differ from {commit}:a ({digest(b'x')})"),
        ):
            with self.subTest(label):
                self.assertEqual(pin_problems(files, commit, committed.get),
                                 [Problem("pin", "", "a", want)] if want else [])
        with self.subTest("no commit"):
            self.assertEqual(pin_problems({"a": b"x"}, None, {"a": b"x"}.get), [Problem(
                "pin", "", "HEAD",
                "HEAD cannot be resolved, so the bytes read are bound to no commit")])

    def test_edit_sequence_matches_runner(self):
        """falsify.py applies one file's edits in order, each to the text the
        earlier ones left, so an earlier edit can remove or repeat a later
        anchor that is found once in the original."""
        original = b"alpha beta\n"
        for pairs, reason in (
            ((("alpha beta", "gamma"), ("beta", "delta")),
             "edits[1]: old is found 0 times, not once"),
            ((("alpha", "beta"), ("beta", "delta")), "edits[1]: old is found 2 times, not once"),
            ((("alpha", "one"), ("beta", "two")), None),
        ):
            with self.subTest(pairs=pairs):
                for old, _new in pairs:
                    self.assertEqual(original.decode().count(old), 1)
                entry = dict(GOOD_HOST, edits=[{"file": "notes.txt", "old": old, "new": new}
                                               for old, new in pairs])
                found = anchor_problems([entry], overlay(nothing, {"notes.txt": original}))
                self.assertEqual(
                    found, [Problem("anchor", "ST1", "notes.txt", reason)] if reason else [])
        with self.subTest("a CRLF file read as the runner reads it"):
            entry = dict(GOOD_HOST, edits=[{"file": "notes.txt", "old": "alpha\nbeta", "new": "x"}])
            self.assertEqual(
                anchor_problems([entry], overlay(nothing, {"notes.txt": b"alpha\r\nbeta\r\n"})), [])
        with self.subTest("the merged base is unchanged on disk"):
            for path, data in merged_base()[0].files.items():
                disk = REPO / path
                self.assertEqual(disk.read_bytes() if disk.is_file() else None, data,
                                 f"{path} changed while the probe ran")

    def test_strict_json_refusals(self):
        """The one reader refuses NaN, Infinity, -Infinity, a duplicate key,
        bytes that are not UTF-8, and broken syntax. Each case is fed to the
        falsifiers probe and to the asks probe, and each reason is exact.

        Codex's two round-3 repros are here: ``"about": NaN`` on a valid
        falsifier document, and ``"extra": NaN`` on a valid asks document.
        ``json.loads`` accepts both, and both probes would then report no
        problem. A duplicate key is the same shape: the default reader keeps
        the last value and the probes accept the document.
        """
        valid = document_with('"about": "plain"')
        files = tree()
        files["falsifiers.json"] = valid
        files["asks.json"] = valid
        self.assertEqual(problems_in(files), [], "the valid document was refused")

        nested = document_with('"note": 1').replace(
            b'"kind": "read"', b'"kind": "read", "kind": "read"', 1)
        cases = (
            ("about NaN", document_with('"about": NaN'), "NaN is not strict JSON"),
            ("extra NaN", document_with('"extra": NaN'), "NaN is not strict JSON"),
            ("Infinity", document_with('"about": Infinity'), "Infinity is not strict JSON"),
            ("-Infinity", document_with('"about": -Infinity'), "-Infinity is not strict JSON"),
            ("duplicate about", document_with('"about": 1, "about": 2'),
             "duplicate key 'about'"),
            ("duplicate kind", nested, "duplicate key 'kind'"),
            ("not UTF-8", b"\xff", "the file is not UTF-8"),
            ("broken syntax", b"{", "the file is not JSON"),
        )
        for label, raw, reason in cases:
            with self.subTest(label):
                planted_files = tree()
                planted_files["falsifiers.json"] = raw
                planted_files["asks.json"] = raw
                self.assertEqual(problems_in(planted_files, "parse"), [Problem(
                    "parse", "", "falsifiers.json", reason)])
                self.assertEqual(problems_in(planted_files, "asks"), [Problem(
                    "asks", "", "asks.json", reason)])

    def test_report_names_the_commit_it_read(self):
        """A fake git answers A, then B, to successive HEAD lookups. Only A
        has the bytes the snapshot read. The report names A. It does not
        print zero differences next to B.

        That is the round-2 failure: the pin used the first resolution and
        the record resolved HEAD again. One extra ``rev-parse`` of HEAD in
        the report is enough to fail this test.
        """
        commit_a = "a" * 40
        commit_b = "b" * 40
        lookups = []
        calls = []
        real = falsifier_data.execute

        def fake(root, args):
            calls.append(args)
            if args[0] == "rev-parse":
                lookups.append(args)
                sha = commit_a if len(lookups) == 1 else commit_b
                return (sha + "\n").encode()
            if args[0] == "cat-file":
                spec = args[-1]
                commit, _sep, path = spec.partition(":")
                if commit != commit_a:
                    return b"bytes-only-at-A"
                file = Path(root) / path
                return file.read_bytes() if file.is_file() else None
            if args[0] == "log":
                if commit_a not in args or any("HEAD" in arg or commit_b in arg for arg in args):
                    return (commit_b + " other\n").encode()
                return (commit_a + " pinned\n").encode()
            if args[0] == "rev-list":
                if any("HEAD" in arg or commit_b in arg for arg in args) or commit_a not in "".join(args):
                    return (commit_b + "\n").encode()
                return (commit_a + "\n").encode()
            return None

        falsifier_data.execute = fake
        merged_base.cache_clear()
        try:
            text = report()
        finally:
            falsifier_data.execute = real
            merged_base.cache_clear()

        self.assertEqual(len(lookups), 1, lookups)
        self.assertIn("HEAD^{commit}", lookups[0][-1])
        for args in calls:
            if args[0] == "rev-parse":
                continue
            for arg in args:
                self.assertNotIn("HEAD", arg)
                self.assertNotIn(commit_b, arg)
        self.assertIn(f"read at HEAD {commit_a}", text)
        self.assertNotIn(f"read at HEAD {commit_b}", text)
        self.assertIn("files read that differ from HEAD: 0 of ", text)
        self.assertNotIn(commit_b, text)
        self.assertIn(commit_a + " pinned", text)
        self.assertFalse("0 of" in text and f"read at HEAD {commit_b}" in text, text)

    def test_new_finding_fails_gate(self):
        """A recorded finding hides only its own problems: a second malformed
        entry beside it still fails the gate."""
        found = problems_in(tree([dict(GOOD_HOST, tests=[]),
                                  dict(GOOD_HOST, id="ST3", tests=[])]), "caught")
        self.assertEqual(len(found), 2, "two caught entries with no test are two problems")
        first, second = found
        known = {"agent-host-000": (first,)}
        self.assertEqual(unexpected([first], known), [])
        self.assertEqual(unexpected([first, second], known), [second])
        self.assertEqual(unexpected([first, second], {}), [first, second])

    def test_discovery_contains_all_probes(self):
        """Every probe is discovered under its name; a probe renamed out of
        discovery, or left off the roster, fails here."""
        self.assertEqual(sorted(method_name(case) for case in discovered()),
                         sorted(PROBES + finding_tests()))

    def test_expected_failures_are_recorded_findings(self):
        """Guard (b): an expected failure is a recorded finding, marked on its
        own test, never on a whole class; and each recorded finding has its
        file under lab/redteam/findings."""
        cases = discovered()
        whole = sorted({type(case).__name__ for case in cases
                        if getattr(case, "__unittest_expecting_failure__", False)})
        self.assertEqual(whole, [], "a whole class is marked as an expected failure")
        marked = sorted(method_name(case) for case in cases if getattr(
            getattr(case, method_name(case)), "__unittest_expecting_failure__", False))
        self.assertEqual(marked, sorted(finding_tests()))
        for finding in KNOWN_FINDINGS:
            self.assertTrue((FINDINGS / f"{finding}.md").is_file(),
                            f"{finding} has no finding file")


if __name__ == "__main__":
    unittest.main()
