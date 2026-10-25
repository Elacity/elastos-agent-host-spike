"""Static honesty probe over the merged agent-host falsifiers and asks.

The agent-host re-score rests on examples/agent-host/falsifiers.json: each
entry claims that a planted bug is caught by its named tests. This probe reads
that file, asks.json, falsify.py and the Rust sources, read only: no cargo,
and the runner is parsed, never imported. It checks that every claim is
well-formed and anchored:

- falsifiers.json parses, each entry has its fields, and no id repeats;
- every `caught` entry names at least one test;
- every named test exists: a #[test] fn for `host`, and for `selftest` a
  SELF_TEST_CASES key bound to a function falsify.py defines. Any other
  command has no static lookup here, so it fails closed;
- every edit's old text is found exactly once, each file's edits applied in
  order, the way falsify.py's Mutation applies them;
- asks.json has its schema, and every ask a known kind and a resource.

Each probe also plants one defect in a copy of the merged data and requires
the same rule to report exactly that defect, so a clean result is not vacuous
(guard d).

Every file is read once into one snapshot, and the pin test binds that
snapshot to one commit, HEAD resolved once: the bytes read must be the bytes
committed there. A failure prints that commit, and the sha256 and last change
of every file read (guard a).

A reproduced defect becomes a finding, lab/redteam/findings/<id>.md, listed in
KNOWN_FINDINGS with an expected-failure test named test_finding_<id> (guard b).
A finding hides only the problems it records: any other problem still fails
the gate. The probe writes no file.

Not checked here: the module path before the last `::` of a host test name,
and whether each named test really fails under its mutation. Both need cargo,
so they are the dynamic re-run's job.

Run: python3 -I -B -m unittest discover -s lab/redteam/py
(-B keeps __pycache__ out of the lane folder.)
"""
import ast
import collections
import copy
import functools
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
AGENT_HOST = REPO / "examples" / "agent-host"
FINDINGS = REPO / "lab" / "redteam" / "findings"
SOURCE_DIRS = ("src", "tests")

# The values falsifiers.json documents in its own `about` text.
COMMANDS = ("host", "e2e", "selftest")
EXPECTS = ("caught", "compile_error", "survives")
FIELDS = (("id", str), ("title", str), ("command", str), ("expect", str),
          ("edits", list), ("tests", list))
# The declaration's schema, and the kinds proposal_kind in src/lib.rs accepts.
ASKS_SCHEMA = "elastos.agent-host.asks/v1"
ASK_KINDS = ("read", "edit", "restore", "run", "child", "init", "hosted", "journal-append")

# `#[test]`, then any other attributes or line comments, then the fn itself.
TEST_FN = re.compile(r"#\[test\](?:\s*(?:#\[[^\n]*\]|//[^\n]*))*\s*"
                     r"(?:pub(?:\([^)\n]*\))?\s+)?(?:async\s+)?fn\s+(\w+)")
ANY_FN = re.compile(r"\bfn\s+(\w+)")

Problem = collections.namedtuple("Problem", "rule entry file reason")

# Guard (b): finding id -> the exact problems it records. Each id also has its
# file under lab/redteam/findings and an expected-failure test named
# test_finding_<id> that asserts those problems are gone. Empty: the probe
# found nothing on the merged base.
KNOWN_FINDINGS = {}

# Every test this module holds. A probe renamed out of discovery would stop
# running without a failure, so the roster is checked.
PROBES = (
    "test_falsifiers_json_parses_and_ids_are_unique",
    "test_every_caught_falsifier_lists_at_least_one_test",
    "test_every_named_test_exists_in_the_sources",
    "test_every_edit_old_string_occurs_exactly_once",
    "test_asks_json_conforms_to_schema",
    "test_source_pin_matches_snapshot",
    "test_probe_refusal_reasons",
    "test_edit_sequence_matches_runner",
    "test_new_finding_fails_gate",
    "test_discovery_contains_all_probes",
    "test_expected_failures_are_recorded_findings",
)


class Snapshot:
    """The files the probe reads, each read once and kept, so every rule and
    the pin judge the same bytes. A name is resolved first, and read only when
    it lies inside the repository."""

    def __init__(self):
        self.files = {}  # repository path -> bytes, or None when absent

    def read(self, name):
        """The bytes of examples/agent-host/<name>, or LookupError(reason)."""
        path = (AGENT_HOST / name).resolve()
        if not path.is_relative_to(REPO):
            raise LookupError("the file is outside the repository")
        key = path.relative_to(REPO).as_posix()
        if key not in self.files:
            self.files[key] = path.read_bytes() if path.is_file() else None
        if self.files[key] is None:
            raise LookupError("the file does not exist")
        return self.files[key]

    @staticmethod
    def rust_names():
        """The .rs files under src/ and tests/, relative to examples/agent-host."""
        return sorted(path.relative_to(AGENT_HOST).as_posix()
                      for folder in SOURCE_DIRS for path in (AGENT_HOST / folder).rglob("*.rs"))


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


def text_of(read, name):
    """The text falsify.py sees, as Path.read_text(encoding="utf-8") gives it:
    strict UTF-8, with every line ending read as a newline."""
    try:
        return io.TextIOWrapper(io.BytesIO(read(name)), encoding="utf-8").read()
    except UnicodeDecodeError:
        raise LookupError("the file is not UTF-8") from None


def falsifier_entries(read):
    """(the well-formed entries, problems) for falsifiers.json: it parses into
    a non-empty falsifiers list, each entry has its fields and known values,
    and no id is used twice."""
    def problem(entry, reason):
        return Problem("parse", entry, "falsifiers.json", reason)

    try:
        document = json.loads(text_of(read, "falsifiers.json"))
    except LookupError as error:
        return [], [problem("", str(error))]
    except ValueError:
        return [], [problem("", "the file is not JSON")]
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


def missing_tests(entries, read, rust_names):
    """Problems for named tests the sources do not define. Each command has
    its own lookup; a command without one fails closed."""
    lookups = {}
    problems = []
    for entry in entries:
        if entry["expect"] not in ("caught", "survives"):
            continue
        command = entry["command"]
        if command not in lookups:
            lookups[command] = lookup_for(command, read, rust_names)
        where, reason = lookups[command]
        for name in entry["tests"]:
            why = reason(name)
            if why:
                problems.append(Problem("named", entry["id"], where, why))
    return problems


def lookup_for(command, read, rust_names):
    """(where the names are looked up, name -> why it is missing or None)."""
    if command == "host":
        return ", ".join(rust_names), host_lookup(read, rust_names)
    if command == "selftest":
        return "falsify.py", case_lookup(read)
    return "", lambda _name: f"command {command!r} has no static test lookup"


def host_lookup(read, rust_names):
    """A host name is found when a #[test] fn has its leaf, the part after the
    last ::. A fn of that name without #[test] is not a test."""
    tests, fns = set(), set()
    for name in rust_names:
        text = text_of(read, name)
        tests.update(TEST_FN.findall(text))
        fns.update(ANY_FN.findall(text))

    def reason(name):
        leaf = name.rsplit("::", 1)[-1]
        if leaf in tests:
            return None
        if leaf in fns:
            return f"fn {leaf} is not marked #[test]"
        return f"no #[test] fn {leaf}"
    return reason


def case_lookup(read):
    """A self-test name is found when it is a key of falsify.py's
    SELF_TEST_CASES literal bound to a function falsify.py defines."""
    try:
        cases, defs = runner_cases(read)
    except LookupError as error:
        message = str(error)
        return lambda _name: message

    def reason(name):
        if name not in cases:
            return f"{name!r} is not a SELF_TEST_CASES key"
        if cases[name] not in defs:
            return f"{name!r} maps to {cases[name]}, which falsify.py does not define"
        return None
    return reason


def runner_cases(read):
    """({case name: function name}, top-level function names) from falsify.py,
    read with ast. The last SELF_TEST_CASES assignment wins, as at run time."""
    try:
        tree = ast.parse(text_of(read, "falsify.py"))
    except (SyntaxError, ValueError):
        raise LookupError("falsify.py does not parse") from None
    defs = {node.name for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    cases = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if (any(isinstance(target, ast.Name) and target.id == "SELF_TEST_CASES"
                for target in targets) and isinstance(node.value, ast.Dict)):
            cases = {key.value: getattr(value, "id", None)
                     for key, value in zip(node.value.keys, node.value.values)
                     if isinstance(key, ast.Constant) and isinstance(key.value, str)}
    if cases is None:
        raise LookupError("falsify.py has no SELF_TEST_CASES table")
    return cases, defs


def anchor_problems(entries, read):
    """Problems for edits falsify.py could not apply. As in Mutation.__enter__,
    one file's edits apply in order, each to the text the earlier ones left,
    and each old text must be found exactly once at its turn."""
    problems = []
    for entry in entries:
        by_file = {}
        for at, edit in enumerate(entry["edits"]):
            by_file.setdefault(edit["file"], []).append((at, edit))
        for name, edits in by_file.items():
            try:
                text = text_of(read, name)
            except LookupError as error:
                problems.append(Problem("anchor", entry["id"], name, str(error)))
                continue
            for at, edit in edits:
                count = text.count(edit["old"])
                if count != 1:
                    problems.append(Problem("anchor", entry["id"], name,
                                            f"edits[{at}]: old is found {count} times, not once"))
                    break
                text = text.replace(edit["old"], edit["new"])
    return problems


def asks_problems(read):
    """Problems for asks.json: its schema, and a known kind and a non-empty
    resource in every ask."""
    def problem(entry, reason):
        return Problem("asks", entry, "asks.json", reason)

    try:
        document = json.loads(text_of(read, "asks.json"))
    except LookupError as error:
        return [problem("", str(error))]
    except ValueError:
        return [problem("", "the file is not JSON")]
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


def probe(read, rust_names):
    """Every rule over one tree: (the well-formed entries, {rule: problems})."""
    entries, parsed = falsifier_entries(read)
    return entries, {
        "parse": parsed,
        "caught": caught_without_tests(entries),
        "named": missing_tests(entries, read, rust_names),
        "anchor": anchor_problems(entries, read),
        "asks": asks_problems(read),
    }


def git(*args):
    """The stdout of one read-only git command in the repository, or None.
    GIT_* variables are dropped, so the repository is the one this file is in."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, env=env)
    except OSError:
        return None
    return done.stdout if done.returncode == 0 else None


def head_commit():
    """HEAD as a full commit hash, or None when git cannot resolve it."""
    out = git("rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    return out.decode("ascii").strip() if out else None


def digest(data):
    return "absent" if data is None else "sha256 " + hashlib.sha256(data).hexdigest()


def pin_problems(files, commit, committed):
    """Problems binding the bytes read to one commit: every file read must
    hold exactly the bytes the commit has at that path. committed(path) gives
    those bytes, or None when the commit has no such file."""
    if commit is None:
        return [Problem("pin", "", "HEAD",
                        "HEAD cannot be resolved, so the bytes read are bound to no commit")]
    problems = []
    for path, data in sorted(files.items()):
        want = committed(path)
        if data != want:
            problems.append(Problem("pin", "", path, f"the bytes read ({digest(data)}) differ "
                                    f"from {commit}:{path} ({digest(want)})"))
    return problems


def unexpected(problems, known=None):
    """The problems no recorded finding covers. A finding hides only the
    problems it records, so a second defect beside it still fails the gate."""
    known = KNOWN_FINDINGS if known is None else known
    recorded = {problem for found in known.values() for problem in found}
    return [problem for problem in problems if problem not in recorded]


def described(problems, files):
    """The problems, as KNOWN_FINDINGS records them, then where they were read
    (guard a): HEAD, and the sha256 and last change of every file read."""
    lines = [repr(problem) for problem in problems]
    lines.append(f"read at HEAD {head_commit() or '(unresolved)'}")
    for path, data in sorted(files.items()):
        change = git("log", "-1", "--format=%H %s", "HEAD", "--", path)
        lines.append(f"  {path} {digest(data)}, last changed in "
                     f"{change.decode('utf-8', 'replace').strip() if change else '(unknown)'}")
    return "\n".join(lines)


@functools.lru_cache(maxsize=None)
def merged_base():
    """The rules over the checked-out base, run once, so every test judges one
    snapshot: (snapshot, the well-formed entries, {rule: problems})."""
    snapshot = Snapshot()
    entries, problems = probe(snapshot.read, snapshot.rust_names())
    return snapshot, entries, problems


def merged_document(name):
    return json.loads(text_of(merged_base()[0].read, name))


def with_entries(entries):
    return {"falsifiers.json": json.dumps({"falsifiers": entries}).encode()}


def planted(changed):
    """The rules over a disposable copy of the merged base with some files
    replaced, judged by the same functions. Only the problems the merged base
    does not already have are returned."""
    snapshot = Snapshot()
    _entries, found = probe(overlay(snapshot.read, changed), snapshot.rust_names())
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
            self.fail("\n" + described(new, snapshot.files))

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

    def test_every_named_test_exists_in_the_sources(self):
        entries = copy.deepcopy(merged_base()[1])
        named = [entry for entry in entries
                 if entry["expect"] in ("caught", "survives") and entry["tests"]]
        self.assertTrue(named, "no named test to check")
        self.assert_clean("named")
        with self.subTest("a host test renamed away from its fn"):
            host = next((entry for entry in named if entry["command"] == "host"), None)
            if host is None:
                self.skipTest("the merged base has no host entry to plant in")
            leaf = host["tests"][0].rsplit("::", 1)[-1] + "_renamed_by_redteam"
            host["tests"][0] += "_renamed_by_redteam"
            self.assertEqual(planted(with_entries(entries))["named"], [Problem(
                "named", host["id"], ", ".join(Snapshot.rust_names()), f"no #[test] fn {leaf}")])
        with self.subTest("a self-test key removed from falsify.py"):
            selftest = next((entry for entry in named if entry["command"] == "selftest"), None)
            if selftest is None:
                self.skipTest("the merged base has no selftest entry to plant in")
            case = selftest["tests"][0]
            removed = without_case(text_of(merged_base()[0].read, "falsify.py"), case)
            # Every entry that names the case loses it, and nothing else does.
            reason = f"{case!r} is not a SELF_TEST_CASES key"
            self.assertEqual(planted({"falsify.py": removed.encode()})["named"], [
                Problem("named", entry["id"], "falsify.py", reason)
                for entry in named for name in entry["tests"]
                if entry["command"] == "selftest" and name == case])

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
        commit = head_commit()
        committed = {path: git("cat-file", "blob", f"{commit}:{path}") for path in snapshot.files}
        new = pin_problems(snapshot.files, commit, committed.get)
        if new:
            self.fail("\n" + described(new, snapshot.files))
        # A changed source under the same pin is caught, and the report names
        # the commit and the sha256 of the changed bytes.
        path = "examples/agent-host/falsifiers.json"
        changed = dict(snapshot.files)
        changed[path] += b"\n"
        problems = pin_problems(changed, commit, committed.get)
        self.assertEqual(problems, [Problem("pin", "", path, (
            f"the bytes read ({digest(changed[path])}) differ from {commit}:{path} "
            f"({digest(snapshot.files[path])})"))])
        report = described(problems, changed)
        self.assertIn(f"read at HEAD {commit}", report)
        self.assertIn(f"{path} {digest(changed[path])}, last changed in ", report)


def without_case(runner, case):
    """falsify.py's text without the SELF_TEST_CASES item keyed `case`."""
    for node in ast.parse(runner).body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and any(
                getattr(target, "id", None) == "SELF_TEST_CASES" for target in node.targets)):
            for key, value in zip(node.value.keys, node.value.values):
                if isinstance(key, ast.Constant) and key.value == case:
                    lines = runner.splitlines(keepends=True)
                    del lines[key.lineno - 1:value.end_lineno]
                    return "".join(lines)
    raise LookupError(f"no SELF_TEST_CASES item {case!r}")


# One small tree every rule passes. Each control below breaks one thing in it.
GOOD_SOURCE = b"fn helper() {}\n\n#[test]\nfn a_test() {}\n"
GOOD_RUNNER = b'def case():\n    return True\n\n\nSELF_TEST_CASES = {\n    "a case": case,\n}\n'
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
    _entries, found = probe(overlay(nothing, files), ["src/lib.rs"])
    return found[rule] if rule else [problem for problems in found.values() for problem in problems]


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

        def named(entry, file, reason):
            return [Problem("named", entry, file, reason)]

        def anchor(entry, file, reason):
            return [Problem("anchor", entry, file, reason)]

        def ask(entry, reason):
            return [Problem("asks", entry, "asks.json", reason)]

        untested = {key: value for key, value in GOOD_HOST.items() if key != "tests"}
        unbound = b'def case():\n    return True\n\nSELF_TEST_CASES = {"a case": gone}\n'
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
            ("a host test with no fn", host(tests=["tests::gone"]),
             named("ST1", "src/lib.rs", "no #[test] fn gone")),
            ("a survivor's host test with no fn", host(expect="survives", tests=["tests::gone"]),
             named("ST1", "src/lib.rs", "no #[test] fn gone")),
            ("a host test that is a plain fn", host(tests=["tests::helper"]),
             named("ST1", "src/lib.rs", "fn helper is not marked #[test]")),
            ("an e2e test has no static lookup", host(command="e2e"),
             named("ST1", "", "command 'e2e' has no static test lookup")),
            ("a self-test case with no key", tree([GOOD_HOST, dict(GOOD_SELFTEST, tests=["gone"])]),
             named("ST2", "falsify.py", "'gone' is not a SELF_TEST_CASES key")),
            ("a self-test key bound to no function", tree(runner=unbound),
             named("ST2", "falsify.py", "'a case' maps to gone, which falsify.py does not define")),
            ("falsify.py has no table", tree(runner=b"def case():\n    return True\n"),
             named("ST2", "falsify.py", "falsify.py has no SELF_TEST_CASES table")),
            ("falsify.py does not parse", tree(runner=b"def case(:\n    return True\n"),
             named("ST2", "falsify.py", "falsify.py does not parse")),
            ("falsify.py is missing", tree(runner=None),
             named("ST2", "falsify.py", "the file does not exist")
             + anchor("ST2", "falsify.py", "the file does not exist")),
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
