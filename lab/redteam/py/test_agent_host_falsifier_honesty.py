"""Static honesty probe over the merged agent-host falsifiers and asks.

The agent-host re-score rests on examples/agent-host/falsifiers.json: each
entry claims that a planted bug is caught by its named tests. This probe reads
that file, asks.json, falsify.py and the Rust sources, read only: no cargo,
and the runner is parsed, never imported. It checks that every claim is
well-formed and anchored:

- falsifiers.json parses, each entry has its fields, and no id repeats;
- every `caught` entry names at least one test;
- every named test exists the way the run looks it up. falsify.py lists a
  `host` name with --exact, so it needs exactly one test at that full path:
  a #[test] fn item in code (never text in a comment or a string), in the
  inline mods of a crate root, not #[ignore], under no cfg but cfg(test). A
  `selftest` name needs a key of falsify.py's SELF_TEST_CASES, bound to a
  function defined once, by a plain top-level def before the table. The
  table is followed only in the one shape whose run-time value is its
  literal: one top-level dict literal, after it only read. Any other mention
  of it, a star import, or a builtin that runs code from a string, is
  refused with its line. Any other command has no static lookup, so it fails
  closed;
- every edit's old text is found exactly once, each file's edits applied in
  order, the way falsify.py's Mutation applies them;
- asks.json has its schema, and every ask a known kind and a resource.

Each probe also plants one defect in a copy of the merged data and requires
the same rule to report exactly that defect, so a clean result is not vacuous
(guard d).

Every file is read once into one snapshot, and the pin test binds that
snapshot to one commit, HEAD resolved once: the bytes read must be the bytes
committed there. After the tests the run prints its record: the problems each
rule found, HEAD, and for every file read its sha256, its last change and the
commit that brought that change onto HEAD's first-parent line, whose subject
names the PR (guard a). A failure prints the same record.

A reproduced defect becomes a finding, lab/redteam/findings/<id>.md, listed in
KNOWN_FINDINGS with an expected-failure test named test_finding_<id> (guard b).
A finding hides only the problems it records: any other problem still fails
the gate. The probe writes no file.

Not checked here: whether each named test really runs and fails under its
mutation, a name reached only through a computed key (globals()[name],
globals().update(mapping)), and a macro that writes or rewrites a Rust test.
Each needs a run, so each is the dynamic re-run's job.

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

# Rust, read the way the compiler reads it: comments, strings and character
# literals are found first, so no text inside them is taken for code. Block
# comments nest; a raw string ends only at a quote with as many # as it
# opened with; a ' that does not close a one-character literal is a lifetime.
RUST_LITERAL = re.compile(r"""
    (?P<comment>//|/\*)
  | (?P<raw>\b[bc]?r(?P<hashes>\#*)")
  | (?P<string>(?:\b[bc])?")
  | (?P<char>'(?:[^'\\\n]|\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|[^\n]))')
""", re.VERBOSE)
STRING_REST = re.compile(r'(?:[^"\\]|\\.)*"', re.DOTALL)
BLOCK_MARK = re.compile(r"/\*|\*/")
# Then, in the code left: a fn or inline mod item with its outer attributes,
# a macro call or definition, an inner attribute, and every bracket.
ATTR_BODY = r"[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*"
OUTER_ATTR = re.compile(r"\#\s*\[(" + ATTR_BODY + r")\]")
RUST_TOKEN = re.compile(r"""
    (?P<attrs>(?:\#\s*\[""" + ATTR_BODY + r"""\]\s*)*)
    (?: (?:\bpub\b\s*(?:\([^()]*\)\s*)?)?(?:\b(?:async|const|unsafe|extern|default)\s+)*
        \b(?:fn\s+(?P<fn>\w+)|mod\s+(?P<mod>\w+)\s*(?=\{))
      | (?P<macro>\bmacro_rules\s*!\s*\w+\s*(?=[(\[{])|\b\w+\s*!\s*(?=[(\[{]))
      | \#\s*!\s*\[(?P<inner>""" + ATTR_BODY + r""")\]
      | (?P<open>[(\[{])
      | (?P<close>[)\]}]) )
""", re.VERBOSE)
BRACKETS = {")": "(", "]": "[", "}": "{"}
ANY_FN = re.compile(r"\bfn\s+(\w+)")
UNBALANCED = ("the brackets do not balance once comments and strings are blanked, "
              "so this static lookup cannot place its tests")
RustFn = collections.namedtuple("RustFn", "leaf path test problem")

# falsify.py's table of self-test cases.
TABLE = "SELF_TEST_CASES"
# The reads of the table the lookup follows: none of them can change a dict.
TABLE_READS = ("items", "keys", "values", "get")
TABLE_CHANGES = ("clear", "pop", "popitem", "setdefault", "update")
# Builtins that run code from a string, which a static lookup cannot read:
# any mention of these, and compile as a bare name (re.compile is not it).
RUNS_CODE = ("exec", "eval")
BINDINGS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.alias, ast.Global,
            ast.Nonlocal, ast.arg, ast.ExceptHandler)
TABLE_REFUSALS = {
    "binds": f"binds {TABLE} other than by its one top-level dict literal",
    "changes": f"changes {TABLE} in place",
    "uses": f"uses {TABLE} in a way this static lookup does not follow",
    "string": f"spells {TABLE} as a string",
}

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
    "test_clean_report_pins_commit_and_merge",
    "test_probe_refusal_reasons",
    "test_rust_code_keeps_only_code",
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


def rust_code(text):
    """text with every comment, string and character literal blanked to
    spaces, each newline kept, so a scan sees only code, at the same offsets.
    LookupError(reason) when a comment or a string does not end."""
    parts, at = [], 0
    while True:
        found = RUST_LITERAL.search(text, at)
        if found is None:
            return "".join(parts) + text[at:]
        end = literal_end(text, found)
        parts += [text[at:found.start()], re.sub(r"[^\n]", " ", text[found.start():end])]
        at = end


def literal_end(text, found):
    """Where the comment or literal that `found` opens ends."""
    if found["comment"] == "//":
        end = text.find("\n", found.end())
        return len(text) if end < 0 else end
    if found["comment"]:
        depth = 1
        for mark in BLOCK_MARK.finditer(text, found.end()):
            depth += 1 if mark[0] == "/*" else -1
            if not depth:
                return mark.end()
        raise LookupError("a block comment does not end")
    if found["raw"]:
        close = '"' + found["hashes"]
        end = text.find(close, found.end())
        if end < 0:
            raise LookupError("a string does not end")
        return end + len(close)
    if found["string"]:
        rest = STRING_REST.match(text, found.end())
        if rest is None:
            raise LookupError("a string does not end")
        return rest.end()
    return found.end()  # a character literal is whole in the match


def attributes(text):
    """The outer attributes in text, each without its spaces: `test`,
    `cfg(test)`, `ignore=` (rust_code has already blanked any string)."""
    return [re.sub(r"\s+", "", body) for body in OUTER_ATTR.findall(text)]


def gated(attrs):
    """Whether attrs build their item only under some cfg other than
    cfg(test). cargo test sets test; no other cfg is evaluated here."""
    return any(attr.startswith("cfg_attr(") or (attr.startswith("cfg(") and attr != "cfg(test)")
               for attr in attrs)


def crate_root(file):
    """Whether a source file is a crate root, so that its inline mods alone
    give a test's full path: src/lib.rs, src/main.rs, src/bin/*.rs, tests/*.rs."""
    return file in ("src/lib.rs", "src/main.rs") or bool(
        re.fullmatch(r"(?:src/bin|tests)/[^/]+\.rs", file))


def rust_fns(code, file):
    """Every fn item in one file's code, as rust_code leaves it: its leaf, its
    full path (None when it is no module item of a crate root), whether it
    is marked #[test], and why cargo would not run it as a test, or None.
    LookupError(reason) when the brackets do not balance."""
    regions = [["file", None, False, ""]]  # kind, mod name, gated, bracket
    opening, fns = None, []
    for token in RUST_TOKEN.finditer(code):
        if token["fn"] is not None:
            fns.append(rust_fn(token["fn"], attributes(token["attrs"]), regions, file))
        elif token["mod"] is not None:
            opening = ["mod", token["mod"], gated(attributes(token["attrs"]))]
        elif token["macro"] is not None:
            opening = ["macro", None, False]
        elif token["inner"] is not None:
            regions[-1][2] = regions[-1][2] or gated([re.sub(r"\s+", "", token["inner"])])
        elif token["open"] is not None:
            regions.append((opening or ["block", None, False]) + [token["open"]])
            opening = None
        else:
            if len(regions) == 1 or regions[-1][3] != BRACKETS[token["close"]]:
                raise LookupError(UNBALANCED)
            regions.pop()
    if len(regions) > 1:
        raise LookupError(UNBALANCED)
    return fns


def rust_fn(leaf, attrs, regions, file):
    """One fn item, placed by the regions open around it."""
    test = "test" in attrs
    kinds = [region[0] for region in regions[1:]]
    if "macro" in kinds:
        return RustFn(leaf, None, test, f"#[test] fn {leaf} is only inside a macro, "
                      "which this static lookup does not expand")
    if "block" in kinds:
        return RustFn(leaf, None, test, f"#[test] fn {leaf} is inside a block, not a module "
                      "item, so the test harness does not collect it")
    if not crate_root(file):
        return RustFn(leaf, None, test, f"#[test] fn {leaf} is in {file}, which is not a "
                      "crate root this static lookup places")
    path = "::".join([region[1] for region in regions[1:]] + [leaf])
    if gated(attrs) or any(region[2] for region in regions):
        return RustFn(leaf, path, test, f"#[test] fn {path} is behind a cfg this static "
                      "lookup does not evaluate; it reads only cfg(test)")
    if any(attr == "ignore" or attr.startswith("ignore=") for attr in attrs):
        return RustFn(leaf, path, test, f"#[test] fn {path} is marked #[ignore], "
                      "so cargo test does not run it")
    return RustFn(leaf, path, test, None)


def host_lookup(read, rust_names):
    """A host name is found when exactly one test answers to it, as
    falsify.py's --exact list requires: a #[test] fn item at that full path
    that cargo would run (see rust_fn). Otherwise the reason says what stands
    there instead: a test elsewhere, a fn that is no test, or only text in a
    comment or a string."""
    tests, plain, written, broken = [], set(), set(), []
    for file in rust_names:
        try:
            text = text_of(read, file)
            fns = rust_fns(rust_code(text), file)
        except LookupError as error:
            broken.append(f"{file}: {error}")
            continue
        tests += [(file, fn) for fn in fns if fn.test]
        plain.update(fn.leaf for fn in fns if not fn.test)
        written.update(ANY_FN.findall(text))

    def reason(name):
        if broken:
            return broken[0]
        leaf = name.rsplit("::", 1)[-1]
        found = [(file, fn) for file, fn in tests if fn.leaf == leaf]
        live = [file for file, fn in found if fn.path == name and not fn.problem]
        if len(live) == 1:
            return None
        if live:
            return (f"{name} is a #[test] fn in {len(live)} files ({', '.join(live)}), "
                    "but falsify.py's --exact list must find exactly one")
        stuck = [fn.problem for _file, fn in found if fn.problem and fn.path in (name, None)]
        if stuck:
            return stuck[0]
        elsewhere = [fn.path for _file, fn in found if fn.path]
        if elsewhere:
            return f"no #[test] fn at {name}; #[test] fn {leaf} is at {', '.join(elsewhere)}"
        if leaf in plain:
            return f"fn {leaf} is not marked #[test]"
        if leaf in written:
            return f"fn {leaf} is only inside a comment or a string"
        return f"no #[test] fn {leaf}"
    return reason


def case_lookup(read):
    """A self-test name is found when it is a key of falsify.py's
    SELF_TEST_CASES table, bound to a function falsify.py defines once, by a
    plain top-level def before the table."""
    try:
        cases, binding = runner_cases(read)
    except LookupError as error:
        message = str(error)
        return lambda _name: message

    def reason(name):
        if name not in cases:
            return f"{name!r} is not a {TABLE} key"
        why = binding(cases[name])
        return f"{name!r} maps to {cases[name]}, {why}" if why else None
    return reason


def runner_cases(read):
    """({case name: function name}, function name -> why it is not bound the
    way the table needs, or None), from falsify.py, read with ast.

    The table is followed only in the one shape whose run-time value is its
    literal: one top-level SELF_TEST_CASES = {"name": function, ...}, after it
    only read (iterated, tested with in, indexed, or read through items, keys,
    values or get). Any other mention of the name is refused with its line,
    and so are a star import and a builtin that runs code from a string."""
    try:
        tree = ast.parse(text_of(read, "falsify.py"))
    except (SyntaxError, ValueError):
        raise LookupError("falsify.py does not parse") from None
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    index = name_index(tree, parents)
    table, refusals = None, []
    for node in index[TABLE]:
        use = table_use(node, parents, tree)
        if use == "literal" and table is None:
            table = parents[node]
        elif use != "read":
            refusals.append((line_of(node, parents),
                             TABLE_REFUSALS["binds" if use == "literal" else use]))
    refusals += [(line_of(node, parents), f"names {name}, which runs code this static lookup "
                  "cannot read") for name in RUNS_CODE + ("compile",) for node in index[name]
                 if name in RUNS_CODE or isinstance(node, ast.Name)]
    refusals += [(node.lineno, "imports *, which can bind any name this static lookup follows")
                 for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                 and any(alias.name == "*" for alias in node.names)]
    if refusals:
        line, reason = min(refusals)
        raise LookupError(f"falsify.py line {line} {reason}")
    if table is None:
        raise LookupError(f"falsify.py has no {TABLE} table")
    cases = {}
    for key, value in zip(table.value.keys, table.value.values):
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)
                and isinstance(value, ast.Name)):
            raise LookupError(f"falsify.py line {value.lineno}: a {TABLE} item is not "
                              "a string key bound to a name")
        cases[key.value] = value.id
    return cases, lambda function: case_binding(index[function], parents, tree, table)


def name_index(tree, parents):
    """{name: every node that names it, in source order}. A node names a name
    through an identifier field (a Name, a def, an import, a keyword argument,
    an attribute, a global), or as a string constant equal to it."""
    index = collections.defaultdict(list)
    for node in ast.walk(tree):
        values = [node.value] if isinstance(node, ast.Constant) else [
            item for _field, value in ast.iter_fields(node)
            for item in (value if isinstance(value, list) else [value])]
        names = {value.decode("latin-1") if isinstance(value, bytes) else value
                 for value in values if isinstance(value, (str, bytes))}
        for name in names:
            index[name].append(node)
    for nodes in index.values():
        nodes.sort(key=lambda node: (line_of(node, parents), getattr(node, "col_offset", 0)))
    return index


def line_of(node, parents):
    """The line a node is on; an import's alias takes its statement's line."""
    while not hasattr(node, "lineno"):
        node = parents[node]
    return node.lineno


def table_use(node, parents, tree):
    """How one node that names the table uses it: literal, read, binds,
    changes, string or uses. Only the literal and the reads are followed."""
    parent = parents.get(node)
    if isinstance(node, ast.Constant):
        return "string"
    if isinstance(node, BINDINGS) or (
            isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Load)):
        return "binds"
    if not isinstance(node, ast.Name):
        return "uses"
    if isinstance(node.ctx, ast.Store):
        if isinstance(parent, ast.AugAssign):
            return "changes"
        if (isinstance(parent, ast.Assign) and parent.targets == [node]
                and isinstance(parent.value, ast.Dict) and parent in tree.body):
            return "literal"
        return "binds"
    if isinstance(node.ctx, ast.Del):
        return "binds"
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return "read" if isinstance(parent.ctx, ast.Load) else "changes"
    if isinstance(parent, ast.Attribute) and parent.value is node:
        call = parents.get(parent)
        if parent.attr in TABLE_READS and isinstance(call, ast.Call) and call.func is parent:
            return "read"
        return "changes" if parent.attr in TABLE_CHANGES else "uses"
    if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)) and parent.iter is node:
        return "read"
    if isinstance(parent, ast.Compare) and any(
            comparator is node and isinstance(op, (ast.In, ast.NotIn))
            for op, comparator in zip(parent.ops, parent.comparators)):
        return "read"
    return "uses"


def case_binding(named, parents, tree, table):
    """Why a table function, named by these nodes, is not bound once, by a
    plain top-level def before the table, or None. A read of the name binds
    nothing; any other mention does, a string equal to it included."""
    bound = [node for node in named
             if not (isinstance(node, (ast.Name, ast.Attribute))
                     and isinstance(node.ctx, ast.Load))]
    if not bound:
        return "which falsify.py does not define"
    first = bound[0]
    if len(bound) > 1:
        verb = "spells as a string" if isinstance(bound[1], ast.Constant) else "binds again"
        return f"which falsify.py {verb} at line {line_of(bound[1], parents)}"
    if not (isinstance(first, ast.FunctionDef) and not first.decorator_list
            and first in tree.body):
        return (f"which falsify.py line {line_of(first, parents)} binds by something other "
                "than a plain top-level def")
    if first.lineno > table.lineno:
        return f"whose def at line {first.lineno} comes after the table at line {table.lineno}"
    return None


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


def committed_bytes(commit, paths):
    """{path: its bytes at commit, or None when the commit has no such file}."""
    return {path: git("cat-file", "blob", f"{commit}:{path}") for path in paths}


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


def commit_line(commit):
    """`hash subject` for one commit, or None."""
    out = git("log", "-1", "--format=%H %s", commit)
    return out.decode("utf-8", "replace").strip() if out else None


def last_change(path):
    """`hash subject` of the last commit that changed path at HEAD, or None."""
    out = git("log", "-1", "--format=%H %s", "HEAD", "--", path)
    return out.decode("utf-8", "replace").strip() if out else None


@functools.lru_cache(maxsize=None)
def first_parent_line():
    """HEAD's first-parent line, newest first, or None when git cannot tell."""
    out = git("rev-list", "--first-parent", "HEAD")
    return None if out is None else tuple(out.decode("ascii").split())


def entry_point(change):
    """The commit that brought `change` onto HEAD's first-parent line: the
    merge of its pull request, or `change` itself when it was committed on
    that line. None when git cannot tell."""
    line = first_parent_line()
    after = git("rev-list", "--ancestry-path", f"{change}..HEAD")
    if line is None or after is None:
        return None
    if change in line:
        return change
    descendants = set(after.decode("ascii").split())
    return next((commit for commit in reversed(line) if commit in descendants), None)


def pinned(files):
    """Where the bytes were read (guard a): HEAD, then every file read with its
    sha256, its last change, and the commit that brought that change onto
    HEAD's first-parent line; a merge's subject names its PR."""
    lines = [f"read at HEAD {head_commit() or '(unresolved)'}"]
    for path, data in sorted(files.items()):
        change = last_change(path)
        lines.append(f"  {path} {digest(data)}, last changed in {change or '(unknown)'}")
        entry = entry_point(change.split()[0]) if change else None
        if entry:
            lines.append(f"    first on HEAD's first-parent line in {commit_line(entry)}")
    return "\n".join(lines)


def unexpected(problems, known=None):
    """The problems no recorded finding covers. A finding hides only the
    problems it records, so a second defect beside it still fails the gate."""
    known = KNOWN_FINDINGS if known is None else known
    recorded = {problem for found in known.values() for problem in found}
    return [problem for problem in problems if problem not in recorded]


def described(problems, files):
    """The problems, as KNOWN_FINDINGS records them, then where they were read."""
    return "\n".join([repr(problem) for problem in problems] + [pinned(files)])


@functools.lru_cache(maxsize=None)
def merged_base():
    """The rules over the checked-out base, run once, so every test judges one
    snapshot: (snapshot, the well-formed entries, {rule: problems})."""
    snapshot = Snapshot()
    entries, problems = probe(snapshot.read, snapshot.rust_names())
    return snapshot, entries, problems


def report():
    """The run's record (guard a), printed after the tests: the problems each
    rule found on the merged base, how many files read differ from HEAD's
    bytes, and where each was read. unittest's own line below it is the
    verdict; this record is never one."""
    snapshot, _entries, problems = merged_base()
    commit = head_commit()
    differ = pin_problems(snapshot.files, commit, committed_bytes(commit, snapshot.files).get)
    counts = ", ".join(f"{rule} {len(found)}" for rule, found in problems.items())
    return (f"agent-host honesty probe: problems by rule: {counts}; recorded findings: "
            f"{', '.join(KNOWN_FINDINGS) or 'none'}; files read that differ from HEAD: "
            f"{len(differ)} of {len(snapshot.files)}\n{pinned(snapshot.files)}")


def tearDownModule():
    print("\n" + report(), file=sys.stderr)


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
        # The entries as merged: the first subtest renames a test in its copy.
        merged = [entry for entry in merged_base()[1]
                  if entry["expect"] in ("caught", "survives") and entry["tests"]]
        where = ", ".join(Snapshot.rust_names())

        def every(command, wanted, reason):
            """The problem reason gives for every merged test of command that wanted accepts."""
            return [Problem("named", entry["id"], "falsify.py" if command == "selftest" else where,
                            reason)
                    for entry in merged for name in entry["tests"]
                    if entry["command"] == command and wanted(name)]

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
        lib = text_of(merged_base()[0].read, "src/lib.rs")
        host = next((entry for entry in merged if entry["command"] == "host"), None)
        for label, change, reason in (
                # The reviewer's repro on the merged source: the test is gone
                # from the code, and its text is left in a block comment.
                ("a host test left only in a comment",
                 lambda leaf: lib.replace(f"fn {leaf}(", f"fn {leaf}_renamed_by_redteam(")
                 + f"\n/*\n#[test]\nfn {leaf}() {{}}\n*/\n",
                 lambda name, leaf: f"fn {leaf} is only inside a comment or a string"),
                ("a host test marked #[ignore]",
                 lambda leaf: lib.replace(f"fn {leaf}(", f"#[ignore]\n    fn {leaf}("),
                 lambda name, leaf: f"#[test] fn {name} is marked #[ignore], "
                                    "so cargo test does not run it")):
            with self.subTest(label):
                if host is None:
                    self.skipTest("the merged base has no host entry to plant in")
                name = host["tests"][0]
                leaf = name.rsplit("::", 1)[-1]
                self.assertEqual(lib.count(f"fn {leaf}("), 1, f"fn {leaf} is not defined once")
                self.assertEqual(
                    planted({"src/lib.rs": change(leaf).encode()})["named"],
                    every("host", lambda test: test.rsplit("::", 1)[-1] == leaf,
                          reason(name, leaf)))
        runner = text_of(merged_base()[0].read, "falsify.py")
        selftest = next((entry for entry in merged if entry["command"] == "selftest"), None)
        for label, statement, reason in (
                # The reviewer's two repros, each just above the main guard.
                ("the table rebound with another expression", lambda case: f"{TABLE} = dict()",
                 "binds SELF_TEST_CASES other than by its one top-level dict literal"),
                ("a case deleted from the table", lambda case: f"del {TABLE}[{case!r}]",
                 "changes SELF_TEST_CASES in place")):
            with self.subTest(label):
                if selftest is None:
                    self.skipTest("the merged base has no selftest entry to plant in")
                text, line = before_main(runner, statement(selftest["tests"][0]))
                self.assertEqual(planted({"falsify.py": text.encode()})["named"],
                                 every("selftest", lambda test: True,
                                       f"falsify.py line {line} {reason}"))

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
        committed = committed_bytes(commit, snapshot.files)
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

    def test_clean_report_pins_commit_and_merge(self):
        """The record printed after the tests names HEAD, and for every file
        read its sha256, its last change, and the commit that brought that
        change onto HEAD's first-parent line. git confirms each such commit is
        on that line and holds the change, and that its first parent does not,
        so it is the first one that does."""
        snapshot = merged_base()[0]
        record = report()
        commit = head_commit()
        self.assertIsNotNone(commit, "HEAD cannot be resolved")
        self.assertIn(f"read at HEAD {commit}", record)
        self.assertIn("files read that differ from HEAD: 0 of ", record)
        line = git("rev-list", "--first-parent", "HEAD").decode("ascii").split()
        for path, data in sorted(snapshot.files.items()):
            with self.subTest(path):
                change = last_change(path)
                self.assertIsNotNone(change, f"{path} has no commit at HEAD")
                self.assertIn(f"  {path} {digest(data)}, last changed in {change}\n", record + "\n")
                changed_in = change.split()[0]
                entry = entry_point(changed_in)
                self.assertIn(entry, line)
                self.assertIsNotNone(git("merge-base", "--is-ancestor", changed_in, entry))
                self.assertIsNone(git("merge-base", "--is-ancestor", changed_in, entry + "^"))
                self.assertIn(f"    first on HEAD's first-parent line in {commit_line(entry)}",
                              record)


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


def before_main(runner, statement):
    """falsify.py's text with one statement just above its main guard, and the
    line that statement is on."""
    at = runner.index('\nif __name__ == "__main__":') + 1
    return runner[:at] + statement + "\n" + runner[at:], runner[:at].count("\n") + 1


# One small tree every rule passes. Each control below breaks one thing in it.
GOOD_SOURCE = b"fn helper() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn a_test() {}\n}\n"
RUNNER_CASE = "def a_case():\n    return True\n\n\n"
RUNNER_TABLE = 'SELF_TEST_CASES = {\n    "a case": a_case,\n}\n\n\n'
# Every read of the table the lookup follows; none of them can change it.
RUNNER_READS = '''def run(only):
    if only not in SELF_TEST_CASES:
        return False
    names = [name for name in SELF_TEST_CASES]
    for name in SELF_TEST_CASES.keys():
        assert name in SELF_TEST_CASES and name in names
    for case in SELF_TEST_CASES.values():
        assert callable(case)
    for name, case in SELF_TEST_CASES.items():
        if name == only:
            return case() and SELF_TEST_CASES.get(name) is SELF_TEST_CASES[name]
    return False
'''
GOOD_RUNNER = (RUNNER_CASE + RUNNER_TABLE + RUNNER_READS).encode()
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
    """The problems every rule finds in a fixture tree, or one rule's. Its
    Rust files are the .rs files it holds under src/ and tests/."""
    rust_names = sorted(name for name in files
                        if name.endswith(".rs") and name.split("/", 1)[0] in SOURCE_DIRS)
    _entries, found = probe(overlay(nothing, files), rust_names)
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

        def rust(lib, extra=()):
            """The good tree with src/lib.rs replaced, and more Rust files."""
            files = tree(source=lib.encode())
            files.update((name, text.encode()) for name, text in extra)
            return files

        def in_tests(body):
            """src/lib.rs with body as the inside of its mod tests."""
            return "fn helper() {}\n\n#[cfg(test)]\nmod tests {\n" + body + "}\n"

        def appended(text):
            return tree(runner=GOOD_RUNNER + text.encode())

        def assembled(*parts):
            return tree(runner="".join(parts).encode())

        def parse(entry, reason):
            return [Problem("parse", entry, "falsifiers.json", reason)]

        def named(entry, file, reason):
            return [Problem("named", entry, file, reason)]

        def anchor(entry, file, reason):
            return [Problem("anchor", entry, file, reason)]

        def ask(entry, reason):
            return [Problem("asks", entry, "asks.json", reason)]

        def runner_refused(line, reason):
            return named("ST2", "falsify.py", f"falsify.py line {line} {reason}")

        def case_refused(reason):
            return named("ST2", "falsify.py", f"'a case' maps to a_case, {reason}")

        untested = {key: value for key, value in GOOD_HOST.items() if key != "tests"}
        unbound = b'def case():\n    return True\n\nSELF_TEST_CASES = {"a case": gone}\n'
        hidden = named("ST1", "src/lib.rs", "fn a_test is only inside a comment or a string")
        behind_cfg = named("ST1", "src/lib.rs", "#[test] fn tests::a_test is behind a cfg this "
                           "static lookup does not evaluate; it reads only cfg(test)")
        ignored = named("ST1", "src/lib.rs", "#[test] fn tests::a_test is marked #[ignore], "
                        "so cargo test does not run it")
        unbalanced = named("ST1", "src/lib.rs", "src/lib.rs: the brackets do not balance once "
                           "comments and strings are blanked, so this static lookup cannot place "
                           "its tests")
        a_test_mod = "mod tests {\n    #[test]\n    fn a_test() {}\n}\n"
        end = GOOD_RUNNER.count(b"\n") + 1  # the line of anything appended
        binds = "binds SELF_TEST_CASES other than by its one top-level dict literal"
        changes = "changes SELF_TEST_CASES in place"
        uses = "uses SELF_TEST_CASES in a way this static lookup does not follow"
        not_plain = "binds by something other than a plain top-level def"
        bad_item = ("falsify.py line {}: a SELF_TEST_CASES item is not a string key bound to "
                    "a name").format(RUNNER_CASE.count("\n") + 2)
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
            # The reviewer's repro, byte for byte: the test only in a comment.
            ("a host test only in a block comment",
             tree(source=b"fn helper() {}\n/*\n#[test]\nfn a_test() {}\n*/\n"), hidden),
            ("a host test only in line comments",
             rust(in_tests("    // #[test]\n    // fn a_test() {}\n")), hidden),
            ("a host test only in a nested block comment",
             rust(in_tests("    /* outer /* inner */\n    #[test]\n    fn a_test() {}\n    */\n")),
             hidden),
            ("a host test only in a string",
             rust(in_tests('    const S: &str = "#[test] fn a_test() {}";\n')), hidden),
            ("a host test only in a raw string that holds a quote",
             rust(in_tests('    const S: &str = r##"say "#[test] fn a_test() {}"##;\n')), hidden),
            ("a quote or a brace in a char literal is no string or bracket",
             rust("fn helper() {}\nfn quote<'a>(text: &'a str) -> char {\n"
                  "    if text.is_empty() { '\"' } else { '{' }\n}\n\n#[cfg(test)]\n" + a_test_mod),
             []),
            ("an ignored host test",
             rust(in_tests("    #[test]\n    #[ignore]\n    fn a_test() {}\n")), ignored),
            ("an ignored host test with a reason",
             rust(in_tests('    #[test]\n    #[ignore = "slow"]\n    fn a_test() {}\n')), ignored),
            ("a host test behind a cfg",
             rust(in_tests("    #[test]\n    #[cfg(any())]\n    fn a_test() {}\n")), behind_cfg),
            ("a host test behind a cfg_attr",
             rust(in_tests("    #[cfg_attr(test, ignore)]\n    #[test]\n    fn a_test() {}\n")),
             behind_cfg),
            ("a host test in a mod behind a cfg",
             rust("fn helper() {}\n\n#[cfg(any())]\n" + a_test_mod), behind_cfg),
            ("a host test in a file behind an inner cfg",
             rust("#![cfg(any())]\n" + GOOD_SOURCE.decode()), behind_cfg),
            ("a host test only inside a macro",
             rust(in_tests("    macro_rules! make {\n        () => {\n            #[test]\n"
                           "            fn a_test() {}\n        };\n    }\n")),
             named("ST1", "src/lib.rs", "#[test] fn a_test is only inside a macro, which this "
                   "static lookup does not expand")),
            ("a host test inside a fn body",
             rust(in_tests("    fn outer() {\n        #[test]\n        fn a_test() {}\n    }\n")),
             named("ST1", "src/lib.rs", "#[test] fn a_test is inside a block, not a module "
                   "item, so the test harness does not collect it")),
            ("a host test at another path",
             rust("fn helper() {}\n\nmod other {\n    #[test]\n    fn a_test() {}\n}\n"),
             named("ST1", "src/lib.rs", "no #[test] fn at tests::a_test; #[test] fn a_test is "
                   "at other::a_test")),
            ("a host test in a module file",
             rust("fn helper() {}\nmod extra;\n",
                  (("src/extra.rs", "#[cfg(test)]\n" + a_test_mod),)),
             named("ST1", "src/extra.rs, src/lib.rs", "#[test] fn a_test is in src/extra.rs, "
                   "which is not a crate root this static lookup places")),
            ("a host test in an integration test crate",
             rust("fn helper() {}\n", (("tests/it.rs", a_test_mod),)), []),
            ("a host test in two crate roots",
             rust(GOOD_SOURCE.decode(), (("tests/it.rs", a_test_mod),)),
             named("ST1", "src/lib.rs, tests/it.rs", "tests::a_test is a #[test] fn in 2 files "
                   "(src/lib.rs, tests/it.rs), but falsify.py's --exact list must find "
                   "exactly one")),
            ("a bracket left open", rust("fn helper() {}\nmod tests {\n"), unbalanced),
            ("a bracket closed twice", rust("fn helper() {}\n}\n"), unbalanced),
            ("a bracket closed by another kind", rust("fn helper() {}\nconst A: [u8; 1] = [0);\n"),
             unbalanced),
            ("a block comment that does not end", rust("fn helper() {}\n/* never closed\n"),
             named("ST1", "src/lib.rs", "src/lib.rs: a block comment does not end")),
            ("a string that does not end", rust('fn helper() {}\nconst S: &str = "never closed;\n'),
             named("ST1", "src/lib.rs", "src/lib.rs: a string does not end")),
            ("a Rust file that is not UTF-8", tree(source=b"fn helper() {}\xff"),
             named("ST1", "src/lib.rs", "src/lib.rs: the file is not UTF-8")
             + anchor("ST1", "src/lib.rs", "the file is not UTF-8")),
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
            # The reviewer's two repros: a later binding and a deleted key.
            ("the table rebound with another expression", appended("SELF_TEST_CASES = dict()\n"),
             runner_refused(end, binds)),
            ("a case deleted from the table", appended('del SELF_TEST_CASES["a case"]\n'),
             runner_refused(end, changes)),
            ("a case popped from the table", appended('SELF_TEST_CASES.pop("a case")\n'),
             runner_refused(end, changes)),
            ("a case replaced in the table", appended('SELF_TEST_CASES["a case"] = run\n'),
             runner_refused(end, changes)),
            ("the table merged in place", appended("SELF_TEST_CASES |= {}\n"),
             runner_refused(end, changes)),
            ("a second table literal", appended('SELF_TEST_CASES = {"a case": a_case}\n'),
             runner_refused(end, binds)),
            ("the table bound inside a block", appended("if True:\n    SELF_TEST_CASES = {}\n"),
             runner_refused(end + 1, binds)),
            ("the table deleted", appended("del SELF_TEST_CASES\n"), runner_refused(end, binds)),
            ("the table declared global", appended("def reset():\n    global SELF_TEST_CASES\n"),
             runner_refused(end + 1, binds)),
            ("the table imported", appended("from json import loads as SELF_TEST_CASES\n"),
             runner_refused(end, binds)),
            ("the table aliased", appended("cases = SELF_TEST_CASES\n"), runner_refused(end, uses)),
            ("the table passed on", appended("print(SELF_TEST_CASES)\n"),
             runner_refused(end, uses)),
            ("the table patched by keyword", appended("globals().update(SELF_TEST_CASES={})\n"),
             runner_refused(end, uses)),
            ("the table named in a string", appended('globals()["SELF_TEST_CASES"] = {}\n'),
             runner_refused(end, "spells SELF_TEST_CASES as a string")),
            ("code run from a string", appended('exec("pass")\n'),
             runner_refused(end, "names exec, which runs code this static lookup cannot read")),
            ("code run through builtins", appended('import builtins\nbuiltins.eval("1")\n'),
             runner_refused(end + 1, "names eval, which runs code this static lookup cannot read")),
            ("code compiled by the builtin", appended('compile("1", "x", "single")\n'),
             runner_refused(end, "names compile, which runs code this static lookup cannot read")),
            ("re.compile is not that builtin",
             appended('import re\nPATTERN = re.compile("x")\n'), []),
            ("a star import", appended("from os import *\n"),
             runner_refused(end, "imports *, which can bind any name this static lookup follows")),
            ("a table item that is not a name",
             assembled(RUNNER_CASE, 'SELF_TEST_CASES = {\n    "a case": lambda: True,\n}\n',
                       RUNNER_READS), named("ST2", "falsify.py", bad_item)),
            ("an unpacked table item",
             assembled(RUNNER_CASE, 'SELF_TEST_CASES = {\n    **{"a case": a_case},\n}\n',
                       RUNNER_READS), named("ST2", "falsify.py", bad_item)),
            ("a case function bound again", appended("a_case = run\n"),
             case_refused(f"which falsify.py binds again at line {end}")),
            ("a case function named in a string", appended('globals()["a_case"] = run\n'),
             case_refused(f"which falsify.py spells as a string at line {end}")),
            ("a case function defined after the table",
             assembled(RUNNER_TABLE, RUNNER_CASE, RUNNER_READS),
             case_refused("whose def at line {} comes after the table at line 1".format(
                 RUNNER_TABLE.count("\n") + 1))),
            ("a decorated case function",
             assembled("@staticmethod\n", RUNNER_CASE, RUNNER_TABLE, RUNNER_READS),
             case_refused(f"which falsify.py line 2 {not_plain}")),
            ("an async case function", assembled("async ", RUNNER_CASE, RUNNER_TABLE, RUNNER_READS),
             case_refused(f"which falsify.py line 1 {not_plain}")),
            ("a case function inside a block",
             assembled("if True:\n    def a_case():\n        return True\n\n\n", RUNNER_TABLE,
                       RUNNER_READS), case_refused(f"which falsify.py line 2 {not_plain}")),
            ("a case function bound by assignment",
             assembled("def helper():\n    return True\n\n\na_case = helper\n", RUNNER_TABLE,
                       RUNNER_READS), case_refused(f"which falsify.py line 5 {not_plain}")),
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

    def test_rust_code_keeps_only_code(self):
        """rust_code blanks each comment, string and character literal to
        spaces and changes nothing else: every offset and newline is kept,
        and lifetimes, labels and raw identifiers stay code. A comment or a
        string that does not end is refused with its reason."""
        for text, code in (
            ('a // b "c\nd', "a d"),
            ("a /* b /* c */ d */ e", "a e"),
            ('a "b \\" // c" d', "a d"),
            ('a "b\nc" d', "a d"),
            ('a r##"b "# c"## d', "a d"),
            ('a b"x" br"y" c"z" cr#"w"# d', "a d"),
            ("a '\"' b \"c\" d", "a b d"),
            ("a '{' b '\\'' c '\\\\' d '\\u{7b}' e '\\u{1_F600}' f", "a b c d e f"),
            ("fn f<'a>(x: &'a str) -> &'a str { x }", "fn f<'a>(x: &'a str) -> &'a str { x }"),
            ("'outer: loop { break 'outer; }", "'outer: loop { break 'outer; }"),
            ("let r#type = b'x';", "let r#type = b ;"),
        ):
            with self.subTest(text=text):
                blanked = rust_code(text)
                self.assertEqual(len(blanked), len(text))
                self.assertTrue(all(kept == was or (kept == " " and was != "\n")
                                    for kept, was in zip(blanked, text)), blanked)
                self.assertEqual(" ".join(blanked.split()), code)
        for text, reason in (
            ("a /* b", "a block comment does not end"),
            ("a /* b /* c */", "a block comment does not end"),
            ('a "b', "a string does not end"),
            ('a r#"b"', "a string does not end"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(LookupError) as refused:
                    rust_code(text)
                self.assertEqual(str(refused.exception), reason)

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
