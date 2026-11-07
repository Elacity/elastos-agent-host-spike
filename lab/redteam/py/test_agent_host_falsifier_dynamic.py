"""Dynamic re-run of the agent-host grade-point falsifiers.

Task 006 checks that each caught entry names a test and that its anchors
apply. This probe checks the two things that naming cannot show: cargo's own
test list contains each host test exactly once, and the six entries the
re-score rests on (FC10, FE01, FS64, FS01, FS02, FS03) make every named test
fail. FS01, FS02 and FS03 disable three different guards and name one test.
A falsifier is caught only when every named test fails.

The crate is exported with ``git archive`` of the snapshot commit into a
fresh temporary directory. Cargo runs there, offline and locked, with one
target directory inside that temporary directory. The falsifier document is
read from that export through ``falsifier_data``, and checked against the
blob at the same commit. Edits apply only through ``falsifier_data.apply_edits``.
Nothing in this module imports or runs ``examples/agent-host/falsify.py``.

A clean run says only that these six host falsifiers are dynamically caught
as claimed, and that every named host test exists, on that commit. A skipped
entry is not that sentence. A name cargo does not list once, or a named test
that still passes, is a finding for the agent-host lane.

Run: python3 -I -m unittest discover -s lab/redteam/py
"""

from __future__ import annotations

import collections
import os
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath

import falsifier_data


REPO = Path(__file__).resolve().parents[3]
FINDINGS = REPO / "lab" / "redteam" / "findings"
FALSIFIERS = "examples/agent-host/falsifiers.json"
LIB = "examples/agent-host/src/lib.rs"
HOST_ROOT = PurePosixPath("examples/agent-host")
GRADE_IDS = ("FC10", "FE01", "FS64", "FS01", "FS02", "FS03")
CLEAN = (
    "these six host falsifiers are dynamically caught as claimed, "
    "and every named host test exists, on {commit}"
)
STALE = "{entry_id}: stale anchor, owned by task 006"

# The cargo tests. A renamed probe drops out of this tuple and out of discovery.
CARGO_TESTS = (
    "test_baseline_named_tests_pass",
    "test_every_named_host_test_is_listed_once",
    "test_grade_point_falsifiers_are_dynamically_caught",
    "test_toolchain_present_or_skip",
)
CHECK_TESTS = (
    "test_all_named_tests_must_fail",
    "test_apply_errors_are_not_stale",
    "test_build_stays_inside_the_export",
    "test_discovery_contains_the_probe",
    "test_duplicate_name_is_rejected_without_the_missing_check",
    "test_expected_failures_are_recorded_findings",
    "test_export_paths_follow_the_crate",
    "test_falsifier_skipped_apply_is_not_a_catch",
    "test_falsifier_zero_tests_are_not_a_pass",
    "test_harness_errors_are_not_catches",
    "test_host_count_comes_from_the_document",
    "test_missing_name_is_rejected_without_the_duplicate_check",
    "test_missing_toolchain_skips_every_probe_test",
    "test_new_failure_is_not_expected",
    "test_partial_skip_is_not_clean",
    "test_snapshot_bytes_are_pinned",
)

# Guard (b). Empty until a live probe reproduces a defect. A finding hides
# only the problems recorded here.
KNOWN_FINDINGS = {}

FIRST_TIMEOUT_S = 40 * 60
NEXT_TIMEOUT_S = 20 * 60
QUERY_TIMEOUT_S = 30

_INCLUDE = re.compile(r"""include_(?:str|bytes)!\(\s*"([^"]*)"\s*\)""")
_PATH = re.compile(r"""\bpath:\s*"([^"]*)"\s*""")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_RUNNING = re.compile(r"Running [^(]*\(([^)]+)\)")
_TEST_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;", re.MULTILINE)
_LOADER_ERROR = re.compile(
    r"dyld(?:\[[^\]]*\])?: |error while loading shared libraries|Library not loaded:")
_PROCESS_ERROR = re.compile(
    r"could not execute process|never executed"
    r"|process didn't exit successfully|\(signal: \d+, SIG[A-Z0-9]+\)")
_BUILD_ERROR = re.compile(r"could not compile|aborting due to \d+ previous error")
_HARNESS_ERROR = re.compile(
    r"\b(?:error|Error)(?:\[[^\]]*\])?:\s|Traceback \(most recent call last\)")
_TEST_FAILED_FOOTER = re.compile(
    r"^[ \t]*error: test failed, to rerun pass", re.MULTILINE)
_OWN_FAILURE_TEXT = re.compile(
    r"^---- .+ stdout ----\n(?:.*\n)*?^failures:$\n?", re.MULTILINE)

Problem = collections.namedtuple("Problem", "rule entry test reason")
STARTED = 0.0
STATE = None


class ExportError(Exception):
    """The pinned tree could not be exported. This is not a stale anchor."""


class CommandFailed(Exception):
    """Cargo did not finish. A timeout is not a caught test."""


class BuildFailed(Exception):
    """The unmutated export did not build. The probe stops, and does not skip."""


class StaleAnchor(Exception):
    """``apply_edits`` found an old string a count other than one."""

    def __init__(self, entry_id, name, index, count):
        self.entry_id = entry_id
        self.reason = STALE.format(entry_id=entry_id)
        super().__init__(
            f"{self.reason} ({name} edits[{index}] is found {count} times, not once)")


class Outcome:
    """What one cargo invocation of one named test did."""

    def __init__(self, kind, detail):
        self.kind = kind
        self.detail = detail

    def __repr__(self):
        return f"Outcome({self.kind}, {self.detail!r})"


class EntryRun:
    """One grade-point entry after its own export was mutated, or skipped."""

    def __init__(self, entry_id, names, outcomes=None, skip=None):
        self.entry_id = entry_id
        self.names = list(names)
        self.outcomes = dict(outcomes or {})
        self.skip = skip


class State:
    """The one cargo session. The report and the cargo tests share it."""

    def __init__(self):
        self.toolchain = None
        self.commit = None
        self.pin_text = ""
        self.host_count = 0
        self.name_count = 0
        self.list_problems = []
        self.baseline = {}
        self.catches = []
        self.grade = []
        self.export_root = None
        self.owner_lib = None
        self.owner_json = None
        self.finished = False


def toolchain_reason():
    """Why the host toolchain cannot run this probe, or None when it can.

    The same string is the skip reason for every cargo test.
    """
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    if cargo is None and rustc is None:
        return "cargo and rustc for the host target are missing"
    if cargo is None:
        return "cargo is missing"
    if rustc is None:
        return "rustc for the host target is missing"
    try:
        info = subprocess.run(
            [rustc, "-vV"], capture_output=True, text=True, timeout=QUERY_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"rustc for the host target is missing: {error}"
    if info.returncode != 0:
        detail = (info.stderr or info.stdout or "").strip()
        return f"rustc for the host target is missing: {detail}"
    host = ""
    for line in info.stdout.splitlines():
        if line.startswith("host: "):
            host = line.split(" ", 1)[1].strip()
    if not host:
        return "rustc for the host target is missing: rustc -vV named no host"
    try:
        sysroot = subprocess.run(
            [rustc, "--print", "sysroot"], capture_output=True, text=True,
            timeout=QUERY_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"rustc for the host target {host} is missing: {error}"
    if sysroot.returncode != 0:
        detail = (sysroot.stderr or sysroot.stdout or "").strip()
        return f"rustc for the host target {host} is missing: {detail}"
    lib = Path(sysroot.stdout.strip()) / "lib" / "rustlib" / host / "lib"
    if not lib.is_dir():
        return f"rustc for the host target {host} is missing: no {lib}"
    return None


def strip_ansi(text):
    return _ANSI.sub("", text or "")


def tail(text, limit):
    body = (text or "").strip()
    if len(body) <= limit:
        return body
    return body[-limit:]


def git_env():
    """The process environment without ``GIT_*``, so git uses the given repo."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def listed_counts(output):
    """How many times each full test name appears in cargo's ``--list`` output.

    A listed test is one line whose text is ``<name>: test``. A summary line
    and a ``Running`` line are not tests.
    """
    counts = collections.Counter()
    for line in strip_ansi(output).splitlines():
        suffix = ": test"
        if line.endswith(suffix) and line[:-len(suffix)]:
            counts[line[:-len(suffix)]] += 1
    return counts


def listed_zero_reason(name):
    return f"{name} is listed 0 times"


def listed_many_reason(name, count):
    return f"{name} is listed {count} times"


def list_problems(entries, counts):
    """One problem per host test cargo does not list exactly once.

    A missing name and a repeated name are different reasons. The count of
    host entries is the length of ``entries``, which is the pinned document.
    """
    owners = collections.OrderedDict()
    for entry in entries:
        for name in entry["tests"]:
            owners.setdefault(name, []).append(entry["id"])
    problems = []
    for name, ids in owners.items():
        count = counts.get(name, 0)
        if count == 0:
            problems.append(Problem(
                "list", ",".join(ids), name, listed_zero_reason(name)))
        elif count != 1:
            problems.append(Problem(
                "list", ",".join(ids), name, listed_many_reason(name, count)))
    return problems


def host_entries(document):
    """The entries whose command is ``host``, in document order."""
    if not isinstance(document, dict) or not isinstance(document.get("falsifiers"), list):
        raise AssertionError("falsifiers.json has no falsifiers list")
    hosts = []
    for entry in document["falsifiers"]:
        if isinstance(entry, dict) and entry.get("command") == "host":
            hosts.append(entry)
    ids = [entry.get("id") for entry in hosts]
    repeated = sorted({str(name) for name in ids if ids.count(name) > 1})
    if repeated:
        raise AssertionError("a host id is repeated: " + ", ".join(repeated))
    return hosts


def host_test_names(entries):
    """Each test named by a host entry, once, in first-seen order."""
    names = []
    seen = set()
    for entry in entries:
        tests = entry.get("tests")
        if not isinstance(tests, list):
            raise AssertionError(f"{entry.get('id')}: tests is not a list")
        for name in tests:
            if not isinstance(name, str) or not name:
                raise AssertionError(f"{entry.get('id')}: a test name is empty")
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def require_grade(hosts):
    """The six grade-point entries, in grade order, each with edits and tests."""
    by_id = {entry["id"]: entry for entry in hosts}
    missing = [name for name in GRADE_IDS if name not in by_id]
    if missing:
        raise AssertionError(
            "the pinned falsifiers.json has no host entry for " + ", ".join(missing))
    selected = []
    for name in GRADE_IDS:
        entry = by_id[name]
        tests = entry.get("tests")
        edits = entry.get("edits")
        if not isinstance(tests, list) or not tests:
            raise AssertionError(f"{name}: the entry names no test")
        if not isinstance(edits, list) or not edits:
            raise AssertionError(f"{name}: edits is empty")
        for index, edit in enumerate(edits):
            if not (isinstance(edit, dict) and all(
                    isinstance(edit.get(key), str) for key in ("file", "old", "new"))):
                raise AssertionError(f"{name}: edits[{index}] is not an edit")
        selected.append(entry)
    return selected


def _summaries(output):
    return [(status, int(passed), int(failed))
            for status, passed, failed in _TEST_RESULT.findall(output)]


def _harness_is_clean(output):
    """True when the output has no loader, process, or harness error.

    A failed test's own captured section, and cargo's ``error: test failed``
    footer, are the test's result. They are not a second error.
    """
    if _LOADER_ERROR.search(output) or _PROCESS_ERROR.search(output):
        return False
    if _BUILD_ERROR.search(output):
        return False
    body = _OWN_FAILURE_TEXT.sub("", output)
    body = _TEST_FAILED_FOOTER.sub("", body)
    return not _HARNESS_ERROR.search(body)


def command_error_kind(output):
    """``loader``, ``process``, or ``build`` when cargo never ran the test.

    Loader is decided before process, and process before build, so one
    output has one kind. A normal test summary is none of these.
    """
    if _LOADER_ERROR.search(output):
        return "loader"
    if _PROCESS_ERROR.search(output):
        return "process"
    if _BUILD_ERROR.search(output) and not _summaries(output):
        return "build"
    return None


def classify_test_run(code, output):
    """Classify one ``cargo test -- --exact NAME`` result.

    Exit 0 with zero tests is not a pass: a filter that matches nothing
    exits 0. A nonzero exit is a catch only when the harness ran exactly
    one test and that test failed, with no loader, process, or build error.
    """
    text = strip_ansi(output)
    kind = command_error_kind(text)
    if kind == "loader":
        return Outcome("loader", "the test process did not load: " + tail(text, 500))
    if kind == "process":
        return Outcome("process", "the test process did not run: " + tail(text, 500))
    if kind == "build":
        return Outcome("build", "the crate did not build: " + tail(text, 500))
    results = _summaries(text)
    passed = sum(item[1] for item in results)
    failed = sum(item[2] for item in results)
    ran = passed + failed
    if not results:
        if code != 0:
            return Outcome("harness", "cargo exited without a test result: " + tail(text, 500))
        return Outcome("other", "cargo exited 0 with no test result")
    if not _harness_is_clean(text):
        return Outcome("harness", "the harness reported an error: " + tail(text, 500))
    if code == 0 and passed == 1 and failed == 0 and ran == 1:
        return Outcome("passed", "1 passed")
    if code == 0 and ran == 0:
        return Outcome("zero", "cargo ran 0 tests and exited 0")
    if code != 0 and passed == 0 and failed == 1 and ran == 1:
        return Outcome("failed", "1 failed")
    if passed:
        return Outcome("passed", f"{passed} passed, {failed} failed")
    return Outcome("count", f"cargo ran {ran} tests, exit {code}")


def baseline_problem(entry_id, name, outcome):
    """None when this named test passed as exactly one run. Zero tests is not a pass."""
    if outcome is None:
        return f"{entry_id} {name} did not run"
    if outcome.kind != "passed":
        return f"{entry_id} {name} is not a pass: {outcome.kind}: {outcome.detail}"
    return None


def catch_problem(entry_id, names, outcomes):
    """None only when every named test failed.

    One passing test is enough to refuse the catch, including when another
    named test failed. A loader, process, or build error is not a catch.
    """
    missing = [name for name in names if name not in outcomes]
    if missing:
        return f"{entry_id} did not run: {', '.join(missing)}"
    passed = [name for name in names if outcomes[name].kind == "passed"]
    if passed:
        return f"{entry_id} still pass: {', '.join(passed)}"
    other = [name for name in names if outcomes[name].kind != "failed"]
    if other:
        detail = ", ".join(
            f"{name} ({outcomes[name].kind}: {outcomes[name].detail})" for name in other)
        return f"{entry_id} was not caught: {detail}"
    return None


def contained(host_root, name):
    """``host_root/name`` when ``name`` stays inside the exported crate."""
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or not name:
        raise ExportError(f"{name}: the edit path leaves the export")
    host = host_root.resolve()
    path = (host / name).resolve()
    if not path.is_relative_to(host):
        raise ExportError(f"{name}: the edit path leaves the export")
    return path


def apply_entry(export_root, entry):
    """Apply one entry with ``apply_edits`` and return the original bytes.

    A count other than one raises ``StaleAnchor`` before any write. A missing
    file or a path that leaves the export raises, and is not a stale anchor.
    """
    host = Path(export_root) / "examples" / "agent-host"
    grouped = collections.OrderedDict()
    for index, edit in enumerate(entry["edits"]):
        grouped.setdefault(edit["file"], []).append((index, edit))
    planned = []
    for name, edits in grouped.items():
        path = contained(host, name)
        if not path.is_file():
            raise OSError(f"{name}: the file does not exist")
        raw = path.read_bytes()
        updated, failed = falsifier_data.apply_edits(falsifier_data.text_of(raw), edits)
        if failed:
            at, count = failed
            raise StaleAnchor(entry["id"], name, at, count)
        planned.append((path, raw, updated))
    for path, _raw, updated in planned:
        path.write_text(updated, encoding="utf-8")
    return [(path, raw) for path, raw, _updated in planned]


def restore_files(originals):
    """Put the exported originals back so the next entry starts clean."""
    for path, raw in originals or []:
        path.write_bytes(raw)


def mutation_result(entry, apply, run_one):
    """Run ``entry`` on a clean export. Only a stale anchor becomes a skip."""
    try:
        originals = apply(entry)
    except StaleAnchor as error:
        return EntryRun(entry["id"], entry["tests"], skip=error.reason)
    try:
        outcomes = {name: run_one(name) for name in entry["tests"]}
        return EntryRun(entry["id"], entry["tests"], outcomes=outcomes)
    finally:
        restore_files(originals)


def _repo_path(base, raw):
    """``base/raw`` collapsed to a repo-relative path, or an export error."""
    if not raw:
        raise ExportError("the crate names an empty path")
    joined = PurePosixPath(posixpath.normpath(posixpath.join(base, raw)))
    if joined.is_absolute() or ".." in joined.parts:
        raise ExportError(f"the crate path leaves the repository: {raw}")
    return joined.as_posix()


def referenced_repo_paths(lib_text):
    """Repo-relative paths named by ``include_str!``, ``include_bytes!`` and ``path:``.

    An include is relative to ``src/lib.rs``. ``path:`` is the wit-bindgen
    path, which is relative to the crate directory.
    """
    found = []
    seen = set()

    def add(path):
        if path not in seen:
            seen.add(path)
            found.append(path)

    for match in _INCLUDE.finditer(lib_text):
        add(_repo_path("examples/agent-host/src", match.group(1)))
    for match in _PATH.finditer(lib_text):
        add(_repo_path("examples/agent-host", match.group(1)))
    return found


def export_paths(lib_text):
    """The archive paths. The crate directory covers paths inside it."""
    paths = ["examples/agent-host", "rust-toolchain.toml"]
    for path in referenced_repo_paths(lib_text):
        if path == "examples/agent-host" or path.startswith("examples/agent-host/"):
            continue
        if path not in paths:
            paths.append(path)
    return paths


def archive(repo, commit, dest, paths):
    """``git archive commit paths | tar -x`` into ``dest``. The bytes are the commit."""
    if not paths:
        raise ExportError("the export names no path")
    env = git_env()
    packed = subprocess.run(
        ["git", "-C", str(repo), "archive", commit, *paths],
        capture_output=True, env=env)
    if packed.returncode != 0:
        detail = packed.stderr.decode("utf-8", "replace").strip()
        raise ExportError(detail or f"git archive failed for {commit}")
    extracted = subprocess.run(
        ["tar", "-x", "-C", str(dest)], input=packed.stdout, capture_output=True)
    if extracted.returncode != 0:
        detail = extracted.stderr.decode("utf-8", "replace").strip()
        raise ExportError(detail or "tar failed")


def read_export_bytes(export_root, name="falsifiers.json"):
    """Bytes of an exported agent-host file, through the shared snapshot reader.

    The base is the snapshot's resolved root. A temporary directory on macOS
    is reached through a symbolic link, and the unresolved path is outside
    that root.
    """
    snapshot = falsifier_data.Snapshot(export_root)
    return snapshot.read_relative(snapshot.root / "examples" / "agent-host", name)


def pinned_document(export_root, commit, run):
    """The falsifier document in the export, refused when it is not the blob."""
    data = read_export_bytes(export_root)
    blob = falsifier_data.blob_at(run, commit, FALSIFIERS)
    if data != blob:
        raise AssertionError(
            "falsifiers.json bytes are the checkout, not the pinned export: "
            f"read {falsifier_data.digest(data)}, pinned {falsifier_data.digest(blob)}")
    return falsifier_data.load_json(data), data


def cargo_env(target_dir):
    env = git_env()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_TERM_COLOR"] = "never"
    env["RUST_TEST_THREADS"] = env.get("RUST_TEST_THREADS", "2")
    return env


def run_command(argv, cwd, env, timeout):
    """Run ``argv``. On a timeout the process group is killed and the probe fails."""
    proc = subprocess.Popen(
        argv, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors="replace", start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        raise CommandFailed(
            f"{shlex.join(argv)} timed out after {timeout}s\n"
            f"stderr:\n{tail(err, 2000)}") from None
    return proc.returncode, out or "", err or ""


def require_export_build(output, export_root, target_dir):
    """The test binary cargo ran is under the export's target directory."""
    root = Path(target_dir).resolve()
    export = Path(export_root).resolve()
    found = []
    for text in _RUNNING.findall(output):
        path = Path(text.strip())
        if not path.is_absolute():
            path = export / path
        found.append(path.resolve())
    if not found:
        raise BuildFailed(
            "cargo did not report a test binary\n" + tail(output, 1500))
    for path in found:
        if not path.is_relative_to(root):
            raise BuildFailed(f"cargo built {path}, outside the export target {root}")


def cargo_test(export_root, target_dir, args, timeout):
    manifest = Path(export_root) / "examples" / "agent-host" / "Cargo.toml"
    if not manifest.is_file():
        raise ExportError(f"the export has no {manifest.name}")
    argv = [
        "cargo", "test", "--offline", "--locked",
        "--manifest-path", str(manifest), "--", *args,
    ]
    code, out, err = run_command(argv, export_root, cargo_env(target_dir), timeout)
    output = strip_ansi(out + "\n" + err)
    if code == 0:
        require_export_build(output, export_root, target_dir)
    return code, output, err, argv


def run_exact(export_root, target_dir, name, timeout):
    """List the name with ``--exact``, then run that one test with ``--exact``.

    The list must be the single line ``<name>: test``. A compile failure is
    a build outcome, not a failed test.
    """
    code, listed, _err, _argv = cargo_test(
        export_root, target_dir, ["--exact", name, "--list"], timeout)
    if code != 0:
        return classify_test_run(code, listed)
    count = listed_counts(listed).get(name, 0)
    if count != 1:
        return Outcome("list", listed_many_reason(name, count) if count else listed_zero_reason(name))
    code, output, _err, _argv = cargo_test(
        export_root, target_dir, ["--exact", name], timeout)
    return classify_test_run(code, output)


def clean_claim(commit, *, listed_once, catches):
    """The clean sentence, and only when every grade-point entry was caught.

    A stale-anchor skip, a missing test name, or a short run has no sentence.
    """
    if not listed_once or not commit or len(catches) != len(GRADE_IDS):
        return None
    if [item.entry_id for item in catches] != list(GRADE_IDS):
        return None
    if any(item.skip for item in catches):
        return None
    for item in catches:
        if catch_problem(item.entry_id, item.names, item.outcomes):
            return None
    return CLEAN.format(commit=commit)


def format_report(state, elapsed):
    """The record printed after this module. A skip is written as SKIPPED."""
    lines = []
    if state is None or (not state.toolchain and not state.finished):
        lines.append("SKIPPED: the dynamic probe did not finish")
    elif state.toolchain:
        lines.append(f"SKIPPED: {state.toolchain}")
    else:
        claim = clean_claim(
            state.commit, listed_once=not state.list_problems, catches=state.catches)
        if claim:
            lines.append(claim)
        for item in state.catches:
            if item.skip:
                lines.append(f"SKIPPED: {item.skip}")
            else:
                problem = catch_problem(item.entry_id, item.names, item.outcomes)
                if problem:
                    lines.append(problem)
        if state.list_problems:
            lines.append("named host tests are not listed once: " + "; ".join(
                problem.reason for problem in state.list_problems))
        if state.pin_text:
            lines.append(state.pin_text)
        if state.host_count:
            lines.append(
                f"host entries: {state.host_count}; named host tests: {state.name_count}")
    lines.append(f"wall time: {elapsed:.1f}s")
    return "\n".join(lines)


def unexpected(problems, known=None):
    """Problems no recorded finding covers. A finding hides only its own."""
    known = KNOWN_FINDINGS if known is None else known
    recorded = {problem for found in known.values() for problem in found}
    return [problem for problem in problems if problem not in recorded]


def _note(text):
    print(text, file=sys.stderr, flush=True)


def build_session():
    """Export the snapshot commit, list every host test, run the six entries."""
    global STATE
    state = State()
    STATE = state
    state.owner_lib = (REPO / LIB).read_bytes()
    state.owner_json = (REPO / FALSIFIERS).read_bytes()
    snapshot = falsifier_data.Snapshot(REPO)
    commit = snapshot.commit
    if not commit:
        raise ExportError("HEAD cannot be resolved, so the export has no pinned commit")
    state.commit = commit
    lib_blob = falsifier_data.blob_at(snapshot.run, commit, LIB)
    json_blob = falsifier_data.blob_at(snapshot.run, commit, FALSIFIERS)
    if lib_blob is None or json_blob is None:
        raise ExportError("the pinned commit has no agent-host crate")
    state.pin_text = snapshot.describe(
        {FALSIFIERS: json_blob, LIB: lib_blob}, commit)
    dest = Path(tempfile.mkdtemp(prefix="agent-host-dynamic-")).resolve()
    state.export_root = dest
    try:
        _note(f"exporting {commit}")
        archive(REPO, commit, dest, export_paths(falsifier_data.text_of(lib_blob)))
        document, _data = pinned_document(dest, commit, snapshot.run)
        hosts = host_entries(document)
        grade = require_grade(hosts)
        state.grade = grade
        state.host_count = len(hosts)
        names = host_test_names(hosts)
        state.name_count = len(names)
        target = dest / "target"
        _note(f"listing {state.name_count} named host tests from {state.host_count} entries")
        code, output, err, argv = cargo_test(dest, target, ["--list"], FIRST_TIMEOUT_S)
        if code != 0:
            raise BuildFailed(
                f"the unmutated export did not build on {commit}\n"
                f"cargo exited {code}: {shlex.join(argv)}\n"
                f"stderr:\n{tail(strip_ansi(err), 4000)}\n"
                f"combined:\n{tail(output, 2000)}")
        counts = listed_counts(output)
        if not counts:
            raise BuildFailed(
                f"cargo listed no tests on {commit}\n"
                f"stderr:\n{tail(strip_ansi(err), 2000)}\n"
                f"combined:\n{tail(output, 2000)}")
        state.list_problems = list_problems(hosts, counts)
        for name in host_test_names(grade):
            _note(f"baseline {name}")
            state.baseline[name] = run_exact(dest, target, name, NEXT_TIMEOUT_S)
        for entry in grade:
            _note(f"mutating {entry['id']}")
            state.catches.append(run_mutation(dest, target, entry))
        state.finished = True
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        state.export_root = None
        raise
    return state


def run_mutation(export_root, target_dir, entry):
    """One grade-point entry from a clean export, then the originals restored."""
    def apply(one):
        return apply_entry(export_root, one)

    def run_one(name):
        return run_exact(export_root, target_dir, name, NEXT_TIMEOUT_S)

    return mutation_result(entry, apply, run_one)


def _install_finding_tests():
    """A recorded finding gets its own expected-failure test and no other."""
    for finding_id, problems in KNOWN_FINDINGS.items():
        def test(self, finding_id=finding_id, problems=problems):
            live = unexpected(problems, {})
            self.assertEqual(live, [], f"{finding_id} no longer matches the recorded problems")
            raise AssertionError(f"{finding_id} still reproduces")

        test.__name__ = "test_finding_" + finding_id.replace("-", "_")
        setattr(AgentHostDynamicProbe, test.__name__, unittest.expectedFailure(test))


class AgentHostDynamicChecks(unittest.TestCase):
    """The probe's own rules, on fixtures. They do not build the crate."""

    def test_host_count_comes_from_the_document(self):
        document = {"falsifiers": [
            {"id": "H1", "command": "host", "tests": ["tests::a"]},
            {"id": "E", "command": "e2e", "tests": ["tests::e"]},
            {"id": "H2", "command": "host", "tests": ["tests::b", "tests::a"]},
            {"id": "S", "command": "selftest", "tests": ["case"]},
        ]}
        hosts = host_entries(document)
        self.assertEqual([entry["id"] for entry in hosts], ["H1", "H2"])
        self.assertEqual(host_test_names(hosts), ["tests::a", "tests::b"])

    def test_missing_name_is_rejected_without_the_duplicate_check(self):
        name = "tests::not_in_the_binary"
        present = "tests::real"
        entries = [{"id": "FX", "tests": [name]}]
        counts = {present: 1}
        found = list_problems(entries, counts)
        self.assertEqual([problem.reason for problem in found], [listed_zero_reason(name)])
        # The duplicate check, alone, does not see a missing name.
        self.assertIsNone(_duplicate_only(name, counts.get(name, 0)))
        duplicated = "tests::twice"
        self.assertEqual(_duplicate_only(duplicated, 2), listed_many_reason(duplicated, 2))
        self.assertIsNone(_missing_only(duplicated, 2))

    def test_duplicate_name_is_rejected_without_the_missing_check(self):
        name = "tests::twice"
        entries = [{"id": "FX", "tests": [name]}]
        found = list_problems(entries, {name: 2})
        self.assertEqual([problem.reason for problem in found], [listed_many_reason(name, 2)])
        # The missing check, alone, does not see a repeated name.
        self.assertIsNone(_missing_only(name, 2))
        absent = "tests::absent"
        self.assertEqual(_missing_only(absent, 0), listed_zero_reason(absent))
        self.assertIsNone(_duplicate_only(absent, 0))
        self.assertNotEqual(listed_zero_reason(absent), listed_many_reason(name, 2))

    def test_all_named_tests_must_fail(self):
        names = ["tests::one", "tests::two"]
        outcomes = {
            "tests::one": Outcome("failed", "1 failed"),
            "tests::two": Outcome("passed", "1 passed"),
        }
        reason = catch_problem("FX", names, outcomes)
        self.assertIn("still pass: tests::two", reason)
        # One failure would satisfy an ANY rule. The catch rule refuses it.
        self.assertTrue(any(outcomes[name].kind == "failed" for name in names))
        self.assertIsNone(catch_problem("FX", names, {
            "tests::one": Outcome("failed", "1 failed"),
            "tests::two": Outcome("failed", "1 failed"),
        }))

    def test_harness_errors_are_not_catches(self):
        samples = (
            ("build", 101, "error[E0425]: cannot find value `missing`\n"
             "error: could not compile `agent-host` (lib test)\n"),
            ("loader", 134, "dyld[7]: Library not loaded: @rpath/libmissing.dylib\n"),
            ("process", 101, "error: could not execute process `/tmp/agent_host-test` "
             "(never executed)\nCaused by:\n  No such file or directory (os error 2)\n"),
        )
        kinds = []
        for kind, code, output in samples:
            got = classify_test_run(code, output)
            self.assertEqual(got.kind, kind, got.detail)
            self.assertNotEqual(got.kind, "failed")
            kinds.append(got.kind)
        self.assertEqual(len(set(kinds)), 3)
        # The planted classifier treats every nonzero exit as a caught failure.
        planted = [_nonzero_is_catch(code, output).kind for _kind, code, output in samples]
        self.assertEqual(planted, ["failed", "failed", "failed"])
        failed = classify_test_run(101, _FAILED_OUTPUT)
        passed = classify_test_run(0, _PASSED_OUTPUT)
        self.assertEqual(failed.kind, "failed")
        self.assertEqual(passed.kind, "passed")
        self.assertEqual(classify_test_run(0, _PASSED_WITH_DOCTEST).kind, "passed")

    def test_build_stays_inside_the_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp).resolve()
            target = export / "target"
            binary = target / "debug" / "deps" / "agent_host-abc"
            inside = f"     Running unittests src/lib.rs ({binary})\n"
            require_export_build(inside, export, target)
            leaked = export.parent / "owner" / "target" / "debug" / "deps" / "agent_host-abc"
            outside = f"     Running unittests src/lib.rs ({leaked})\n"
            with self.assertRaises(BuildFailed) as refused:
                require_export_build(outside, export, target)
            self.assertIn("outside the export target", str(refused.exception))
            with self.assertRaises(BuildFailed) as missing:
                require_export_build("Finished test profile\n", export, target)
            self.assertIn("did not report a test binary", str(missing.exception))

    def test_apply_errors_are_not_stale(self):
        entry = {"id": "FS64", "tests": ["tests::one"], "edits": []}

        def apply_io(_entry):
            raise OSError("reading the export failed")

        def apply_export(_entry):
            raise ExportError("git archive failed")

        with self.assertRaises(OSError):
            mutation_result(entry, apply_io, lambda _name: None)
        with self.assertRaises(ExportError):
            mutation_result(entry, apply_export, lambda _name: None)
        ran = []
        skipped = mutation_result(
            entry, lambda _entry: (_ for _ in ()).throw(StaleAnchor("FS64", "src/lib.rs", 0, 0)),
            lambda name: ran.append(name))
        self.assertEqual(skipped.skip, "FS64: stale anchor, owned by task 006")
        self.assertEqual(ran, [])
        # A handler that skips every exception would hide the export and the read.
        self.assertEqual(_skip_every_error(entry, apply_io).skip,
                         "FS64: stale anchor, owned by task 006")
        self.assertEqual(_skip_every_error(entry, apply_export).skip,
                         "FS64: stale anchor, owned by task 006")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _commit_file(repo, "examples/agent-host/Cargo.toml", b"[package]\nname = \"t\"\n")
            commit = _rev_parse(repo)
            dest = Path(tmp) / "export"
            dest.mkdir()
            with self.assertRaises(ExportError) as refused:
                archive(repo, commit, dest, ["examples/agent-host/missing.rs"])
            self.assertIn("missing.rs", str(refused.exception))

    def test_partial_skip_is_not_clean(self):
        catches = [_caught(entry_id) for entry_id in GRADE_IDS]
        commit = "a" * 40
        self.assertEqual(
            clean_claim(commit, listed_once=True, catches=catches),
            CLEAN.format(commit=commit))
        catches[-1] = EntryRun("FS03", ["tests::one"], skip="FS03: stale anchor, owned by task 006")
        self.assertIsNone(clean_claim(commit, listed_once=True, catches=catches))
        self.assertIsNone(clean_claim(commit, listed_once=False, catches=[_caught(i) for i in GRADE_IDS]))
        state = State()
        state.finished = True
        state.commit = commit
        state.pin_text = f"read at HEAD {commit}"
        state.host_count = 3
        state.name_count = 3
        state.catches = catches
        text = format_report(state, 1.0)
        self.assertIn("SKIPPED: FS03: stale anchor, owned by task 006", text)
        self.assertNotIn("dynamically caught as claimed", text)
        # The planted report would call five catches a clean run of all six.
        self.assertIn("dynamically caught as claimed", _claim_despite_skips(commit, catches))

    def test_snapshot_bytes_are_pinned(self):
        pinned = b'{"marker":"pinned"}\n'
        dirty = b'{"marker":"checkout"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve() / "repo"
            repo.mkdir()
            _commit_file(repo, FALSIFIERS, pinned)
            commit = _rev_parse(repo)
            target = repo / FALSIFIERS
            target.write_bytes(dirty)
            checkout = falsifier_data.Snapshot(repo).read_relative(
                repo / "examples" / "agent-host", "falsifiers.json")
            self.assertEqual(checkout, dirty)
            self.assertNotEqual(checkout, pinned)
            export = Path(tmp) / "export"
            export.mkdir()
            archive(repo, commit, export, ["examples/agent-host"])
            run = falsifier_data.Snapshot(repo).run
            document, data = pinned_document(export, commit, run)
            self.assertEqual(data, pinned)
            self.assertEqual(document["marker"], "pinned")
            with self.assertRaises(AssertionError) as refused:
                pinned_document(repo, commit, run)
            self.assertIn("checkout", str(refused.exception))

    def test_export_paths_follow_the_crate(self):
        text = (
            'include_str!("../asks.json");\n'
            'include_bytes!("../../../capsules/model-provider/src/local_llama.rs");\n'
            'path: "../../elastos/wit",\n'
            'include_str!("lib.rs");\n'
        )
        self.assertEqual(referenced_repo_paths(text), [
            "examples/agent-host/asks.json",
            "capsules/model-provider/src/local_llama.rs",
            "examples/agent-host/src/lib.rs",
            "elastos/wit",
        ])
        exported = export_paths(text)
        self.assertEqual(exported[0], "examples/agent-host")
        self.assertIn("rust-toolchain.toml", exported)
        self.assertIn("elastos/wit", exported)
        self.assertIn("capsules/model-provider/src/local_llama.rs", exported)
        self.assertNotIn("examples/agent-host/asks.json", exported)
        with self.assertRaises(ExportError):
            referenced_repo_paths('include_str!("../../../../outside");')

    def test_falsifier_zero_tests_are_not_a_pass(self):
        entry = {"id": "FX", "tests": ["tests::does_not_exist"]}
        zero = classify_test_run(0, _ZERO_OUTPUT)
        self.assertEqual(zero.kind, "zero")

        def counted_as_pass(code, output):
            """The planted bug: exit 0 with zero tests is a pass."""
            got = classify_test_run(code, output)
            if got.kind == "zero":
                return Outcome("passed", "counted a run of zero tests as a pass")
            return got

        self.assertEqual(counted_as_pass(0, _ZERO_OUTPUT).kind, "passed")
        self.assertIsNotNone(baseline_problem("FX", entry["tests"][0], zero))

        class Honest(AgentHostDynamicProbe):
            uses_cargo = False

            def grade_entries(self):
                return [entry]

            def baseline_outcome(self, _entry, _name):
                return zero

        with self.assertRaises(AssertionError) as refused:
            Honest().test_baseline_named_tests_pass()
        self.assertIn("0 tests", str(refused.exception))
        self.assertIn("tests::does_not_exist", str(refused.exception))

        class Restored(Honest):
            def baseline_outcome(self, _entry, _name):
                return classify_test_run(0, _PASSED_WITH_DOCTEST)

        restored = classify_test_run(0, _PASSED_WITH_DOCTEST)
        self.assertEqual(restored.kind, "passed")
        Restored().test_baseline_named_tests_pass()

    def test_falsifier_skipped_apply_is_not_a_catch(self):
        entry = {"id": "FC10", "tests": ["tests::a_model_summary_that_changes_a_required_fact_is_refused"]}
        passed = Outcome("passed", "1 passed")
        failed = Outcome("failed", "1 failed")
        skipped_apply = EntryRun(entry["id"], entry["tests"], outcomes={entry["tests"][0]: passed})
        self.assertIn("still pass", catch_problem(entry["id"], entry["tests"], skipped_apply.outcomes))

        class Planted(AgentHostDynamicProbe):
            """The bug: the edit-apply step is skipped, so the test still passes."""

            uses_cargo = False

            def grade_entries(self):
                return [entry]

            def mutated_outcomes(self, _entry):
                return skipped_apply

        with self.assertRaises(AssertionError) as refused:
            Planted().test_grade_point_falsifiers_are_dynamically_caught()
        self.assertIn("still pass", str(refused.exception))

        restored = mutation_result(
            entry, lambda _entry: [], lambda _name: failed)
        self.assertIsNone(catch_problem(entry["id"], entry["tests"], restored.outcomes))

        class Restored(Planted):
            def mutated_outcomes(self, _entry):
                return restored

        Restored().test_grade_point_falsifiers_are_dynamically_caught()

    def test_new_failure_is_not_expected(self):
        recorded = Problem("list", "FS01", "tests::gone", "tests::gone is listed 0 times")
        fresh = Problem("catch", "FC10", "tests::kept", "FC10 still pass: tests::kept")
        known = {"agent-host-002": (recorded,)}
        self.assertEqual(unexpected([recorded], known), [])
        self.assertEqual(unexpected([recorded, fresh], known), [fresh])

        class Broad(unittest.TestCase):
            @unittest.expectedFailure
            def test_probe(self):
                self.assertEqual(unexpected([recorded, fresh], known), [])

        broad = _run(Broad)
        self.assertEqual(broad.failures, [])
        self.assertEqual(len(broad.expectedFailures), 1)
        self.assertEqual(broad.unexpectedSuccesses, [])

        class Split(unittest.TestCase):
            def test_fresh_defect(self):
                self.assertEqual(unexpected([recorded, fresh], known), [])

        split = _run(Split)
        self.assertEqual(split.expectedFailures, [])
        self.assertEqual(len(split.failures), 1)
        self.assertIn("FC10", split.failures[0][1])
        live = [case for case in discovered()
                if method_name(case) == "test_every_named_host_test_is_listed_once"]
        self.assertEqual(len(live), 1)
        self.assertFalse(getattr(
            getattr(live[0], method_name(live[0])),
            "__unittest_expecting_failure__", False))

    def test_missing_toolchain_skips_every_probe_test(self):
        reason = "cargo is missing"

        class Absent(AgentHostDynamicProbe):
            uses_cargo = False
            skip_reason = reason

        result = _run(Absent)
        names = [method_name(test) for test, why in result.skipped]
        self.assertEqual(sorted(names), sorted(CARGO_TESTS))
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        for _test, why in result.skipped:
            self.assertEqual(why, reason)
        state = State()
        state.toolchain = reason
        text = format_report(state, 0.2)
        self.assertIn(f"SKIPPED: {reason}", text)
        self.assertNotIn("dynamically caught as claimed", text)

    def test_expected_failures_are_recorded_findings(self):
        cases = discovered()
        whole = sorted({type(case).__name__ for case in cases
                        if getattr(case, "__unittest_expecting_failure__", False)})
        self.assertEqual(whole, [], "a whole class is marked as an expected failure")
        marked = sorted(
            method_name(case) for case in cases
            if getattr(getattr(case, method_name(case)), "__unittest_expecting_failure__", False))
        self.assertEqual(marked, sorted(
            "test_finding_" + name.replace("-", "_") for name in KNOWN_FINDINGS))
        for finding in KNOWN_FINDINGS:
            self.assertTrue((FINDINGS / f"{finding}.md").is_file(), f"{finding} has no finding file")

    def test_discovery_contains_the_probe(self):
        found = sorted(method_name(case) for case in discovered())
        self.assertEqual(found, sorted(CARGO_TESTS + CHECK_TESTS + tuple(
            "test_finding_" + name.replace("-", "_") for name in KNOWN_FINDINGS)))


def _missing_only(name, count):
    if count == 0:
        return listed_zero_reason(name)
    return None


def _duplicate_only(name, count):
    if count > 1:
        return listed_many_reason(name, count)
    return None


def _nonzero_is_catch(code, output):
    """The planted classifier: any nonzero exit is a caught test."""
    if code != 0:
        return Outcome("failed", "nonzero exit")
    return classify_test_run(code, output)


def _skip_every_error(entry, apply):
    """The planted handler: every exception is reported as a stale anchor."""
    try:
        return mutation_result(entry, apply, lambda _name: None)
    except Exception:
        return EntryRun(entry["id"], entry["tests"], skip=STALE.format(entry_id=entry["id"]))


def _caught(entry_id):
    name = "tests::one"
    return EntryRun(entry_id, [name], outcomes={name: Outcome("failed", "1 failed")})


def _claim_despite_skips(commit, catches):
    """The planted report: skips are ignored and the rest are called a clean run."""
    ran = [item for item in catches if not item.skip]
    if ran and all(not catch_problem(item.entry_id, item.names, item.outcomes) for item in ran):
        return CLEAN.format(commit=commit)
    return None


def _run(case_cls):
    # A nested case stays out of this module, so running it does not call
    # setUpModule again and does not print the report early.
    case_cls.__module__ = "agent_host_dynamic_fixture"
    result = unittest.TestResult()
    unittest.TestLoader().loadTestsFromTestCase(case_cls).run(result)
    # Skipped tests are (test, reason). Keep the cases beside the result.
    result.skipped_cases = [test for test, _why in result.skipped]
    return result


def _git(repo, *args):
    env = git_env()
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, env=env)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise AssertionError(detail or f"git {' '.join(args)} failed")
    return proc


def _commit_file(repo, relative, content):
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    if not (repo / ".git").exists():
        _git(repo, "init")
    hooks = repo / "empty-hooks"
    hooks.mkdir(exist_ok=True)
    _git(repo, "-c", f"core.hooksPath={hooks}", "add", relative)
    _git(repo, "-c", "user.email=probe@example.invalid", "-c", "user.name=probe",
         "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={hooks}",
         "commit", "-m", "pin")


def _rev_parse(repo):
    return _git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()


def discovered():
    pending = [unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])]
    cases = []
    while pending:
        item = pending.pop()
        if isinstance(item, unittest.TestSuite):
            pending.extend(list(item))
        else:
            cases.append(item)
    return cases


def method_name(case):
    return case.id().rsplit(".", 1)[-1]


_PASSED_OUTPUT = """running 1 test
test tests::one ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
_PASSED_WITH_DOCTEST = _PASSED_OUTPUT + """
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
_FAILED_OUTPUT = """running 1 test
test tests::one ... FAILED

failures:

---- tests::one stdout ----
assertion failed

failures:
    tests::one

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--lib`
"""
_ZERO_OUTPUT = """running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""


class AgentHostDynamicProbe(unittest.TestCase):
    """Cargo's list and the six grade-point falsifiers, on the pinned export."""

    uses_cargo = True
    skip_reason = None

    @classmethod
    def setUpClass(cls):
        if not cls.uses_cargo:
            return
        reason = toolchain_reason()
        if reason:
            cls.skip_reason = reason
            state = State()
            state.toolchain = reason
            global STATE
            STATE = state
            return
        cls.skip_reason = None
        build_session()

    @classmethod
    def tearDownClass(cls):
        root = STATE.export_root if STATE is not None else None
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)
            STATE.export_root = None

    def setUp(self):
        if type(self).skip_reason:
            self.skipTest(type(self).skip_reason)
        if STATE is None or STATE.owner_lib is None:
            return
        if (REPO / LIB).read_bytes() != STATE.owner_lib:
            raise AssertionError("the probe wrote examples/agent-host/src/lib.rs")
        if (REPO / FALSIFIERS).read_bytes() != STATE.owner_json:
            raise AssertionError("the probe wrote examples/agent-host/falsifiers.json")

    def grade_entries(self):
        return STATE.grade

    def baseline_outcome(self, _entry, name):
        return STATE.baseline[name]

    def mutated_outcomes(self, entry):
        for item in STATE.catches:
            if item.entry_id == entry["id"]:
                return item
        raise AssertionError(f"{entry['id']} was not run")

    def test_toolchain_present_or_skip(self):
        reason = toolchain_reason()
        if reason:
            self.skipTest(reason)
        self.assertIsNone(reason)
        self.assertIsNone(STATE.toolchain)

    def test_every_named_host_test_is_listed_once(self):
        problems = STATE.list_problems
        fresh = unexpected(problems)
        if fresh:
            sample = ", ".join(problem.test for problem in fresh[:8])
            self.fail(
                f"{len(fresh)} named host tests are not listed once "
                f"(first: {sample})\n" + "\n".join(problem.reason for problem in fresh))
        self.assertEqual(fresh, [])

    def test_baseline_named_tests_pass(self):
        problems = []
        for entry in self.grade_entries():
            for name in entry["tests"]:
                problem = baseline_problem(entry["id"], name, self.baseline_outcome(entry, name))
                if problem:
                    problems.append(problem)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_grade_point_falsifiers_are_dynamically_caught(self):
        problems = []
        skips = []
        for entry in self.grade_entries():
            result = self.mutated_outcomes(entry)
            if result.skip:
                skips.append(result.skip)
                continue
            problem = catch_problem(result.entry_id, result.names, result.outcomes)
            if problem:
                problems.append(problem)
        self.assertEqual(problems, [], "\n".join(problems))
        if skips:
            self.skipTest("; ".join(skips))


_install_finding_tests()


def setUpModule():
    global STARTED
    STARTED = time.monotonic()


def tearDownModule():
    elapsed = time.monotonic() - STARTED
    root = STATE.export_root if STATE is not None else None
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)
        STATE.export_root = None
    print("\n" + format_report(STATE, elapsed), file=sys.stderr)
