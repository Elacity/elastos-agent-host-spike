#!/usr/bin/env python3
"""Break each agent-host check, see its named tests fail, restore it.

Usage (from anywhere):
  python3 -I examples/agent-host/falsify.py              # every falsifier
  python3 -I examples/agent-host/falsify.py FS           # one prefix
  python3 -I examples/agent-host/falsify.py FS01 FS03    # some ids
  python3 -I examples/agent-host/falsify.py --list       # ids, commands, expectations
  python3 -I examples/agent-host/falsify.py --self-test  # the runner checks itself
  python3 -I examples/agent-host/falsify.py --self-test --with-repo  # and one real falsifier
  python3 -I examples/agent-host/falsify.py --self-test-case NAME  # one named case

The falsifiers are data, in falsifiers.json next to this file. Each one
replaces exact text (found exactly once) in a file and requires every named
test to FAIL. The verdict comes from exit codes: the mutated code is built
first (a build that fails is its own result); then each named test is listed
with `--exact` (exactly one test must match) and run alone with `--exact`.
A non-zero exit alone is not a catch: the harness evidence must be error-free
(a harness or loader error marker at any position on a line, on either
stream, after terminal formatting is stripped, is NOT RUN and never a catch)
and a summary must say that test ran and failed. Every mode uses this one
proof, `survives` included: one named test that still passes means the
falsifier SURVIVED, and a survivor counts
only when at least one of its named tests ran and none reported failed. A
survivor whose named test did not run is NOT RUN.

The original file's bytes are kept as a hard link while the mutated copy is
in place, and the restore is a rename, so it needs no free space. The restore
runs on error, Ctrl-C and SIGTERM, and signals stay blocked until every
original is back, so an interrupt during the edit leaves the source unchanged
before the error propagates. A backup left by a killed run is put back before
anything else. The runner stops when the disk has less than 2 GiB free or a
command reports a full disk.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error, 3 when it stopped for a full disk.
"""
from collections import namedtuple
import contextlib
import io
import json
import inspect
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DATA = HERE / "falsifiers.json"
# Each provider crate is its own workspace with its own lockfile.
PROVIDER_MANIFEST = REPO / "capsules" / "model-provider" / "Cargo.toml"
# One table for every provider crate. Each entry is the crate's workspace
# manifest, so a provider command exists only with the manifest its spec
# builds and tests: a second branch per crate would be a second copy of the
# same rule (P10).
PROVIDER_CRATES = {
    "provider": PROVIDER_MANIFEST,
    "did": REPO / "capsules" / "did-provider" / "Cargo.toml",
    "wallet": REPO / "capsules" / "wallet-provider" / "Cargo.toml",
}
BACKUP_SUFFIX = ".falsify-original"
# Capture ancestor ownership once. The environment then publishes that set
# plus this process's live backups to children; it is not a local ownership
# source after publication. Each live mutation restores its own backup.
OWNED_BACKUPS_ENV = "FALSIFY_OWNED_BACKUPS"
INHERITED_BACKUPS = frozenset(
    pathlib.Path(name).resolve()
    for name in os.environ.get(OWNED_BACKUPS_ENV, "").split(os.pathsep) if name)
OWNED_BACKUPS = set()
MIN_FREE_BYTES = int(os.environ.get("FALSIFY_MIN_FREE_BYTES", 2 * 1024**3))
COMMANDS = ("host", *PROVIDER_CRATES, "e2e", "selftest")
# Self-test scratch stays in this lane's report directory, so a run writes
# only below a path the lane owns.
SELF_TEST_DIR = HERE / "handoff" / "reports" / ".falsify-selftest"
DISK_FULL = ("No space left on device", "ENOSPC", "Disk quota exceeded")
# The test harness prints this line after every run of the binary. A panic in
# a test body can print anything, including a fake FAILED line, before it.
TEST_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;", re.MULTILINE)
# Terminal formatting is not evidence: a colored label reads as its plain
# text, so a marker cannot hide behind a color escape.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# A harness error marker is the `error:` label with a message after it, and it
# counts anywhere on a line: a prefixed message such as
# `test-bin: error: ...` carries the same marker. Identifiers such as
# `BusError::Denied` do not match: no word boundary precedes `error` inside a
# longer word, and a space must follow the colon.
HARNESS_ERROR = re.compile(
    r"\b(?:error|Error)(?:\[[^\]]*\])?:\s|Traceback \(most recent call last\)")
# A loader reports these with a prefix, for example `/test-bin: error while
# loading shared libraries: ...` or `dyld[1234]: Library not loaded: ...`, so
# the line start does not carry the marker and the phrase counts anywhere.
LOADER_ERROR = re.compile(
    r"dyld(?:\[[^\]]*\])?: |error while loading shared libraries|Library not loaded:")
# Cargo says the test process never started, or died abnormally: that report
# is not a failed test, and it stays evidence when the ordinary failure footer
# is removed.
CARGO_FAILURE = re.compile(
    r"could not execute process|never executed"
    r"|process didn't exit successfully|\(signal: \d+, SIG[A-Z0-9]+\)")
# Cargo prints this footer after an ordinary failing test: the harness ran the
# test and the test failed, so the footer itself is not a harness error. Only
# the footer text is removed; anything after it on the same line is checked.
TEST_FAILED = re.compile(r"^[ \t]*error: test failed, to rerun pass", re.MULTILINE)
# A named self-test case runs in its own process. A non-zero exit alone does
# not say the case ran: a loading error also exits non-zero. The child prints
# one marker line only after the case returns, and the runner requires both.
CASE_PASSED = 0
CASE_FAILED = 1
CASE_USAGE = 2
CASE_ERROR = 3


def case_marker(name, word):
    return f"self-test case {name!r}: {word}"


ParsedArgv = namedtuple(
    "ParsedArgv", "path mode name filters keep_backups with_repo")


def refuse(reason):
    """Stop before any work: an unsupported option is never a selection."""
    print(f"usage: {reason}", file=sys.stderr)
    raise SystemExit(CASE_USAGE)


def parse_argv(argv):
    """The data file and the mode, from the arguments alone.

    This is the front door: it reads no file, runs no test and changes
    nothing. An option it does not know stops the run here with status 2 and
    its own reason, so a typo can never select work.
    """
    path = DATA
    from_selected = False
    filters = []
    keep_backups = False
    with_repo = False
    want_list = False
    want_cases = False
    want_self_test = False
    case_name = None
    at = 0
    while at < len(argv):
        token = argv[at]
        if token == "--from":
            if at + 1 >= len(argv) or argv[at + 1].startswith("-"):
                refuse("--from needs a path, not an option")
            at += 1
            path = pathlib.Path(argv[at])
            from_selected = True
        elif token.startswith("--from="):
            refuse("--from=PATH is not supported; use --from PATH")
        elif token == "--list":
            want_list = True
        elif token == "--keep-backups":
            keep_backups = True
        elif token == "--with-repo":
            with_repo = True
        elif token == "--self-test-cases":
            want_cases = True
        elif token == "--self-test":
            want_self_test = True
        elif token == "--self-test-case":
            if at + 1 >= len(argv) or argv[at + 1].startswith("-"):
                refuse("--self-test-case needs a case name, not an option")
            at += 1
            case_name = argv[at]
        elif token.startswith("-"):
            refuse(f"unknown option {token}")
        else:
            filters.append(token)
        at += 1
    if want_list:
        mode = "list"
    elif want_cases:
        mode = "self-test-cases"
    elif case_name is not None:
        mode = "self-test-case"
    elif want_self_test:
        mode = "self-test"
    else:
        mode = "run"
    if mode == "run" and not filters and not from_selected and (keep_backups or with_repo):
        refuse("--keep-backups and --with-repo need a mode, --from PATH, or an id prefix")
    return ParsedArgv(path, mode, case_name, filters, keep_backups, with_repo)


class DiskFull(Exception):
    pass


def load_refuse(path, reason):
    """Stop on a data file that cannot load: status 2 and one clear reason. A
    refusal never selects work and never counts as zero falsifiers run."""
    print(f"{path}: {reason}", file=sys.stderr)
    raise SystemExit(CASE_USAGE)


def load(path=DATA):
    """The entries, or a refusal with status 2 when the data file is missing,
    is not JSON, or has the wrong document shape."""
    try:
        if not path.is_file():
            load_refuse(path, "the data file does not exist")
        text = path.read_text(encoding="utf-8")
    except OSError:
        load_refuse(path, "the data file cannot be read")
    except UnicodeDecodeError:
        load_refuse(path, "the data file is not JSON")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        load_refuse(path, "the data file is not JSON")
    if not isinstance(doc, dict):
        load_refuse(path, "the document is not an object")
    if "falsifiers" not in doc:
        load_refuse(path, "the document has no falsifiers list")
    entries = doc["falsifiers"]
    if not isinstance(entries, list):
        load_refuse(path, "falsifiers is not a list")
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        load_refuse(path, "an id is used twice")
    for entry in entries:
        if entry["command"] not in COMMANDS:
            load_refuse(path, f"{entry['id']}: unknown command {entry['command']!r}")
        if entry["expect"] not in ("caught", "compile_error", "survives"):
            load_refuse(path, f"{entry['id']}: unknown expect {entry['expect']!r}")
        if entry["expect"] in ("caught", "survives") and not entry["tests"]:
            load_refuse(path, f"{entry['id']}: no named tests")
    return entries


# The provider files this runner's falsifiers mutate, relative to REPO. Each
# exact target is restored on startup; every other provider file stays with
# its owning runner. The model provider's confinement profile and its
# confinement test harness are targets because cc-model-confine's list mutates
# them through the `provider` command (F-cc1e edits tests/confine/main.rs).
# The did and wallet files are the confine lane's edit files, which its `did`
# and `wallet` lists name from the repository root; every DID12 and later
# entry edits tests/confine.rs. A killed run therefore restores a harness
# instead of leaving a weakened confinement test behind.
PROVIDER_TARGETS = (
    "capsules/model-provider/src/local_memory.rs",
    "capsules/model-provider/src/journal.rs",
    "capsules/model-provider/src/contract.rs",
    "capsules/model-provider/confine.sb",
    "capsules/model-provider/tests/confine/main.rs",
    "capsules/did-provider/src/main.rs",
    "capsules/did-provider/confine.sb",
    "capsules/did-provider/tests/confine.rs",
    "capsules/wallet-provider/src/main.rs",
    "capsules/wallet-provider/confine.sb",
    "capsules/wallet-provider/tests/confine.rs",
    "capsules/model-provider/src/local_llama.rs",
    "capsules/model-provider/src/adapters.rs",
)


def owned_backups():
    """The backup paths held by this process or handed down by a caller. The
    environment carries them into nested runs, so each one knows which
    backups belong to a live mutation instead of a killed run."""
    return OWNED_BACKUPS | INHERITED_BACKUPS


def publish_owned_backups():
    names = sorted(str(path) for path in owned_backups())
    if names:
        os.environ[OWNED_BACKUPS_ENV] = os.pathsep.join(names)
    else:
        os.environ.pop(OWNED_BACKUPS_ENV, None)


def own_backup(backup):
    OWNED_BACKUPS.add(backup.resolve())
    publish_owned_backups()


def disown_backup(backup):
    OWNED_BACKUPS.discard(backup.resolve())
    publish_owned_backups()


def recover_backups():
    """Restore this runner's originals: agent-host files and this lane's exact
    provider targets. Other provider files stay with their owning runners.
    Recovery is independent of the data file selected for the next run, and it
    never touches a backup a caller still owns."""
    owned = owned_backups()
    backups = set(HERE.rglob("*" + BACKUP_SUFFIX))
    for name in PROVIDER_TARGETS:
        target = REPO / name
        backups.update(target.parent.glob(target.name + BACKUP_SUFFIX))
    for backup in sorted(backups):
        if backup.resolve() in owned:
            continue
        target = backup.with_name(backup.name[: -len(BACKUP_SUFFIX)])
        os.replace(backup, target)
        os.utime(target)
        print(f"recovered {target.relative_to(REPO)} from a killed run")


def check_disk():
    free = shutil.disk_usage(REPO).free
    if free < MIN_FREE_BYTES:
        raise DiskFull(f"only {free // 1024**2} MiB free")


def block_interruptions():
    """Ignore Ctrl-C and SIGTERM while the originals are put back. Returns
    (signal number, previous handler) pairs for restore_interruptions."""
    saved = []
    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            saved.append((number, signal.getsignal(number)))
            signal.signal(number, signal.SIG_IGN)
    return saved


def restore_interruptions(saved):
    for number, handler in saved:
        signal.signal(number, handler)


class BackupCollision(Exception):
    """A backup this run did not create is already there. The link decides
    ownership: this run stops before it touches the caller's bytes."""


class Mutation:
    """Apply one falsifier's edits; undo them on exit, whatever happened."""

    def __init__(self, entry, base=HERE):
        self.entry = entry
        self.base = base
        self.applied = []  # (path, backup, original bytes)

    def __enter__(self):
        by_file = {}
        for edit in self.entry["edits"]:
            by_file.setdefault(edit["file"], []).append(edit)
        texts = {}
        for name, edits in by_file.items():
            path = self.base / name
            # One path rule: an edit names a file under examples/agent-host.
            # A missing file is a refusal with its reason, not a read error,
            # and it is decided before any link or write (P11).
            if not path.is_file():
                raise LookupError(
                    f"{name}: the file does not exist; "
                    "edit paths are relative to examples/agent-host")
            text = path.read_text(encoding="utf-8")
            for edit in edits:
                count = text.count(edit["old"])
                if count != 1:
                    raise LookupError(f"{name}: the original text is found {count} times, not once")
                text = text.replace(edit["old"], edit["new"])
            texts[path] = text
        try:
            for path, text in texts.items():
                original = path.read_bytes()
                backup = path.with_name(path.name + BACKUP_SUFFIX)
                # The link decides ownership: a backup that already exists
                # belongs to another run, and consuming it would put that
                # run's original back. Signals stay off across the link and
                # the record, so a kill cannot leave an owned backup
                # unrecorded.
                saved = block_interruptions()
                try:
                    try:
                        os.link(path, backup)
                    except FileExistsError as error:
                        raise BackupCollision(
                            f"{backup} is a backup this run did not create; "
                            "the edit is not applied") from error
                    self.applied.append((path, backup, original))
                    own_backup(backup)
                finally:
                    restore_interruptions(saved)
                tmp = path.with_name(path.name + ".falsify-tmp")
                try:
                    tmp.write_text(text, encoding="utf-8")
                    os.replace(tmp, path)
                finally:
                    if tmp.exists():
                        tmp.unlink()
            # Inside the try: an interrupt after the last replacement but
            # before __enter__ returns must still restore (task 004).
            return self
        except BaseException as error:
            # Python does not call __exit__ when __enter__ raises, and a
            # Ctrl-C or SIGTERM can arrive just after a replacement. Put every
            # original back before the interruption goes on.
            self.restore()
            if isinstance(error, OSError) and "No space" in str(error):
                raise DiskFull(str(error)) from error
            raise

    def restore(self):
        saved = block_interruptions()
        try:
            for path, backup, original in reversed(self.applied):
                if backup.exists():
                    os.replace(backup, path)
                    # The rename brings back the original's old mtime; touch
                    # it, so cargo does not take the mutated build for a fresh
                    # one.
                    os.utime(path)
                    if path.read_bytes() != original:
                        raise SystemExit(
                            f"{path}: restored bytes differ from the saved original; stop")
                disown_backup(backup)
            self.applied = []
        finally:
            restore_interruptions(saved)

    def __exit__(self, *_):
        self.restore()
        return False


def spec(command, manifest=None, cargo_flags=("--locked",)):
    """How to build and run one named test, for a command."""
    if command == "host":
        cargo = ["cargo", "test", *cargo_flags, "--manifest-path", str(manifest or HERE / "Cargo.toml")]
        return {
            "build": [(cargo + ["--no-run"], REPO)],
            "one": (cargo + ["--"], REPO, []),
        }
    if command in PROVIDER_CRATES:
        # Each provider crate is its own workspace with its own lockfile, so
        # its test command names --locked and that crate's manifest directly.
        cargo = ["cargo", "test", "--locked",
                 "--manifest-path", str(manifest or PROVIDER_CRATES[command])]
        return {
            "build": [(cargo + ["--no-run"], REPO)],
            "one": (cargo + ["--"], REPO, []),
        }
    if command == "selftest":
        # A change to this runner is checked by its own self-test. A fresh
        # process reads the mutated file; --keep-backups stops it from taking
        # this run's backup of falsify.py for a killed run's leftover. Each
        # named case runs in its own process, as each named test does.
        base = ["python3", "-I", str(HERE / "falsify.py"), "--keep-backups"]
        return {"build": [], "one": (base, REPO, [])}
    cargo = ["cargo", "test", "-p", "elastos-server", "--lib"]
    return {
        "build": [(["bash", str(HERE / "build.sh")], REPO), (cargo + ["--no-run"], REPO / "elastos")],
        "one": (cargo + ["--"], REPO / "elastos", ["--ignored"]),
    }


def run(argv, cwd):
    """Run a command; return its exit code and its output. The output is read
    only to stop on a full disk and to see the harness's own summary line,
    never to decide that a test passed."""
    env = dict(os.environ, RUST_TEST_THREADS=os.environ.get("RUST_TEST_THREADS", "2"))
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    # Keep each stream's line structure: a marker at the start of stderr is
    # still at the start of a line when stdout ends without a newline. Joining
    # the bytes directly would fuse the last stdout line with the first stderr
    # line and hide the marker. Terminal formatting is stripped here, once,
    # so every reader sees the plain text.
    output = ANSI.sub("", done.stdout + "\n" + done.stderr)
    if any(word in output for word in DISK_FULL):
        raise DiskFull("a command reported a full disk")
    return done.returncode, output


def harness_results(output):
    return [(status, int(passed), int(failed))
            for status, passed, failed in TEST_RESULT.findall(output)]


def harness_is_error_free(output):
    """True only when no harness or loader error marker is in the output. A
    test body can print a fake FAILED summary, and a harness that fails to
    load the test prints no summary of its own, so any error marker makes
    every summary in that output untrustworthy. The text keeps its separators:
    a marker may end at a line break, and only the Cargo footer text is
    removed."""
    if LOADER_ERROR.search(output) or CARGO_FAILURE.search(output):
        return False
    return not HARNESS_ERROR.search(TEST_FAILED.sub("", output))


def ran_and_failed(output):
    """True only when the harness evidence is error-free and a summary says
    one test ran and failed, with no other summary saying a test ran and
    passed. A test body can print a fake summary; the harness prints the real
    one after it, and a harness or loader error is never a catch."""
    results = harness_results(output)
    failed = any(status == "FAILED" and failed >= 1 and passed == 0
                 for status, passed, failed in results)
    returned = any(passed >= 1 for _status, passed, _failed in results)
    return failed and not returned and harness_is_error_free(output)


def evaluate(entry, how):
    """(build_failed, outcomes), from exit codes only. outcomes maps each named
    test to "failed", "passed" or "not run". Every expect mode, `survives`
    included, is proved by this same per-named-test rule; no mode reads the
    whole suite's exit code."""
    for argv, cwd in how["build"]:
        if run(argv, cwd)[0] != 0:
            return True, {}
    argv, cwd, extra = how["one"]
    outcomes = {}
    for name in entry["tests"]:
        if entry.get("command") == "selftest":
            # Each named case is its own process, so one case cannot carry a
            # verdict for another. The case counts only when the child exits
            # with its result AND prints the marker it writes after the case
            # returns. A loading error, an unknown name, or a signal is not run.
            code, output = run(argv + extra + ["--self-test-case", name], cwd)
            lines = output.splitlines()
            if code == CASE_PASSED and case_marker(name, "OK") in lines:
                outcomes[name] = "passed"
            elif code == CASE_FAILED and case_marker(name, "FAILED") in lines:
                outcomes[name] = "failed"
            else:
                outcomes[name] = "not run"
            continue
        # Exactly one test must answer to the name; the list is read for that
        # count only (a list run prints no test output).
        _, listed = run(argv + extra + ["--exact", name, "--list"], cwd)
        if [line for line in listed.splitlines() if line == f"{name}: test"] != [f"{name}: test"]:
            outcomes[name] = "not run"
            continue
        code, output = run(argv + extra + ["--exact", name], cwd)
        if code == 0:
            ran = any(passed >= 1 for _status, passed, _failed in harness_results(output))
            outcomes[name] = "passed" if ran else "not run"
        elif ran_and_failed(output):
            outcomes[name] = "failed"
        else:
            outcomes[name] = "not run"
    return False, outcomes


def verdict(entry, build_failed, outcomes):
    """(ok, word, detail): ok is whether the falsifier did what it expects."""
    expect = entry["expect"]
    if expect == "compile_error":
        return (True, "CAUGHT (does not build)", "") if build_failed else (False, "SURVIVED", "it builds")
    if build_failed:
        return False, "BUILD FAILED", "the mutation must build so its tests can fail"
    missing = [name for name in entry["tests"] if outcomes.get(name, "not run") == "not run"]
    if missing:
        return False, "NOT RUN", "did not run: " + ", ".join(missing)
    if not entry["tests"]:
        return False, "NOT RUN", "no named tests"
    failed = [name for name in entry["tests"] if outcomes.get(name) == "failed"]
    passed = [name for name in entry["tests"] if outcomes.get(name) == "passed"]
    if expect == "survives":
        if failed and passed:
            return (False, "NOT A SURVIVOR",
                    "failed: " + ", ".join(failed) + "; still pass: " + ", ".join(passed))
        if failed:
            return True, "CAUGHT (listed as a survivor)", ""
        return True, "SURVIVED (expected, by design)", ""
    if passed:
        return False, "SURVIVED", "still pass: " + ", ".join(passed)
    return True, "CAUGHT", ""


def falsify(entry, how=None):
    check_disk()
    with Mutation(entry):
        result = evaluate(entry, how or spec(entry["command"]))
    return verdict(entry, *result)


def reported(entry):
    """One falsifier's result. A data mismatch and a backup this run does not
    own each keep their own word and reason, so neither reads as a catch."""
    try:
        return falsify(entry)
    except LookupError as error:
        return False, "NO MATCH", str(error)
    except BackupCollision as error:
        return False, "BACKUP TAKEN", str(error)


REAL_CRATE = {
    "Cargo.toml": """[package]
name = "falsify_selftest"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
""",
    "src/lib.rs": """#[cfg(test)]
mod tests {
    #[test]
    fn genuinely_passing() {
        println!("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out");
    }

    #[test]
    fn fails_with_a_fake_line() {
        panic!("\\ntest tests::genuinely_passing ... FAILED");
    }

    #[test]
    fn fails_plainly() {
        assert!(false, "planted failure");
    }
}
""",
}

STUB_LIST_MISSING = """import sys
print("tests::some_other_test: test")
raise SystemExit(0)
"""

STUB_HARNESS_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FILTERED_OUT = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out")
raise SystemExit(0)
"""

STUB_FAKE_SUMMARY_INDENTED_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("  error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_STDOUT_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("error: could not load the test harness")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_SPLIT_STREAMS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stdout.write("partial output: ")
sys.stderr.write("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_DYLD_PID = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("dyld[1234]: Library not loaded: libmissing.dylib")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_PREFIXED_LOADER = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("/test-bin: error while loading shared libraries: libmissing.so: cannot open shared object file")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_PREFIXED_HARNESS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("test-bin: error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_COLORED_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("\\x1b[31merror\\x1b[0m: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_FOOTER_THEN_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: test failed, to rerun pass `--lib` error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_SPLIT_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error:")
print("  could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_CARGO_LAUNCH_FAILURE = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stderr.write(
    "error: test failed, to rerun pass `--lib`\\n\\n"
    "Caused by:\\n"
    "  could not execute process `test-bin` (never executed)\\n\\n"
    "Caused by:\\n"
    "    No such file or directory (os error 2)\\n")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_CARGO_CRASH = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stderr.write(
    "error: test failed, to rerun pass `--lib`\\n\\n"
    "Caused by:\\n"
    "  process didn't exit successfully: `/tmp/test-bin` (signal: 11, SIGSEGV)\\n")
raise SystemExit(101)
"""

STUB_SURVIVOR_RAN = """import sys
if "--exact" in sys.argv:
    if "--list" in sys.argv:
        print("tests::planted_check: test")
        raise SystemExit(0)
    print("running 1 test")
    print("test tests::planted_check ... ok")
    print()
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out")
raise SystemExit(101)
"""

STUB_SPLIT_STREAMS = """import sys
sys.stdout.write("partial output: ")
sys.stderr.write("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_CASE_RAN_FAILED = """import sys
name = sys.argv[sys.argv.index('--self-test-case') + 1]
print(f"self-test case {name!r}: FAILED")
raise SystemExit(1)
"""

STUB_CASE_RAN_PASSED = """import sys
name = sys.argv[sys.argv.index('--self-test-case') + 1]
print(f"self-test case {name!r}: OK")
raise SystemExit(0)
"""

STUB_CASE_LOADING_ERROR = """import sys
print("Traceback (most recent call last):")
print("RuntimeError: the case module did not load")
raise SystemExit(1)
"""

STUB_CASE_SIGNAL = """import os
import signal
os.kill(os.getpid(), signal.SIGTERM)
"""

INTERRUPTION_ENTRY = {
    "id": "ST",
    "command": "host",
    "expect": "caught",
    "edits": [{"file": "interrupted.txt", "old": "original bytes", "new": "mutated bytes"}],
    "tests": [],
}


def verdict_cases():
    """The verdict logic truth table."""
    ok = True
    two = {"id": "ST", "expect": "caught", "tests": ["a", "b"]}
    cases = [
        ((two, False, {"a": "failed", "b": "passed"}), (False, "SURVIVED")),
        ((two, False, {"a": "failed", "b": "failed"}), (True, "CAUGHT")),
        ((two, False, {"a": "failed", "b": "not run"}), (False, "NOT RUN")),
        ((two, True, {}), (False, "BUILD FAILED")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "passed"}),
         (True, "SURVIVED (expected, by design)")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "not run"}),
         (False, "NOT RUN")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "failed"}),
         (True, "CAUGHT (listed as a survivor)")),
        (({"id": "ST", "expect": "survives", "tests": ["a", "b"]},
          False, {"a": "failed", "b": "passed"}), (False, "NOT A SURVIVOR")),
        (({"id": "ST", "expect": "survives", "tests": []}, False, {}), (False, "NOT RUN")),
        (({"id": "ST", "expect": "compile_error", "tests": []}, False, {}), (False, "SURVIVED")),
    ]
    for args, want in cases:
        got = verdict(*args)[:2]
        if got != want:
            print(f"self-test: verdict {args[1:]} -> {got}, want {want}")
            ok = False
    return ok


def a_named_test_that_does_not_run_is_not_a_catch():
    """Two planted failures: no test answers to the name, and a harness
    error exits non-zero without running one. Neither is a catch (task 004)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "caught", "tests": ["tests::planted_check"]}
        for title, text in (("name is not listed", STUB_LIST_MISSING),
                            ("harness error", STUB_HARNESS_ERROR),
                            ("exit 0 but no test ran", STUB_FILTERED_OUT),
                            ("fake summary with an indented error",
                             STUB_FAKE_SUMMARY_INDENTED_ERROR),
                            ("fake summary with an error on stdout",
                             STUB_FAKE_SUMMARY_STDOUT_ERROR),
                            ("fake summary then an error across the stream boundary",
                             STUB_FAKE_SUMMARY_SPLIT_STREAMS),
                            ("fake summary with a dyld process id error",
                             STUB_FAKE_SUMMARY_DYLD_PID),
                            ("fake summary with a prefixed loader error",
                             STUB_FAKE_SUMMARY_PREFIXED_LOADER),
                            ("fake summary with a prefixed harness error",
                             STUB_FAKE_SUMMARY_PREFIXED_HARNESS),
                            ("fake summary with a colored error label",
                             STUB_FAKE_SUMMARY_COLORED_ERROR),
                            ("fake summary with an error after the cargo footer",
                             STUB_FAKE_SUMMARY_FOOTER_THEN_ERROR),
                            ("fake summary with an error split after its colon",
                             STUB_FAKE_SUMMARY_SPLIT_ERROR),
                            ("fake summary with a cargo launch failure",
                             STUB_FAKE_SUMMARY_CARGO_LAUNCH_FAILURE),
                            ("fake summary with an abnormal test-process exit",
                             STUB_FAKE_SUMMARY_CARGO_CRASH)):
            stub = SELF_TEST_DIR / "stub.py"
            stub.write_text(text, encoding="utf-8")
            how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
            got = verdict(entry, *evaluate(entry, how))
            print(f"self-test: {title}: {got[1]} ({got[2]})")
            if got[:2] != (False, "NOT RUN"):
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def interruption_restores():
    """Ctrl-C or SIGTERM right after a replacement: the original comes back
    before the interruption goes on (task 004)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "interrupted.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    real_replace = os.replace
    replaced = []

    def replace_then_interrupt(src, dst):
        real_replace(src, dst)
        replaced.append(dst)
        if len(replaced) == 1:
            raise KeyboardInterrupt

    os.replace = replace_then_interrupt
    interrupted = False
    try:
        with Mutation(INTERRUPTION_ENTRY, SELF_TEST_DIR):
            pass
    except KeyboardInterrupt:
        interrupted = True
    finally:
        os.replace = real_replace
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption during replacement: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return interrupted and restored and not backup.exists()


def real_catch_counts():
    """A real catch still counts when every named test runs and fails, and a
    passing test beside them is SURVIVED. A fake FAILED line in a panic does
    not change either verdict."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for name, text in REAL_CRATE.items():
            path = SELF_TEST_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        how = spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "tests": ["tests::fails_with_a_fake_line", "tests::fails_plainly"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: every named test runs and fails: {got[1]} ({got[2]})")
        if got[:2] != (True, "CAUGHT"):
            ok = False
        beside = {"id": "ST", "command": "host", "expect": "caught",
                  "tests": ["tests::genuinely_passing", "tests::fails_plainly"]}
        got = verdict(beside, *evaluate(beside, how))
        print(f"self-test: a passing test beside a failing one: {got[1]} ({got[2]})")
        if got[:2] != (False, "SURVIVED") or "tests::genuinely_passing" not in got[2]:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def interruption_at_the_end_of_the_edit():
    """An interrupt after the last replacement but before __enter__ returns:
    the original still comes back (task 004, review finding 2)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "boundary.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    lines, start = inspect.getsourcelines(Mutation.__enter__)
    at = next(start + offset for offset, line in enumerate(lines) if line.strip() == "return self")
    entered = []

    def trace(frame, event, _arg):
        if frame.f_code is Mutation.__enter__.__code__:
            if event == "call":
                entered.append(frame)
            elif event == "line" and frame.f_lineno == at and len(entered) == 1:
                entered.append(frame)
                raise KeyboardInterrupt
        return trace

    entry = {"id": "ST", "command": "host", "expect": "caught",
             "edits": [{"file": "boundary.txt", "old": "original bytes", "new": "mutated bytes"}],
             "tests": []}
    interrupted = False
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        with Mutation(entry, SELF_TEST_DIR):
            pass
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sys.settrace(previous)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption at the end of the edit: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return interrupted and restored and not backup.exists()


def another_lanes_backup_is_not_recovered():
    """Recovery keeps foreign backups, including a neighbour of MP01's
    source file. The runner owns that exact provider target."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        repo = SELF_TEST_DIR / "lanes"
        here = repo / "examples" / "agent-host"
        here.mkdir(parents=True)
        data = here / "falsifiers.json"
        data.write_text('{"falsifiers": []}', encoding="utf-8")
        owned = here / "owned.txt"
        foreign = repo / "capsules" / "wallet-provider" / "src" / "lib.rs"
        foreign.parent.mkdir(parents=True)
        neighbour = repo / "capsules" / "model-provider" / "src" / "lib.rs"
        neighbour.parent.mkdir(parents=True)
        for target in (owned, foreign, neighbour):
            target.write_text("mutated bytes\n", encoding="utf-8")
            target.with_name(target.name + BACKUP_SUFFIX).write_text(
                "original bytes\n", encoding="utf-8")
        saved = HERE, REPO, DATA, SELF_TEST_DIR
        globals().update(HERE=here, REPO=repo, DATA=data,
                         SELF_TEST_DIR=repo / "self-test")
        try:
            code = main(["--from", str(data), "--list"])
        finally:
            globals().update(HERE=saved[0], REPO=saved[1], DATA=saved[2],
                             SELF_TEST_DIR=saved[3])
        owned_restored = (owned.read_text() == "original bytes\n"
                          and not owned.with_name(owned.name + BACKUP_SUFFIX).exists())
        foreign_kept = (foreign.read_text() == "mutated bytes\n"
                        and foreign.with_name(foreign.name + BACKUP_SUFFIX).exists())
        neighbour_kept = (neighbour.read_text() == "mutated bytes\n"
                          and neighbour.with_name(neighbour.name + BACKUP_SUFFIX).read_text()
                          == "original bytes\n")
        print(f"self-test: another lane's backup on restart: exit={code}, "
              f"owned restored={owned_restored}, foreign kept={foreign_kept}")
        if code != 0 or not owned_restored or not foreign_kept:
            ok = False
        if not neighbour_kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_killed_provider_edit_is_recovered():
    """Kill real and synthetic provider edits in an isolated tree, restart
    through main(), and repeat the edit. This lane's model-provider targets,
    the model provider's confinement test harness, and the confine lane's five
    did/wallet targets plus its did confinement test harness all come back in
    either startup mode. Foreign backups, including both providers'
    confinement documents and each harness's support neighbour, stay with
    their owners."""
    owned = {entry["id"]: entry
             for entry in load(REPO / "capsules/model-provider/falsifiers.json")
             if entry["id"] in ("MP01", "MP02", "MP05", "MP12", "MP15", "MP16")}
    profile = "../../capsules/model-provider/confine.sb"
    # The did and wallet targets and both confinement test harnesses are
    # named here, not read from the table, so a target dropped from
    # PROVIDER_TARGETS is caught (PV44, PV45, PV47, PV48). Their original
    # bytes are written in the isolated tree, never read from the real
    # crates.
    synthetic = ("../../capsules/model-provider/tests/confine/main.rs",
                 "../../capsules/did-provider/src/main.rs",
                 "../../capsules/did-provider/confine.sb",
                 "../../capsules/did-provider/tests/confine.rs",
                 "../../capsules/wallet-provider/src/main.rs",
                 "../../capsules/wallet-provider/confine.sb",
                 "../../capsules/wallet-provider/tests/confine.rs")
    entry = {"id": "MP01+MP02+MP05+MP12+MP15+MP16",
             "edits": [edit for owned_entry in owned.values() for edit in owned_entry["edits"]]
             + [{"file": "owned.txt", "old": "original bytes", "new": "mutated bytes"},
                {"file": profile, "old": "original bytes", "new": "mutated bytes"}]
             + [{"file": name, "old": "original bytes", "new": "mutated bytes"}
                for name in synthetic]}
    originals = {edit["file"]: (HERE / edit["file"]).read_bytes()
                 for owned_entry in owned.values() for edit in owned_entry["edits"]}
    originals["owned.txt"] = b"original bytes\n"
    originals[profile] = b"original bytes\n"
    for name in synthetic:
        originals[name] = b"original bytes\n"
    child = """import json, os, pathlib, runpy, signal, sys
runner = runpy.run_path(sys.argv[1])
runner['Mutation'](json.loads(sys.argv[2]), pathlib.Path(sys.argv[3])).__enter__()
os.kill(os.getpid(), signal.SIGKILL)
"""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for mode in ("provider", "default"):
            repo = SELF_TEST_DIR / mode
            here = repo / "examples/agent-host"
            here.mkdir(parents=True)
            data = here / "falsifiers.json"
            data.write_text('{"falsifiers": []}', encoding="utf-8")
            provider_data = repo / "capsules/model-provider/falsifiers.json"
            provider_data.parent.mkdir(parents=True)
            provider_data.write_text(json.dumps({"falsifiers": list(owned.values())}),
                                     encoding="utf-8")
            for name, original in originals.items():
                target = here / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original)
                os.utime(target, (1, 1))
            foreign_targets = [repo / "capsules/wallet-provider/src/local_memory.rs",
                               repo / "capsules/model-provider/src/lib.rs",
                               repo / "capsules/model-provider/CONFINEMENT.md",
                               repo / "capsules/did-provider/CONFINEMENT.md",
                               repo / "capsules/model-provider/tests/confine/support.rs",
                               repo / "capsules/did-provider/tests/support.rs"]
            for target in foreign_targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"foreign mutation\n")
                target.with_name(target.name + BACKUP_SUFFIX).write_bytes(b"foreign original\n")
            killed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", child, str(HERE / "falsify.py"),
                 json.dumps(entry), str(here)], capture_output=True, text=True, timeout=10)
            planted = all(
                (here / name).read_bytes() != original
                and (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).read_bytes()
                == original for name, original in originals.items())
            if killed.returncode != -signal.SIGKILL or not planted:
                print(f"self-test: provider kill: exit={killed.returncode}, planted={planted}")
                return False
            argv = ["--from", str(provider_data), "--list"] if mode == "provider" else ["--list"]
            with mock.patch.dict(globals(), HERE=here, REPO=repo, DATA=data):
                code = main(argv)
            restored = all(
                (here / name).read_bytes() == original
                and not (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).exists()
                and (here / name).stat().st_mtime_ns > 1_000_000_000
                for name, original in originals.items())
            foreign_kept = all(
                target.read_bytes() == b"foreign mutation\n"
                and target.with_name(target.name + BACKUP_SUFFIX).read_bytes() == b"foreign original\n"
                for target in foreign_targets)
            print(f"self-test: provider {mode} restart: exit={code}, restored={restored}, "
                  f"foreign kept={foreign_kept}")
            if code != 0 or not restored or not foreign_kept:
                ok = False
                continue
            with Mutation(entry, here):
                if any((here / name).read_bytes() == original
                       for name, original in originals.items()):
                    ok = False
            if any((here / name).read_bytes() != original
                   or (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).exists()
                   for name, original in originals.items()):
                ok = False
    except Exception as error:
        print(f"self-test: provider restart raised {type(error).__name__}: {error}")
        return False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_edit_of_a_missing_file_is_refused():
    """An edit whose file does not exist is refused by Mutation before any
    link or write, with the one path-rule reason; reported() returns it as
    NO MATCH, so a missing file is never a catch (task 014). An exception
    escaping reported() fails this case instead of erroring it out."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        name = "missing.txt"
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{"file": name, "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["tests::planted_check"]}
        reason = (f"{name}: the file does not exist; "
                  "edit paths are relative to examples/agent-host")
        path = SELF_TEST_DIR / name
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        real_mutation = Mutation
        got = None
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            try:
                got = reported(entry)
            except BaseException as error:
                print(f"self-test: missing file raised {type(error).__name__}: {error}")
                ok = False
        created = path.exists() or backup.exists()
        print(f"self-test: edit of a missing file: {got}, created={created}")
        if got != (False, "NO MATCH", reason):
            ok = False
        if created:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def the_streams_keep_their_own_lines():
    """stdout and stderr are joined at a line boundary, so a marker at the
    start of stderr is still at the start of a line when stdout ends without
    a newline (task 010 review finding 1)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_SPLIT_STREAMS, encoding="utf-8")
        _, output = run(["python3", "-I", str(stub)], SELF_TEST_DIR)
        kept = "error: could not load the test harness" in output.splitlines()
        print(f"self-test: the streams keep their own lines: kept={kept}")
        return kept
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_self_test_case_counts_only_when_it_ran():
    """The named case ran and failed -> a catch. A loading error that exits
    non-zero, or a signal, is not run and not a catch (review finding 1)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "selftest", "expect": "caught",
                 "tests": ["planted case"]}
        cases = (
            ("ran and failed", STUB_CASE_RAN_FAILED, (True, "CAUGHT")),
            ("ran and passed", STUB_CASE_RAN_PASSED, (False, "SURVIVED")),
            ("loading error", STUB_CASE_LOADING_ERROR, (False, "NOT RUN")),
            ("signal", STUB_CASE_SIGNAL, (False, "NOT RUN")),
        )
        for title, text, want in cases:
            stub = SELF_TEST_DIR / "stub.py"
            stub.write_text(text, encoding="utf-8")
            how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
            got = verdict(entry, *evaluate(entry, how))
            print(f"self-test: self-test case {title}: {got[1]} ({got[2]})")
            if got[:2] != want:
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def load_refused(path, reason):
    """True only when load(path) stops with status 2 and exactly `reason`.
    A bypass that lets a read, JSON or shape exception escape fails the case,
    so that falsifier is caught instead of the case erroring out."""
    message = io.StringIO()
    try:
        with contextlib.redirect_stderr(message):
            load(path)
    except SystemExit as stop:
        code = stop.code
    except Exception as error:
        print(f"self-test: load({path}) raised {type(error).__name__}: {error}")
        return False
    else:
        print(f"self-test: load({path}) returned without a refusal")
        return False
    print(f"self-test: load({path}) -> exit {code}: {message.getvalue().strip()}")
    return code == CASE_USAGE and message.getvalue() == f"{path}: {reason}\n"


def a_data_file_refusal(name, text, reason):
    """One crafted data file under the self-test dir: load() stops with status
    2 and exactly reason. No file is written when text is None."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        path = SELF_TEST_DIR / name
        if text is not None:
            SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
            if isinstance(text, bytes):
                path.write_bytes(text)
            else:
                path.write_text(text, encoding="utf-8")
        return load_refused(path, reason)
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_missing_data_file_is_refused():
    """A path with no file is a refusal, not an empty run."""
    return a_data_file_refusal("missing.json", None, "the data file does not exist")


def an_unreadable_data_file_is_refused():
    """An existing file whose read fails gives the exact read refusal."""
    with mock.patch.object(pathlib.Path, "read_text", side_effect=PermissionError("denied")):
        return a_data_file_refusal("unreadable.json", '{"falsifiers": []}',
                                   "the data file cannot be read")


def an_unreadable_data_path_is_refused():
    """An inaccessible parent makes the initial stat fail: the shared OSError
    refusal gives exit 2 and the read reason, not a traceback."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "stat-denied.json"
        path.write_text('{"falsifiers": []}', encoding="utf-8")
        with mock.patch.object(pathlib.Path, "stat",
                               side_effect=PermissionError("denied")):
            return load_refused(path, "the data file cannot be read")
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def an_invalid_utf8_data_file_is_refused():
    """Invalid UTF-8 reaches the decode refusal before JSON parsing."""
    return a_data_file_refusal("invalid-utf8.json", b'{"falsifiers": []}\xff',
                               "the data file is not JSON")


def a_non_json_data_file_is_refused():
    """Text that is not JSON is a refusal, not an empty run."""
    return a_data_file_refusal("not-json.json", "this is not JSON\n",
                               "the data file is not JSON")


def a_data_document_must_be_an_object():
    """A JSON body that is not an object is a refusal with its own reason."""
    return a_data_file_refusal("root-list.json", json.dumps(["falsifiers"]),
                               "the document is not an object")


def a_data_document_needs_a_falsifiers_list():
    """An object without a falsifiers key is a refusal with its own reason."""
    return a_data_file_refusal("no-falsifiers.json", json.dumps({"entries": []}),
                               "the document has no falsifiers list")


def falsifiers_must_be_a_list():
    """A falsifiers value that is not a list is a refusal with its own reason."""
    return a_data_file_refusal("falsifiers-object.json",
                               json.dumps({"falsifiers": {}}),
                               "falsifiers is not a list")


def a_duplicate_id_is_refused():
    """Two entries with one id are a refusal with status 2."""
    entry = {"id": "ST", "command": "host", "expect": "caught", "tests": ["tests::x"]}
    return a_data_file_refusal("duplicate.json",
                               json.dumps({"falsifiers": [entry, dict(entry)]}),
                               "an id is used twice")


def an_unknown_command_is_refused():
    """A command outside COMMANDS is a refusal with its own reason."""
    entry = {"id": "ST", "command": "bogus", "expect": "caught", "tests": ["tests::x"]}
    return a_data_file_refusal("unknown-command.json",
                               json.dumps({"falsifiers": [entry]}),
                               "ST: unknown command 'bogus'")


def an_unknown_expect_is_refused():
    """An expect outside the known values is a refusal with its own reason."""
    entry = {"id": "ST", "command": "host", "expect": "bogus", "tests": ["tests::x"]}
    return a_data_file_refusal("unknown-expect.json",
                               json.dumps({"falsifiers": [entry]}),
                               "ST: unknown expect 'bogus'")


def a_survivor_needs_its_named_test_to_run():
    """A survives entry whose named test did not run is NOT RUN, never a
    survivor. load() refuses a survives entry with no named test, the same as
    a caught entry (task 005)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        data = SELF_TEST_DIR / "falsifiers.json"
        data.write_text(json.dumps({"falsifiers": [
            {"id": "ST", "title": "no test", "command": "host",
             "expect": "survives", "edits": [], "tests": []}]}), encoding="utf-8")
        if not load_refused(data, "ST: no named tests"):
            ok = False
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_HARNESS_ERROR, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: survivor whose named test did not run: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_survivor_is_proved_by_its_named_tests():
    """A genuine survivor counts only when its named test ran and passed under
    the mutation. The stub's whole suite fails, which used to be read as "the
    mutation is caught": only the named test proves it (task 005)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_SURVIVOR_RAN, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: survivor whose named test ran and passed: {got[1]} ({got[2]})")
        if got[:2] != (True, "SURVIVED (expected, by design)"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def refusal(argv):
    """(exit code, reason) from parse_argv, with its message captured."""
    message = io.StringIO()
    with contextlib.redirect_stderr(message):
        try:
            parse_argv(argv)
        except SystemExit as stop:
            return stop.code, message.getvalue()
    return None, message.getvalue()


def from_option_selects_path():
    """--from names the data file; without it the path is the default."""
    ok = True
    default = parse_argv([])
    print(f"self-test: default path: {default.path}, mode {default.mode}")
    if default.path != DATA or default.mode != "run":
        ok = False
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    picked = parse_argv(["--from", str(chosen)])
    print(f"self-test: --from path: {picked.path}")
    if picked.path != chosen:
        ok = False
    return ok


def unknown_option_is_refused():
    """Every unsupported option stops at the front door with status 2 and a
    reason that names it, even beside --list or after --from PATH."""
    ok = True
    for argv, option in (
        (["--help"], "--help"),
        (["--typo"], "--typo"),
        (["--list", "--typo"], "--typo"),
        (["--from", str(DATA), "--typo"], "--typo"),
        (["FS01", "--bogus"], "--bogus"),
    ):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if code != 2 or option not in reason:
            ok = False
        if reason != f"usage: unknown option {option}\n":
            ok = False
    return ok


def equals_form_is_refused():
    """The equals form is refused and names the separated form to use."""
    ok = True
    for argv in (["--from=capsules/model-provider/falsifiers.json"], ["--from="]):
        code, reason = refusal(argv)
        print(f"self-test: {argv[0]} -> exit {code}: {reason.strip()}")
        if code != 2 or "use --from PATH" not in reason:
            ok = False
        if reason != "usage: --from=PATH is not supported; use --from PATH\n":
            ok = False
    return ok


def from_without_a_path_is_refused():
    """--from needs a path, not a missing value and not another option."""
    ok = True
    for argv in (["--from"], ["--from", "--typo"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if code != 2 or "--from needs a path" not in reason:
            ok = False
        if reason != "usage: --from needs a path, not an option\n":
            ok = False
    return ok


def modifier_only_invocation_is_refused():
    """Modifiers need an explicit mode, data file, or id prefix."""
    ok = True
    for argv in (["--with-repo"], ["--keep-backups"],
                 ["--with-repo", "--keep-backups"],
                 ["--keep-backups", "--with-repo"],
                 ["--with-repo", "--with-repo"],
                 ["--keep-backups", "--keep-backups"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if (code != 2 or reason != "usage: --keep-backups and --with-repo need a mode, "
                "--from PATH, or an id prefix\n"):
            ok = False
    return ok


def modifiers_preserve_explicit_selection():
    """Each modifier remains available beside an explicit selection."""
    ok = True
    for modifiers in (["--with-repo"], ["--keep-backups"],
                      ["--keep-backups", "--with-repo"]):
        for selection, mode, name, filters in (
            (["--from", str(DATA)], "run", None, []),
            (["FS01"], "run", None, ["FS01"]),
            (["--list"], "list", None, []),
            (["--self-test-cases"], "self-test-cases", None, []),
            (["--self-test"], "self-test", None, []),
            (["--self-test-case", "from option selects path"],
             "self-test-case", "from option selects path", []),
        ):
            for argv in (modifiers + selection, selection + modifiers):
                try:
                    parsed = parse_argv(argv)
                except SystemExit as stop:
                    print(f"self-test: {argv} -> unexpected exit {stop.code}")
                    ok = False
                    continue
                if parsed != ParsedArgv(DATA, mode, name, filters,
                                        "--keep-backups" in modifiers,
                                        "--with-repo" in modifiers):
                    print(f"self-test: {argv} -> {parsed}")
                    ok = False
    return ok


def self_test_case_without_a_name_is_refused():
    """A named case requires a value; another option cannot supply it."""
    ok = True
    for argv in (["--self-test-case"], ["--self-test-case", "--typo"],
                 ["--self-test-case", "--list"],
                 ["--list", "--self-test-case"],
                 ["--list", "--self-test-case", "--self-test"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if (code != 2 or reason != "usage: --self-test-case needs a case name, not an option\n"):
            ok = False
    return ok


def argv_refusal_precedes_work():
    """main() refuses an unsupported option before recovery or loading. Both
    are stubbed, so this case reads no file and touches no backup."""
    ok = True
    touched = []
    saved = recover_backups, load

    def stub_recover():
        touched.append("recover_backups")

    def stub_load(*_args, **_kwargs):
        touched.append("load")
        return []

    globals()["recover_backups"] = stub_recover
    globals()["load"] = stub_load
    try:
        for argv, reason in (
            (["--typo"], "unknown option --typo"),
            (["--list", "--typo"], "unknown option --typo"),
            (["--from=path"], "--from=PATH is not supported; use --from PATH"),
            (["--from"], "--from needs a path, not an option"),
            (["--from", "--list"], "--from needs a path, not an option"),
            (["--self-test-case"], "--self-test-case needs a case name, not an option"),
            (["--self-test-case", "--list"], "--self-test-case needs a case name, not an option"),
            (["--with-repo"], "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
            (["--keep-backups"], "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
            (["--with-repo", "--keep-backups"],
             "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
        ):
            touched.clear()
            code = None
            message = io.StringIO()
            with contextlib.redirect_stderr(message):
                try:
                    main(argv)
                except SystemExit as stop:
                    code = stop.code
            print(f"self-test: main {' '.join(argv)} -> exit {code}, touched={touched}")
            if code != 2 or touched:
                ok = False
            if message.getvalue() != f"usage: {reason}\n":
                ok = False
    finally:
        globals()["recover_backups"], globals()["load"] = saved
    return ok


def provider_spec_uses_locked_manifest():
    """Every provider crate is a registered command, and both its build and
    run argv name --locked and the manifest that follows --manifest-path.
    The expected manifests are written here, so a table that maps one crate
    to another crate's manifest is caught (PV43)."""
    ok = True
    expected = {
        "provider": str(REPO / "capsules" / "model-provider" / "Cargo.toml"),
        "did": str(REPO / "capsules" / "did-provider" / "Cargo.toml"),
        "wallet": str(REPO / "capsules" / "wallet-provider" / "Cargo.toml"),
    }
    for command, manifest in expected.items():
        if command not in COMMANDS:
            print(f"self-test: {command} is not a registered command")
            ok = False
            continue
        how = spec(command)
        build = how["build"]
        one, cwd, _extra = how["one"]
        print(f"self-test: {command} build {[argv for argv, _cwd in build]}")
        print(f"self-test: {command} run {one}")
        if cwd != REPO:
            ok = False
        if len(build) != 1 or build[0][1] != REPO:
            ok = False
        else:
            argv = build[0][0]
            if (argv[:2] != ["cargo", "test"] or "--locked" not in argv
                    or "--no-run" not in argv):
                ok = False
            if ("--manifest-path" not in argv
                    or argv[argv.index("--manifest-path") + 1:argv.index("--manifest-path") + 2]
                    != [manifest]):
                ok = False
        if (one[:2] != ["cargo", "test"] or "--locked" not in one
                or "--" not in one or "--no-run" in one):
            ok = False
        if ("--manifest-path" not in one
                or one[one.index("--manifest-path") + 1:one.index("--manifest-path") + 2]
                != [manifest]):
            ok = False
    return ok


def list_mode_displays():
    """--list displays the loaded entries. It never selects work, and it may
    name the file it displays."""
    ok = True
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    for argv, want_path in ((["--list"], DATA), (["--list", "--from", str(chosen)], chosen)):
        parsed = parse_argv(argv)
        print(f"self-test: {' '.join(argv)} -> mode {parsed.mode}, path {parsed.path}")
        if parsed.mode != "list" or parsed.path != want_path:
            ok = False
    return ok


def prefix_token_still_selects():
    """A bare token still filters by id prefix, with or without --from."""
    ok = True
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    for argv, want in ((["FS01", "FS03"], ["FS01", "FS03"]),
                       (["--from", str(chosen), "FS01"], ["FS01"])):
        parsed = parse_argv(argv)
        print(f"self-test: {' '.join(argv)} -> mode {parsed.mode}, filters {parsed.filters}")
        if parsed.mode != "run" or parsed.filters != want:
            ok = False
    return ok


def a_nested_list_is_listed():
    """A nested main() against a crafted list displays it. This is the first
    step of the cross-process case below: the nested run must leave a
    caller's backup alone."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        data = SELF_TEST_DIR / "nested-list.json"
        data.write_text(json.dumps({"falsifiers": [
            {"id": "ST", "title": "nested entry", "command": "host",
             "expect": "caught", "edits": [], "tests": ["tests::x"]}]}),
            encoding="utf-8")
        listed = io.StringIO()
        with contextlib.redirect_stdout(listed):
            code = main(["--from", str(data), "--list"])
        text = listed.getvalue()
        print(f"self-test: nested list -> exit {code}: {text.strip()}")
        return code == 0 and "nested entry" in text
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_nested_run_keeps_the_callers_backup():
    """Cross-process: an outer `survives` mutation of the non-JSON refusal is
    active on a copy of this runner. A first case runs a nested main()
    without --keep-backups, then PV20's case still sees the mutation, so the
    verdict is NOT A SURVIVOR. The caller's backup keeps the original bytes,
    and --keep-backups keeps a backup this process does not own."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        runner = SELF_TEST_DIR / "falsify.py"
        source = (HERE / "falsify.py").read_bytes()
        runner.write_bytes(source)
        (SELF_TEST_DIR / "falsifiers.json").write_text(
            '{"falsifiers": []}', encoding="utf-8")
        pv20 = next(entry for entry in load(REPO / "capsules/model-provider/falsifiers.json")
                    if entry["id"] == "PV20")
        entry = {"id": "ST", "command": "selftest", "expect": "survives",
                 "tests": ["a nested list is listed",
                           "a non-json data file is refused"]}
        how = {"build": [], "one": (["python3", "-I", str(runner), "--keep-backups"],
                                    HERE, [])}
        backup = runner.with_name(runner.name + BACKUP_SUFFIX)
        with Mutation(pv20, SELF_TEST_DIR):
            got = verdict(entry, *evaluate(entry, how))
            mutated = str(pv20["edits"][0]["new"]) in runner.read_text(encoding="utf-8")
            kept = backup.exists() and backup.read_bytes() == source
            print(f"self-test: nested ownership: {got[1]} ({got[2]}), "
                  f"mutated={mutated}, caller backup kept={kept}")
            if got[:2] != (False, "NOT A SURVIVOR"):
                ok = False
            if "a non-json data file is refused" not in got[2]:
                ok = False
            if not mutated or not kept:
                ok = False
        stale = SELF_TEST_DIR / "stale.txt"
        stale.write_text("mutated bytes\n", encoding="utf-8")
        stale_backup = stale.with_name(stale.name + BACKUP_SUFFIX)
        stale_backup.write_text("caller original\n", encoding="utf-8")
        code, _output = run(["python3", "-I", str(runner), "--keep-backups", "--list"], HERE)
        stale_kept = (code == 0 and stale.read_text(encoding="utf-8") == "mutated bytes\n"
                      and stale_backup.read_text(encoding="utf-8") == "caller original\n")
        print(f"self-test: --keep-backups keeps an unowned backup: exit={code}, "
              f"kept={stale_kept}")
        if not stale_kept:
            ok = False
        if runner.read_bytes() != source or backup.exists():
            print("self-test: nested ownership: the caller's copy was not restored")
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def released_backups_are_recovered_again():
    """Two killed-edit recoveries run in one child interpreter. Local
    ownership ends after restore, while the child's recovery and subsequent
    ownership publications keep the active ancestor's backup protected."""
    ok = True
    before = owned_backups()
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "ancestor.txt"
        original = b"ancestor original\n"
        path.write_bytes(original)
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        entry = {"edits": [{"file": path.name, "old": "ancestor original",
                            "new": "ancestor mutation"}]}
        child = """import os, pathlib, runpy, sys
from unittest import mock
runner = runpy.run_path(sys.argv[1])
state = runner['main'].__globals__
root = pathlib.Path(sys.argv[2])
state['SELF_TEST_DIR'] = root / 'recovery'
inherited = runner['owned_backups']()
ok = True
for attempt in range(2):
    recovered = runner['a_killed_provider_edit_is_recovered']()
    published = {pathlib.Path(name).resolve()
                 for name in os.environ.get(runner['OWNED_BACKUPS_ENV'], '').split(os.pathsep)
                 if name}
    released = runner['owned_backups']() == inherited and published == inherited
    with mock.patch.dict(state, HERE=root, REPO=root):
        runner['recover_backups']()
    print(f'self-test: recovery cycle {attempt + 1}: recovered={recovered}, released={released}')
    if not recovered or not released:
        ok = False
sys.exit(0 if ok else 1)
"""
        with Mutation(entry, SELF_TEST_DIR):
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", child, str(HERE / "falsify.py"),
                 str(SELF_TEST_DIR)], capture_output=True, text=True, timeout=30)
            kept = (path.read_bytes() == b"ancestor mutation\n"
                    and backup.exists() and backup.read_bytes() == original)
            print(result.stdout, end="")
            print(f"self-test: repeated recovery: exit={result.returncode}, "
                  f"ancestor kept={kept}")
            if result.returncode != 0 or not kept:
                print(result.stderr, end="")
                ok = False
        if path.read_bytes() != original or backup.exists() or owned_backups() != before:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_backup_this_run_did_not_make_is_refused():
    """A competing backup appears inside os.link(). The link decides
    ownership: the edit stops with its own reason and result, the caller's
    file and backup keep their bytes, and no backup is recorded for restore.
    A backup that is already there at the start gets the same refusal."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "planted.txt"
        original = "original bytes\n"
        caller_backup = "a caller's backup\n"
        path.write_text(original, encoding="utf-8")
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        entry = {"id": "ST", "command": "selftest", "expect": "caught",
                 "edits": [{"file": path.name, "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["a nested list is listed"]}
        reason = f"{backup} is a backup this run did not create; the edit is not applied"

        def bytes_or_none(target):
            return target.read_bytes() if target.exists() else None

        # A backup the caller made is already there.
        backup.write_text(caller_backup, encoding="utf-8")
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            try:
                got = reported(entry)
            except BaseException as error:
                print(f"self-test: reported collision raised {type(error).__name__}: {error}")
                got = None
        unchanged = bytes_or_none(path) == original.encode("utf-8")
        backup_kept = bytes_or_none(backup) == caller_backup.encode("utf-8")
        print(f"self-test: backup collision: {got}, unchanged={unchanged}, "
              f"backup kept={backup_kept}")
        if got != (False, "BACKUP TAKEN", reason):
            ok = False
        if not unchanged or not backup_kept:
            ok = False
        backup.unlink(missing_ok=True)

        # The same refusal when the competing backup appears inside our link.
        real_link = os.link

        def competing_link(src, dst, *args, **kwargs):
            pathlib.Path(dst).write_text(caller_backup, encoding="utf-8")
            return real_link(src, dst, *args, **kwargs)

        mutation = Mutation(entry, SELF_TEST_DIR)
        got_class = got_reason = None
        with mock.patch.object(os, "link", competing_link):
            try:
                with mutation:
                    pass
            except BackupCollision as error:
                got_class = type(error).__name__
                got_reason = str(error)
            except BaseException as error:
                print(f"self-test: collision raised {type(error).__name__}: {error}")
                ok = False
        unchanged = bytes_or_none(path) == original.encode("utf-8")
        backup_kept = bytes_or_none(backup) == caller_backup.encode("utf-8")
        unrecorded = mutation.applied == []
        print(f"self-test: link collision: class={got_class}, unchanged={unchanged}, "
              f"backup kept={backup_kept}, unrecorded={unrecorded}")
        if got_class != "BackupCollision" or got_reason != reason:
            print(f"self-test: link collision reason: {got_reason!r}")
            ok = False
        if not unchanged or not backup_kept or not unrecorded:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


# Each self-test case is named, so a falsifier names one and the runner runs
# it on its own. A name not listed here is not a case: the runner reports it
# as not run, never as caught.
SELF_TEST_CASES = {
    "verdict cases": verdict_cases,
    "a named test that does not run is not a catch": a_named_test_that_does_not_run_is_not_a_catch,
    "an interrupted edit is restored": interruption_restores,
    "another lane's backup is not recovered": another_lanes_backup_is_not_recovered,
    "a killed provider edit is recovered": a_killed_provider_edit_is_recovered,
    "an edit of a missing file is refused": an_edit_of_a_missing_file_is_refused,
    "a missing data file is refused": a_missing_data_file_is_refused,
    "an unreadable data file is refused": an_unreadable_data_file_is_refused,
    "an unreadable data path is refused": an_unreadable_data_path_is_refused,
    "an invalid utf8 data file is refused": an_invalid_utf8_data_file_is_refused,
    "a non-json data file is refused": a_non_json_data_file_is_refused,
    "a data document must be an object": a_data_document_must_be_an_object,
    "a data document needs a falsifiers list": a_data_document_needs_a_falsifiers_list,
    "falsifiers must be a list": falsifiers_must_be_a_list,
    "a duplicate id is refused": a_duplicate_id_is_refused,
    "an unknown command is refused": an_unknown_command_is_refused,
    "an unknown expect is refused": an_unknown_expect_is_refused,
    "an interrupt at the end of the edit is restored": interruption_at_the_end_of_the_edit,
    "the streams keep their own lines": the_streams_keep_their_own_lines,
    "a real catch counts": real_catch_counts,
    "a self-test case counts only when it ran": a_self_test_case_counts_only_when_it_ran,
    "a survivor needs its named test to run": a_survivor_needs_its_named_test_to_run,
    "a survivor is proved by its named tests": a_survivor_is_proved_by_its_named_tests,
    "from option selects path": from_option_selects_path,
    "unknown option is refused": unknown_option_is_refused,
    "equals form is refused": equals_form_is_refused,
    "from without a path is refused": from_without_a_path_is_refused,
    "modifier only invocation is refused": modifier_only_invocation_is_refused,
    "modifiers preserve explicit selection": modifiers_preserve_explicit_selection,
    "self-test case without a name is refused": self_test_case_without_a_name_is_refused,
    "argv refusal precedes work": argv_refusal_precedes_work,
    "provider spec uses locked manifest": provider_spec_uses_locked_manifest,
    "list mode displays": list_mode_displays,
    "prefix token still selects": prefix_token_still_selects,
    "a nested list is listed": a_nested_list_is_listed,
    "a nested run keeps the caller's backup": a_nested_run_keeps_the_callers_backup,
    "released backups are recovered again": released_backups_are_recovered_again,
    "a backup this run did not make is refused": a_backup_this_run_did_not_make_is_refused,
}


def self_test(entries, with_repo, only=None):
    """Run the named self-test cases, or only `only`; with the repo, also one
    real falsifier with a passing name added and as listed."""
    ok = True
    try:
        for name, case in SELF_TEST_CASES.items():
            if only is not None and name != only:
                continue
            if not case():
                print(f"self-test: {name}: FAILED")
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    if with_repo and only is None:
        real = next(entry for entry in entries if entry["command"] == "host" and entry["expect"] == "caught")
        still_passing = "tests::compaction_keeps_a_skill_node"
        got = falsify(dict(real, tests=real["tests"] + [still_passing]))
        print(f"self-test: {real['id']} with {still_passing} added -> {got[1]} ({got[2]})")
        if got[:2] != (False, "SURVIVED") or still_passing not in got[2]:
            ok = False
        got = falsify(real)
        print(f"self-test: {real['id']} as listed -> {got[1]}")
        if got[:2] != (True, "CAUGHT"):
            ok = False
    if only is not None:
        print(case_marker(only, "OK" if ok else "FAILED"))
        return ok
    print("self-test:", "OK" if ok else "FAILED")
    return ok


def stop_on_term(*_):
    raise KeyboardInterrupt


def main(argv):
    signal.signal(signal.SIGTERM, stop_on_term)
    parsed = parse_argv(argv)
    # --keep-backups is for a self-test that runs on a mutated copy of this
    # file: the backup belongs to the caller's mutation, not to a killed run.
    if not parsed.keep_backups:
        recover_backups()
    entries = load(parsed.path)
    if parsed.mode == "list":
        for entry in entries:
            print(f"{entry['id']:6} {entry['command']:8} {entry['expect']:13} {entry['title']}")
        return 0
    if parsed.mode == "self-test-cases":
        for name in SELF_TEST_CASES:
            print(name)
        return 0
    if parsed.mode == "self-test-case":
        name = parsed.name
        if name not in SELF_TEST_CASES:
            print(f"no self-test case named {name}")
            return CASE_USAGE
        try:
            ok = self_test(entries, False, only=name)
        except BaseException as error:
            # The case did not complete, so its name must not carry a verdict.
            print(f"self-test case {name!r}: ERROR: {type(error).__name__}: {error}")
            return CASE_ERROR
        return CASE_PASSED if ok else CASE_FAILED
    if parsed.mode == "self-test":
        return 0 if self_test(entries, parsed.with_repo) else 1
    chosen = [entry for entry in entries if not parsed.filters or any(
        entry["id"] == arg or entry["id"].startswith(arg) for arg in parsed.filters)]
    if not chosen:
        print("no falsifier matches", " ".join(parsed.filters))
        return 2
    counts = {}
    bad = []
    ran_e2e = False
    stopped_for_disk = False
    try:
        for entry in chosen:
            start = time.monotonic()
            ok, word, detail = reported(entry)
            ran_e2e |= entry["command"] == "e2e"
            counts[word] = counts.get(word, 0) + 1
            if not ok:
                bad.append(entry["id"])
            print(f"{entry['id']:6} {word:30} {time.monotonic() - start:5.0f}s  {entry['title']}"
                  + (f"\n       {detail}" if detail else ""), flush=True)
    except DiskFull as error:
        stopped_for_disk = True
        print(f"stopped: disk full ({error}); every file is restored")
        if ran_e2e:
            print("the guest rebuild is deferred until there is free space; "
                  "the next e2e run builds before its tests")
        return 3
    except KeyboardInterrupt:
        print("stopped: interrupted; every file is restored")
        return 1
    finally:
        if ran_e2e and not stopped_for_disk:
            # run-e2e.sh rebuilt the guest from a mutated source; build it again.
            # A full disk cannot build, so that rebuild waits for free space.
            subprocess.run(["bash", str(HERE / "build.sh")], cwd=REPO, capture_output=True)
    print("summary:", ", ".join(f"{count} {word}" for word, count in sorted(counts.items())),
          f"of {len(chosen)}")
    if bad:
        print("not as expected:", " ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
