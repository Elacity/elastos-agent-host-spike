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
test to FAIL. The mutated code is built first (a build that fails is its own
result); then each named test is listed with `--exact` (exactly one test must
match) and run alone with `--exact`. A non-zero exit alone is not a catch: the
harness's own run must name the test, close with a summary that says it ran
and failed, exit with its own code for that result, and report no error or
crash of its own on stderr. A harness error, a loading error or a killed
process is NOT RUN and never a catch. One named test that still passes means
SURVIVED. Both modes ask one catch decision: a `survives` entry that stops
surviving is a catch only when that proof passes, and a `compile_error` entry
reports a failed build as its own result, never as a catch.

The original file's bytes are kept as a hard link while the mutated copy is
in place, and the restore is a rename, so it needs no free space. Every
mutation runs inside guard_mutation, whose finally holds the restore in its
own frame: an interrupt during the edit, at the edit's own return, or before
the restore takes its own guard restores before the error propagates (the
last case is retried), and signals stay blocked until every original is back.
A backup left by a killed run is put back before anything else. The runner
stops when the disk has less than 2 GiB free or a command reports a full
disk.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error, 3 when it stopped for a full disk.
"""
import json
import dis
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import namedtuple

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DATA = HERE / "falsifiers.json"
BACKUP_SUFFIX = ".falsify-original"
MIN_FREE_BYTES = int(os.environ.get("FALSIFY_MIN_FREE_BYTES", 2 * 1024**3))
COMMANDS = ("host", "e2e", "selftest")
SELF_TEST_DIR = HERE / ".falsify-selftest"
DISK_FULL = ("No space left on device", "ENOSPC", "Disk quota exceeded")
# The test harness prints this line after every run of the binary. A panic in
# a test body can print anything, including a fake FAILED line, before it.
TEST_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;", re.MULTILINE)
# A named self-test case runs in its own process. A non-zero exit alone does
# not say the case ran: a loading error also exits non-zero. The child prints
# one marker line only after the case returns, and the runner requires both.
CASE_PASSED = 0
CASE_FAILED = 1
CASE_USAGE = 2
CASE_ERROR = 3


def case_marker(name, word):
    return f"self-test case {name!r}: {word}"


class DiskFull(Exception):
    pass


def load():
    doc = json.loads(DATA.read_text(encoding="utf-8"))
    entries = doc["falsifiers"]
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        sys.exit("falsifiers.json: an id is used twice")
    for entry in entries:
        if entry["command"] not in COMMANDS or entry["expect"] not in (
            "caught",
            "compile_error",
            "survives",
        ):
            sys.exit(f"falsifiers.json: {entry['id']}: unknown command or expect")
        if entry["expect"] == "caught" and not entry["tests"]:
            sys.exit(f"falsifiers.json: {entry['id']}: no named tests")
    return entries


def recover_backups():
    """Put back any original left by a run that was killed mid-falsifier."""
    for backup in HERE.rglob("*" + BACKUP_SUFFIX):
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


class Mutation:
    """One falsifier's edits, applied by apply() and undone by restore().
    guard_mutation is the only way in: it holds the restore in its own frame."""

    def __init__(self, entry, base=HERE):
        self.entry = entry
        self.base = base
        self.applied = []  # (path, backup, original bytes)

    def apply(self):
        by_file = {}
        for edit in self.entry["edits"]:
            by_file.setdefault(edit["file"], []).append(edit)
        texts = {}
        for name, edits in by_file.items():
            path = self.base / name
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
                # Record the backup before making it: an interrupt between the
                # link and the next line leaves the source unchanged, and a
                # backup that does exist is still restored.
                self.applied.append((path, backup, original))
                os.link(path, backup)
                tmp = path.with_name(path.name + ".falsify-tmp")
                try:
                    tmp.write_text(text, encoding="utf-8")
                    os.replace(tmp, path)
                finally:
                    if tmp.exists():
                        tmp.unlink()
        except BaseException as error:
            # guard_mutation's finally puts the originals back, for a Ctrl-C
            # or SIGTERM just after a replacement too. This frame only adds
            # the disk-full reason.
            if isinstance(error, OSError) and "No space" in str(error):
                raise DiskFull(str(error)) from error
            raise

    def restore(self):
        saved = block_interruptions()
        try:
            for path, backup, original in reversed(self.applied):
                if not backup.exists():
                    continue
                os.replace(backup, path)
                # The rename brings back the original's old mtime; touch it, so
                # cargo does not take the mutated build for a fresh one.
                os.utime(path)
                if path.read_bytes() != original:
                    raise SystemExit(f"{path}: restored bytes differ from the saved original; stop")
            self.applied = []
        finally:
            restore_interruptions(saved)


def guard_mutation(entry, body, base=HERE):
    """Apply the edits, run body(), and always put the originals back.

    Every mutation goes through here. The restore loop sits in this frame's
    finally, so an interrupt at the return boundary of apply(), in body(), at
    the return of body(), or at the call that starts the restoration itself is
    caught and the restoration runs again. applied empties only after every
    original is back; the interrupt that came in goes on after that."""
    mutation = Mutation(entry, base)
    try:
        mutation.apply()
        return body()
    finally:
        pending = None
        while True:
            try:
                mutation.restore()
                break
            except KeyboardInterrupt as error:
                if not mutation.applied:
                    raise
                pending = error
        if pending is not None:
            raise pending


def spec(command, manifest=None, cargo_flags=("--locked",)):
    """How to build, run one test, and run the whole suite, for a command."""
    if command == "host":
        cargo = ["cargo", "test", *cargo_flags, "--manifest-path", str(manifest or HERE / "Cargo.toml")]
        return {
            "build": [(cargo + ["--no-run"], REPO)],
            "one": (cargo + ["--"], REPO, []),
            "suite": (cargo, REPO),
        }
    if command == "selftest":
        # A change to this runner is checked by its own self-test. A fresh
        # process reads the mutated file; --keep-backups stops it from taking
        # this run's backup of falsify.py for a killed run's leftover. Each
        # named case runs in its own process, as each named test does.
        base = ["python3", "-I", str(HERE / "falsify.py"), "--keep-backups"]
        return {"build": [], "one": (base, REPO, []), "suite": (base + ["--self-test"], REPO)}
    cargo = ["cargo", "test", "-p", "elastos-server", "--lib"]
    return {
        "build": [(["bash", str(HERE / "build.sh")], REPO), (cargo + ["--no-run"], REPO / "elastos")],
        "one": (cargo + ["--"], REPO / "elastos", ["--ignored"]),
        "suite": (["bash", str(HERE / "run-e2e.sh")], REPO),
    }


Finished = namedtuple("Finished", "code stdout stderr output")


def run(argv, cwd):
    """Run a command. The stdout is read for the harness's own run and closing
    summary; the stderr is read for an error the harness reported itself; the
    combined output is read only to stop on a full disk."""
    env = dict(os.environ, RUST_TEST_THREADS=os.environ.get("RUST_TEST_THREADS", "2"))
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    output = done.stdout + done.stderr
    if any(word in output for word in DISK_FULL):
        raise DiskFull("a command reported a full disk")
    return Finished(done.returncode, done.stdout, done.stderr, output)


# A harness starts each run with this line; a test body cannot print after the
# summary of its own run, so the run's last summary line is the harness's own.
RUN_HEADER = re.compile(r"^running (\d+) tests?$", re.MULTILINE)
# Cargo prints this line after a run whose named test really did fail; any
# other error line on stderr comes from the harness itself, before or instead
# of a run. A crashed test binary makes cargo add a "Caused by: ... didn't
# exit successfully" block, so the run did not complete.
CARGO_TEST_FAILED = "error: test failed, to rerun pass "
CRASHED = "didn't exit successfully"
# libtest exits 101 when a test fails and 0 when every test passes. Any other
# code is a crash or a tool failure, not a run.
TEST_FAILURE = 101


def harness_error(stderr):
    """True when stderr reports an error that is not cargo's line for a
    completed, failed run, or reports that the test process crashed. A loading
    error or a crash is not a run."""
    if CRASHED in stderr:
        return True
    errors = [line for line in stderr.splitlines() if line.startswith("error:")]
    return any(not line.startswith(CARGO_TEST_FAILED) for line in errors)


def run_blocks(stdout):
    """The body of each run a harness starts with "running N tests"; a body
    ends where the next run starts."""
    starts = list(RUN_HEADER.finditer(stdout))
    return [stdout[match.end():starts[at + 1].start() if at + 1 < len(starts) else len(stdout)]
            for at, match in enumerate(starts)]


def summary_at_the_end(body):
    """The summary that ends a run, or None. A test body can print a fake
    summary inside the run, but its text comes before the harness's summary."""
    lines = [line for line in body.splitlines() if line.strip()]
    match = TEST_RESULT.match(lines[-1]) if lines else None
    return (match.group(1), int(match.group(2)), int(match.group(3))) if match else None


def named_outcome(result, name):
    """failed, passed or not run, from the run that names this test. No run
    that names it, no closing summary for that run, or an error the harness
    reported itself means it did not run."""
    if harness_error(result.stderr):
        return "not run"
    for body in run_blocks(result.stdout):
        if f"test {name} ... " not in body:
            continue
        summary = summary_at_the_end(body)
        if summary is None:
            return "not run"
        status, passed, failed = summary
        if status == "FAILED" and failed >= 1:
            return "failed"
        if status == "ok" and passed >= 1:
            return "passed"
        return "not run"
    return "not run"


def named_outcomes(entry, how):
    """Map each named test to "failed", "passed" or "not run". Every mode
    that reports a catch uses this one proof."""
    argv, cwd, extra = how["one"]
    outcomes = {}
    for name in entry["tests"]:
        if entry.get("command") == "selftest":
            # Each named case is its own process, so one case cannot carry a
            # verdict for another. The case counts only when the child exits
            # with its result AND prints the marker it writes after the case
            # returns. A loading error, an unknown name, or a signal is not run.
            result = run(argv + extra + ["--self-test-case", name], cwd)
            lines = result.stdout.splitlines()
            if result.code == CASE_PASSED and case_marker(name, "OK") in lines:
                outcomes[name] = "passed"
            elif result.code == CASE_FAILED and case_marker(name, "FAILED") in lines:
                outcomes[name] = "failed"
            else:
                outcomes[name] = "not run"
            continue
        # Exactly one test must answer to the name; the list is read for that
        # count only (a list run prints no test output).
        listed = run(argv + extra + ["--exact", name, "--list"], cwd).stdout
        if [line for line in listed.splitlines() if line == f"{name}: test"] != [f"{name}: test"]:
            outcomes[name] = "not run"
            continue
        result = run(argv + extra + ["--exact", name], cwd)
        # The run's own closing summary must name the test and end a run with
        # no harness error or crash; the exit code must be the harness's own
        # code for that result, so a killed or broken process is not a run.
        proof = named_outcome(result, name)
        if proof == "failed" and result.code != TEST_FAILURE:
            proof = "not run"
        elif proof == "passed" and result.code != 0:
            proof = "not run"
        outcomes[name] = proof
    return outcomes


def evaluate(entry, how):
    """(build_failed, outcomes, suite_passed). outcomes maps each named test to
    "failed", "passed" or "not run"; suite_passed says whether the whole suite
    ran clean for a survives entry."""
    for argv, cwd in how["build"]:
        if run(argv, cwd).code != 0:
            return True, {}, None
    if entry["expect"] == "survives":
        argv, cwd = how["suite"]
        suite_passed = run(argv, cwd).code == 0
        # A suite that fails is not a catch by itself: prove it the same way
        # every mode proves a catch, with its named tests.
        return False, {} if suite_passed else named_outcomes(entry, how), suite_passed
    return False, named_outcomes(entry, how), None


def catch_proof(tests, outcomes):
    """(proved, missing, passing): the one catch decision. A catch is proved
    only when every named test ran and failed; every mode that reports one
    asks this function."""
    missing = [name for name in tests if outcomes.get(name) == "not run"]
    passing = [name for name in tests if outcomes.get(name) != "failed"]
    return not missing and not passing, missing, passing


def verdict(entry, build_failed, outcomes, suite_passed):
    """(ok, word, detail): ok is whether the falsifier did what it expects."""
    expect = entry["expect"]
    if expect == "compile_error":
        # A failed build is its own result. No named test ran, so it cannot
        # claim a catch, which is reserved for the named-test proof.
        if build_failed:
            return True, "COMPILE ERROR (as expected)", ""
        return False, "SURVIVED", "it builds"
    if build_failed:
        return False, "BUILD FAILED", "the mutation must build so its tests can fail"
    if expect == "survives" and suite_passed:
        return True, "SURVIVED (expected, by design)", ""
    proved, missing, passing = catch_proof(entry["tests"], outcomes)
    if not proved:
        if not entry["tests"]:
            return False, "SUITE FAILED (not a catch)", "no named tests to prove it"
        if expect == "survives":
            return (False, "SUITE FAILED (not a catch)",
                    "no proof: " + ", ".join(dict.fromkeys(missing + passing)))
        if missing:
            return False, "NOT RUN", "did not run: " + ", ".join(missing)
        return False, "SURVIVED", "still pass: " + ", ".join(passing)
    return True, "CAUGHT", ""


def falsify(entry, how=None):
    check_disk()
    result = guard_mutation(entry, lambda: evaluate(entry, how or spec(entry["command"])))
    return verdict(entry, *result)


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

# The test body prints its own run header, test line and summary on stdout,
# then the harness reports an error on stderr. The fabricated summary ends a
# run, so only a clean stderr keeps it from counting.
STUB_FAKE_SUMMARY_THEN_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: could not load the test harness", file=sys.stderr)
raise SystemExit(101)
"""

# The same fabricated run with the error left on stdout: it ends the run, so
# the closing-summary rule alone rejects it.
STUB_FAKE_SUMMARY_ERROR_ON_STDOUT = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: could not load the test harness")
raise SystemExit(101)
"""

# The child lists the test, prints a fabricated run and failure summary, then
# dies by signal. No test body ran and libtest wrote no summary.
STUB_FAKE_SUMMARY_THEN_SIGNAL = """import os
import signal
import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stdout.flush()
os.kill(os.getpid(), signal.SIGTERM)
"""

# The same fabrication with cargo's exit code and crash block, as when a test
# binary dies by signal under cargo test.
STUB_FAKE_SUMMARY_CARGO_CRASH = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: test failed, to rerun pass `--lib`", file=sys.stderr)
print("\\nCaused by:\\n  process didn't exit successfully: `binary` (signal: 15, SIGTERM: termination signal)", file=sys.stderr)
raise SystemExit(101)
"""

STUB_FILTERED_OUT = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out")
raise SystemExit(0)
"""

STUB_SUITE_ERROR = """import sys
print("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_SUITE_FAILS_AND_TEST_FAILS = """import sys
name = sys.argv[sys.argv.index('--exact') + 1] if '--exact' in sys.argv else 'tests::planted_check'
if '--list' in sys.argv:
    print(f"{name}: test")
    raise SystemExit(0)
print("running 1 test")
print(f"test {name} ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_SUITE_FAILS_TEST_PASSES = """import sys
name = sys.argv[sys.argv.index('--exact') + 1] if '--exact' in sys.argv else 'tests::planted_check'
if '--list' in sys.argv:
    print(f"{name}: test")
    raise SystemExit(0)
if '--exact' in sys.argv:
    print("running 1 test")
    print(f"test {name} ... ok")
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
    raise SystemExit(0)
print("running 1 test")
print(f"test {name} ... FAILED")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
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
    survivor = {"id": "ST", "expect": "survives", "tests": ["a"]}
    cases = [
        ((two, False, {"a": "failed", "b": "passed"}, None), (False, "SURVIVED")),
        ((two, False, {"a": "failed", "b": "failed"}, None), (True, "CAUGHT")),
        ((two, False, {"a": "failed", "b": "not run"}, None), (False, "NOT RUN")),
        ((two, True, {}, None), (False, "BUILD FAILED")),
        (({"id": "ST", "expect": "survives", "tests": []}, False, {}, True), (True, "SURVIVED (expected, by design)")),
        ((survivor, False, {"a": "failed"}, False), (True, "CAUGHT")),
        ((survivor, False, {}, False), (False, "SUITE FAILED (not a catch)")),
        ((survivor, False, {"a": "not run"}, False), (False, "SUITE FAILED (not a catch)")),
        ((survivor, False, {"a": "passed"}, False), (False, "SUITE FAILED (not a catch)")),
        (({"id": "ST", "expect": "compile_error", "tests": []}, False, {}, None), (False, "SURVIVED")),
        # A failed build is its own result, never a catch, even when the entry
        # names tests that did not run (review finding 3).
        (({"id": "ST", "expect": "compile_error", "tests": []}, True, {}, None),
         (True, "COMPILE ERROR (as expected)")),
        (({"id": "ST", "expect": "compile_error", "tests": ["never-ran"]}, True, {}, None),
         (True, "COMPILE ERROR (as expected)")),
    ]
    for args, want in cases:
        got = verdict(*args)[:2]
        if got != want:
            print(f"self-test: verdict {args[1:]} -> {got}, want {want}")
            ok = False
    # One catch decision serves both modes: the decision itself, then each mode
    # against it with the same outcomes.
    proofs = [
        ((("a",), {"a": "failed"}), (True, [], [])),
        ((("a",), {"a": "not run"}), (False, ["a"], ["a"])),
        ((("a",), {"a": "passed"}), (False, [], ["a"])),
        ((("a", "b"), {"a": "failed", "b": "failed"}), (True, [], [])),
        ((("a", "b"), {"a": "failed", "b": "passed"}), (False, [], ["b"])),
    ]
    for args, want in proofs:
        got = catch_proof(*args)
        if got != want:
            print(f"self-test: catch proof {args} -> {got}, want {want}")
            ok = False
    for outcomes, caught, survived in (
        ({"a": "failed"}, (True, "CAUGHT"), (True, "CAUGHT")),
        ({"a": "not run"}, (False, "NOT RUN"), (False, "SUITE FAILED (not a catch)")),
        ({"a": "passed"}, (False, "SURVIVED"), (False, "SUITE FAILED (not a catch)")),
    ):
        for entry, suite, want in ((survivor, False, survived), ({**two, "tests": ["a"]}, None, caught)):
            got = verdict(entry, False, outcomes, suite)[:2]
            if got != want:
                print(f"self-test: mode {entry['expect']} {outcomes} -> {got}, want {want}")
                ok = False
    return ok


def a_named_test_that_does_not_run_is_not_a_catch():
    """Planted failures: no test answers to the name, a harness error exits
    non-zero without running one, and a test body prints a summary line before
    the harness errors. None is a catch (task 004)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "caught", "tests": ["tests::planted_check"]}
        for title, text in (("name is not listed", STUB_LIST_MISSING),
                            ("harness error", STUB_HARNESS_ERROR),
                            ("fake summary then harness error on stderr", STUB_FAKE_SUMMARY_THEN_ERROR),
                            ("fake summary then harness error on stdout", STUB_FAKE_SUMMARY_ERROR_ON_STDOUT),
                            ("fake summary then signal", STUB_FAKE_SUMMARY_THEN_SIGNAL),
                            ("fake summary then cargo crash block", STUB_FAKE_SUMMARY_CARGO_CRASH),
                            ("exit 0 but no test ran", STUB_FILTERED_OUT)):
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


def a_survives_entry_caught_only_with_its_named_tests():
    """A survives entry whose suite fails is a catch only when its named
    tests ran and failed. The suite exit code alone, or a named test that still
    passes, is not a catch (task 004, review finding 3)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        cases = (
            ("suite errors, no test ran", STUB_SUITE_ERROR, (False, "SUITE FAILED (not a catch)")),
            ("suite fails, the named test fails", STUB_SUITE_FAILS_AND_TEST_FAILS, (True, "CAUGHT")),
            ("suite fails, the named test passes", STUB_SUITE_FAILS_TEST_PASSES,
             (False, "SUITE FAILED (not a catch)")),
        )
        for title, text, want in cases:
            stub = SELF_TEST_DIR / "stub.py"
            stub.write_text(text, encoding="utf-8")
            how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, []),
                   "suite": (["python3", "-I", str(stub)], SELF_TEST_DIR)}
            got = verdict(entry, *evaluate(entry, how))
            print(f"self-test: survives entry: {title}: {got[1]} ({got[2]})")
            if got[:2] != want:
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
        guard_mutation(INTERRUPTION_ENTRY, lambda: None, SELF_TEST_DIR)
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
    """An interrupt at apply()'s own return: Python 3.9 pops the handler
    before RETURN_VALUE, so apply cannot restore itself. guard_mutation's
    finally still restores first (task 004, review finding 2)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "boundary.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    at = [instruction.offset for instruction in dis.get_instructions(Mutation.apply)
          if instruction.opname == "RETURN_VALUE"][-1]
    traced = []

    def trace(frame, event, _arg):
        if frame.f_code is Mutation.apply.__code__:
            frame.f_trace_opcodes = True
            if event == "opcode" and frame.f_lasti == at:
                traced.append(frame.f_lasti)
                raise KeyboardInterrupt
        return trace

    entry = {"id": "ST", "command": "host", "expect": "caught",
             "edits": [{"file": "boundary.txt", "old": "original bytes", "new": "mutated bytes"}],
             "tests": []}
    interrupted = False
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        guard_mutation(entry, lambda: None, SELF_TEST_DIR)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sys.settrace(previous)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption at the end of the edit: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return bool(traced) and interrupted and restored and not backup.exists()


def interruption_before_the_restore_runs():
    """A KeyboardInterrupt at the call into Mutation.restore arrives before
    restore() takes its own signal guard. The restoration is retried, the
    original comes back, and only then does the interrupt go on (task 004,
    review finding 2)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "restore-entry.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    injected = []

    def trace(frame, event, _arg):
        if frame.f_code is Mutation.restore.__code__ and event == "call" and not injected:
            injected.append(frame)
            raise KeyboardInterrupt
        return trace

    entry = {"id": "ST", "command": "host", "expect": "caught",
             "edits": [{"file": "restore-entry.txt", "old": "original bytes", "new": "mutated bytes"}],
             "tests": []}
    interrupted = False
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        guard_mutation(entry, lambda: None, SELF_TEST_DIR)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sys.settrace(previous)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption before the restore runs: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return bool(injected) and interrupted and restored and not backup.exists()


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


# Each self-test case is named, so a falsifier names one and the runner runs
# it on its own. A name not listed here is not a case: the runner reports it
# as not run, never as caught.
SELF_TEST_CASES = {
    "verdict cases": verdict_cases,
    "a named test that does not run is not a catch": a_named_test_that_does_not_run_is_not_a_catch,
    "a survives entry is a catch only with its named tests": a_survives_entry_caught_only_with_its_named_tests,
    "an interrupted edit is restored": interruption_restores,
    "an interrupt at the end of the edit is restored": interruption_at_the_end_of_the_edit,
    "an interrupt before the restore runs is retried": interruption_before_the_restore_runs,
    "a real catch counts": real_catch_counts,
    "a self-test case counts only when it ran": a_self_test_case_counts_only_when_it_ran,
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
    # --keep-backups is for a self-test that runs on a mutated copy of this
    # file: the backup belongs to the caller's mutation, not to a killed run.
    if "--keep-backups" not in argv:
        recover_backups()
    entries = load()
    if "--list" in argv:
        for entry in entries:
            print(f"{entry['id']:6} {entry['command']:8} {entry['expect']:13} {entry['title']}")
        return 0
    if "--self-test-cases" in argv:
        for name in SELF_TEST_CASES:
            print(name)
        return 0
    if "--self-test-case" in argv:
        at = argv.index("--self-test-case")
        if at + 1 >= len(argv):
            print("--self-test-case needs a name")
            return CASE_USAGE
        name = argv[at + 1]
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
    if "--self-test" in argv:
        return 0 if self_test(entries, "--with-repo" in argv) else 1
    chosen = [entry for entry in entries if not argv or any(
        entry["id"] == arg or entry["id"].startswith(arg) for arg in argv)]
    if not chosen:
        print("no falsifier matches", " ".join(argv))
        return 2
    counts = {}
    bad = []
    ran_e2e = False
    stopped_for_disk = False
    try:
        for entry in chosen:
            start = time.monotonic()
            try:
                ok, word, detail = falsify(entry)
            except LookupError as error:
                ok, word, detail = False, "NO MATCH", str(error)
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
        left = sorted(str(backup.relative_to(REPO)) for backup in HERE.rglob("*" + BACKUP_SUFFIX))
        if left:
            print("stopped: interrupted; originals left to restore: " + ", ".join(left))
        else:
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
