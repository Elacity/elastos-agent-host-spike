#!/usr/bin/env python3
"""Break each agent-host check, see its named tests fail, restore it.

Usage (from anywhere):
  python3 -I examples/agent-host/falsify.py              # every falsifier
  python3 -I examples/agent-host/falsify.py FS           # one prefix
  python3 -I examples/agent-host/falsify.py FS01 FS03    # some ids
  python3 -I examples/agent-host/falsify.py --list       # ids, commands, expectations
  python3 -I examples/agent-host/falsify.py --list FILE  # run that list (MP01, or ids too)
  python3 -I examples/agent-host/falsify.py --self-test  # the runner checks itself
  python3 -I examples/agent-host/falsify.py --self-test --with-repo  # and one real falsifier
  python3 -I examples/agent-host/falsify.py --self-test-case NAME  # one named case

The falsifiers are data, in falsifiers.json next to this file; `--list FILE`
reads that file instead. Each one replaces exact text (found exactly once) in
a file and requires every named test to FAIL. The verdict comes from exit
codes: the mutated code is built first (a build that fails is its own result);
then each named test is listed
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

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DATA = HERE / "falsifiers.json"
BACKUP_SUFFIX = ".falsify-original"
MIN_FREE_BYTES = int(os.environ.get("FALSIFY_MIN_FREE_BYTES", 2 * 1024**3))
COMMANDS = ("host", "provider", "e2e", "selftest")
EXPECTS = ("caught", "compile_error", "survives")
SELF_TEST_DIR = HERE / ".falsify-selftest"
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


class DiskFull(Exception):
    pass


class ListError(SystemExit):
    """A list that cannot be read or trusted: exit 2, with its own reason.
    SystemExit keeps one refusal type inside load(), and main() turns it into
    the usage status."""

    exit_status = 2


def load(path=DATA):
    if not path.is_file():
        raise ListError(f"{path}: the list file does not exist")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ListError(f"{path}: the list is not JSON: {error}") from error
    if not isinstance(doc, dict) or not isinstance(doc.get("falsifiers"), list):
        raise ListError(f'{path}: the list is not a {{"falsifiers": [...]}} document')
    entries = doc["falsifiers"]
    for entry in entries:
        if not isinstance(entry, dict) or any(
                key not in entry for key in ("id", "command", "expect", "tests")):
            raise ListError(f"{path}: every falsifier needs an id, a command, an expect and a tests list")
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ListError(f"{path}: an id is used twice")
    for entry in entries:
        if entry["command"] not in COMMANDS:
            raise ListError(f"{path}: {entry['id']}: unknown command {entry['command']!r}")
        if entry["expect"] not in EXPECTS:
            raise ListError(f"{path}: {entry['id']}: unknown expectation {entry['expect']!r}")
        if entry["expect"] in ("caught", "survives") and not entry["tests"]:
            kind = "a caught entry" if entry["expect"] == "caught" else "a survives entry"
            raise ListError(f"{path}: {entry['id']}: {kind} needs at least one named test")
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
    if command == "provider":
        # The provider crate is its own workspace: same locked, no-run build
        # and one-test run, against its own manifest.
        cargo = ["cargo", "test", *cargo_flags, "--manifest-path",
                 str(manifest or REPO / "capsules/model-provider/Cargo.toml")]
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


def run_mode(argv):
    """(mode, path, ids): `--list` alone shows the default list (`display`);
    `--list FILE` runs FILE, and a run with no `--list` reads the default
    (`run`). ids are the id or prefix arguments, without the option or the
    path it selected."""
    if "--list" not in argv:
        return "run", DATA, [arg for arg in argv if not arg.startswith("--")]
    at = argv.index("--list")
    if at + 1 >= len(argv) or argv[at + 1].startswith("--"):
        return "display", DATA, []
    return "run", pathlib.Path(argv[at + 1]), [
        arg for index, arg in enumerate(argv)
        if not arg.startswith("--") and index != at + 1]


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
        refused = False
        try:
            load(data)
        except SystemExit as error:
            refused = str(error) == f"{data}: ST: a survives entry needs at least one named test"
        print(f"self-test: a survives entry with no named test: refused={refused}")
        if not refused:
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


def provider_spec_uses_locked_manifest():
    """The provider command builds and runs the provider crate's own tests,
    with the lock held, and names the provider manifest as the option's own
    value, one named test at a time."""
    how = spec("provider")
    build = how["build"][0][0]
    one = how["one"][0]
    manifest = str(REPO / "capsules/model-provider/Cargo.toml")

    def pins_manifest(argv):
        if "--manifest-path" not in argv:
            return False
        at = argv.index("--manifest-path")
        return at + 1 < len(argv) and argv[at + 1] == manifest

    ok = "--locked" in build and "--locked" in one and pins_manifest(build) and pins_manifest(one)
    print(f"self-test: provider build argv: {' '.join(build)}")
    print(f"self-test: provider run argv: {' '.join(one)}")
    return ok


def list_option_selects_path():
    """--list FILE runs FILE for a relative or an absolute path; the argv is
    the only input, so this proves the routing, not just load()."""
    absolute = str(REPO / "capsules/model-provider/falsifiers.json")
    relative = "capsules/model-provider/falsifiers.json"
    got = (run_mode(["--list", relative]), run_mode(["--list", absolute]))
    want = (("run", pathlib.Path(relative), []), ("run", pathlib.Path(absolute), []))
    print(f"self-test: --list paths: {got}")
    return got == want


def the_selected_path_is_not_a_falsifier_id():
    """The path --list selected is not an id or a prefix to match."""
    path = str(REPO / "capsules/model-provider/falsifiers.json")
    got = (run_mode(["--list", path, "MP01"]), run_mode([]), run_mode(["FS01"]))
    want = (("run", pathlib.Path(path), ["MP01"]), ("run", DATA, []), ("run", DATA, ["FS01"]))
    print(f"self-test: ids beside --list: {got}")
    return got == want


def bare_list_option_behavior():
    """A bare --list shows the default list and does not run it."""
    got = run_mode(["--list"])
    print(f"self-test: bare --list: {got}")
    return got == ("display", DATA, [])


def refusal_reason(path):
    """The one reason load() gives for a crafted list, or None when it reads
    the list. Any other error is not a refusal, so the case that expects a
    reason fails on it."""
    try:
        load(path)
    except ListError as error:
        return str(error)
    except Exception as error:
        return f"raised {type(error).__name__}: {error}"
    return None


def the_one_refusal(write):
    """Craft one list, load it, and return (path, reason). The reason is None
    when load() accepted the list."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    try:
        path = SELF_TEST_DIR / "falsifiers.json"
        write(path)
        return path, refusal_reason(path)
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def one_entry(**fields):
    entry = {"id": "ST", "command": "host", "expect": "caught",
             "edits": [], "tests": ["tests::planted_check"]}
    entry.update(fields)
    return json.dumps({"falsifiers": [entry]})


def missing_list_file_is_refused():
    """A list path that does not exist is a refusal with its own reason."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "absent.json"
        reason = refusal_reason(path)
        print(f"self-test: missing list file: {reason}")
        return reason == f"{path}: the list file does not exist"
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def load_reads_the_given_list():
    """load() reads the file it is given, not the default list."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "given.json"
        path.write_text(json.dumps({"falsifiers": [
            {"id": "XY01", "command": "host", "expect": "caught", "edits": [], "tests": ["t"]},
            {"id": "XY02", "command": "selftest", "expect": "survives", "edits": [], "tests": ["t"]},
        ]}), encoding="utf-8")
        got = [entry["id"] for entry in load(path)]
        print(f"self-test: ids from the given list: {got}")
        return got == ["XY01", "XY02"]
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_list_that_is_not_json_is_refused():
    """Text that is not JSON is refused; the reason names the file."""
    path, reason = the_one_refusal(lambda p: p.write_text("not json at all", encoding="utf-8"))
    print(f"self-test: a list that is not JSON: {reason}")
    return reason is not None and reason.startswith(f"{path}: the list is not JSON: ")


def a_list_without_falsifiers_is_refused():
    """A JSON document with no falsifiers list is refused."""
    path, reason = the_one_refusal(
        lambda p: p.write_text(json.dumps({"entries": []}), encoding="utf-8"))
    print(f"self-test: a list without falsifiers: {reason}")
    return reason == f'{path}: the list is not a {{"falsifiers": [...]}} document'


def an_unknown_command_is_refused():
    """A command the runner does not know is refused, with its own reason."""
    path, reason = the_one_refusal(
        lambda p: p.write_text(one_entry(command="curl"), encoding="utf-8"))
    print(f"self-test: an unknown command: {reason}")
    return reason == f"{path}: ST: unknown command 'curl'"


def an_unknown_expectation_is_refused():
    """An expectation the runner does not know is refused, with its own reason."""
    path, reason = the_one_refusal(
        lambda p: p.write_text(one_entry(expect="maybe"), encoding="utf-8"))
    print(f"self-test: an unknown expectation: {reason}")
    return reason == f"{path}: ST: unknown expectation 'maybe'"


def a_caught_entry_needs_named_tests():
    """A caught entry with no named test is refused, with its own reason."""
    path, reason = the_one_refusal(
        lambda p: p.write_text(one_entry(tests=[]), encoding="utf-8"))
    print(f"self-test: a caught entry with no named test: {reason}")
    return reason == f"{path}: ST: a caught entry needs at least one named test"


# Each self-test case is named, so a falsifier names one and the runner runs
# it on its own. A name not listed here is not a case: the runner reports it
# as not run, never as caught.
SELF_TEST_CASES = {
    "provider spec uses the locked manifest": provider_spec_uses_locked_manifest,
    "list option selects its path": list_option_selects_path,
    "the selected path is not a falsifier id": the_selected_path_is_not_a_falsifier_id,
    "bare list option behavior": bare_list_option_behavior,
    "load reads the given list": load_reads_the_given_list,
    "a missing list file is refused": missing_list_file_is_refused,
    "a list that is not JSON is refused": a_list_that_is_not_json_is_refused,
    "a list without falsifiers is refused": a_list_without_falsifiers_is_refused,
    "an unknown command is refused": an_unknown_command_is_refused,
    "an unknown expectation is refused": an_unknown_expectation_is_refused,
    "a caught entry needs named tests": a_caught_entry_needs_named_tests,
    "verdict cases": verdict_cases,
    "a named test that does not run is not a catch": a_named_test_that_does_not_run_is_not_a_catch,
    "an interrupted edit is restored": interruption_restores,
    "an interrupt at the end of the edit is restored": interruption_at_the_end_of_the_edit,
    "the streams keep their own lines": the_streams_keep_their_own_lines,
    "a real catch counts": real_catch_counts,
    "a self-test case counts only when it ran": a_self_test_case_counts_only_when_it_ran,
    "a survivor needs its named test to run": a_survivor_needs_its_named_test_to_run,
    "a survivor is proved by its named tests": a_survivor_is_proved_by_its_named_tests,
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
    mode, path, wanted = run_mode(argv)
    try:
        entries = load(path)
    except ListError as error:
        print(f"falsify.py: {error}", file=sys.stderr)
        return error.exit_status
    if mode == "display":
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
    chosen = [entry for entry in entries if not wanted or any(
        entry["id"] == arg or entry["id"].startswith(arg) for arg in wanted)]
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
