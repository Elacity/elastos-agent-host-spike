#!/usr/bin/env python3
"""Break each agent-host check, see its named tests fail, restore it.

Usage (from anywhere):
  python3 -I examples/agent-host/falsify.py              # every falsifier
  python3 -I examples/agent-host/falsify.py CF           # one prefix
  python3 -I examples/agent-host/falsify.py CL24 TB01    # some ids
  python3 -I examples/agent-host/falsify.py --list       # ids, commands, expectations
  python3 -I examples/agent-host/falsify.py --self-test  # the runner checks itself
  python3 -I examples/agent-host/falsify.py --self-test --with-repo  # and one real falsifier
  python3 -I examples/agent-host/falsify.py --self-test-case NAME  # one named case

The falsifiers are data, in falsifiers.json next to this file. Each one
replaces exact text (found exactly once) in a file and requires every named
test to FAIL. The verdict comes only from exit codes, never from test output:
the mutated code is built first (a build that fails is its own result); then
each named test is listed with `--exact` (exactly one test must match) and
run on its own with `--exact`, and it failed only if that run exits non-zero.
A self-test falsifier names self-test cases instead; each case runs in its own
process (`--self-test-case NAME`), and a name no case answers to is not run.
One named test that still passes means the falsifier SURVIVED. A file is restored from the original's bytes after every
falsifier, also on error, Ctrl-C or SIGTERM, including one that arrives during the replacement itself: the original
is kept as a hard link while the mutated copy is in place, and the restore is a rename, so it needs no free
space. A backup left by a killed run is put back before anything else. The
runner stops when the disk has less than 2 GiB free or a command reports a
full disk.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error, 3 when it stopped for a full disk.
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DATA = HERE / "falsifiers.json"
BACKUP_SUFFIX = ".falsify-original"
MIN_FREE_BYTES = int(os.environ.get("FALSIFY_MIN_FREE_BYTES", 2 * 1024**3))
COMMANDS = ("host", "e2e", "selftest")
SELF_TEST_DIR = HERE / ".falsify-selftest"
DISK_FULL = ("No space left on device", "ENOSPC", "Disk quota exceeded")


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
                os.link(path, backup)
                self.applied.append((path, backup, original))
                tmp = path.with_name(path.name + ".falsify-tmp")
                try:
                    tmp.write_text(text, encoding="utf-8")
                    os.replace(tmp, path)
                finally:
                    if tmp.exists():
                        tmp.unlink()
        except BaseException as error:
            # Python does not call __exit__ when __enter__ raises, and a
            # Ctrl-C or SIGTERM can arrive just after a replacement. Put every
            # original back before the interruption goes on.
            self.__exit__(None, None, None)
            if isinstance(error, OSError) and "No space" in str(error):
                raise DiskFull(str(error)) from error
            raise
        return self

    def __exit__(self, *_):
        for path, backup, original in reversed(self.applied):
            os.replace(backup, path)
            # The rename brings back the original's old mtime; touch it, so
            # cargo does not take the mutated build for a fresh one.
            os.utime(path)
            if path.read_bytes() != original:
                sys.exit(f"{path}: restored bytes differ from the saved original; stop")
        self.applied = []
        return False


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


def run(argv, cwd):
    """Run a command; return its exit code and its output. The output is read
    only to stop on a full disk, never to decide a verdict."""
    env = dict(os.environ, RUST_TEST_THREADS=os.environ.get("RUST_TEST_THREADS", "2"))
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    output = done.stdout + done.stderr
    if any(word in output for word in DISK_FULL):
        raise DiskFull("a command reported a full disk")
    return done.returncode, output


def evaluate(entry, how):
    """(build_failed, outcomes, suite_passed), from exit codes only.
    outcomes maps each named test to "failed", "passed" or "not run"."""
    for argv, cwd in how["build"]:
        if run(argv, cwd)[0] != 0:
            return True, {}, None
    if entry["expect"] == "survives":
        argv, cwd = how["suite"]
        return False, {}, run(argv, cwd)[0] == 0
    argv, cwd, extra = how["one"]
    if entry.get("command") == "selftest":
        # Each named case is its own process, so one case cannot carry a
        # verdict for another. Exit 2 means no case answers to the name.
        outcomes = {}
        for name in entry["tests"]:
            code, _ = run(argv + extra + ["--self-test-case", name], cwd)
            outcomes[name] = "not run" if code == 2 else "failed" if code != 0 else "passed"
        return False, outcomes, None
    outcomes = {}
    for name in entry["tests"]:
        # Exactly one test must answer to the name; the list is read for that
        # count only (a list run prints no test output).
        _, listed = run(argv + extra + ["--exact", name, "--list"], cwd)
        if [line for line in listed.splitlines() if line == f"{name}: test"] != [f"{name}: test"]:
            outcomes[name] = "not run"
            continue
        code, _ = run(argv + extra + ["--exact", name], cwd)
        outcomes[name] = "failed" if code != 0 else "passed"
    return False, outcomes, None


def verdict(entry, build_failed, outcomes, suite_passed):
    """(ok, word, detail): ok is whether the falsifier did what it expects."""
    expect = entry["expect"]
    if expect == "compile_error":
        return (True, "CAUGHT (does not build)", "") if build_failed else (False, "SURVIVED", "it builds")
    if build_failed:
        return False, "BUILD FAILED", "the mutation must build so its tests can fail"
    if expect == "survives":
        if suite_passed:
            return True, "SURVIVED (expected, by design)", ""
        return True, "CAUGHT (listed as a survivor)", ""
    missing = [name for name in entry["tests"] if outcomes.get(name) == "not run"]
    if missing:
        return False, "NOT RUN", "not exactly one test or case by this name: " + ", ".join(missing)
    passing = [name for name in entry["tests"] if outcomes.get(name) != "failed"]
    if passing:
        return False, "SURVIVED", "still pass: " + ", ".join(passing)
    return True, "CAUGHT", ""


def falsify(entry, how=None):
    check_disk()
    with Mutation(entry):
        result = evaluate(entry, how or spec(entry["command"]))
    return verdict(entry, *result)


FAKE_LINE_CRATE = {
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
    fn genuinely_passing() {}

    #[test]
    fn fails_with_a_fake_line() {
        panic!("\\ntest tests::genuinely_passing ... FAILED\\n");
    }
}
""",
}


INTERRUPTION_ENTRY = {
    "id": "ST",
    "command": "host",
    "expect": "caught",
    "edits": [{"file": "interrupted.txt", "old": "original bytes", "new": "mutated bytes"}],
    "tests": [],
}


def interruption_restores():
    """Ctrl-C or SIGTERM right after a replacement: the original comes back
    and the interruption goes on."""
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


def verdict_cases():
    """The verdict logic truth table."""
    ok = True
    two = {"id": "ST", "expect": "caught", "tests": ["a", "b"]}
    cases = [
        ((two, False, {"a": "failed", "b": "passed"}, None), (False, "SURVIVED")),
        ((two, False, {"a": "failed", "b": "failed"}, None), (True, "CAUGHT")),
        ((two, False, {"a": "failed", "b": "not run"}, None), (False, "NOT RUN")),
        ((two, True, {}, None), (False, "BUILD FAILED")),
        (({"id": "ST", "expect": "survives", "tests": []}, False, {}, True), (True, "SURVIVED (expected, by design)")),
        (({"id": "ST", "expect": "compile_error", "tests": []}, False, {}, None), (False, "SURVIVED")),
    ]
    for args, want in cases:
        got = verdict(*args)[:2]
        if got != want:
            print(f"self-test: verdict {args[1:]} -> {got}, want {want}")
            ok = False
    return ok


def fake_line_verdict():
    """Codex's case on a throwaway crate: a passing test and a failing test
    whose panic prints a fake FAILED line for the passing one."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for name, text in FAKE_LINE_CRATE.items():
            path = SELF_TEST_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        how = spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))
        argv, cwd = how["suite"]
        _, output = run(argv, cwd)
        fooled = "test tests::genuinely_passing ... FAILED" in output
        entry = {"id": "ST", "expect": "caught",
                 "tests": ["tests::genuinely_passing", "tests::fails_with_a_fake_line"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: fake FAILED line in the output: {fooled}; verdict -> {got[1]} ({got[2]})")
        if not fooled or got[:2] != (False, "SURVIVED") or "tests::genuinely_passing" not in got[2]:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def case_attribution():
    """A name the runner does not run is never credited: two named cases,
    one failing, one passing, and an unknown name are each decided on their
    own process (Codex at 11dd10e)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(
            "import sys\n"
            "at = sys.argv.index('--self-test-case')\n"
            "name = sys.argv[at + 1]\n"
            "raise SystemExit({'fails': 1, 'passes': 0}.get(name, 2))\n",
            encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        entry = {"id": "ST", "command": "selftest", "expect": "caught",
                 "tests": ["fails", "passes"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: a passing name beside a failing one: {got[1]} ({got[2]})")
        if got[:2] != (False, "SURVIVED") or "passes" not in got[2]:
            ok = False
        unknown = dict(entry, tests=["no-such-case"])
        got = verdict(unknown, *evaluate(unknown, how))
        print(f"self-test: an unknown case name: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def no_rebuild_after_disk_full():
    """A full disk ends the run; the guest rebuild is deferred, not started.
    The mutation in PX58 removes the stop condition, and this case fails."""
    real_run = subprocess.run
    real_load = globals()["load"]
    real_falsify = globals()["falsify"]
    entries = [
        {"id": "S1", "command": "e2e", "expect": "caught", "edits": [],
         "tests": ["a"], "title": "one e2e entry"},
        {"id": "S2", "command": "e2e", "expect": "caught", "edits": [],
         "tests": ["a"], "title": "the entry that reports a full disk"},
    ]
    calls = []

    def fake_falsify(entry):
        if entry["id"] == "S2":
            raise DiskFull("a command reported a full disk")
        return True, "CAUGHT", ""

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    globals()["load"] = lambda: entries
    globals()["falsify"] = fake_falsify
    subprocess.run = fake_run
    try:
        # --keep-backups: the outer process holds this file's mutation backup.
        code = main(["--keep-backups", "S"])
    finally:
        subprocess.run = real_run
        globals()["load"] = real_load
        globals()["falsify"] = real_falsify
    rebuilt = [argv for argv in calls if any("build.sh" in part for part in argv)]
    print(f"self-test: disk-full stop: exit={code}, guest rebuilds={len(rebuilt)}")
    return code == 3 and not rebuilt


# Each self-test case is named, so a falsifier names one and the runner runs
# it on its own. A name not listed here is not a case: the runner reports it
# as not run, never as caught.
SELF_TEST_CASES = {
    "verdict cases": verdict_cases,
    "fake FAILED line in the output": fake_line_verdict,
    "interruption during replacement": interruption_restores,
    "named case attribution": case_attribution,
    "no rebuild after a full disk": no_rebuild_after_disk_full,
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
        real = next(entry for entry in entries if entry["id"] == "TB01")
        still_passing = "tests::a_child_without_a_budget_is_refused"
        got = falsify(dict(real, tests=real["tests"] + [still_passing]))
        print(f"self-test: TB01 with {still_passing} added -> {got[1]} ({got[2]})")
        if got[:2] != (False, "SURVIVED") or still_passing not in got[2]:
            ok = False
        got = falsify(real)
        print(f"self-test: TB01 as listed -> {got[1]}")
        if got[:2] != (True, "CAUGHT"):
            ok = False
    if only is not None:
        print(f"self-test case {only!r}: {'OK' if ok else 'FAILED'}")
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
            print(f"{entry['id']:6} {entry['command']:4} {entry['expect']:13} {entry['title']}")
        return 0
    if "--self-test-cases" in argv:
        for name in SELF_TEST_CASES:
            print(name)
        return 0
    if "--self-test-case" in argv:
        at = argv.index("--self-test-case")
        if at + 1 >= len(argv):
            print("--self-test-case needs a name")
            return 2
        name = argv[at + 1]
        if name not in SELF_TEST_CASES:
            print(f"no self-test case named {name}")
            return 2
        return 0 if self_test(entries, False, only=name) else 1
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
