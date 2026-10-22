#!/usr/bin/env python3
"""Break each agent-host check, see its named tests fail, restore it.

Usage (from anywhere):
  python3 -I examples/agent-host/falsify.py              # every falsifier
  python3 -I examples/agent-host/falsify.py CF           # one prefix
  python3 -I examples/agent-host/falsify.py CL24 TB01    # some ids
  python3 -I examples/agent-host/falsify.py --list       # ids, commands, expectations
  python3 -I examples/agent-host/falsify.py --self-test  # the runner checks itself

The falsifiers are data, in falsifiers.json next to this file. Each one
replaces exact text (found exactly once) in a file, runs its command, and
requires every named test to FAIL. One named test that still passes means the
falsifier SURVIVED. A file is restored from the original's bytes after every
falsifier, also on error or Ctrl-C: the original is kept as a hard link while
the mutated copy is in place, and the restore is a rename, so it needs no free
space. A backup left by a killed run is put back before anything else. The
runner stops when the disk has less than 2 GiB free or a command reports a
full disk.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error, 3 when it stopped for a full disk.
"""
import json
import os
import pathlib
import re
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
COMMANDS = {
    "host": ["cargo", "test", "--locked", "--manifest-path", str(HERE / "Cargo.toml")],
    "e2e": ["bash", str(HERE / "run-e2e.sh")],
}
TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", re.M)
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

    def __init__(self, entry):
        self.entry = entry
        self.applied = []  # (path, backup, original bytes)

    def __enter__(self):
        by_file = {}
        for edit in self.entry["edits"]:
            by_file.setdefault(edit["file"], []).append(edit)
        texts = {}
        for name, edits in by_file.items():
            path = HERE / name
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
        except OSError as error:
            self.__exit__(None, None, None)
            if "No space" in str(error):
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


def run_command(command):
    env = dict(os.environ, RUST_TEST_THREADS=os.environ.get("RUST_TEST_THREADS", "2"))
    done = subprocess.run(COMMANDS[command], cwd=REPO, env=env, capture_output=True, text=True)
    log = done.stdout + done.stderr
    if any(word in log for word in DISK_FULL):
        raise DiskFull("the command reported a full disk")
    results = {name: state for name, state in TEST_LINE.findall(log)}
    built = bool(results) or "test result:" in log
    compile_error = not built and ("could not compile" in log or "error[" in log)
    return results, compile_error, done.returncode


def verdict(entry, results, compile_error):
    """(ok, word, detail): ok is whether the falsifier did what it expects."""
    expect = entry["expect"]
    if expect == "compile_error":
        return (True, "CAUGHT (does not build)", "") if compile_error else (False, "SURVIVED", "it builds")
    if compile_error:
        return False, "BUILD FAILED", "the mutation must build so its tests can fail"
    failed = sorted(name for name, state in results.items() if state == "FAILED")
    if expect == "survives":
        if failed:
            return True, "CAUGHT (listed as a survivor)", ", ".join(failed)
        return True, "SURVIVED (expected, by design)", ""
    missing = [name for name in entry["tests"] if name not in results]
    if missing:
        return False, "NOT RUN", "named tests not in the output: " + ", ".join(missing)
    passing = [name for name in entry["tests"] if results[name] != "FAILED"]
    if passing:
        return False, "SURVIVED", "still pass: " + ", ".join(passing)
    extra = [name for name in failed if name not in entry["tests"]]
    return True, "CAUGHT", (f"also failed: {', '.join(extra)}" if extra else "")


def falsify(entry):
    check_disk()
    with Mutation(entry):
        results, compile_error, _ = run_command(entry["command"])
    return verdict(entry, results, compile_error)


def self_test(entries):
    """The verdict logic, then one real falsifier with a passing name added."""
    ok = True
    two = {"id": "ST", "expect": "caught", "tests": ["a", "b"]}
    cases = [
        (two, {"a": "FAILED", "b": "ok"}, False, (False, "SURVIVED")),
        (two, {"a": "FAILED", "b": "FAILED"}, False, (True, "CAUGHT")),
        (two, {"a": "FAILED"}, False, (False, "NOT RUN")),
        (two, {}, True, (False, "BUILD FAILED")),
        ({"id": "ST", "expect": "survives", "tests": []}, {"a": "ok"}, False, (True, "SURVIVED (expected, by design)")),
        ({"id": "ST", "expect": "compile_error", "tests": []}, {"a": "ok"}, False, (False, "SURVIVED")),
    ]
    for entry, results, compile_error, want in cases:
        got = verdict(entry, results, compile_error)[:2]
        if got != want:
            print(f"self-test: verdict {results} -> {got}, want {want}")
            ok = False
    real = next(entry for entry in entries if entry["id"] == "TB01")
    still_passing = "tests::a_child_without_a_budget_is_refused"
    widened = dict(real, tests=real["tests"] + [still_passing])
    got = falsify(widened)
    print(f"self-test: TB01 with {still_passing} added -> {got[1]} ({got[2]})")
    if got[:2] != (False, "SURVIVED") or still_passing not in got[2]:
        ok = False
    got = falsify(real)
    print(f"self-test: TB01 as listed -> {got[1]}")
    if got[:2] != (True, "CAUGHT"):
        ok = False
    print("self-test:", "OK" if ok else "FAILED")
    return ok


def stop_on_term(*_):
    raise KeyboardInterrupt


def main(argv):
    signal.signal(signal.SIGTERM, stop_on_term)
    recover_backups()
    entries = load()
    if "--list" in argv:
        for entry in entries:
            print(f"{entry['id']:6} {entry['command']:4} {entry['expect']:13} {entry['title']}")
        return 0
    if "--self-test" in argv:
        return 0 if self_test(entries) else 1
    chosen = [entry for entry in entries if not argv or any(
        entry["id"] == arg or entry["id"].startswith(arg) for arg in argv)]
    if not chosen:
        print("no falsifier matches", " ".join(argv))
        return 2
    counts = {}
    bad = []
    ran_e2e = False
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
        print(f"stopped: disk full ({error}); every file is restored")
        return 3
    except KeyboardInterrupt:
        print("stopped: interrupted; every file is restored")
        return 1
    finally:
        if ran_e2e:
            # run-e2e.sh rebuilt the guest from a mutated source; build it again.
            subprocess.run(["bash", str(HERE / "build.sh")], cwd=REPO, capture_output=True)
    print("summary:", ", ".join(f"{count} {word}" for word, count in sorted(counts.items())),
          f"of {len(chosen)}")
    if bad:
        print("not as expected:", " ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
