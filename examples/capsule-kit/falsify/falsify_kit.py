"""The capsule kit's mutation runner (kit item A4).

A falsifier breaks one check by replacing exact text in a file, requires the
mutant to compile, runs EVERY test named for it, and requires EVERY one to
FAIL. A case where any named test still passes is reported as SURVIVED, with
the tests that passed: a named test that does not notice the mutant proves
nothing about it. The file is restored from its saved bytes afterwards, also
on error or Ctrl-C. Each capsule's falsify scripts keep only their cases and say how to run
their tests; this module does the rest. Moved here from the photo viewer's and
the documents viewer's runners.

A case is (name, path, replacements, tests[, appends]):
- path: the file to change (a link is followed, so a shared source is changed
  where it lives);
- replacements: [(old, new)]; each old text must occur exactly once;
- tests: a list of whatever the capsule's `test_fails` function takes, one per
  named test;
- appends: optional [(path, text)] added to other files while the case runs.

Scripts import it with `sys.path.insert(0, <kit>/falsify)`, so they still run
with `python3 -I`.
"""
import os
import pathlib
import re
import subprocess
import sys


def env():
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return environment


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, env=env(), capture_output=True, text=True)


def check(cases):
    """Every old text occurs exactly once in its file."""
    for case in cases:
        name, path, replacements = case[0], pathlib.Path(case[1]), case[2]
        text = path.read_text()
        for old, _ in replacements:
            if text.count(old) != 1:
                raise SystemExit(f"{name}: expected the text once in {path}, found {text.count(old)}")


def falsify(cases, prepare, test_fails, parts=(), show_tests=False):
    """Runs each case whose name holds one of `parts` (all if none).

    `prepare()` builds the mutant once (and stops the run if it does not
    compile); it may be None. `test_fails(test)` runs one named test and says
    whether it failed. Every named test is run, even after one has failed,
    and the case is caught only if all of them failed. Returns the names of
    the cases that survived."""
    missed = []
    for case in cases:
        name, path, replacements, tests = case[:4]
        appends = case[4] if len(case) > 4 else []
        if parts and not any(part in name for part in parts):
            continue
        path = pathlib.Path(path)
        touched = [path] + [pathlib.Path(other) for other, _ in appends]
        saved = {each: each.read_bytes() for each in touched}
        try:
            text = saved[path].decode()
            for old, new in replacements:
                text = text.replace(old, new)
            path.write_text(text)
            for other, extra in appends:
                other = pathlib.Path(other)
                other.write_text(other.read_text() + extra)
            if prepare is not None:
                prepare()
            results = [(test, test_fails(test)) for test in tests]
        finally:
            for each, data in saved.items():
                each.write_bytes(data)
        survivors = [test for test, failed in results if not failed]
        caught = bool(results) and not survivors
        suffix = f" -> {', '.join(map(str, tests))}" if show_tests else ""
        if caught:
            print(f"caught: {name}{suffix}", flush=True)
        else:
            passed = ", ".join(map(str, survivors)) or "no test named"
            print(f"SURVIVED: {name}{suffix} (still passing: {passed})", flush=True)
            missed.append(name)
    return missed


def cargo_compiles(cwd, args):
    """A mutant that does not compile proves nothing: stop the run."""
    build = run(["cargo", "test", "--locked", *args, "--no-run"], cwd)
    if build.returncode != 0:
        print(build.stderr[-3000:])
        raise SystemExit("a falsifier does not compile")


def cargo_test_fails(cwd, args, name):
    """Runs one test by its exact name; it must exist."""
    result = run(["cargo", "test", "--locked", *args, "--", "--exact", name], cwd)
    if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
        raise SystemExit(f"no test {name} in {cwd}\n{result.stdout[-1500:]}{result.stderr[-1500:]}")
    return result.returncode != 0


def node_test_fails(test_file, name):
    """Runs the node tests whose names match; the named test must run and
    fail. A test file that does not load, or a name that no test has, stops
    the run: a startup error proves nothing about the mutant."""
    result = subprocess.run(
        [
            "node",
            "--test",
            "--test-reporter=tap",
            f"--test-name-pattern={name}",
            str(test_file),
        ],
        capture_output=True,
        text=True,
    )
    out = result.stdout
    if "TAP version 13" not in out:
        raise SystemExit(
            f"{test_file} did not load: {(result.stderr or out).strip()[-1500:]}"
        )
    # The runner calls this with a name pattern, as `--test-name-pattern`
    # does. Every test that matches must have run and failed: one that ran
    # and passed, or no result at all, proves nothing about the mutant.
    pattern = re.compile(name)
    matched_subtest = False
    results = []
    for line in out.splitlines():
        subtest = re.match(r"^\s*# Subtest: (.*)$", line)
        if subtest:
            if pattern.search(subtest.group(1)):
                matched_subtest = True
            continue
        result_line = re.match(r"^\s*(not ok|ok) \d+ - (.*?)(?:\s+#.*)?$", line)
        if result_line and pattern.search(result_line.group(2)):
            results.append(result_line.group(1) == "not ok")
    if results:
        return all(results)
    if matched_subtest:
        raise SystemExit(f"no result for test {name!r} in {test_file}")
    # A file that fails while loading reports itself as a failing test named
    # after the file; anything else means the name matched nothing.
    base = pathlib.Path(test_file).name
    wrapper = None
    for line in out.splitlines():
        match = re.match(r"^\s*(not ok|ok) \d+ - (.*)$", line)
        if match and match.group(2) in (str(test_file), base):
            wrapper = match.group(1)
            break
    if wrapper == "not ok":
        raise SystemExit(f"{test_file} did not load:\n{out.strip()[-1500:]}")
    raise SystemExit(f"no test matches {name!r} in {test_file}")


def main(groups, args=None, done="all falsifiers caught"):
    """`groups`: [(cases, prepare, test_fails, flag or None, show_tests)]. A
    group with a flag runs only when that flag is given. --check confirms every anchor;
    other arguments filter cases by name."""
    args = sys.argv[1:] if args is None else args
    parts = [arg for arg in args if not arg.startswith("--")]
    for cases, *_ in groups:
        check(cases)
    if "--check" in args:
        print(f"all {sum(len(cases) for cases, *_ in groups)} anchors found once")
        return
    missed = []
    for cases, prepare, test_fails, flag, show_tests in groups:
        if flag is None or flag in args:
            missed += falsify(cases, prepare, test_fails, parts, show_tests)
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) survived: {missed}")
    print(done)
