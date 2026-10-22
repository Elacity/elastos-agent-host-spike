"""The capsule kit's mutation runner (kit item A4).

A falsifier breaks one check by replacing exact text in a file, requires the
mutant to compile, runs the tests that must catch it, and requires them to
FAIL. The file is restored from its saved bytes afterwards, also on error or
Ctrl-C. Each capsule's falsify scripts keep only their cases and say how to run
their tests; this module does the rest. Moved here from the photo viewer's and
the documents viewer's runners.

A case is (name, path, replacements, tests[, appends]):
- path: the file to change (a link is followed, so a shared source is changed
  where it lives);
- replacements: [(old, new)]; each old text must occur exactly once;
- tests: whatever the capsule's `failing` function takes;
- appends: optional [(path, text)] added to other files while the case runs.

Scripts import it with `sys.path.insert(0, <kit>/falsify)`, so they still run
with `python3 -I`.
"""
import os
import pathlib
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


def falsify(cases, failing, parts=(), show_tests=False):
    """Runs each case whose name holds one of `parts` (all if none). Returns
    the names of the cases not caught."""
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
            caught = failing(tests)
        finally:
            for each, data in saved.items():
                each.write_bytes(data)
        suffix = f" -> {', '.join(map(str, tests))}" if show_tests else ""
        print(f"{'caught' if caught else 'MISSED'}: {name}{suffix}", flush=True)
        if not caught:
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
    """Runs the node tests whose names match; at least one must exist."""
    result = subprocess.run(
        ["node", "--test", f"--test-name-pattern={name}", str(test_file)], capture_output=True, text=True
    )
    if "# tests 0" in result.stdout:
        raise SystemExit(f"no test matches {name!r}")
    return result.returncode != 0


def main(groups, args=None, done="all falsifiers caught"):
    """`groups`: [(cases, failing, flag or None, show_tests)]. A group with a
    flag runs only when that flag is given. --check confirms every anchor;
    other arguments filter cases by name."""
    args = sys.argv[1:] if args is None else args
    parts = [arg for arg in args if not arg.startswith("--")]
    for cases, *_ in groups:
        check(cases)
    if "--check" in args:
        print(f"all {sum(len(cases) for cases, *_ in groups)} anchors found once")
        return
    missed = []
    for cases, failing, flag, show_tests in groups:
        if flag is None or flag in args:
            missed += falsify(cases, failing, parts, show_tests)
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    print(done)
