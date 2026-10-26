#!/usr/bin/env python3
"""Falsifier runner for lab/fail-closed-linux.

Each file in mutants/ plants one bug. For each plant the runner copies this
crate to target/falsify/<id>/crate, applies the replacement in that copy, and
runs the named tests with the copy's own CARGO_TARGET_DIR and build dir. A
plant is caught when every named test fails. The control plant changes only a
comment and must survive: the whole suite passes on its copy.

Plant grammar:

    id: <one token>
    expect: caught | survive          (default: caught)
    file: <path relative to the crate>
    test: <target>::<test name>       (one or more; `test: *` runs the suite)
    --- old
    <exact text, present exactly once in that file>
    --- new
    <replacement>
    --- end

<target> is `lib`, `simulated` or `real_kernel`.

usage: python3 falsify.py [--jobs N] [--only ID] [--keep]
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

LANE = Path(__file__).resolve().parent
WORK = LANE / "target" / "falsify"
NOT_COPIED = ("target", "__pycache__", ".git")
TIMEOUT_SECONDS = 900


@dataclass
class Plant:
    id: str
    file: str
    tests: list
    old: str
    new: str
    expect: str = "caught"


@dataclass
class Outcome:
    plant: Plant
    verdict: str
    detail: str
    passed: list = field(default_factory=list)


def parse(path):
    header = {"tests": []}
    old, new, section = [], [], "header"
    for line in path.read_text().splitlines():
        if section == "header":
            if line == "--- old":
                section = "old"
            elif line.strip():
                key, sep, value = line.partition(": ")
                if not sep or key not in ("id", "expect", "file", "test"):
                    sys.exit(f"{path.name}: unexpected header line {line!r}")
                if key == "test":
                    header["tests"].append(value.strip())
                else:
                    header[key] = value.strip()
        elif section == "old":
            if line == "--- new":
                section = "new"
            else:
                old.append(line)
        elif section == "new":
            if line == "--- end":
                section = "end"
            else:
                new.append(line)
        elif line.strip():
            sys.exit(f"{path.name}: text after --- end")
    if section != "end":
        sys.exit(f"{path.name}: missing --- end")
    for key in ("id", "file"):
        if key not in header:
            sys.exit(f"{path.name}: missing {key}")
    if not header["tests"]:
        sys.exit(f"{path.name}: missing test")
    expect = header.get("expect", "caught")
    if expect not in ("caught", "survive"):
        sys.exit(f"{path.name}: expect must be caught or survive")
    if Path(header["file"]).is_absolute() or ".." in Path(header["file"]).parts:
        sys.exit(f"{path.name}: file must be relative to the crate")
    for test in header["tests"]:
        if test != "*" and "::" not in test:
            sys.exit(f"{path.name}: test {test!r} needs <target>::<name>")
    return Plant(
        header["id"], header["file"], header["tests"], "\n".join(old), "\n".join(new), expect
    )


def cargo(crate, args, env):
    return subprocess.run(
        ["cargo", *args],
        cwd=crate,
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )


def result_of(name, stdout):
    for verdict in ("FAILED", "ok"):
        if re.search(rf"^test {re.escape(name)} \.\.\. {verdict}$", stdout, re.M):
            return verdict
    return "missing"


def run_plant(plant, keep):
    base = WORK / plant.id
    shutil.rmtree(base, ignore_errors=True)
    crate = base / "crate"
    shutil.copytree(LANE, crate, ignore=shutil.ignore_patterns(*NOT_COPIED))
    source = crate / plant.file
    text = source.read_text()
    count = text.count(plant.old)
    if count != 1:
        shutil.rmtree(base, ignore_errors=True)
        return Outcome(plant, "ERROR", f"old text occurs {count} times in {plant.file}")
    source.write_text(text.replace(plant.old, plant.new, 1))

    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(base / "target"),
        CARGO_BUILD_BUILD_DIR=str(base / "build"),
        RUST_TEST_THREADS="2",
        CARGO_INCREMENTAL="0",
    )
    logs = []
    try:
        if plant.tests == ["*"]:
            run = cargo(crate, ["test", "--locked", "--no-fail-fast"], env)
            logs.append(run.stdout + run.stderr)
            passed = re.findall(r"^test (\S+) \.\.\. ok$", run.stdout, re.M)
            failed = re.findall(r"^test (\S+) \.\.\. FAILED$", run.stdout, re.M)
            if run.returncode == 0 and passed and not failed:
                outcome = Outcome(plant, "SURVIVED", f"{len(passed)} tests passed", passed)
            else:
                outcome = Outcome(plant, "KILLED", f"failed: {failed or 'build or harness'}")
        else:
            groups = {}
            for test in plant.tests:
                target, name = test.split("::", 1)
                groups.setdefault(target, []).append(name)
            results = {}
            compiled = True
            for target, names in groups.items():
                selector = ["--lib"] if target == "lib" else ["--test", target]
                run = cargo(crate, ["test", "--locked", *selector, "--", "--exact", *names], env)
                logs.append(run.stdout + run.stderr)
                if "could not compile" in run.stderr:
                    compiled = False
                for name in names:
                    results[f"{target}::{name}"] = result_of(name, run.stdout)
            summary = ", ".join(f"{test} {verdict}" for test, verdict in results.items())
            if all(verdict == "FAILED" for verdict in results.values()):
                outcome = Outcome(plant, "CAUGHT", summary)
            elif not compiled:
                outcome = Outcome(plant, "ERROR", "the mutant did not compile")
            elif "missing" in results.values():
                outcome = Outcome(plant, "ERROR", f"named test not run: {summary}")
            else:
                outcome = Outcome(plant, "MISSED", summary)
    except subprocess.TimeoutExpired:
        outcome = Outcome(plant, "ERROR", f"cargo ran longer than {TIMEOUT_SECONDS}s")
    (WORK / f"{plant.id}.log").write_text("\n".join(logs))
    if not keep:
        shutil.rmtree(base, ignore_errors=True)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--keep", action="store_true", help="keep each mutant copy")
    args = parser.parse_args()

    plants = [parse(path) for path in sorted((LANE / "mutants").glob("*.txt"))]
    ids = [plant.id for plant in plants]
    if len(ids) != len(set(ids)):
        sys.exit("duplicate plant id")
    if args.only:
        plants = [plant for plant in plants if plant.id in args.only]
    if not plants:
        sys.exit("no plants selected")
    WORK.mkdir(parents=True, exist_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        outcomes = list(pool.map(lambda plant: run_plant(plant, args.keep), plants))

    for outcome in outcomes:
        print(f"{outcome.verdict:<9}{outcome.plant.id}  {outcome.detail}")
    mutants = [o for o in outcomes if o.plant.expect == "caught"]
    controls = [o for o in outcomes if o.plant.expect == "survive"]
    caught = sum(o.verdict == "CAUGHT" for o in mutants)
    survived = sum(o.verdict == "SURVIVED" for o in controls)
    print(f"falsifiers: {caught}/{len(mutants)} caught; controls: {survived}/{len(controls)} survived")
    print(f"logs: {WORK}/<id>.log")
    ok = caught == len(mutants) and survived == len(controls)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
