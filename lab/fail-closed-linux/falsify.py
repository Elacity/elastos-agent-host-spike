#!/usr/bin/env python3
"""Plant each bug in falsifiers.json in a scratch copy of this crate and require
every named test to FAIL at an assertion.

  python3 -I lab/fail-closed-linux/falsify.py              # every falsifier
  python3 -I lab/fail-closed-linux/falsify.py F-FC03 F-FC11  # some ids
  python3 -I lab/fail-closed-linux/falsify.py --list

The working tree is never edited: each bug goes into a copy under a scratch
directory. Before any bug, every named test runs once on the unmutated copy and
must pass; a test that fails or does not run there makes its falsifier NOT RUN.
A bug whose build fails is BUILD FAILED, never a catch. A falsifier is CAUGHT
only when each of its named tests ran and failed. A falsifier with
"expect": "survives" (the runner's own control: a change that alters nothing)
must be SURVIVED, which shows the runner does not call everything caught.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error.
"""
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DESIGN_DOC = pathlib.Path("capsules/wallet-provider/CONFINEMENT-LINUX.md")
COPY_ITEMS = ("Cargo.toml", "Cargo.lock", "src", "tests")


def load():
    data = json.loads((HERE / "falsifiers.json").read_text())
    return data["falsifiers"]


def make_copy(root):
    crate = root / "lab" / "fail-closed-linux"
    crate.mkdir(parents=True)
    for item in COPY_ITEMS:
        source = HERE / item
        if source.is_dir():
            shutil.copytree(source, crate / item)
        else:
            shutil.copy2(source, crate / item)
    doc = root / DESIGN_DOC
    doc.parent.mkdir(parents=True)
    shutil.copy2(REPO / DESIGN_DOC, doc)
    return crate


def run_test(crate, target_dir, spec):
    test_file, name = spec.split("::", 1)
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir), CARGO_TERM_COLOR="never")
    proc = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "--test", test_file, "--", "--exact", name],
        cwd=crate, env=env, capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    if "could not compile" in out or "error[E" in out or "error: failed to" in out:
        return "BUILD FAILED", out
    if f"test {name} ... FAILED" in out:
        return "FAILED", out
    if f"test {name} ... ok" in out and proc.returncode == 0:
        return "PASSED", out
    return "NOT RUN", out


def apply_edits(crate, edits):
    for edit in edits:
        path = crate / edit["file"]
        text = path.read_text()
        if text.count(edit["find"]) != 1:
            return f"{edit['file']}: the text to replace is found {text.count(edit['find'])} times, not once"
        path.write_text(text.replace(edit["find"], edit["replace"]))
    return None


def main(argv):
    falsifiers = load()
    if argv == ["--list"]:
        for item in falsifiers:
            print(f"{item['id']}  expect {item.get('expect', 'caught')}  {item['claim']}")
            for spec in item["tests"]:
                print(f"    {spec}")
        return 0
    if any(arg.startswith("-") for arg in argv):
        print(__doc__, file=sys.stderr)
        return 2
    chosen = [item for item in falsifiers if not argv or any(item["id"].startswith(prefix) for prefix in argv)]
    if not chosen:
        print(f"no falsifier matches {argv}", file=sys.stderr)
        return 2

    machine = platform.machine()
    ok = True
    with tempfile.TemporaryDirectory(prefix="fcl-falsify-") as scratch:
        scratch = pathlib.Path(scratch)
        # One target directory per copy. Cargo names an artifact by a hash that
        # does not depend on the copy's path, so a shared directory lets one
        # copy run a binary built from another copy's source.
        baseline_crate = make_copy(scratch / "baseline")
        baseline_target = scratch / "target-baseline"
        baseline = {}

        def baseline_of(spec):
            if spec not in baseline:
                baseline[spec] = run_test(baseline_crate, baseline_target, spec)
            return baseline[spec]

        for index, item in enumerate(chosen):
            expect = item.get("expect", "caught")
            if item.get("only_arch") and item["only_arch"] != machine:
                print(f"{item['id']}  SKIPPED  only on {item['only_arch']}, this host is {machine}")
                continue
            bad = [spec for spec in item["tests"] if baseline_of(spec)[0] != "PASSED"]
            if bad:
                print(f"{item['id']}  NOT RUN  unmutated test did not pass: {bad[0]} ({baseline_of(bad[0])[0]})")
                print("\n".join("    " + line for line in baseline_of(bad[0])[1].splitlines()[-15:]))
                ok = False
                continue
            crate = make_copy(scratch / f"mutant-{index}")
            problem = apply_edits(crate, item["edits"])
            if problem:
                print(f"{item['id']}  NOT RUN  {problem}")
                ok = False
                continue
            target_dir = scratch / f"target-mutant-{index}"
            results = {spec: run_test(crate, target_dir, spec) for spec in item["tests"]}
            kinds = {spec: result[0] for spec, result in results.items()}
            if any(kind in ("BUILD FAILED", "NOT RUN") for kind in kinds.values()):
                verdict = "BUILD FAILED" if "BUILD FAILED" in kinds.values() else "NOT RUN"
            elif all(kind == "FAILED" for kind in kinds.values()):
                verdict = "CAUGHT"
            elif all(kind == "PASSED" for kind in kinds.values()):
                verdict = "SURVIVED"
            else:
                verdict = "PARTIAL"
            met = (verdict == "CAUGHT") if expect == "caught" else (verdict == "SURVIVED")
            ok = ok and met
            detail = ", ".join(f"{spec.split('::')[1]}: {kind}" for spec, kind in kinds.items())
            print(f"{item['id']}  {verdict}{'' if met else '  (UNEXPECTED, expected ' + expect + ')'}  {detail}")
            if verdict in ("BUILD FAILED", "NOT RUN"):
                bad_spec = next(spec for spec, kind in kinds.items() if kind == verdict)
                print("\n".join("    " + line for line in results[bad_spec][1].splitlines()[-15:]))
    caught = "all falsifiers did what they expect" if ok else "AT LEAST ONE FALSIFIER DID NOT"
    print(caught)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
