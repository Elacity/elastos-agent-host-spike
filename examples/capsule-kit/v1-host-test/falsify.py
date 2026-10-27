#!/usr/bin/env python3
"""This test code stands in for the Runtime's launch by CID, which does not exist yet.

Usage: RUST_TEST_THREADS=2 python3 -I falsify.py [--check] [name-part ...]

Each mutant must compile and fail exactly its named test in the full host-test
suite. The kit runner restores the source bytes after each case, also on error.
"""
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "falsify"))
import falsify_kit as kit  # noqa: E402

CASES = [
    ("stand-in membership bypassed", "stand_in.rs",
     "if !binding.members.contains(resource) {",
     "if false && !binding.members.contains(resource) {",
     "guard_denies_a_read_outside_the_binding"),
    ("stand-in caller bypassed", "stand_in.rs",
     "if !binding.active || capsule != binding.instance_id || principal != binding.principal {",
     "if false {",
     "guard_denies_a_closed_or_foreign_call"),
    ("stand-in grant prefix bypassed", "stand_in.rs",
     "if !token.is_empty() && !token.starts_with(&prefix) {",
     "if false && !token.is_empty() && !token.starts_with(&prefix) {",
     "guard_rejects_a_grant_from_another_binding"),
    ("stand-in re-admission bypassed", "stand_in.rs",
     "if let Err(reason) = (binding.readmit)() {",
     "if let Err(reason) = Ok(()) {",
     "guard_calls_readmit_before_each_effect"),
    ("stand-in dispatch bypassed in run", "lib.rs",
     "        let response = dispatch(&mut *host.lock().unwrap(), line, capsule, principal);",
     "        let response = host.lock().unwrap().answer(line);",
     "run_calls_dispatch_with_the_bus_caller"),
]


def build():
    kit.cargo_compiles(HERE, ["--lib"])


def test_fails(name):
    return kit.cargo_test_fails(HERE, ["--lib"], f"stand_in_tests::{name}")


def test_failures():
    result = kit.run(["cargo", "test", "--locked", "--lib"], HERE)
    if "test result:" not in result.stdout:
        print(result.stdout[-3000:], result.stderr[-3000:])
        raise SystemExit("a falsifier stops the tests")
    return {
        match.group(1).removeprefix("stand_in_tests::")
        for match in re.finditer(r"^test (\S+) \.\.\. FAILED$", result.stdout, re.MULTILINE)
    }


def main():
    cases = [
        (name, HERE / "src" / file, [(old, new)], [test])
        for name, file, old, new, test in CASES
    ]
    kit.main(
        [(cases, build, test_fails, None, True, test_failures)],
        done="all 5 stand-in guard falsifiers caught",
    )


if __name__ == "__main__":
    main()
