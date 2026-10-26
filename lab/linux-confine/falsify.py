#!/usr/bin/env python3
"""Remove the socket denial, show the standing check fail, restore it.

The standing check is did_profile_permits_its_operations_and_refuses_the_rest.
It fails with "socket denial did not hold" when DENY_SOCKET is false.
"""

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "src" / "policy.rs"
OLD = "pub const DENY_SOCKET: bool = true;"
NEW = "pub const DENY_SOCKET: bool = false;"
TEST = "did_profile_permits_its_operations_and_refuses_the_rest"
CAUGHT = "socket denial did not hold"


def cargo(extra):
    return subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(HERE / "Cargo.toml"),
            "--",
            TEST,
            "--exact",
            *extra,
        ],
        cwd=HERE.parent.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def main():
    original = SOURCE.read_text()
    if original.count(OLD) != 1 or NEW in original:
        print("F-LC-SOCKET NOT RUN: the denial line is not the standing true value")
        return 1
    baseline = cargo(["--nocapture"])
    if baseline.returncode != 0:
        print(baseline.stdout)
        print("F-LC-SOCKET NOT RUN: the standing test failed before the edit")
        return 1
    try:
        SOURCE.write_text(original.replace(OLD, NEW, 1))
        mutated = cargo([])
    finally:
        SOURCE.write_text(original)
    if mutated.returncode == 0 or CAUGHT not in mutated.stdout:
        print(mutated.stdout)
        print("F-LC-SOCKET SURVIVED")
        return 1
    print("F-LC-SOCKET CAUGHT")
    print(mutated.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
