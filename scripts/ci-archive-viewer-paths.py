#!/usr/bin/env python3
"""Decide whether a pull request must run the archive-viewer parser job.

The parser job runs the guest tests and the host-test fuel gate. A pull
request skips it only when no changed path is examples/archive-viewer, one
of the direct inputs below, or one of the check files below. An empty change
list, one of those paths, or a failed `git diff` runs it.

The archive-viewer-paths job in .github/workflows/ci.yml runs this on a pull
request, with BASE_REF and HEAD_SHA set and the full history checked out. It
loads this file from the pull request's base commit.
"""
import os
import subprocess
import sys

PREFIX = "examples/archive-viewer/"
# The files that choose or run this check. A pull request that changes one of
# them runs the parser, including a change to this file.
CHECK_FILES = frozenset({
    "scripts/ci-archive-viewer-paths.py",
    "scripts/ci-archive-viewer-paths-test.py",
    "scripts/ci-release-policy-test.py",
    "scripts/test-source-gate.sh",
    ".github/workflows/ci.yml",
    ".github/workflows/examples-nightly.yml",
})
# Direct inputs of the parser, outside examples/archive-viewer. The guest
# crate, the documents model, and the fuel harness are path dependencies.
# The component build reads the builder and the Bus v1 WIT file. A neighbour
# whose name only starts the same way is not an input.
DIRECT_PREFIXES = (
    "examples/capsule-kit/guest/",
    "examples/docs-viewer/model/",
    "examples/capsule-kit/v1-host-test/",
)
DIRECT_FILES = frozenset({
    "examples/capsule-kit/guest",
    "examples/docs-viewer/model",
    "examples/capsule-kit/v1-host-test",
    "scripts/build-component-capsule.sh",
    "elastos/wit/elastos-bus-v1.wit",
})


def triggers(path):
    """True when this path is the archive viewer, a direct input, or a check file."""
    return (path == "examples/archive-viewer" or path.startswith(PREFIX) or path in CHECK_FILES
            or path in DIRECT_FILES or any(path.startswith(prefix) for prefix in DIRECT_PREFIXES))


def must_run(paths):
    """The parser runs unless there is a change and none of it is a trigger."""
    return not paths or any(triggers(path) for path in paths)


def changed_paths(base, head, cwd=None):
    """Every path the pull request changes, as scripts/ci-installed-app-paths.py
    reads them. Renames are not paired, so a moved file is both its old and its
    new path."""
    listing = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", "-z", f"{base}...{head}"],
        cwd=cwd, capture_output=True, check=True).stdout
    return [os.fsdecode(path) for path in listing.split(b"\0") if path]


def decide(environ, cwd=None):
    """(run, reason) for this pull request. An unreadable change list runs the parser."""
    try:
        paths = changed_paths("origin/" + environ["BASE_REF"], environ["HEAD_SHA"], cwd)
    except (KeyError, OSError, subprocess.CalledProcessError) as error:
        return True, f"the changed paths could not be read ({type(error).__name__})"
    if not must_run(paths):
        return False, f"none of {len(paths)} changed paths is the archive viewer, a direct input, or a check file"
    hit = sorted(path for path in paths if triggers(path))
    if not hit:
        return True, "no changed path"
    return True, f"{len(hit)} of {len(paths)} changed paths select the archive parser, first {hit[0]!r}"


def main():
    run, reason = decide(os.environ)
    print(f"archive parser {'runs' if run else 'is skipped'}: {reason}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"run={'true' if run else 'false'}\n")


if __name__ == "__main__":
    sys.exit(main())
