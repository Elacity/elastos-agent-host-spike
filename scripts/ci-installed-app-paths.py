#!/usr/bin/env python3
"""Decide whether a pull request must run the installed-app CI jobs.

source-home-linux, source-home-linux-arm64 and update-hop-linux build the whole
installed app and drive it. A pull request skips them only when every path it
changes is a notes or lab path that those jobs never read. An empty change
list, one path outside the list or a failed `git diff` runs them.

The installed-app-paths job in .github/workflows/ci.yml runs this on a pull
request, with BASE_REF and HEAD_SHA set and the full history checked out.
"""
import os
import subprocess
import sys

# Lab crates that a manifest outside lab/ names by path: capsules/model-provider
# has a dev-dependency on lab/agent-conformance, which names the other two. The
# locked release build of that capsule loads their manifests to resolve its
# dependencies. It does not compile them, so their other files are lab files.
LAB_CRATES_THE_BUILD_LOADS = ("lab/agent-conformance/", "lab/capsule-identity/", "lab/grant-binding/")
# The Runtime serves these from its source checkout (ALLOWED_DOCS in
# elastos/crates/elastos-server/src/api/handlers/docs.rs).
SERVED_BY_THE_RUNTIME = frozenset(
    {"ROADMAP.md", "docs/ARCHITECTURE.md", "docs/OVERVIEW.md", "docs/GETTING_STARTED.md"})


def is_notes_or_lab(path):
    """True for a path the installed-app jobs never read: lab/, docs/ and a
    Markdown file at the repository root, less the two exceptions above."""
    if path in SERVED_BY_THE_RUNTIME:
        return False
    if path.startswith(LAB_CRATES_THE_BUILD_LOADS) and path.endswith("/Cargo.toml"):
        return False
    if path.startswith(("lab/", "docs/")):
        return True
    return "/" not in path and path.endswith(".md")


def must_run(paths):
    """The jobs run unless there is a change and every changed path is notes or lab."""
    return not paths or not all(is_notes_or_lab(path) for path in paths)


def changed_paths(base, head, cwd=None):
    """Every path the pull request changes, as scripts/pr-substance.py reads them.
    Renames are not paired, so a moved file is both its old and its new path."""
    listing = subprocess.run(["git", "diff", "--no-renames", "--name-only", "-z", f"{base}...{head}"],
                             cwd=cwd, capture_output=True, check=True).stdout
    return [os.fsdecode(path) for path in listing.split(b"\0") if path]


def decide(environ, cwd=None):
    """(run, reason) for this pull request. An unreadable change list runs the jobs."""
    try:
        paths = changed_paths("origin/" + environ["BASE_REF"], environ["HEAD_SHA"], cwd)
    except (KeyError, OSError, subprocess.CalledProcessError) as error:
        return True, f"the changed paths could not be read ({type(error).__name__})"
    if not must_run(paths):
        return False, f"all {len(paths)} changed paths are notes or lab files"
    other = sorted(path for path in paths if not is_notes_or_lab(path))
    if not other:
        return True, "no changed path"
    return True, f"{len(other)} of {len(paths)} changed paths are not notes or lab files, first {other[0]!r}"


def main():
    run, reason = decide(os.environ)
    print(f"installed-app jobs {'run' if run else 'are skipped'}: {reason}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"run={'true' if run else 'false'}\n")


if __name__ == "__main__":
    sys.exit(main())
