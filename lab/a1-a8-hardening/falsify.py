#!/usr/bin/env python3
"""Apply one falsifier from falsifiers.json, run its named tests, restore.

Usage: python3 lab/a1-a8-hardening/falsify.py <ID>

CAUGHT means every named test ran and failed at a listed fail_needle
(default: the refusal assertion). The edited files are restored
byte-identical (SHA-256 checked) even on error.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import sys

LANE = pathlib.Path(__file__).resolve().parent
REPO = LANE.parent.parent
DEFAULT_NEEDLE = "expected nonzero exit and the exact"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def target(entry, edit):
    base = REPO if entry["command"] == "runtime-local" else LANE
    return base / edit["file"]


def test_file(name):
    for path in sorted((LANE / "tests").glob("*.rs")):
        if f"fn {name}()" in path.read_text():
            return path.stem
    raise SystemExit(f"named test not found: {name}")


def needles(entry):
    listed = entry.get("fail_needles")
    if listed:
        return listed
    return [DEFAULT_NEEDLE]


def run_test(name, entry):
    env = dict(os.environ)
    env.pop("RUSTFLAGS", None)
    env.update(
        CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(LANE / "target/host"),
        CARGO_BUILD_BUILD_DIR=str(LANE / "target/host-build"),
        CARGO_INCREMENTAL="0",
        RUST_TEST_THREADS="2",
    )
    command = [
        "cargo", "test", "--locked", "--manifest-path", str(LANE / "Cargo.toml"),
        "--test", test_file(name), name, "--", "--exact", "--nocapture",
    ]
    result = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    evidence = [line for line in output.splitlines() if line.startswith(("a1 ", "a8 "))]
    ran_and_failed = f"test {name} ... FAILED" in output
    caught = (
        result.returncode != 0
        and ran_and_failed
        and any(needle in output for needle in needles(entry))
    )
    return caught, result.returncode, evidence, output


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    entries = json.loads((LANE / "falsifiers.json").read_text())["falsifiers"]
    entry = next((e for e in entries if e["id"] == sys.argv[1]), None)
    if entry is None:
        raise SystemExit(f"unknown falsifier: {sys.argv[1]}")
    originals = {}
    for edit in entry["edits"]:
        path = target(entry, edit)
        text = path.read_text()
        if text.count(edit["old"]) != 1:
            raise SystemExit(f"anchor must occur exactly once in {edit['file']}")
        originals.setdefault(path, (path.read_bytes(), sha(path)))
    results = []
    try:
        for edit in entry["edits"]:
            path = target(entry, edit)
            path.write_text(path.read_text().replace(edit["old"], edit["new"], 1))
        for name in entry["tests"]:
            results.append((name, *run_test(name, entry)))
    finally:
        for path, (data, digest) in originals.items():
            path.write_bytes(data)
            if sha(path) != digest:
                raise SystemExit(f"restore failed for {path}")
    verdict = "CAUGHT" if results and all(r[1] for r in results) else "MISSED"
    for name, caught, code, evidence, output in results:
        print(f"{entry['id']} {name}: exit {code}, {'caught' if caught else 'not caught'}")
        for line in evidence:
            print(f"  {line}")
        if not caught:
            print(output[-4000:])
    for path, (_, digest) in originals.items():
        print(f"restored {path.relative_to(REPO)} sha256 {digest}")
    print(f"{entry['id']}: {verdict} (expected {entry['expect']})")
    sys.exit(0 if verdict == "CAUGHT" else 1)


if __name__ == "__main__":
    main()
