#!/usr/bin/env python3
"""One viewer's recorded container hash, checked against the artifact's bytes.

Usage: recorded_hash_gate.py <viewer-name> [--artifact FILE] [--record FILE]
                             [--names] [--falsify]

The whole record is read, so one changed value fails every gate by name. The
artifact hashed is --artifact, else the reference artifact of that name under
repro/reference/ (the container-built bytes the record names); check-recorded-hash.py
compares its bytes with the record. --names prints the one name this run checked,
for recorded_names_test.py. ELASTOS_RECORDED_HASHES, else recorded-hashes.txt here.
"""
import argparse
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check-recorded-hash.py"
REFERENCE = HERE / "reference"


def entries(record):
    pairs = [line.split() for line in record.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    for pair in pairs:
        if len(pair) != 2:
            sys.exit(f"{record}: malformed entry {pair}")
        name, value = pair
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            sys.exit(f"{record}: {name} hash is not 64 lowercase hex: {value!r}")
    return pairs


def check(name, artifact, record):
    result = subprocess.run([sys.executable, "-I", str(CHECK), name, str(artifact),
                             "--record", str(record)], capture_output=True, text=True)
    if result.returncode or result.stdout:
        detail = (result.stderr or result.stdout).strip()
        sys.exit(f"recorded hash gate {name}: MISMATCH: {detail}")


def self_test():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        artifact, record = root / "artifact", root / "record"
        recorded = hashlib.sha256(b"original").hexdigest()
        record.write_text(f"viewer {recorded}\n")
        artifact.write_bytes(b"original")
        check("viewer", artifact, record)
        artifact.write_bytes(b"changed")
        result = subprocess.run([sys.executable, "-I", str(CHECK), "viewer", str(artifact),
                                 "--record", str(record)], capture_output=True, text=True)
        if result.returncode != 1 or f"recorded hash for viewer is {recorded}" not in result.stderr:
            sys.exit("the recorded hash check did not refuse changed bytes by name")


def changed(value):
    """A valid 64-character value that differs from the recorded one."""
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def falsify(name, record):
    with tempfile.TemporaryDirectory() as temporary:
        copy = pathlib.Path(temporary) / "recorded-hashes.txt"
        copy.write_text("".join(f"{n} {changed(v) if n == name else v}\n"
                                for n, v in entries(record)))
        result = subprocess.run([sys.executable, "-I", __file__, name], capture_output=True,
                                text=True, env=dict(os.environ, ELASTOS_RECORDED_HASHES=str(copy)))
        if result.returncode == 0 or name not in result.stderr or "MISMATCH" not in result.stderr:
            sys.exit(f"a changed {name} value was not caught as a mismatch by name:\n{result.stderr}")
        print(f"caught: a changed {name} value in the record -> {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("--artifact", type=pathlib.Path)
    parser.add_argument("--record", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("ELASTOS_RECORDED_HASHES")
                                             or HERE / "recorded-hashes.txt"))
    parser.add_argument("--names", action="store_true",
                        help="print the one name this run checked, for the gate-listing test")
    parser.add_argument("--falsify", action="store_true")
    args = parser.parse_args()
    names = [name for name, _ in entries(args.record)]
    if args.name not in names:
        sys.exit(f"{args.record}: no recorded hash for {args.name}")
    artifact = args.artifact or REFERENCE / f"{args.name}.component.wasm"
    if not artifact.is_file():
        sys.exit(f"recorded hash gate {args.name}: no artifact at {artifact}")
    check(args.name, artifact, args.record)
    self_test()
    if args.falsify:
        falsify(args.name, args.record)
    if args.names:
        print(f"checked-name: {args.name}")
    print(f"recorded hash gate {args.name}: OK, {len(names)} recorded names, "
          f"artifact {artifact.name} matches")


if __name__ == "__main__":
    main()
