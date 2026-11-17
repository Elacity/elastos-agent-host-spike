#!/usr/bin/env python3
"""Every name in repro/recorded-hashes.txt is checked by some gate (kit item A3).

Usage: recorded_names_test.py [--record FILE]

A gate is the viewer's own verify.sh: it either runs the kit's
recorded_hash_gate.py for its name, or its repro/recorded_hash_test.py, which
checks the whole record. ELASTOS_RECORDED_HASHES, else the kit's record.
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLES = HERE.parent.parent


def gate_for(name):
    verify = EXAMPLES / name / "verify.sh"
    if not verify.is_file():
        return None
    text = verify.read_text()
    if re.search(rf"recorded_hash_gate\.py\"?\s+{re.escape(name)}\b", text):
        return verify
    if (EXAMPLES / name / "repro" / "recorded_hash_test.py").is_file() \
            and "repro/recorded_hash_test.py" in text:
        return verify
    return None


def falsify(record):
    """One name added to a copy of the record must fail, naming the name and gate."""
    with tempfile.TemporaryDirectory() as temporary:
        copy = pathlib.Path(temporary) / "recorded-hashes.txt"
        copy.write_text(record.read_text() + f"unchecked-viewer {'0' * 64}\n")
        result = subprocess.run(
            [sys.executable, "-I", __file__], capture_output=True, text=True,
            env=dict(os.environ, ELASTOS_RECORDED_HASHES=str(copy)))
        if result.returncode == 0 or "unchecked-viewer" not in result.stderr:
            raise SystemExit(f"an unchecked name was not caught by name:\n{result.stderr}")
        if str(EXAMPLES / "unchecked-viewer" / "verify.sh") not in result.stderr:
            raise SystemExit(f"the unchecked name did not name its gate:\n{result.stderr}")
        print("caught: a name no gate checks -> unchecked-viewer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("ELASTOS_RECORDED_HASHES")
                                             or HERE / "recorded-hashes.txt"))
    parser.add_argument("--falsify", action="store_true",
                        help="add an unchecked name to a copy of the record")
    args = parser.parse_args()
    names = [line.split()[0] for line in args.record.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    for name in names:
        gate = gate_for(name)
        if gate is None:
            raise SystemExit(f"{args.record}: {name} is not checked by any gate "
                             f"(expected {EXAMPLES / name / 'verify.sh'})")
    print(f"all {len(names)} recorded names are checked by a gate")
    if args.falsify:
        falsify(args.record)


if __name__ == "__main__":
    main()
