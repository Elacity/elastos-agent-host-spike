#!/usr/bin/env python3
"""Every name in repro/recorded-hashes.txt is checked by a gate that runs it.

Usage: recorded_names_test.py [--record FILE] [--falsify]

Each gate is the viewer's own verify.sh, executed with ELASTOS_HASH_NAMES=1:
that mode runs the same hash_gate call the full gate runs and prints
`checked-name: <name>`. Only a name that command actually checked counts, not a
mention in the file. ELASTOS_RECORDED_HASHES, else the kit's record.
"""
import argparse
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLES = HERE.parent.parent


def recorded_names(record):
    return [line.split()[0] for line in record.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def checked_by_gate(name, record):
    """Run the gate's listing mode and return the name it says it checked."""
    verify = EXAMPLES / name / "verify.sh"
    if not verify.is_file():
        raise SystemExit(f"{EXAMPLES / name}: no verify.sh at {verify}")
    env = dict(os.environ, ELASTOS_HASH_NAMES="1", ELASTOS_RECORDED_HASHES=str(record))
    try:
        result = subprocess.run(["bash", str(verify)], capture_output=True, text=True,
                                env=env, timeout=120)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{verify}: ELASTOS_HASH_NAMES=1 did not stop the gate at its "
                         f"hash check (no listing mode)")
    if result.returncode != 0:
        raise SystemExit(f"{verify}: the gate's listing mode failed:\n{result.stderr}")
    checked = [line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
               if line.startswith("checked-name:")]
    return checked


def falsify(record):
    """One name added to a copy of the record must fail, naming the name and gate."""
    with tempfile.TemporaryDirectory() as temporary:
        copy = pathlib.Path(temporary) / "recorded-hashes.txt"
        copy.write_text(record.read_text() + f"unchecked-viewer {'0' * 64}\n")
        result = subprocess.run(
            [sys.executable, "-I", __file__, "--record", str(copy)],
            capture_output=True, text=True)
        if result.returncode == 0 or "unchecked-viewer" not in result.stderr:
            raise SystemExit(f"an unchecked name was not caught by name:\n{result.stderr}")
        if str(EXAMPLES / "unchecked-viewer" / "verify.sh") not in result.stderr:
            raise SystemExit(f"the unchecked name did not name its gate:\n{result.stderr}")
        print("caught: a name no gate runs -> unchecked-viewer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("ELASTOS_RECORDED_HASHES")
                                             or HERE / "recorded-hashes.txt"))
    parser.add_argument("--falsify", action="store_true",
                        help="add an unchecked name to a copy of the record")
    args = parser.parse_args()
    names = recorded_names(args.record)
    for name in names:
        checked = checked_by_gate(name, args.record)
        if checked != [name]:
            raise SystemExit(f"{EXAMPLES / name / 'verify.sh'}: the gate checked "
                             f"{checked or 'no name'}, not {name}")
    print(f"all {len(names)} recorded names are checked by a gate that ran")
    if args.falsify:
        falsify(args.record)


if __name__ == "__main__":
    main()
