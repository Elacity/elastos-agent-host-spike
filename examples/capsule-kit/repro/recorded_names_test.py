#!/usr/bin/env python3
"""Every name in repro/recorded-hashes.txt has a hash check in its viewer's gate.

Usage: recorded_names_test.py [--record FILE] [--falsify]

Each gate is the viewer's own verify.sh. A name counts only when that file has
`hash_gate <name> --artifact "${HASH_ARTIFACT}"` as a top-level command (column 0,
not commented, not inside a block), and the checker that line calls, run here on
the same artifact with --names, reports that it checked the name. verify.sh has
no mode that skips its other checks. ELASTOS_RECORDED_HASHES, else the kit's record.
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


def recorded_names(record):
    return [line.split()[0] for line in record.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def checked_by_gate(name, record):
    """The gate has a top-level hash check line for this name; the checker confirms the name.

    This reads the gate's text and does not watch verify.sh run; the verify.sh receipts show the run."""
    verify = EXAMPLES / name / "verify.sh"
    if not verify.is_file():
        raise SystemExit(f"{EXAMPLES / name}: no verify.sh at {verify}")
    lines = verify.read_text().splitlines()
    call = f'hash_gate {name} --artifact "${{HASH_ARTIFACT}}"'
    if call not in lines:
        raise SystemExit(f"{verify}: no top-level `{call}` line; the gate does not run this name's hash check")
    artifact = None
    for line in lines:
        found = re.fullmatch(r'HASH_ARTIFACT="\$\{REPO_ROOT\}/(.+)"', line)
        if found:
            artifact = EXAMPLES.parent / found.group(1)
    if artifact is None:
        raise SystemExit(f"{verify}: no top-level HASH_ARTIFACT=\"${{REPO_ROOT}}/...\" line")
    env = dict(os.environ, ELASTOS_RECORDED_HASHES=str(record))
    result = subprocess.run([sys.executable, "-I", str(HERE / "recorded_hash_gate.py"), name,
                             "--artifact", str(artifact), "--names"],
                            capture_output=True, text=True, env=env, timeout=120)
    if result.returncode != 0:
        raise SystemExit(f"{verify}: the hash check for {name} failed:\n{result.stderr}")
    return [line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
            if line.startswith("checked-name:")]


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
    print(f"all {len(names)} recorded names have a top-level hash check in their gate, and the checker confirms each")
    if args.falsify:
        falsify(args.record)


if __name__ == "__main__":
    main()
