#!/usr/bin/env python3
"""Run each viewer gate's recorded-hash path and check its output.

Usage: recorded_names_test.py [--record FILE] [--falsify]

The viewer's verify.sh owns the hash command in both its full run and its
--recorded-hash-only path. This test reads the gate's result, not its source.
ELASTOS_RECORDED_HASHES selects a record copy for a falsifier.
"""
import argparse
import os
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLES = HERE.parent.parent


def recorded_names(record):
    return [line.split()[0] for line in record.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def run_gate(name, record):
    verify = EXAMPLES / name / "verify.sh"
    if not verify.is_file():
        raise SystemExit(f"{EXAMPLES / name}: no verify.sh at {verify}")
    result = subprocess.run(
        ["bash", str(verify), "--recorded-hash-only"],
        cwd=verify.parent, capture_output=True, text=True, timeout=180,
        env=dict(os.environ, ELASTOS_RECORDED_HASHES=str(record)),
        check=False,
    )
    return verify, result


def checked_by_gate(name, record, count):
    verify, result = run_gate(name, record)
    line = (f"recorded hash gate {name}: OK, {count} recorded names, "
            f"artifact {name}.component.wasm matches")
    if result.returncode or result.stdout.splitlines().count(line) != 1:
        raise SystemExit(
            f"{verify}: missing the successful hash line for {name} "
            f"(exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
        )
    return line


def falsify(record, names):
    """An unlisted gate and a changed recorded value must both be caught."""
    with tempfile.TemporaryDirectory() as temporary:
        copy = pathlib.Path(temporary) / "recorded-hashes.txt"
        copy.write_text(record.read_text() + f"unchecked-viewer {'0' * 64}\n")
        missing = str(EXAMPLES / "unchecked-viewer" / "verify.sh")
        try:
            run_gate("unchecked-viewer", copy)
        except SystemExit as error:
            if missing not in str(error):
                raise SystemExit(f"an unchecked name was not caught by gate: {error}")
        else:
            raise SystemExit("an unchecked name was not caught by gate")
        print("caught: a name no gate runs -> unchecked-viewer")

        for name in names:
            changed = []
            for line in record.read_text().splitlines():
                fields = line.split()
                if len(fields) == 2 and fields[0] == name:
                    value = fields[1]
                    line = f"{name} {value[:-1]}{'0' if value[-1] != '0' else '1'}"
                changed.append(line)
            copy.write_text("\n".join(changed) + "\n")
            verify, result = run_gate(name, copy)
            if result.returncode == 0 or f"recorded hash gate {name}: MISMATCH:" not in result.stderr:
                raise SystemExit(
                    f"{verify}: changed hash for {name} was not refused:\n"
                    f"{result.stdout}\n{result.stderr}"
                )
            print(f"caught: a changed {name} hash -> {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("ELASTOS_RECORDED_HASHES")
                                             or HERE / "recorded-hashes.txt"))
    parser.add_argument("--falsify", action="store_true")
    args = parser.parse_args()
    names = recorded_names(args.record)
    for name in names:
        print(checked_by_gate(name, args.record, len(names)))
    print(f"all {len(names)} recorded names passed their viewer gate's hash check")
    if args.falsify:
        falsify(args.record, names)


if __name__ == "__main__":
    main()
