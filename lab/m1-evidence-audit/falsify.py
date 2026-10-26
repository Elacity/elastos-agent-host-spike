#!/usr/bin/env python3
"""Falsifiers for the M1 evidence checker.

F-M1-ROW: delete one required evidence row from a temp copy of the
catalog. audit.py must exit 1 and name that row.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from checks import REQUIRED_ROWS
AUDIT = HERE / "audit.py"
EVIDENCE = HERE / "evidence.json"
FALSIFIER = "F-M1-ROW"
REMOVED_ROW = "C1-init-requires-storage"


def run_audit(evidence: Path, root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(AUDIT), "--evidence", str(evidence), "--root", str(root), "--quiet"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )


def falsify_row(root: Path) -> int:
    catalog = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    found = False
    for check in catalog["checks"]:
        before = len(check["rows"])
        check["rows"] = [row for row in check["rows"] if row["id"] != REMOVED_ROW]
        if len(check["rows"]) != before:
            found = True
    if not found:
        print(f"{FALSIFIER}: catalog no longer has {REMOVED_ROW}")
        return 2
    if REMOVED_ROW not in REQUIRED_ROWS["C1"]:
        print(f"{FALSIFIER}: {REMOVED_ROW} is not a required C1 row")
        return 2

    with tempfile.TemporaryDirectory(prefix="m1-evidence-audit-") as tmp:
        copy = Path(tmp) / "evidence.json"
        copy.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        baseline = run_audit(EVIDENCE, root)
        if baseline.returncode != 0:
            print(f"{FALSIFIER}: baseline audit already fails")
            print(baseline.stdout)
            print(baseline.stderr)
            return 2
        planted = run_audit(copy, root)
        text = planted.stdout + planted.stderr
        if planted.returncode != 0 and REMOVED_ROW in text:
            print(f"{FALSIFIER}: CAUGHT (removed {REMOVED_ROW})")
            return 0
        print(f"{FALSIFIER}: MISSED")
        print(f"exit {planted.returncode}")
        print(text)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("id", nargs="?", default=FALSIFIER)
    parser.add_argument("--root", type=Path, default=HERE.parents[1])
    args = parser.parse_args(argv)
    if args.id != FALSIFIER:
        print(f"unknown falsifier {args.id}; known: {FALSIFIER}")
        return 2
    return falsify_row(args.root)


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    raise SystemExit(main())
