#!/usr/bin/env python3
"""Measure the code the Runtime trusts, starting with the core crate: its code lines come from
scripts/core-size.py's own count() of elastos/crates/elastos-runtime, so the two cannot disagree.

  trusted-code.py            a text report
  trusted-code.py --json     the core totals as JSON, for the gate that follows
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("core_size", Path(__file__).with_name("core-size.py"))
core_size = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core_size)


def measure(root):
    totals = core_size.count(core_size.worktree_files(root))
    return {"root": str(root),
            "core": {"crate": core_size.CRATE, "code": totals["code"], "counts": totals,
                     "counter": "scripts/core-size.py:count"}}


def text(report):
    core = report["core"]
    return (f"core crate {core['crate']}: {core['code']} code lines"
            f" ({core['counts']['tests']} tests, {core['counts']['comments']} comments,"
            f" {core['counts']['blank']} blank; {core['counter']})")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        report = measure(args.root)
    except (OSError, ValueError, core_size.Refusal) as error:
        print(f"trusted-code: refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
