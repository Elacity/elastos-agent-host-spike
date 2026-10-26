#!/usr/bin/env python3
"""Pin the reviewed SHA, the bookability verdict, and last-run findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEW = HERE / "REVIEW.md"
LAST = HERE / "last-run.json"
REVIEWED_SHA = "c0b16491076c30366a3504066499c9f5ad831ef2"


def main() -> int:
    text = REVIEW.read_text(encoding="utf-8")
    if REVIEWED_SHA not in text:
        print(f"REVIEW.md does not name {REVIEWED_SHA}", file=sys.stderr)
        return 1
    if "A9 is not bookable" not in text:
        print("REVIEW.md does not state the bookability verdict", file=sys.stderr)
        return 1
    if "| HOLDS |" not in text or "| FALSIFIED |" not in text:
        print("REVIEW.md is missing HOLDS/FALSIFIED rows", file=sys.stderr)
        return 1
    if "RA-3" not in text or "AC-006-STORAGE" not in text:
        print("REVIEW.md does not cite RA-3 / AC-006-STORAGE", file=sys.stderr)
        return 1
    if LAST.exists():
        data = json.loads(LAST.read_text(encoding="utf-8"))
        if data.get("reviewed_sha") != REVIEWED_SHA:
            print("last-run.json SHA mismatch", file=sys.stderr)
            return 1
        if data.get("hashes_before") != data.get("hashes_after"):
            print("last-run.json shows #290 sources changed", file=sys.stderr)
            return 1
        verdicts = {row["id"]: row["verdict"] for row in data.get("findings", [])}
        required = {
            "api-read-write": "HOLDS",
            "host-list": "FALSIFIED",
            "host-hardlink": "FALSIFIED",
            "runtime-enforced": "FALSIFIED",
            "runtime-shared-temp": "FALSIFIED",
        }
        for key, want in required.items():
            got = verdicts.get(key)
            if got != want:
                print(f"last-run.json {key} is {got}, want {want}", file=sys.stderr)
                return 1
        print("check.py: REVIEW.md pins and last-run.json required verdicts hold")
    else:
        print("check.py: REVIEW.md pins hold (no last-run.json yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
