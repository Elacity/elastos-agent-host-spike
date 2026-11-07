#!/usr/bin/env python3
"""Rerun every named plant in the detached worktree at b0cc24c2.

Does not edit this review folder's git tree. Restores the worktree after
each plant. Timeouts are not counted as caught.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

REVIEW = pathlib.Path(__file__).resolve().parent.parent
WORKTREE = pathlib.Path(os.environ.get("REVIEW_WORKTREE", "/tmp/pr-301-a8-r4"))
LANE = WORKTREE / "lab/a1-a8-hardening"
EVIDENCE = pathlib.Path(
    os.environ.get("REVIEW_EVIDENCE", str(REVIEW / "evidence"))
)


def main() -> int:
    entries = json.loads((LANE / "falsifiers.json").read_text())["falsifiers"]
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "falsifiers").mkdir(exist_ok=True)
    summary = []
    status = 0
    for entry in entries:
        ident = entry["id"]
        result = subprocess.run(
            ["python3", str(LANE / "falsify.py"), ident],
            cwd=WORKTREE,
            capture_output=True,
            text=True,
        )
        text = result.stdout + result.stderr
        (EVIDENCE / "falsifiers" / f"{ident}.txt").write_text(text)
        line = next(
            (row for row in text.splitlines() if row.startswith(f"{ident}: ")),
            f"{ident}: NO VERDICT exit {result.returncode}",
        )
        print(line, flush=True)
        summary.append(line)
        if result.returncode != 0:
            status = 1
    (EVIDENCE / "falsifiers" / "summary.txt").write_text("\n".join(summary) + "\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
