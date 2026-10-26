#!/usr/bin/env python3
"""Run every official falsifier, one at a time, from the reviewed worktree."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

WORKTREE = pathlib.Path(os.environ.get("REVIEW_WORKTREE", "/tmp/pr-301-a8-r3"))
EVIDENCE = pathlib.Path(os.environ.get("REVIEW_EVIDENCE", "/tmp/review-a8-301-r3-evidence"))
IDS = [
    "F-A1a",
    "F-A1-runtime",
    "F-A8a",
    "F-A8-runtime",
    "F-A8-forge",
    "F-A8-early",
    "F-A8-skip-guards",
    "F-A8-piece-forge",
    "F-A8-wasm-bus-only",
    "F-A8-direct-request",
    "F-A8-test-writes-lines",
    "F-A8-skip-journal-grants",
]


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    dest = EVIDENCE / "falsifiers"
    dest.mkdir(exist_ok=True)
    rows = []
    for ident in IDS:
        print(f"=== {ident} ===", flush=True)
        result = subprocess.run(
            ["python3", str(WORKTREE / "lab/a1-a8-hardening/falsify.py"), ident],
            cwd=WORKTREE,
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        (dest / f"{ident}.txt").write_text(output)
        print(output[-2000:], flush=True)
        verdict = "CAUGHT" if result.returncode == 0 and f"{ident}: CAUGHT" in output else "MISSED"
        if "exit:timeout" in output or "exit:None" in output:
            verdict = "TIMEOUT-NOT-CAUGHT"
        rows.append(f"{ident}: {verdict} exit={result.returncode}")
    (dest / "summary.txt").write_text("\n".join(rows) + "\n")
    print("\n".join(rows))
    sys.exit(0 if all(row.endswith("exit=0") and "CAUGHT" in row for row in rows) else 1)


if __name__ == "__main__":
    main()
