#!/usr/bin/env python3
"""Re-run every named plant in lab/a1-a8-hardening/falsifiers.json.

Writes one evidence file per id under evidence/falsifiers/.
Does not keep Runtime edits: falsify.py restores SHA-256 itself.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parents[1]
REPO = REVIEW.parents[1]
LANE = REPO / "lab/a1-a8-hardening"
OUT = REVIEW / "evidence/falsifiers"
OUT.mkdir(parents=True, exist_ok=True)

entries = json.loads((LANE / "falsifiers.json").read_text())["falsifiers"]
summary = []
status = 0
for entry in entries:
    ident = entry["id"]
    result = subprocess.run(
        ["python3", str(LANE / "falsify.py"), ident],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    text = result.stdout + result.stderr
    (OUT / f"{ident}.txt").write_text(text)
    line = next((row for row in text.splitlines() if row.startswith(f"{ident}: ")), "")
    verdict = "CAUGHT" if result.returncode == 0 and "CAUGHT" in line else "MISSED"
    if result.returncode != 0:
        status = 1
        verdict = "MISSED"
    summary.append(f"{ident}: {verdict} exit={result.returncode}")
    print(f"{ident}: {verdict} exit={result.returncode}", flush=True)

(OUT / "summary.txt").write_text("\n".join(summary) + "\n")
print(f"{sum(1 for row in summary if 'CAUGHT' in row)} of {len(summary)} plants CAUGHT")
sys.exit(status)
