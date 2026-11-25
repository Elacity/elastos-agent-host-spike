#!/usr/bin/env python3
"""Fail when an ignored advisory's re-review date has passed.

elastos/.cargo/audit.toml lists each ignored advisory on its own quoted line.
The comment above that line says `re-review by YYYY-MM-DD`. A date before
today fails this process and names the advisory. AUDIT_RE_REVIEW_TODAY, as
YYYY-MM-DD, checks another day.
"""

import os
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "elastos/.cargo/audit.toml"
ADVISORY = re.compile(r'^\s*"([A-Z]+-\d{4}-\d+)"')
REVIEW = re.compile(r"re-review by (\d{4}-\d{2}-\d{2})\b")


def today():
    raw = os.environ.get("AUDIT_RE_REVIEW_TODAY")
    if not raw:
        return date.today()
    return date.fromisoformat(raw)


def failures(text, on):
    """Each expired or undated advisory, named."""
    found = []
    in_ignore = False
    pending = None
    used = False
    for line in text.splitlines():
        if not in_ignore:
            if line.strip().startswith("ignore"):
                in_ignore = True
            continue
        if line.strip().startswith("]"):
            break
        reviewed = REVIEW.search(line)
        if reviewed:
            pending = reviewed.group(1)
            used = False
            continue
        match = ADVISORY.match(line)
        if not match:
            continue
        advisory = match.group(1)
        if pending is None or used:
            found.append(f"{advisory}: re-review date is missing")
            continue
        used = True
        try:
            deadline = date.fromisoformat(pending)
        except ValueError:
            found.append(f"{advisory}: re-review date {pending} is not a date")
            continue
        if deadline < on:
            found.append(f"{advisory}: re-review date {pending} has passed")
    if not in_ignore:
        found.append("audit.toml: ignore list is missing")
    return found


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    found = failures(path.read_text(encoding="utf-8"), today())
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
