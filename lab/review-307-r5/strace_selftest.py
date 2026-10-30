#!/usr/bin/env python3
"""Rerun the self-test strace hunt only."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from attack import EVIDENCE, build_standins, hunt_selftest_strace

EVIDENCE.mkdir(parents=True, exist_ok=True)
bins = build_standins()
tmp = Path(tempfile.mkdtemp(prefix="fcl-r5-strace-"))
try:
    result = hunt_selftest_strace(bins, tmp)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
path = EVIDENCE / "selftest-strace.json"
path.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
