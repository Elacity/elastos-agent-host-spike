#!/usr/bin/env python3
"""Re-run every falsifier in lab/demo-a14/falsifiers.json against 39b4b47e."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from run_mutants import CHECKOUT, apply_edit, restore, run_tests

LANE = CHECKOUT / "lab" / "demo-a14"
OUT = Path("/workspace/lab/review-a14-289/mutants/all_claimed.json")


def main() -> int:
    data = json.loads((LANE / "falsifiers.json").read_text(encoding="utf-8"))
    results = []
    restore()
    for item in data["falsifiers"]:
        edit = item["edits"][0]
        print(f"running {item['id']} ...", flush=True)
        applied = apply_edit(CHECKOUT / edit["file"], edit["old"], edit["new"])
        planted = run_tests(item["tests"]) if applied == "applied" else {"exit": 2, "failed": True, "tail": applied}
        restore()
        restored = run_tests(item["tests"]) if applied == "applied" else {"exit": 2, "failed": True, "tail": applied}
        if applied != "applied":
            verdict = "ERROR"
        elif planted["failed"] and not restored["failed"]:
            verdict = "CAUGHT"
        elif not planted["failed"]:
            verdict = "SURVIVED"
        else:
            verdict = "RESTORE_BROKEN"
        print(f"  {verdict}", flush=True)
        results.append({"id": item["id"], "title": item["title"], "verdict": verdict, "applied": applied})
    restore()
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    survived = [r["id"] for r in results if r["verdict"] != "CAUGHT"]
    print(f"wrote {OUT}")
    print("not caught:", survived or "none")
    print(f"caught {sum(r['verdict']=='CAUGHT' for r in results)}/{len(results)}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
