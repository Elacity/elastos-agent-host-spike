#!/usr/bin/env python3
"""Plant every lab/demo-a14/falsifiers.json entry against the detached e6651b29 worktree."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CHECKOUT = Path("/tmp/a14-289-head")
LANE = CHECKOUT / "lab" / "demo-a14"
OUT = Path("/workspace/lab/review-a14-289-r2/mutants/all_claimed.json")
PYTHON = [sys.executable, "-B", "-I", "-m", "unittest", "discover", "-s", "lab/demo-a14/tests"]


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=CHECKOUT, capture_output=True, text=True)


def restore() -> None:
    done = git("checkout", "--", "lab/demo-a14")
    if done.returncode != 0:
        raise SystemExit(f"restore failed: {done.stderr}")


def apply_edit(path: Path, old: str, new: str) -> str:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        return f"edit not unique: {path.name} count={count}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return "applied"


def run_tests(names: list[str]) -> dict:
    cmd = PYTHON + ["-v"]
    for name in names:
        cmd.extend(["-k", name])
    done = subprocess.run(cmd, cwd=CHECKOUT, capture_output=True, text=True)
    tail = "\n".join((done.stderr + done.stdout).strip().splitlines()[-24:])
    return {"exit": done.returncode, "failed": done.returncode != 0, "tail": tail}


def main() -> int:
    restore()
    dirty = git("status", "--porcelain=v1", "--", "lab/demo-a14")
    if dirty.stdout.strip():
        print("worktree already dirty; abort", dirty.stdout)
        return 2
    data = json.loads((LANE / "falsifiers.json").read_text(encoding="utf-8"))
    results = []
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
        results.append(
            {
                "id": item["id"],
                "title": item["title"],
                "verdict": verdict,
                "applied": applied,
                "planted_exit": planted["exit"],
                "restored_exit": restored["exit"],
                "planted_tail": planted["tail"],
            }
        )
    restore()
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    survived = [r["id"] for r in results if r["verdict"] != "CAUGHT"]
    print(f"wrote {OUT}")
    print("not caught:", survived or "none")
    print(f"caught {sum(r['verdict']=='CAUGHT' for r in results)}/{len(results)}")
    return 0 if not survived else 1


if __name__ == "__main__":
    raise SystemExit(main())
