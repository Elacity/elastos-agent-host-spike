#!/usr/bin/env python3
"""Mutate each claimed A14 guard. A surviving mutant is WEAK.

Runs inside the detached 39b4b47e worktree. Restores every file after each
plant. Does not commit and does not touch the review branch sources.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CHECKOUT = Path("/workspace/lab/review-a14-289/checkout")
LANE = CHECKOUT / "lab" / "demo-a14"
OUT = Path("/workspace/lab/review-a14-289/mutants/results.json")
PYTHON = [sys.executable, "-B", "-I", "-m", "unittest", "discover", "-s", "lab/demo-a14/tests"]


def git(*args: str, cwd: Path = CHECKOUT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


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
    tail = "\n".join((done.stderr + done.stdout).strip().splitlines()[-20:])
    return {
        "exit": done.returncode,
        "failed": done.returncode != 0,
        "tail": tail,
    }


def load_claimed() -> list[dict]:
    data = json.loads((LANE / "falsifiers.json").read_text(encoding="utf-8"))
    wanted = {
        "F-A14al": "1 runbook stays on demo branch",
        "F-A14ad": "3 machine check before fetch",
        "F-A14ak": "3 missing wasm refused",
        "F-A14ae": "4 key not written before install can finish",
        "F-A14af": "5 refused run writes summary",
        "F-A14am": "5 step 5 opens only a real path",
        "F-A14aj": "6 outside CARGO_TARGET_DIR refused",
        "F-A14ag": "6 CARGO_TERM_COLOR forced never",
        "F-A14ah": "7 Rosetta refused",
        "F-A14ai": "8 space in HOME refused",
    }
    out = []
    for item in data["falsifiers"]:
        if item["id"] in wanted:
            out.append({**item, "claim": wanted[item["id"]], "kind": "claimed"})
    return out


EXTRA = [
    {
        "id": "X-PASS-SUMMARY",
        "claim": "PASS path must write summary.txt",
        "kind": "extra",
        "file": "lab/demo-a14/demo.py",
        "old": '    say(f"Saved: {run_dir}")\n    write_summary(run_dir, say)\n    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n',
        "new": '    say(f"Saved: {run_dir}")\n    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n',
        "tests": [
            "test_matching_run_walks_every_step",
            "test_run_states_what_the_signature_proves",
        ],
        "expect_fail": True,
    },
    {
        "id": "X-RELATIVE-TARGET",
        "claim": "relative CARGO_TARGET_DIR that walks above the repo is refused",
        "kind": "extra",
        "file": "lab/demo-a14/demo.py",
        "old": "        if target.is_absolute() and not inside(layout.repo, str(target)):\n",
        "new": "        if (target.is_absolute() or str(target).startswith('..')) and not inside(layout.repo, str(target)):\n",
        "tests": ["test_outside_cargo_target_dir_is_refused", "test_relative_cargo_target_dir_is_allowed"],
        "expect_fail": False,
        "note": "strengthening the guard should keep current tests green; used only as a contrast",
    },
    {
        "id": "X-SPACE-CHECKOUT-ONLY",
        "claim": "space in the checkout path is tested",
        "kind": "extra",
        "file": "lab/demo-a14/demo.py",
        "old": '        ("HOME", home),\n        ("the checkout path", layout.repo),\n        ("CARGO_HOME", cargo_home),\n',
        "new": '        ("HOME", home),\n        ("CARGO_HOME", cargo_home),\n',
        "tests": ["test_space_in_home_is_refused"],
        "expect_fail": True,
    },
    {
        "id": "X-QUARANTINE-PREFLIGHT",
        "claim": "preflight quarantine check is pinned",
        "kind": "extra",
        "file": "lab/demo-a14/preflight.sh",
        "old": "  if [ \"$os\" = Darwin ] && command -v xattr >/dev/null 2>&1; then\n",
        "new": "  if false && [ \"$os\" = Darwin ] && command -v xattr >/dev/null 2>&1; then\n",
        "tests": ["test_runbook_stays_on_the_demo_branch", "test_preflight_names_linux_on_this_machine"],
        "expect_fail": True,
    },
    {
        "id": "X-ROSETTA-SYSCTL-FAIL-OPEN",
        "claim": "sysctl failure is treated as not-Rosetta (returns 0)",
        "kind": "extra",
        "file": "lab/demo-a14/demo.py",
        "old": '    except OSError:\n        return "0"\n    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else "0"\n',
        "new": '    except OSError:\n        return "1"\n    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else "1"\n',
        "tests": ["test_rosetta_is_refused", "test_ready_mac_is_allowed"],
        "expect_fail": True,
        "note": "tests inject translated=; they never call proc_translated()",
    },
    {
        "id": "X-INSTALL-NO-SUMMARY",
        "claim": "install refusal writes summary.txt",
        "kind": "extra",
        "file": "lab/demo-a14/demo.py",
        "old": "        refuse(say, \"this machine is not ready.\", problems, again)\n        return EXIT_REFUSED\n",
        "new": "        refuse(say, \"this machine is not ready.\", problems, again)\n        write_summary(new_run_dir(layout), say)\n        return EXIT_REFUSED\n",
        "tests": ["test_install_refuses_before_fetch_when_the_machine_is_not_ready"],
        "expect_fail": True,
        "note": "adding a summary should not break the existing install test; used as contrast if it stays green",
    },
    {
        "id": "X-RUNBOOK-RESET",
        "claim": "runbook must not reset an existing tree",
        "kind": "extra",
        "file": "lab/demo-a14/RUNBOOK.md",
        "old": "git checkout cursor/demo-a14-installed-demo-83e1\n",
        "new": "git checkout cursor/demo-a14-installed-demo-83e1\ngit reset --hard\n",
        "tests": ["test_runbook_stays_on_the_demo_branch"],
        "expect_fail": True,
    },
]


def run_case(case: dict) -> dict:
    restore()
    path = CHECKOUT / case["file"] if "file" in case else None
    if path is None:
        edit = case["edits"][0]
        path = CHECKOUT / edit["file"]
        old, new = edit["old"], edit["new"]
    else:
        old, new = case["old"], case["new"]
    applied = apply_edit(path, old, new)
    result = {
        "id": case["id"],
        "claim": case.get("claim"),
        "kind": case.get("kind"),
        "applied": applied,
        "tests": case["tests"],
        "note": case.get("note"),
    }
    if applied != "applied":
        result["verdict"] = "ERROR"
        restore()
        return result
    planted = run_tests(case["tests"])
    restore()
    restored = run_tests(case["tests"])
    expect_fail = case.get("expect_fail", True)
    if expect_fail:
        if planted["failed"] and not restored["failed"]:
            verdict = "CAUGHT"
        elif not planted["failed"]:
            verdict = "SURVIVED"
        else:
            verdict = "RESTORE_BROKEN"
    else:
        if not planted["failed"] and not restored["failed"]:
            verdict = "STILL_GREEN"
        else:
            verdict = "UNEXPECTED_FAIL"
    result.update(
        {
            "planted": planted,
            "restored": restored,
            "verdict": verdict,
            "expect_fail": expect_fail,
        }
    )
    return result


def main() -> int:
    os.chdir(CHECKOUT)
    dirty = git("status", "--porcelain=v1", "--", "lab/demo-a14")
    if dirty.stdout.strip():
        print("worktree already dirty; abort", dirty.stdout)
        return 2
    results = []
    for case in load_claimed() + EXTRA:
        print(f"running {case['id']} ...", flush=True)
        item = run_case(case)
        print(f"  {item['verdict']}", flush=True)
        results.append(item)
    restore()
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    survived = [r["id"] for r in results if r["verdict"] == "SURVIVED"]
    print("survived:", survived or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
