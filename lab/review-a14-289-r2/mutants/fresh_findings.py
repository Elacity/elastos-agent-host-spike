#!/usr/bin/env python3
"""Fresh mutants for the seven PR 366 findings. Different plants than F-A14al..av."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CHECKOUT = Path("/tmp/a14-289-head")
OUT = Path("/workspace/lab/review-a14-289-r2/mutants/fresh_findings.json")
PYTHON = [sys.executable, "-B", "-I", "-m", "unittest", "discover", "-s", "lab/demo-a14/tests"]

CASES = [
    {
        "id": "X366-1-CHECKOUT-VAR",
        "finding": 1,
        "claim": "step 1 must not check out an existing tree even via $branch",
        "file": "lab/demo-a14/RUNBOOK.md",
        "old": 'git clone --branch "$branch" "$url" "$dest"\n',
        "new": 'git checkout "$branch"\n',
        "tests": ["test_runbook_uses_a_fresh_clone", "test_runbook_stays_on_the_demo_branch"],
        "expect_fail": True,
    },
    {
        "id": "X366-1-SWITCH",
        "finding": 1,
        "claim": "git switch in an existing tree must fail the runbook tests",
        "file": "lab/demo-a14/RUNBOOK.md",
        "old": 'git clone --branch "$branch" "$url" "$dest"\n',
        "new": "git switch cursor/demo-a14-installed-demo-83e1\n",
        "tests": ["test_runbook_uses_a_fresh_clone", "test_runbook_stays_on_the_demo_branch"],
        "expect_fail": True,
        "note": "tests only forbid git checkout, not git switch",
    },
    {
        "id": "X366-2-DROP-E",
        "finding": 2,
        "claim": "dropping only -e from set -euo pipefail must fail the runbook test",
        "file": "lab/demo-a14/RUNBOOK.md",
        "old": "set -euo pipefail\n",
        "new": "set -uo pipefail\n",
        "tests": ["test_runbook_uses_a_fresh_clone", "test_existing_destination_is_refused"],
        "expect_fail": True,
    },
    {
        "id": "X366-3-NO-DOTDOT",
        "finding": 3,
        "claim": "resolved_under must collapse .. or ../elsewhere is accepted again",
        "file": "lab/demo-a14/demo.py",
        "old": "    path_n = Path(os.path.normpath(str(path)))\n",
        "new": "    path_n = Path(str(path))\n",
        "tests": [
            "test_relative_cargo_target_dir_outside_the_repo_is_refused",
            "test_outside_cargo_target_dir_is_refused",
        ],
        "expect_fail": True,
    },
    {
        "id": "X366-4-EMPTY-READY",
        "finding": 4,
        "claim": "install default ready must stay the preflight script, not an empty list",
        "file": "lab/demo-a14/demo.py",
        "old": "    ready = preflight_problems if ready is None else ready\n",
        "new": "    ready = (lambda layout, host_os: []) if ready is None else ready\n",
        "tests": ["test_install_default_ready_runs_preflight"],
        "expect_fail": True,
    },
    {
        "id": "X366-5-ALWAYS-REMOVE",
        "finding": 5,
        "claim": "key removal must stay gated on created_key, or a pre-existing key is deleted",
        "file": "lab/demo-a14/demo.py",
        "old": "    if write_problems and created_key:\n",
        "new": "    if write_problems:\n",
        "tests": [
            "test_failed_write_keeps_a_preexisting_key",
            "test_failed_write_after_sign_removes_only_this_runs_key",
        ],
        "expect_fail": True,
    },
    {
        "id": "X366-5-SKIP-CREATED-FLAG",
        "finding": 5,
        "claim": "created_key must stay False when the key already existed",
        "file": "lab/demo-a14/demo.py",
        "old": "        created_key = (not existed) and layout.signing_key.exists()\n",
        "new": "        created_key = layout.signing_key.exists()\n",
        "tests": ["test_failed_write_keeps_a_preexisting_key"],
        "expect_fail": True,
    },
    {
        "id": "X366-6-NO-MARK",
        "finding": 6,
        "claim": "an install refusal must point this-run at the new summary",
        "file": "lab/demo-a14/demo.py",
        "old": "    write_summary(run_dir, say)\n    mark_this_run(layout, run_dir)\n    return EXIT_REFUSED\n",
        "new": "    write_summary(run_dir, say)\n    return EXIT_REFUSED\n",
        "tests": [
            "test_install_refuses_before_fetch_when_the_machine_is_not_ready",
            "test_install_default_ready_runs_preflight",
        ],
        "expect_fail": True,
    },
    {
        "id": "X366-6-LS-DT",
        "finding": 6,
        "claim": "step 5 must not pick the newest folder by date",
        "file": "lab/demo-a14/RUNBOOK.md",
        "old": "run=$(sed -n '1p' \"$demo_home/this-run\" 2>/dev/null || true)\n",
        "new": "run=$(ls -dt \"$demo_home/runs\"/*/ 2>/dev/null | head -1)\n",
        "tests": ["test_runbook_step_5_opens_only_a_real_path"],
        "expect_fail": True,
    },
    {
        "id": "X366-7-OTHER-NAME",
        "finding": 7,
        "claim": "PASS path must write summary.txt, not another filename",
        "file": "lab/demo-a14/demo.py",
        "old": '    say(f"Saved: {run_dir}")\n    write_summary(run_dir, say)\n    mark_this_run(layout, run_dir)\n    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n',
        "new": '    say(f"Saved: {run_dir}")\n    (run_dir / "notes.txt").write_text("\\n".join(say.lines) + "\\n")\n    mark_this_run(layout, run_dir)\n    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n',
        "tests": ["test_pass_writes_a14_pass_in_this_runs_summary", "test_matching_run_walks_every_step"],
        "expect_fail": True,
    },
]


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
    results = []
    for case in CASES:
        print(f"running {case['id']} ...", flush=True)
        applied = apply_edit(CHECKOUT / case["file"], case["old"], case["new"])
        planted = run_tests(case["tests"]) if applied == "applied" else {"exit": 2, "failed": True, "tail": applied}
        restore()
        restored = run_tests(case["tests"]) if applied == "applied" else {"exit": 2, "failed": True, "tail": applied}
        if applied != "applied":
            verdict = "ERROR"
        elif case["expect_fail"]:
            if planted["failed"] and not restored["failed"]:
                verdict = "CAUGHT"
            elif not planted["failed"]:
                verdict = "SURVIVED"
            else:
                verdict = "RESTORE_BROKEN"
        else:
            verdict = "STILL_GREEN" if (not planted["failed"] and not restored["failed"]) else "UNEXPECTED_FAIL"
        print(f"  {verdict}", flush=True)
        results.append(
            {
                "id": case["id"],
                "finding": case["finding"],
                "claim": case["claim"],
                "verdict": verdict,
                "applied": applied,
                "note": case.get("note"),
                "planted_exit": planted["exit"],
                "restored_exit": restored["exit"],
                "planted_tail": planted["tail"],
            }
        )
    restore()
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    print("survived:", [r["id"] for r in results if r["verdict"] == "SURVIVED"] or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
