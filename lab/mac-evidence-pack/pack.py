#!/usr/bin/env python3
"""One morning pack for the macOS M1 rows that have never been run on Sash's Mac."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from catalog import ROWS, Row, a14_runs_demo, unique_checkouts
from checkout import CheckoutError, checkout_commit, recorded_commit
from grade import Verdict, grade
from paths import PathRefusal, env_home, require_under_home, resolve
from preflight import (
    Facts,
    collect_facts,
    dump_facts,
    format_report,
    load_facts,
    problems,
)


PACK_DIR_NAME = "mac-evidence-pack"


@dataclass
class RowResult:
    row: Row
    verdict: Verdict
    commit_used: str


def default_work_dir(home: Path, *, dry_run: bool) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    label = f"dry-run-{stamp}" if dry_run else stamp
    return home / PACK_DIR_NAME / label


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def format_plan() -> str:
    lines = ["plan:"]
    for branch, commit, pr in unique_checkouts():
        rows = [row.id for row in ROWS if row.commit == commit]
        lines.append(
            f"  PR #{pr}  {branch}  {commit}  rows:{','.join(rows)}"
        )
    for row in ROWS:
        cmds = " ; ".join(" ".join(cmd) for cmd in row.commands)
        lines.append(f"  {row.id}  {cmds}")
        if row.demo_pointer:
            lines.append(f"  {row.id}  pointer: {row.demo_pointer}")
    return "\n".join(lines) + "\n"


def format_summary(
    *,
    work: Path,
    facts: Facts | None,
    gaps: list[str],
    results: list[RowResult],
    dry_run: bool,
) -> str:
    lines = [
        "mac-evidence-pack",
        f"work: {work}",
        f"dry-run: {dry_run}",
    ]
    if facts is not None:
        lines.extend(
            [
                f"os: {facts.os_name}",
                f"macOS: {facts.macos_version or 'n/a'}",
                f"machine: {facts.machine}",
                f"translated: {facts.translated}",
                f"uid: {facts.uid}",
            ]
        )
        if gaps:
            lines.append("preflight: FAIL")
            for gap in gaps:
                lines.append(f"  {gap}")
        else:
            lines.append("preflight: OK")
    else:
        lines.append("preflight: NOT RUN")
    lines.append("rows:")
    for item in results:
        used = item.commit_used or item.row.commit
        lines.append(
            f"{item.row.id}\t{item.verdict.status}\t"
            f"{item.row.branch} {used}\t"
            f"{item.verdict.reason}\t"
            f"evidence: {item.verdict.evidence}"
        )
        if item.row.demo_pointer:
            lines.append(f"{item.row.id}\tpointer\t{item.row.demo_pointer}")
    counts = {"PASS": 0, "FAIL": 0, "NOT RUN": 0}
    for item in results:
        counts[item.verdict.status] = counts.get(item.verdict.status, 0) + 1
    lines.append(
        f"counts: PASS={counts.get('PASS', 0)} "
        f"FAIL={counts.get('FAIL', 0)} "
        f"NOT RUN={counts.get('NOT RUN', 0)}"
    )
    return "\n".join(lines) + "\n"


def print_row(item: RowResult) -> None:
    print(
        f"{item.row.id}  {item.verdict.status}  "
        f"{item.verdict.reason}  evidence: {item.verdict.evidence}",
        flush=True,
    )


def run_fixture_preflights(work: Path) -> str:
    from preflight import facts_from_dict

    fixture_dir = HERE / "fixtures"
    lines = ["fixture preflight:"]
    for path in sorted(fixture_dir.glob("*.json")):
        facts = facts_from_dict(json.loads(path.read_text(encoding="utf-8")))
        gaps = problems(facts)
        status = "PASS" if not gaps else "REFUSED"
        detail = gaps[0] if gaps else "no gaps"
        lines.append(f"  {path.stem}: {status} {detail}")
    text = "\n".join(lines) + "\n"
    write_text(work / "fixture-preflight.txt", text)
    return text


def _row_env(row: Row, work: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_INCREMENTAL"] = "0"
    env["RUST_TEST_THREADS"] = "2"
    env["CARGO_TERM_COLOR"] = "never"
    tmp = work / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    if row.unset_cargo_target:
        env.pop("CARGO_TARGET_DIR", None)
    else:
        target = work / "target" / row.checkout_name
        target.mkdir(parents=True, exist_ok=True)
        env["CARGO_TARGET_DIR"] = str(target)
    return env


def execute_commands(row: Row, checkout: Path, work: Path, evidence: Path) -> int:
    import subprocess

    env = _row_env(row, work)
    chunks: list[str] = []
    status = 0
    for cmd in row.commands:
        chunks.append("$ " + " ".join(cmd) + "\n")
        completed = subprocess.run(
            list(cmd),
            cwd=checkout,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        chunks.append(completed.stdout)
        if completed.stderr:
            chunks.append(completed.stderr)
        chunks.append(f"\nexit {completed.returncode}\n")
        if completed.returncode != 0 and status == 0:
            status = completed.returncode
    if row.demo_pointer:
        chunks.append("\n" + row.demo_pointer + "\n")
    write_text(evidence, "".join(chunks))
    return status


def run_one_row(
    row: Row,
    *,
    work: Path,
    source_repo: Path,
    dry_run: bool,
    skip_reason: str | None,
) -> RowResult:
    evidence = work / "rows" / row.id / "evidence.txt"
    meta = work / "rows" / row.id / "meta.txt"
    write_text(
        meta,
        f"row: {row.id}\nbranch: {row.branch}\ncommit: {row.commit}\npr: {row.pr}\n",
    )
    if dry_run:
        write_text(
            evidence,
            f"NOT RUN: --dry-run; {row.title}\n"
            f"branch: {row.branch}\ncommit: {row.commit}\n",
        )
        return RowResult(
            row,
            grade(
                row,
                exit_code=None,
                evidence_path=evidence,
                skipped="--dry-run; macOS row not executed",
            ),
            row.commit,
        )
    if skip_reason:
        write_text(evidence, f"NOT RUN: {skip_reason}\n")
        return RowResult(
            row,
            grade(
                row,
                exit_code=None,
                evidence_path=evidence,
                skipped=skip_reason,
            ),
            row.commit,
        )
    try:
        checkout = checkout_commit(work, source_repo, row.branch, row.commit)
        try:
            commit_used = recorded_commit(checkout)
        except CheckoutError:
            commit_used = row.commit
        write_text(
            meta,
            f"row: {row.id}\nbranch: {row.branch}\ncommit: {commit_used}\n"
            f"checkout: {checkout}\npr: {row.pr}\n",
        )
        status = execute_commands(row, checkout, work, evidence)
        return RowResult(
            row,
            grade(row, exit_code=status, evidence_path=evidence),
            commit_used,
        )
    except (CheckoutError, PathRefusal, OSError) as error:
        write_text(evidence, f"checkout or run failed: {error}\n")
        return RowResult(
            row,
            grade(
                row,
                exit_code=None,
                evidence_path=evidence,
                crashed=str(error),
            ),
            row.commit,
        )
    except Exception as error:  # noqa: BLE001 — a crashed row must still grade
        write_text(evidence, "crashed:\n" + traceback.format_exc())
        return RowResult(
            row,
            grade(
                row,
                exit_code=None,
                evidence_path=evidence,
                crashed=str(error),
            ),
            row.commit,
        )


def run(
    *,
    work: Path,
    source_repo: Path,
    dry_run: bool,
    facts: Facts | None = None,
    run_row_fn: Callable[..., RowResult] | None = None,
) -> list[RowResult]:
    if a14_runs_demo():
        raise RuntimeError("catalog A14 must not call the demo install or run")
    work.mkdir(parents=True, exist_ok=True)
    (work / "tmp").mkdir(parents=True, exist_ok=True)
    (work / "rows").mkdir(parents=True, exist_ok=True)
    write_text(work / "plan.txt", format_plan())
    print(format_plan(), end="")
    if dry_run:
        print(run_fixture_preflights(work), end="")
    if facts is None:
        facts = collect_facts(home=env_home(), work=work)
    write_text(work / "facts.json", dump_facts(facts))
    gaps = problems(facts)
    write_text(work / "preflight.txt", format_report(facts, gaps))
    print(format_report(facts, gaps), end="")
    skip = None
    if dry_run:
        skip = "--dry-run; macOS row not executed"
    elif gaps:
        skip = "preflight refused: " + gaps[0]
    runner = run_row_fn or run_one_row
    results: list[RowResult] = []
    try:
        for row in ROWS:
            item = runner(
                row,
                work=work,
                source_repo=source_repo,
                dry_run=dry_run,
                skip_reason=skip,
            )
            results.append(item)
            print_row(item)
    except Exception as error:  # noqa: BLE001
        evidence = work / "rows" / "CRASH" / "evidence.txt"
        write_text(evidence, traceback.format_exc())
        crashed = Row(
            id="CRASH",
            title="pack crashed",
            branch="n/a",
            commit="n/a",
            pr=0,
            commands=(),
            expect_text=("crashed",),
        )
        write_text(evidence, "crashed:\n" + traceback.format_exc())
        results.append(
            RowResult(
                crashed,
                grade(
                    crashed,
                    exit_code=None,
                    evidence_path=evidence,
                    crashed=str(error),
                ),
                "n/a",
            )
        )
    finally:
        write_text(
            work / "summary.txt",
            format_summary(
                work=work,
                facts=facts,
                gaps=gaps,
                results=results,
                dry_run=dry_run,
            ),
        )
        print(f"summary: {work / 'summary.txt'}", flush=True)
    return results


def find_repo(start: Path) -> Path:
    cursor = resolve(start)
    for folder in (cursor, *cursor.parents):
        if (folder / ".git").exists():
            return folder
    raise PathRefusal(f"no git checkout at {start}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the macOS M1 evidence rows into one home work dir."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan and pins. Run preflight against fixtures. Do not run macOS rows.",
    )
    parser.add_argument("--work-dir", help="Work dir. Must sit under HOME.")
    parser.add_argument("--facts", help="JSON facts file (tests and fixture runs).")
    parser.add_argument("--repo", help="Source git checkout of this repo.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    home = env_home()
    source = resolve(Path(args.repo)) if args.repo else find_repo(HERE)
    work = resolve(Path(args.work_dir)) if args.work_dir else default_work_dir(
        home, dry_run=args.dry_run
    )
    try:
        require_under_home(work, home, "the work dir")
    except PathRefusal as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 2
    facts = load_facts(Path(args.facts)) if args.facts else None
    results = run(
        work=work,
        source_repo=source,
        dry_run=args.dry_run,
        facts=facts,
    )
    if any(item.verdict.status == "FAIL" for item in results):
        return 1
    if not args.dry_run and any(item.verdict.status != "PASS" for item in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
