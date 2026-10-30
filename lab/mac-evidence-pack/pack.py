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

from catalog import PIN_BY_ID, ROWS, Row, a14_runs_demo, unique_checkouts
from checkout import (
    CheckoutError,
    checkout_commit,
    enclosing_git,
    ensure_owned_clone,
    recorded_commit,
)
from grade import Verdict, grade
from isolate import inspect_runner, isolation_env, row_needs_isolation
from paths import PathRefusal, env_home, require_under_home, resolve
from pins import (
    PACK_BRANCH,
    REMOTE,
    default_pack_clone,
    is_pack_owned,
    pin_block_reason,
)
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
        status = next(row.pin_status for row in ROWS if row.commit == commit)
        lines.append(
            f"  PR #{pr}  {branch}  {commit}  pin:{status}  rows:{','.join(rows)}"
        )
    for row in ROWS:
        cmds = " ; ".join(" ".join(cmd) for cmd in row.commands)
        lines.append(f"  {row.id}  {cmds}")
        if row.demo_pointer:
            lines.append(f"  {row.id}  pointer: {row.demo_pointer}")
    return "\n".join(lines) + "\n"


def format_pins() -> str:
    lines = ["pins:"]
    for row in ROWS:
        extra = f"  {row.pin_reason}" if row.pin_reason else ""
        lines.append(
            f"  {row.id}\t{row.branch}\t{row.commit}\t{row.pin_status}{extra}"
        )
    return "\n".join(lines) + "\n"


def format_summary(
    *,
    work: Path,
    facts: Facts | None,
    gaps: list[str],
    results: list[RowResult],
    dry_run: bool,
    abort: str | None = None,
) -> str:
    lines = [
        "mac-evidence-pack",
        f"work: {work}",
        f"dry-run: {dry_run}",
    ]
    if abort:
        lines.append(f"abort: {abort}")
    lines.append(format_pins().rstrip())
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
            f"pin:{item.row.pin_status}\t"
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
    if row_needs_isolation(row):
        isolated = isolation_env(work)
        for key, value in isolated.items():
            env[key] = value
        (work / "isolated-tmp" / "elastos" / "storage").mkdir(parents=True, exist_ok=True)
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


def _blocked_result(row: Row, evidence: Path, reason: str, commit_used: str) -> RowResult:
    write_text(evidence, f"FAIL: {reason}\n")
    return RowResult(
        row,
        grade(
            row,
            exit_code=None,
            evidence_path=evidence,
            blocked=reason,
        ),
        commit_used,
    )


def _named_block(error: BaseException) -> str | None:
    text = str(error)
    for prefix in (
        "PIN_",
        "FOREIGN_CLONE",
        "PACK_CLONE_FOREIGN",
        "A12_SHARED_TMP_UNREDIRECTABLE",
    ):
        if text.startswith(prefix):
            return text
    return None


def run_one_row(
    row: Row,
    *,
    work: Path,
    pack_clone: Path | None,
    dry_run: bool,
    skip_reason: str | None,
) -> RowResult:
    evidence = work / "rows" / row.id / "evidence.txt"
    meta = work / "rows" / row.id / "meta.txt"
    write_text(
        meta,
        f"row: {row.id}\nbranch: {row.branch}\ncommit: {row.commit}\n"
        f"pr: {row.pr}\npin: {row.pin_status}\n",
    )
    if dry_run:
        write_text(
            evidence,
            f"NOT RUN: --dry-run; {row.title}\n"
            f"branch: {row.branch}\ncommit: {row.commit}\n"
            f"pin: {row.pin_status}\n",
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
        write_text(evidence, f"NOT RUN: {skip_reason}\ncommit: {row.commit}\n")
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
    pin_hold = pin_block_reason(PIN_BY_ID[row.id])
    if pin_hold:
        return _blocked_result(row, evidence, pin_hold, row.commit)
    if pack_clone is None or not is_pack_owned(pack_clone):
        return _blocked_result(
            row,
            evidence,
            "FOREIGN_CLONE: refuses to operate inside existing non-pack clone",
            row.commit,
        )
    try:
        checkout = checkout_commit(work, pack_clone, row.branch, row.commit)
        try:
            commit_used = recorded_commit(checkout)
        except CheckoutError:
            commit_used = row.commit
        if commit_used != row.commit:
            return _blocked_result(
                row,
                evidence,
                f"PIN_MISSING: checkout HEAD {commit_used} is not pin {row.commit}",
                row.commit,
            )
        write_text(
            meta,
            f"row: {row.id}\nbranch: {row.branch}\ncommit: {commit_used}\n"
            f"checkout: {checkout}\npr: {row.pr}\npin: {row.pin_status}\n",
        )
        if row_needs_isolation(row):
            isolated = inspect_runner(checkout)
            if isolated:
                return _blocked_result(row, evidence, isolated, commit_used)
        status = execute_commands(row, checkout, work, evidence)
        return RowResult(
            row,
            grade(row, exit_code=status, evidence_path=evidence),
            commit_used,
        )
    except (CheckoutError, PathRefusal, OSError) as error:
        named = _named_block(error)
        write_text(evidence, f"checkout or run failed: {error}\n")
        if named:
            return RowResult(
                row,
                grade(
                    row,
                    exit_code=None,
                    evidence_path=evidence,
                    blocked=named,
                ),
                row.commit,
            )
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


def write_summary(
    work: Path,
    *,
    facts: Facts | None,
    gaps: list[str],
    results: list[RowResult],
    dry_run: bool,
    abort: str | None = None,
) -> Path:
    path = work / "summary.txt"
    write_text(
        path,
        format_summary(
            work=work,
            facts=facts,
            gaps=gaps,
            results=results,
            dry_run=dry_run,
            abort=abort,
        ),
    )
    print(f"summary: {path}", flush=True)
    return path


def abort_results(reason: str) -> list[RowResult]:
    out: list[RowResult] = []
    for row in ROWS:
        out.append(
            RowResult(
                row,
                Verdict("FAIL", reason, ""),
                row.commit,
            )
        )
    return out


def run(
    *,
    work: Path,
    pack_clone: Path | None,
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
    print(format_pins(), end="")
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
        if skip is None and (pack_clone is None or not is_pack_owned(pack_clone)):
            pack_clone = ensure_owned_clone(default_pack_clone(env_home()))
        for row in ROWS:
            item = runner(
                row,
                work=work,
                pack_clone=pack_clone,
                dry_run=dry_run,
                skip_reason=skip,
            )
            results.append(item)
            print_row(item)
    except (PathRefusal, CheckoutError) as error:
        reason = str(error)
        results.extend(abort_results(reason))
        print(f"REFUSED {reason}", flush=True)
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
        write_summary(
            work,
            facts=facts,
            gaps=gaps,
            results=results,
            dry_run=dry_run,
        )
    return results


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
    parser.add_argument(
        "--pack-clone",
        help="Existing pack-owned clone. Refused if the path is not pack-owned.",
    )
    parser.add_argument(
        "--repo",
        help="Ignored alias kept so old flags fail closed: must be a pack-owned clone.",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Create or reuse $HOME/mac-evidence-pack/pack-clone, then run from it.",
    )
    return parser.parse_args(argv)


def _prepare_work(home: Path, args: argparse.Namespace) -> Path:
    if args.work_dir:
        return resolve(Path(args.work_dir))
    return default_work_dir(home, dry_run=args.dry_run)


def _write_abort(home: Path, work: Path | None, reason: str, dry_run: bool) -> Path:
    dest = work
    if dest is None or not dest:
        dest = default_work_dir(home, dry_run=dry_run)
    try:
        require_under_home(dest, home, "the work dir")
    except PathRefusal:
        dest = default_work_dir(home, dry_run=dry_run)
    dest.mkdir(parents=True, exist_ok=True)
    write_summary(
        dest,
        facts=None,
        gaps=[],
        results=abort_results(reason),
        dry_run=dry_run,
        abort=reason,
    )
    return dest


def resolve_pack_clone(
    home: Path,
    args: argparse.Namespace,
    *,
    create: bool,
) -> Path | None:
    flagged = args.pack_clone or args.repo
    if flagged:
        clone = resolve(Path(flagged))
        if not is_pack_owned(clone):
            raise PathRefusal(
                f"FOREIGN_CLONE: refuses to operate inside existing non-pack clone ({clone})"
            )
        return clone
    here_repo = enclosing_git(HERE)
    if here_repo is not None and is_pack_owned(here_repo):
        return here_repo
    if not create:
        return None
    return ensure_owned_clone(
        default_pack_clone(home),
        remote=REMOTE,
        branch=PACK_BRANCH,
    )


def main(argv: list[str] | None = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]
    args = parse_args(raw)
    try:
        home = env_home()
    except PathRefusal as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 2
    work: Path | None = None
    try:
        work = _prepare_work(home, args)
        require_under_home(work, home, "the work dir")
    except PathRefusal as error:
        print(f"REFUSED {error}", file=sys.stderr)
        _write_abort(home, None, str(error), args.dry_run)
        return 2
    assert work is not None
    try:
        pack_clone = resolve_pack_clone(
            home,
            args,
            create=bool(args.bootstrap),
        )
        if args.bootstrap and pack_clone is not None:
            owned_pack = pack_clone / "lab" / "mac-evidence-pack" / "pack.py"
            if owned_pack.is_file() and resolve(owned_pack) != resolve(Path(__file__)):
                rest = [item for item in raw if item != "--bootstrap"]
                os.execv(
                    sys.executable,
                    [sys.executable, "-I", str(owned_pack), *rest],
                )
    except (PathRefusal, CheckoutError) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        _write_abort(home, work, str(error), args.dry_run)
        return 2
    facts = load_facts(Path(args.facts)) if args.facts else None
    try:
        results = run(
            work=work,
            pack_clone=pack_clone,
            dry_run=args.dry_run,
            facts=facts,
        )
    except (PathRefusal, CheckoutError) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        _write_abort(home, work, str(error), args.dry_run)
        return 2
    if any(item.verdict.status == "FAIL" for item in results):
        return 1
    if not args.dry_run and any(item.verdict.status != "PASS" for item in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
