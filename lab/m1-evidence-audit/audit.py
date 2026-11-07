#!/usr/bin/env python3
"""Read the M1 evidence catalog and flag missing citations.

A row whose expected_present is true must be readable and must contain
its marker. A row whose expected_present is false must be absent.
Required check ids and row ids live in checks.py so deleting a catalog
row is a failure even when the remaining files still parse.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from checks import REQUIRED_CHECKS, REQUIRED_ROWS, ROW_KINDS, VERDICTS

DEFAULT_EVIDENCE = HERE / "evidence.json"


def repo_root() -> Path:
    return HERE.parents[1]


def load_catalog(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_cited(root: Path, row: dict) -> tuple[str | None, str | None]:
    """Return (text, error). error is set when the read does not match expected_present."""
    rel = Path(row["path"])
    expected = bool(row.get("expected_present", True))
    ref = row.get("ref")
    local = root / rel
    text = None
    source = None
    if local.is_file():
        text = local.read_text(encoding="utf-8")
        source = str(rel)
    elif ref:
        proc = subprocess.run(
            ["git", "show", f"{ref}:{rel.as_posix()}"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            text = proc.stdout
            source = f"{ref}:{rel.as_posix()}"
        else:
            err = proc.stderr.strip() or f"git show failed for {ref}:{rel}"
            if expected:
                return None, f"missing cited file {source or rel} ({err})"
            return None, None
    elif expected:
        return None, f"missing cited file {rel}"
    else:
        return None, None

    if text is not None and not expected:
        return text, f"cited as absent but found {source or rel}"
    return text, None


def check_markers(text: str, row: dict) -> list[str]:
    problems = []
    marker = row.get("marker")
    if marker and marker not in text:
        problems.append(f"marker not found: {marker!r} in {row['path']}")
    for extra in row.get("also") or []:
        if extra not in text:
            problems.append(f"also-string not found: {extra!r} in {row['path']}")
    return problems


def skip_as_pass_unlabelled(check: dict, text: str, row: dict) -> str | None:
    if check.get("skip_counted_as_pass"):
        return None
    if row.get("kind") == "skip":
        return None
    if "if !sandbox_available" in text and "return;" in text:
        return (
            f"{check['id']} {row['id']}: {row['path']} returns after "
            "sandbox_available, but skip_counted_as_pass is false"
        )
    return None


def audit(catalog: dict, root: Path) -> list[str]:
    problems: list[str] = []
    checks = catalog.get("checks") or []
    by_id = {c.get("id"): c for c in checks}

    if catalog.get("honest_count") != list(REQUIRED_CHECKS):
        problems.append(
            "honest_count is not "
            + ", ".join(REQUIRED_CHECKS)
        )

    missing_checks = [cid for cid in REQUIRED_CHECKS if cid not in by_id]
    extra_checks = [cid for cid in by_id if cid not in REQUIRED_CHECKS]
    if missing_checks:
        problems.append("missing checks: " + ", ".join(missing_checks))
    if extra_checks:
        problems.append("unexpected checks: " + ", ".join(extra_checks))

    for cid in REQUIRED_CHECKS:
        check = by_id.get(cid)
        if not check:
            continue
        if check.get("verdict") not in VERDICTS:
            problems.append(f"{cid}: verdict must be holds, weak or falsified")
        rows = check.get("rows") or []
        row_ids = [r.get("id") for r in rows]
        for required in REQUIRED_ROWS[cid]:
            if required not in row_ids:
                problems.append(f"{cid}: missing required evidence row {required}")
        seen = set()
        for row in rows:
            rid = row.get("id")
            if not rid:
                problems.append(f"{cid}: row with no id")
                continue
            if rid in seen:
                problems.append(f"{cid}: duplicate row {rid}")
            seen.add(rid)
            if row.get("kind") not in ROW_KINDS:
                problems.append(f"{cid} {rid}: bad kind {row.get('kind')!r}")
            text, err = read_cited(root, row)
            if err:
                problems.append(f"{cid} {rid}: {err}")
                continue
            if text is None:
                continue
            for item in check_markers(text, row):
                problems.append(f"{cid} {rid}: {item}")
            skip = skip_as_pass_unlabelled(check, text, row)
            if skip:
                problems.append(skip)
    return problems


def table(catalog: dict) -> str:
    lines = [
        "| Check | Verdict | Refusal row | Runtime or kernel | Skip counted as pass | Needs Mac |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for check in catalog.get("checks") or []:
        lines.append(
            "| {id} | {verdict} | {refusal} | {runtime} | {skip} | {mac} |".format(
                id=check["id"],
                verdict=check["verdict"],
                refusal="yes" if check.get("refusal_row") else "no",
                runtime=check.get("runtime_or_kernel", "").replace("\n", " "),
                skip="yes" if check.get("skip_counted_as_pass") else "no",
                mac=check.get("needs_mac", ""),
            )
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    catalog = load_catalog(args.evidence)
    problems = audit(catalog, args.root)
    if not args.quiet:
        print(table(catalog))
        print()
    if problems:
        print("MISSING EVIDENCE")
        for item in problems:
            print(f"- {item}")
    elif not args.quiet:
        print("catalog rows resolved")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
