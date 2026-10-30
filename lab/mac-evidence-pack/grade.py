"""Grade one row from its evidence file. Exit 0 without proof is FAIL."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from catalog import Row


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str
    evidence: str


def _cargo_ok(name: str, text: str) -> bool:
    return f"test {name} ... ok" in text or f"| {name} | PASS" in text


def _cargo_failed(name: str, text: str) -> bool:
    return f"test {name} ... FAILED" in text or f"| {name} | FAIL" in text


def _cargo_ignored(name: str, text: str) -> bool:
    return f"test {name} ... ignored" in text


def grade(
    row: Row,
    *,
    exit_code: int | None,
    evidence_path: Path | None,
    crashed: str | None = None,
    skipped: str | None = None,
    blocked: str | None = None,
) -> Verdict:
    evidence = str(evidence_path) if evidence_path is not None else ""
    if skipped:
        return Verdict("NOT RUN", skipped, evidence)
    if blocked:
        return Verdict("FAIL", blocked, evidence)
    if crashed:
        return Verdict("FAIL", f"crashed: {crashed}", evidence)
    if evidence_path is None or not evidence_path.is_file():
        return Verdict(
            "FAIL",
            f"exit {exit_code} with no evidence file",
            evidence,
        )
    try:
        text = evidence_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return Verdict("FAIL", f"evidence file unreadable: {error}", evidence)
    if not text.strip():
        return Verdict("FAIL", "evidence file is empty", evidence)

    for name in row.expect_ok:
        if _cargo_failed(name, text):
            return Verdict("FAIL", f"{name} FAILED", evidence)
        if _cargo_ignored(name, text):
            return Verdict(
                "FAIL",
                f"{name} was ignored; a skip is not a pass",
                evidence,
            )
        if not _cargo_ok(name, text):
            return Verdict(
                "FAIL",
                f"exit {exit_code} without evidence that {name} passed",
                evidence,
            )

    for needle in row.expect_text:
        if needle not in text:
            return Verdict(
                "FAIL",
                f"exit {exit_code} without the line {needle!r}",
                evidence,
            )

    if not row.expect_ok and not row.expect_text:
        return Verdict(
            "FAIL",
            "row has no expected evidence markers",
            evidence,
        )

    if exit_code not in (0,):
        return Verdict("FAIL", f"runner exit {exit_code}", evidence)
    return Verdict("PASS", "expected evidence is present", evidence)
