#!/usr/bin/env python3
"""Check aarch64 guest evidence and write RESULTS.txt from live files.

Exit 0 only when every standing suite passed with at least the expected
counts, every official plant is CAUGHT, and the nonce matches. Missing
files, stale files, or a short suite are a failure.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

RESULT_LINE = re.compile(
    r"test result:\s+\S+\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored"
)
MARK_LINE = re.compile(
    r"LC_MARK nonce=(?P<nonce>\S+) suite=(?P<suite>\S+) exit=(?P<exit>-?\d+) "
    r"passed=(?P<passed>\d+) failed=(?P<failed>\d+) ignored=(?P<ignored>\d+) "
    r"status=(?P<status>\S+)"
)


def load_json(path: pathlib.Path):
    return json.loads(path.read_text())


def parse_result_line(text: str):
    matches = RESULT_LINE.findall(text)
    if not matches:
        return None
    passed, failed, ignored = (int(x) for x in matches[-1])
    return {"passed": passed, "failed": failed, "ignored": ignored}


def read(path: pathlib.Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(errors="replace")


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: check-guest-results.py EVIDENCE EXPECTED.json nonce", file=sys.stderr)
        return 2
    evidence = pathlib.Path(sys.argv[1])
    expected = load_json(pathlib.Path(sys.argv[2]))
    nonce = sys.argv[3]
    mode = sys.argv[4] if len(sys.argv) > 4 else "full"
    problems: list[str] = []

    guest_results = read(evidence / "guest-results.txt")
    console = read(evidence / "qemu-console.txt")
    summary = read(evidence / "summary.txt")
    if nonce and f"nonce={nonce}" not in guest_results and f"nonce={nonce}" not in console:
        problems.append(f"nonce {nonce} missing from guest-results.txt and qemu-console.txt")

    marks = {m.group("suite"): m.groupdict() for m in MARK_LINE.finditer(console)}
    suite_rows = []
    for name, want in expected["suites"].items():
        status = read(evidence / f"{name}.status").strip()
        exit_text = read(evidence / f"{name}.exit").strip()
        log = read(evidence / f"{name}.txt")
        counts = parse_result_line(log) or parse_result_line(summary)
        mark = marks.get(name)
        if mark and mark["nonce"] != nonce:
            problems.append(f"{name}: serial nonce {mark['nonce']} != {nonce}")
        if not status:
            problems.append(f"{name}: missing status file")
        if not exit_text:
            problems.append(f"{name}: missing exit file")
        try:
            exit_rc = int(exit_text) if exit_text else None
        except ValueError:
            exit_rc = None
            problems.append(f"{name}: bad exit file {exit_text!r}")
        if counts is None:
            problems.append(f"{name}: no rust 'test result:' line")
            counts = {"passed": 0, "failed": 0, "ignored": 0}
        if counts["passed"] < want["passed"]:
            problems.append(
                f"{name}: passed {counts['passed']} < expected {want['passed']}"
            )
        if counts["failed"] != want["failed"]:
            problems.append(
                f"{name}: failed {counts['failed']} != expected {want['failed']}"
            )
        if counts["ignored"] < want["ignored"]:
            problems.append(
                f"{name}: ignored {counts['ignored']} < expected {want['ignored']}"
            )
        if status != "PASS" or exit_rc not in (0,):
            problems.append(f"{name}: status={status or 'MISSING'} exit={exit_text or 'MISSING'}")
        if mark:
            if int(mark["exit"]) != (exit_rc if exit_rc is not None else -1):
                problems.append(
                    f"{name}: serial exit {mark['exit']} != 9p exit {exit_text}"
                )
            if int(mark["passed"]) != counts["passed"]:
                problems.append(
                    f"{name}: serial passed {mark['passed']} != log passed {counts['passed']}"
                )
        suite_rows.append((name, status, exit_text, counts, want))

    plant_rows = []
    if mode == "full":
        for plant in expected["plants_caught"]:
            status = read(evidence / f"{plant}.status").strip()
            plant_rows.append((plant, status))
            if status != "CAUGHT":
                problems.append(f"{plant}: status={status or 'MISSING'} (want CAUGHT)")
        for plant in expected["plants_not_run"]:
            status = read(evidence / f"{plant}.status").strip()
            plant_rows.append((plant, status))
            if status and status != "NOT_RUN":
                problems.append(f"{plant}: status={status} (want NOT_RUN)")

    guest_exit = read(evidence / "guest-exit.txt")
    if mode == "full" and "guest_exit=0" not in guest_exit:
        problems.append(f"guest_exit.txt did not report 0: {guest_exit.strip()!r}")

    label = expected.get("label", "")
    if label and label not in read(evidence / "LABEL.txt") and f"LABEL={label}" not in console:
        problems.append("required TCG label missing")

    results_path = evidence / "RESULTS.txt"
    lines = [
        "# GENERATED from this guest run. Not a hand write-up.",
        f"# nonce={nonce}",
        f"# source={evidence}",
        f"# mode={mode}",
        "",
        f"C9 linux-confine on {label}",
        "",
        "Never native aarch64. Never Jetson.",
        "",
        "## Standing suites (live rust output)",
        "",
        "| suite | status | exit | passed | failed | ignored | expected passed |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, status, exit_text, counts, want in suite_rows:
        lines.append(
            f"| {name} | {status or 'MISSING'} | {exit_text or 'MISSING'} | "
            f"{counts['passed']} | {counts['failed']} | {counts['ignored']} | {want['passed']} |"
        )
    lines.extend(["", "## In-guest plants (live status files)", "", "| id | result |", "| --- | --- |"])
    for plant, status in plant_rows:
        lines.append(f"| {plant} | {status or 'MISSING'} |")
    lines.extend(
        [
            "",
            "## Guest markers",
            "",
            f"nonce={nonce}",
            guest_exit.strip() or "guest_exit=MISSING",
            "",
            "Host-only plants F-LC-WRONG-ARCH-CC and F-LC-QEMU-USER-LANDLOCK stay NOT RUN.",
            "make-char / make-block stay NOT PROVEN (no CAP_MKNOD).",
            "socketpair(AF_UNIX) stays the named C9 departure.",
            "",
            "This is an emulated CPU (qemu-system TCG) with a real aarch64 kernel.",
            "It is not a Jetson and not any other aarch64 board.",
            "",
        ]
    )
    if problems:
        lines.extend(["## Host check FAILED", ""])
        lines.extend(f"- {p}" for p in problems)
        lines.append("")
    else:
        lines.append("## Host check PASSED")
        lines.append("")
        lines.append("Every standing suite matched its expected counts.")
        if mode == "full":
            lines.append("Every official in-guest plant was CAUGHT.")
        lines.append("")
    results_path.write_text("\n".join(lines))
    print(results_path.read_text(), end="")
    if problems:
        print("HOST CHECK FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
