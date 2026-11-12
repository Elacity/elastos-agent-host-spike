#!/usr/bin/env python3
"""Check aarch64 guest evidence and write RESULTS.txt from live files.

Exit 0 only when every standing suite passed with the exact expected
counts, every official plant is CAUGHT, every suite has exactly one
LC_MARK serial line that matches the 9p files and the host nonce, qemu
exited 0 without a timeout, guest_exit.txt is exactly one canonical
line, the nonce matches the host pre-boot hash, evidence files do not
predate that run, and the guest proved the test uid could not read the
nonce. Duplicate marks, a substring guest_exit, a replayed tree, missing
files, stale files, a short or inflated suite, or an abnormal qemu exit
are a failure.
"""

from __future__ import annotations

import hashlib
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
GUEST_EXIT_LINE = re.compile(r"^guest_exit=(0|[1-9][0-9]*)$")
PREBOOT_HASH_LINE = re.compile(r"^nonce_sha256=([0-9a-f]{64})$")
PREBOOT_START_LINE = re.compile(r"^run_start=(0|[1-9][0-9]*)$")


def load_json(path: pathlib.Path):
    return json.loads(path.read_text())


def parse_result_line(text: str):
    # Last rust harness line wins. A later forged line must not be ignored.
    matches = RESULT_LINE.findall(text)
    if not matches:
        return None
    passed, failed, ignored = (int(x) for x in matches[-1])
    return {"passed": passed, "failed": failed, "ignored": ignored}


def read(path: pathlib.Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(errors="replace")


def parse_host_context(text: str):
    qemu_exit = None
    qemu_timeout = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("qemu_exit="):
            value = line.split("=", 1)[1].strip()
            try:
                qemu_exit = int(value)
            except ValueError:
                qemu_exit = -1
        if line.startswith("qemu_timeout="):
            qemu_timeout = line.split("=", 1)[1].strip() in ("1", "true", "yes")
    return qemu_exit, qemu_timeout


def nonce_present(nonce: str, guest_results: str, console: str) -> bool:
    token = f"nonce={nonce}"
    return bool(nonce) and (token in guest_results or token in console)


def collect_nonce_problems(nonce: str, guest_results: str, console: str, marks: dict) -> list[str]:
    problems = []
    if not nonce_present(nonce, guest_results, console):
        problems.append(f"nonce {nonce} missing from guest-results.txt and qemu-console.txt")
    for name, mark in marks.items():
        if mark["nonce"] != nonce:
            problems.append(f"{name}: serial nonce {mark['nonce']} != {nonce}")
    return problems


def collect_marks(console: str) -> tuple[dict, list[str]]:
    marks = {}
    problems = []
    for match in MARK_LINE.finditer(console):
        name = match.group("suite")
        if name in marks:
            problems.append(f"{name}: duplicate LC_MARK serial line")
        marks[name] = match.groupdict()
    return marks, problems


def parse_guest_exit(text: str):
    lines = text.splitlines()
    if len(lines) != 1:
        return None
    match = GUEST_EXIT_LINE.fullmatch(lines[0])
    if match is None:
        return None
    return int(match.group(1))


def collect_preboot_problems(
    evidence: pathlib.Path, nonce: str, preboot: pathlib.Path | None
) -> list[str]:
    problems = []
    if preboot is None or not preboot.is_file():
        problems.append("pre-boot nonce record missing")
        return problems
    evidence_real = evidence.resolve()
    preboot_real = preboot.resolve()
    try:
        preboot_real.relative_to(evidence_real)
    except ValueError:
        pass
    else:
        problems.append("pre-boot nonce record is inside the guest-writable evidence dir")
        return problems
    digest = None
    run_start = None
    for raw in preboot.read_text(errors="replace").splitlines():
        hashed = PREBOOT_HASH_LINE.fullmatch(raw)
        started = PREBOOT_START_LINE.fullmatch(raw)
        if hashed:
            digest = hashed.group(1)
        elif started:
            run_start = int(started.group(1))
    if digest is None:
        problems.append("pre-boot nonce hash missing or not sha256 hex")
    elif hashlib.sha256(nonce.encode()).hexdigest() != digest:
        problems.append("nonce does not match the pre-boot record")
    if run_start is None:
        problems.append("pre-boot run_start missing")
    else:
        for child in sorted(evidence.iterdir()):
            if not child.is_file() or child.name == "RESULTS.txt":
                continue
            if int(child.stat().st_mtime) < run_start:
                problems.append(f"{child.name}: evidence file predates the run start")
    return problems


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "usage: check-guest-results.py EVIDENCE EXPECTED.json nonce [mode [PREBOOT]]",
            file=sys.stderr,
        )
        return 2
    evidence = pathlib.Path(sys.argv[1])
    expected = load_json(pathlib.Path(sys.argv[2]))
    nonce = sys.argv[3]
    mode = sys.argv[4] if len(sys.argv) > 4 else "full"
    preboot = pathlib.Path(sys.argv[5]) if len(sys.argv) > 5 else None
    problems: list[str] = []

    guest_results = read(evidence / "guest-results.txt")
    console = read(evidence / "qemu-console.txt")
    summary = read(evidence / "summary.txt")
    host_context = read(evidence / "host-context.txt")

    qemu_exit, qemu_timeout = parse_host_context(host_context)
    if qemu_timeout:
        problems.append("qemu timed out")
    if qemu_exit is None:
        problems.append("qemu_exit missing from host-context.txt")
    elif qemu_exit != 0:
        problems.append(f"qemu_exit={qemu_exit} is non-zero/abnormal")

    marks, mark_problems = collect_marks(console)
    problems.extend(mark_problems)
    problems.extend(collect_nonce_problems(nonce, guest_results, console, marks))
    problems.extend(collect_preboot_problems(evidence, nonce, preboot))

    if mode == "full":
        if "tester_nonce_readable=1" in console:
            problems.append("tester could read the nonce")
        elif "tester_nonce_readable=0" not in console:
            problems.append("guest did not prove tester cannot read the nonce")
        if "evidence_nonce_during_run=1" in console:
            problems.append("evidence/nonce.txt existed during the guest run")
        if "env_has_nonce=1" in console:
            problems.append("/etc/lc-guest.env carried a nonce")

    suite_rows = []
    for name, want in expected["suites"].items():
        status = read(evidence / f"{name}.status").strip()
        exit_text = read(evidence / f"{name}.exit").strip()
        log = read(evidence / f"{name}.txt")
        counts = parse_result_line(log) or parse_result_line(summary)
        mark = marks.get(name)
        if not mark:
            problems.append(f"{name}: missing LC_MARK serial line")
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
        if counts["passed"] != want["passed"]:
            problems.append(
                f"{name}: passed {counts['passed']} != expected {want['passed']}"
            )
        if counts["failed"] != want["failed"]:
            problems.append(
                f"{name}: failed {counts['failed']} != expected {want['failed']}"
            )
        if counts["ignored"] != want["ignored"]:
            problems.append(
                f"{name}: ignored {counts['ignored']} != expected {want['ignored']}"
            )
        if status != "PASS" or exit_rc not in (0,):
            problems.append(f"{name}: status={status or 'MISSING'} exit={exit_text or 'MISSING'}")
        if mark:
            mark_exit = int(mark["exit"])
            if mark_exit != (exit_rc if exit_rc is not None else -1):
                problems.append(
                    f"{name}: serial exit {mark['exit']} != 9p exit {exit_text}"
                )
            if int(mark["passed"]) != counts["passed"]:
                problems.append(
                    f"{name}: serial passed {mark['passed']} != log passed {counts['passed']}"
                )
            if int(mark["failed"]) != counts["failed"]:
                problems.append(
                    f"{name}: serial failed {mark['failed']} != log failed {counts['failed']}"
                )
            if int(mark["ignored"]) != counts["ignored"]:
                problems.append(
                    f"{name}: serial ignored {mark['ignored']} != log ignored {counts['ignored']}"
                )
            if mark["status"] != (status or "MISSING"):
                problems.append(
                    f"{name}: serial status {mark['status']} != 9p status {status or 'MISSING'}"
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
    guest_exit_value = parse_guest_exit(guest_exit)
    if mode == "full" and guest_exit_value != 0:
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
    qemu_note = "qemu_exit=MISSING" if qemu_exit is None else f"qemu_exit={qemu_exit}"
    if qemu_timeout:
        qemu_note += " qemu_timeout=1"
    lines.extend(
        [
            "",
            "## Guest markers",
            "",
            f"nonce={nonce}",
            guest_exit.strip() or "guest_exit=MISSING",
            qemu_note,
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
        lines.append("Every suite had an LC_MARK serial line that matched the 9p files.")
        if mode == "full":
            lines.append("Every official in-guest plant was CAUGHT.")
        lines.append("qemu exited 0 without a timeout.")
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
