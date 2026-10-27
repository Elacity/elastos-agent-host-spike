#!/usr/bin/env python3
"""Check aarch64 guest evidence and write RESULTS.txt from live files.

Exit 0 only when every standing suite passed with the exact expected
counts, every official plant is CAUGHT, every suite has exactly one
LC_MARK serial line that matches the 9p files and the host nonce, qemu
exited 0 without a timeout, guest_exit.txt is exactly one canonical
LF line, the nonce matches the host pre-boot hash and has not been
recorded for this work dir, evidence files sit in [run_start, now+skew],
the pre-boot path is the regular file $WORK/host-preboot.txt bound to
this run, LC_MARK names are exactly the expected set, and the guest
proved the test uid could not read the nonce. A symlink, hardlink, or
'..' PREBOOT path, a reused nonce on this host boot, a future mtime, an
unparseable or unexpected mark, a guest_exit line without exactly one
trailing LF, a colliding extra fail, a preboot from another $WORK, or a
run_start ahead of the host clock is a failure. Used nonces live in a
host-side ledger at a fixed /var/tmp path (not XDG_RUNTIME_DIR). The
live wrapper records the mint before qemu and keeps a sidecar marker so
a missing or unlinked ledger after the first mint is refused. A leftover
symlink at the ledger path is a named refusal.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import re
import sys
import time

RESULT_LINE = re.compile(
    r"test result:\s+\S+\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored"
)
# Byte-exact ASCII grammar. One space between fields. No NBSP, ZWSP, or
# double spaces. A line that contains LC_MARK and misses this shape fails.
MARK_LINE = re.compile(
    r"^LC_MARK nonce=(?P<nonce>[0-9A-Za-z._-]+) suite=(?P<suite>[0-9A-Za-z._-]+) "
    r"exit=(?P<exit>-?[0-9]+) passed=(?P<passed>[0-9]+) failed=(?P<failed>[0-9]+) "
    r"ignored=(?P<ignored>[0-9]+) status=(?P<status>[0-9A-Za-z._-]+)$"
)
GUEST_EXIT_LINE = re.compile(r"^guest_exit=(0|[1-9][0-9]*)$")
PREBOOT_HASH_LINE = re.compile(r"^nonce_sha256=([0-9a-f]{64})$")
PREBOOT_START_LINE = re.compile(r"^run_start=([1-9][0-9]*)$")
PREBOOT_RUN_LINE = re.compile(r"^run_id=([0-9a-f]{16,64})$")
PREBOOT_WORK_LINE = re.compile(r"^work=(/\S+)$")
MTIME_SKEW_SEC = 2


def last_field(text: str, key: str) -> str | None:
    value = None
    prefix = f"{key}="
    for raw in text.splitlines():
        if raw.startswith(prefix):
            value = raw.split("=", 1)[1]
    return value


def run_start_is_implausible(run_start: int, now: int) -> bool:
    # 0 is refused by PREBOOT_START_LINE. Evidence mtimes keep +2s skew.
    # run_start itself must not be in the future.
    return run_start > now


HOST_LEDGER_DIR = pathlib.Path("/var/tmp/linux-confine")
_DIGEST_CHARS = frozenset("0123456789abcdef")


def host_boot_id() -> str:
    boot = pathlib.Path("/proc/sys/kernel/random/boot_id")
    try:
        text = boot.read_text().strip()
    except OSError:
        text = ""
    if text:
        return text.replace("-", "")
    return "unknown"


def used_nonce_path(work_real: pathlib.Path) -> pathlib.Path:
    # Host-side ledger. Guest 9p, a fresh $WORK, and XDG_RUNTIME_DIR
    # cannot reset it. LC_USED_NONCES isolates one test or plant.
    override = os.environ.get("LC_USED_NONCES")
    if override:
        return pathlib.Path(override)
    return HOST_LEDGER_DIR / f"used-nonces-{host_boot_id()}.txt"


def minted_marker_path(used: pathlib.Path) -> pathlib.Path:
    return used.with_name(used.name + ".minted")


def checked_runs_path(used: pathlib.Path) -> pathlib.Path:
    return used.with_name(used.name + ".checked")


def used_nonce_slot_dir(used: pathlib.Path) -> pathlib.Path:
    return used.with_name(used.name + ".d")


def path_is_alias(path: pathlib.Path) -> bool:
    # File and its parent only. Walking to / would false-FAIL a host whose
    # /var/tmp is a symlink.
    if path.is_symlink() or path.parent.is_symlink():
        return True
    try:
        return path.exists() and path.stat().st_nlink > 1
    except OSError:
        return True


def ledger_digests(text: str) -> list[str]:
    digests = []
    for line in text.splitlines():
        if not line:
            continue
        token = line.split()[0]
        if len(token) == 64 and set(token) <= _DIGEST_CHARS:
            digests.append(token)
    return digests


def _ledger_run_ids(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        token = parts[0]
        if len(token) == 64 and set(token) <= _DIGEST_CHARS:
            found[token] = parts[1]
    return found


def _read_locked_text(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, 1 << 20).decode(errors="replace")
    except OSError:
        return ""
    finally:
        os.close(fd)


def _append_locked_line(path: pathlib.Path, line: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        st = os.fstat(fd)
        if st.st_nlink > 1:
            return
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, 1 << 20).decode(errors="replace")
        token = line.split()[0] if line.split() else ""
        if token and token in {ln.split()[0] for ln in data.splitlines() if ln}:
            return
        os.write(fd, (line if line.endswith("\n") else line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_slot(used: pathlib.Path, digest: str) -> None:
    slots = used_nonce_slot_dir(used)
    try:
        slots.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(slots / digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except FileExistsError:
        return
    except OSError:
        return


def consume_run_id(used: pathlib.Path, run_id: str) -> None:
    if not run_id:
        return
    _append_locked_line(checked_runs_path(used), run_id)


def run_id_is_checked(used: pathlib.Path, run_id: str) -> bool:
    if not run_id:
        return False
    text = _read_locked_text(checked_runs_path(used))
    return run_id in {ln.strip() for ln in text.splitlines() if ln.strip()}


def _marker_has_started(used: pathlib.Path) -> bool:
    marker = minted_marker_path(used)
    return marker.is_file() and not marker.is_symlink()


def _complete_digest_count(text: str) -> int:
    return len(ledger_digests(text))


def _ledger_problem(
    used: pathlib.Path, evidence_real: pathlib.Path | None
) -> str | None:
    if used.is_symlink():
        return "used-nonces path is a leftover symlink"
    if path_is_alias(used):
        return "used-nonces path is a symlink or hardlink"
    if used.parent.is_symlink():
        return "used-nonces path is a symlink or hardlink"
    if evidence_real is not None:
        try:
            used.resolve().relative_to(evidence_real)
        except (ValueError, OSError):
            pass
        else:
            return "used-nonces ledger is inside the guest-writable evidence dir"
    return None


def nonce_already_recorded(
    work_real: pathlib.Path,
    digest: str,
    run_id: str | None = None,
    evidence_real: pathlib.Path | None = None,
) -> str | None:
    used = used_nonce_path(work_real)
    path_problem = _ledger_problem(used, evidence_real)
    if path_problem:
        return path_problem
    marker = minted_marker_path(used)
    marker_text = _read_locked_text(marker) if _marker_has_started(used) else ""
    ledger_text = _read_locked_text(used) if used.is_file() and not used.is_symlink() else ""
    if _marker_has_started(used) and (
        not used.is_file()
        or used.is_symlink()
        or _complete_digest_count(ledger_text) == 0
    ):
        return "used-nonces ledger missing after first mint"
    seen = set(ledger_digests(ledger_text))
    seen.update(ledger_digests(marker_text))
    slot = used_nonce_slot_dir(used) / digest
    if slot.is_file() and not slot.is_symlink():
        seen.add(digest)
    if digest not in seen:
        return None
    recorded_run = _ledger_run_ids(ledger_text).get(digest)
    if run_id and not run_id_is_checked(used, run_id):
        if recorded_run is None or recorded_run == run_id:
            consume_run_id(used, run_id)
            return None
    return "nonce was already recorded for this host boot"


def record_minted_nonce(
    work_real: pathlib.Path, digest: str, run_id: str | None = None
) -> None:
    used = used_nonce_path(work_real)
    if used.is_symlink() or path_is_alias(used):
        return
    used.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    boot = host_boot_id()
    token = f"{digest} {run_id or '-'} {boot}"
    _append_locked_line(used, token)
    _append_locked_line(minted_marker_path(used), token)
    _write_slot(used, digest)


def record_used_nonce(
    work_real: pathlib.Path, digest: str, run_id: str | None = None
) -> None:
    record_minted_nonce(work_real, digest, run_id)
    if run_id:
        consume_run_id(used_nonce_path(work_real), run_id)


def work_binding_problems(
    preboot: pathlib.Path, work_real: pathlib.Path | None, host_context: str
) -> list[str]:
    problems = []
    if work_real is None:
        return problems
    if preboot.resolve() != work_real / "host-preboot.txt":
        problems.append("pre-boot path is not the host-preboot file under the bound work dir")
    host_work = last_field(host_context, "work")
    if host_work is None:
        problems.append("host-context work path missing")
    else:
        try:
            host_work_real = pathlib.Path(host_work).resolve()
        except OSError:
            host_work_real = None
        if host_work_real != work_real:
            problems.append("pre-boot work path does not match host-context")
    return problems


def allowed_mark_names(expected: dict) -> set[str]:
    allowed = set(expected["suites"]) | {"guest"}
    allowed |= set(expected.get("plants_caught", []))
    allowed |= set(expected.get("plants_not_run", []))
    return allowed


def collect_unexpected_mark_problems(marks: dict, expected: dict) -> list[str]:
    allowed = allowed_mark_names(expected)
    problems = []
    for name in marks:
        if name not in allowed:
            problems.append(f"{name}: unexpected LC_MARK suite")
    return problems


def collect_unexpected_status_problems(evidence: pathlib.Path, expected: dict) -> list[str]:
    allowed = set(expected["suites"])
    allowed |= set(expected.get("plants_caught", []))
    allowed |= set(expected.get("plants_not_run", []))
    problems = []
    for child in sorted(evidence.iterdir()):
        if child.suffix != ".status" or not child.is_file():
            continue
        if child.stem in allowed:
            continue
        status = child.read_text(errors="replace").strip()
        if status and status != "NOT_RUN":
            problems.append(f"{child.stem}: unexpected status file {status}")
    return problems


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
    for raw in console.splitlines():
        if "LC_MARK" not in raw:
            continue
        match = MARK_LINE.fullmatch(raw)
        if match is None:
            problems.append(f"unparseable LC_MARK line: {raw!r}")
            continue
        name = match.group("suite")
        if name in marks:
            problems.append(f"{name}: duplicate LC_MARK serial line")
        marks[name] = match.groupdict()
    return marks, problems


def parse_guest_exit(text: str):
    if "\r" in text or "\0" in text:
        return None
    if not text.endswith("\n") or text.count("\n") != 1:
        return None
    match = GUEST_EXIT_LINE.fullmatch(text[:-1])
    if match is None:
        return None
    return int(match.group(1))


def collect_preboot_problems(
    evidence: pathlib.Path,
    nonce: str,
    preboot: pathlib.Path | None,
    host_context: str = "",
) -> list[str]:
    problems = []
    if preboot is None:
        problems.append("pre-boot nonce record missing")
        return problems
    if ".." in preboot.parts:
        problems.append("pre-boot path contains ..")
        return problems
    if preboot.is_symlink():
        problems.append("pre-boot path is a symlink")
        return problems
    if not preboot.is_file():
        problems.append("pre-boot nonce record missing")
        return problems
    if preboot.stat().st_nlink > 1:
        problems.append("pre-boot nonce record is a hardlink")
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
    run_id = None
    work_text = None
    for raw in preboot.read_text(errors="replace").splitlines():
        hashed = PREBOOT_HASH_LINE.fullmatch(raw)
        started = PREBOOT_START_LINE.fullmatch(raw)
        run_line = PREBOOT_RUN_LINE.fullmatch(raw)
        work_line = PREBOOT_WORK_LINE.fullmatch(raw)
        if hashed:
            digest = hashed.group(1)
        elif started:
            run_start = int(started.group(1))
        elif run_line:
            run_id = run_line.group(1)
        elif work_line:
            work_text = work_line.group(1)
    if digest is None:
        problems.append("pre-boot nonce hash missing or not sha256 hex")
    elif hashlib.sha256(nonce.encode()).hexdigest() != digest:
        problems.append("nonce does not match the pre-boot record")
    now = int(time.time())
    if run_start is None:
        problems.append("pre-boot run_start missing")
    elif run_start_is_implausible(run_start, now):
        problems.append("pre-boot run_start is implausible (ahead of the host clock)")
        run_start = None
    work_real = None
    if work_text is None:
        problems.append("pre-boot work path missing")
    else:
        work_path = pathlib.Path(work_text)
        if work_path.is_symlink() or not work_path.is_dir():
            problems.append("bound work dir is not a regular directory")
        else:
            work_real = work_path.resolve()
            try:
                work_real.relative_to(evidence_real)
            except ValueError:
                pass
            else:
                problems.append("bound work dir is inside the guest-writable evidence dir")
                work_real = None
    bind_problems = work_binding_problems(preboot, work_real, host_context)
    problems.extend(bind_problems)
    host_run_id = last_field(host_context, "run_id")
    if run_id is None:
        problems.append("pre-boot run_id missing")
    elif host_run_id is None:
        problems.append("host-context run_id missing")
    elif run_id != host_run_id:
        problems.append("pre-boot run_id does not match host-context")
    if digest is not None and work_real is not None and not bind_problems:
        used_problem = nonce_already_recorded(
            work_real, digest, run_id=run_id, evidence_real=evidence_real
        )
        if used_problem:
            problems.append(used_problem)
    if run_start is not None:
        for child in sorted(evidence.iterdir()):
            if not child.is_file() or child.name == "RESULTS.txt":
                continue
            mtime = int(child.stat().st_mtime)
            if mtime < run_start:
                problems.append(f"{child.name}: evidence file predates the run start")
            elif mtime > now + MTIME_SKEW_SEC:
                problems.append(f"{child.name}: evidence file mtime is in the future")
    if digest is not None and work_real is not None and not problems:
        record_used_nonce(work_real, digest, run_id)
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
    problems.extend(collect_unexpected_mark_problems(marks, expected))
    problems.extend(collect_unexpected_status_problems(evidence, expected))
    problems.extend(collect_nonce_problems(nonce, guest_results, console, marks))
    problems.extend(collect_preboot_problems(evidence, nonce, preboot, host_context))

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

    guest_exit_path = evidence / "guest-exit.txt"
    if guest_exit_path.is_file():
        # Text mode would swallow CR. Guest_exit is a byte-exact token.
        guest_exit = guest_exit_path.read_bytes().decode("utf-8", errors="replace")
    else:
        guest_exit = ""
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


def _cli_mint(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: check-guest-results.py --mint-nonce LEDGER NONCE RUN_ID",
            file=sys.stderr,
        )
        return 2
    os.environ["LC_USED_NONCES"] = argv[1]
    digest = hashlib.sha256(argv[2].encode()).hexdigest()
    work = pathlib.Path(argv[1]).resolve().parent
    record_minted_nonce(work, digest, argv[3])
    print(argv[1])
    return 0


def _cli_consume(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: check-guest-results.py --consume-run LEDGER RUN_ID",
            file=sys.stderr,
        )
        return 2
    consume_run_id(pathlib.Path(argv[1]), argv[2])
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mint-nonce":
        sys.exit(_cli_mint(sys.argv[1:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--consume-run":
        sys.exit(_cli_consume(sys.argv[1:]))
    sys.exit(main())
