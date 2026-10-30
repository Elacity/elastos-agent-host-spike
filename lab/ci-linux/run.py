"""Run lab confinement lanes and write a short Linux evidence file.

The workflow calls this on ubuntu-24.04 and on ubuntu-24.04-arm. It looks at
three lane folders:

- lab/linux-confine
- lab/fail-closed-linux
- lab/owned-storage

A folder that is absent is a skip. A skip is not a pass. A lane that is
present runs one of these, in this order:

- ``run-ci-linux.sh`` with bash, and nothing else
- ``cargo test --locked`` when ``Cargo.toml`` and ``Cargo.lock`` are present
- ``python3 -I -m unittest discover`` for ``test_*.py`` in the lane root and,
  separately, in ``tests/``

Cargo without ``Cargo.lock`` is refused. An unlocked build is not evidence.

A passing lane can record rows by printing a whole line, or by appending that
line to the file in ``CI_LINUX_ROWS``:

    CI-LINUX-ROW B4 permitted <reason>
    CI-LINUX-ROW B4 refused <reason>
    CI-LINUX-ROW C9 permitted <reason>
    CI-LINUX-ROW C9 refused <reason>

``B4.suffix`` and ``C9.suffix`` count for that check. The suffix is
``[A-Za-z0-9_-]+``. The reason is the rest of the line and must not be empty.

M1 checks B4 and C9 are proven only when the lanes that ran all exited 0 and
that check has both a permitted row and a refused row. ``confinement_proven``
is ``yes`` only when both checks are proven.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import re
import shlex
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Callable, NamedTuple

LANES = ("linux-confine", "fail-closed-linux", "owned-storage")
CHECKS = ("B4", "C9")
# landlock_create_ruleset is 444 on x86_64 and on aarch64.
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
CLONE_NEWUSER = 0x10000000
ROW_LINE = re.compile(
    r"^CI-LINUX-ROW (?P<check>B4|C9)(?:\.(?P<suffix>[A-Za-z0-9_-]+))? "
    r"(?P<result>permitted|refused) (?P<reason>\S.*)$"
)
CARGO_PASSED = re.compile(r"(?m)^test result: (?:ok|FAILED)\. (\d+) passed;")
UNITTEST_RAN = re.compile(r"(?m)^Ran (\d+) tests? in ")
SHA = re.compile(r"^[0-9a-f]{40}$")
EXPECTED = {
    "linux-x86-64": {"machine": "x86_64", "runner_arch": "X64"},
    "linux-aarch64": {"machine": "aarch64", "runner_arch": "ARM64"},
}
SYSCTLS = (
    ("max_user_namespaces", "/proc/sys/user/max_user_namespaces"),
    ("unprivileged_userns_clone", "/proc/sys/kernel/unprivileged_userns_clone"),
    (
        "apparmor_restrict_unprivileged_userns",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    ),
)
Runner = Callable[[list[str], Path, dict[str, str], int], "CommandResult"]


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def probe_landlock() -> str:
    """Return the Landlock ABI, or unavailable with the errno name."""
    machine = os.uname().machine
    if machine not in ("x86_64", "aarch64"):
        return f"unavailable (syscall number is not pinned for {machine})"
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    rc = libc.syscall(
        ctypes.c_long(LANDLOCK_CREATE_RULESET),
        ctypes.c_void_p(0),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if rc > 0:
        return str(int(rc))
    if rc == 0:
        return "unavailable (reported abi 0)"
    err = ctypes.get_errno()
    return f"unavailable ({errno.errorcode.get(err, 'errno')})"


def probe_seccomp() -> str:
    """Report seccomp from the Seccomp line in /proc/self/status."""
    try:
        text = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0, "error")
        return f"unavailable ({name})"
    for line in text.splitlines():
        if line.startswith("Seccomp:"):
            mode = line.split(":", 1)[1].strip()
            if mode == "0":
                return "available (process mode 0)"
            if mode == "2":
                return "available (process mode 2, a filter is already installed)"
            if mode == "1":
                return "available (process mode 1, strict)"
            return f"available (process mode {mode})"
    return "unavailable (no Seccomp line in /proc/self/status)"


def read_sysctl(path: str) -> str:
    file = Path(path)
    if not file.exists():
        return "absent"
    try:
        return file.read_text(encoding="utf-8").strip() or "empty"
    except OSError:
        return "unreadable"


def format_sysctls() -> str:
    return ", ".join(f"{name}={read_sysctl(path)}" for name, path in SYSCTLS)


def probe_user_namespace_child() -> int:
    """Try unshare(CLONE_NEWUSER) and print available or unavailable."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    ctypes.set_errno(0)
    rc = libc.unshare(CLONE_NEWUSER)
    if rc == 0:
        print("available")
        return 0
    err = ctypes.get_errno()
    print(f"unavailable ({errno.errorcode.get(err, 'errno')})")
    return 0


def probe_user_namespaces(script: Path) -> str:
    """Return the child probe result. A refusal is evidence, not a crash."""
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(script), "--probe-user-namespace"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "unavailable (probe timed out)"
    except OSError as exc:
        return f"unavailable ({exc.strerror})"
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if line == "available" and proc.returncode == 0:
        return "available"
    if line.startswith("unavailable"):
        return line
    detail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    suffix = f" {detail}" if detail else ""
    return f"unavailable (probe exit {proc.returncode}{suffix})"


def probe_commit(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    sha = proc.stdout.strip()
    if proc.returncode != 0 or not SHA.fullmatch(sha):
        return "unknown"
    return sha


def collect_facts(root: Path, script: Path) -> dict[str, str]:
    info = os.uname()
    github_sha = os.environ.get("GITHUB_SHA", "")
    if not SHA.fullmatch(github_sha):
        github_sha = ""
    return {
        "machine": info.machine,
        "kernel": f"{info.sysname} {info.release} {info.machine}",
        "landlock_abi": probe_landlock(),
        "seccomp": probe_seccomp(),
        "user_namespaces": probe_user_namespaces(script),
        "user_namespace_sysctls": format_sysctls(),
        "commit": probe_commit(root),
        "runs_on": os.environ.get("LAB_LINUX_RUNS_ON", "absent"),
        "runner_arch": os.environ.get("RUNNER_ARCH", "absent"),
        "github_sha": github_sha,
    }


def machine_matches(platform: str, facts: dict[str, str]) -> bool:
    expected = EXPECTED[platform]
    if facts["machine"] != expected["machine"]:
        return False
    runner_arch = facts.get("runner_arch", "absent")
    if runner_arch not in ("", "absent") and runner_arch != expected["runner_arch"]:
        return False
    return True


def python_tests(lane: Path) -> list[Path]:
    found = [
        path
        for path in sorted(lane.glob("test_*.py"))
        if path.is_file() and not path.is_symlink()
    ]
    tests = lane / "tests"
    if tests.is_dir() and not tests.is_symlink():
        found.extend(
            path
            for path in sorted(tests.glob("test_*.py"))
            if path.is_file() and not path.is_symlink()
        )
    return found


def plan_lane(root: Path, name: str) -> dict:
    """Decide how to run one lane. This function does not start a command."""
    lane = root / "lab" / name
    if lane.is_symlink():
        return {
            "name": name,
            "status": "failed",
            "reason": f"folder lab/{name} is a symlink",
            "commands": [],
        }
    if not lane.exists():
        return {
            "name": name,
            "status": "skipped",
            "reason": f"folder lab/{name} is absent on this branch",
            "commands": [],
        }
    if not lane.is_dir():
        return {
            "name": name,
            "status": "failed",
            "reason": f"lab/{name} is present and is not a directory",
            "commands": [],
        }
    script = lane / "run-ci-linux.sh"
    if script.exists() or script.is_symlink():
        if script.is_symlink() or not script.is_file():
            return {
                "name": name,
                "status": "failed",
                "reason": f"lab/{name}/run-ci-linux.sh is not a regular file",
                "commands": [],
            }
        return {
            "name": name,
            "status": "run",
            "reason": "",
            "commands": [{"argv": ["bash", str(script)], "cwd": lane, "kind": "script"}],
        }
    commands = []
    cargo = lane / "Cargo.toml"
    if cargo.is_symlink():
        return {
            "name": name,
            "status": "failed",
            "reason": f"lab/{name}/Cargo.toml is a symlink",
            "commands": [],
        }
    if cargo.is_file():
        lock = lane / "Cargo.lock"
        if lock.is_symlink() or not lock.is_file():
            return {
                "name": name,
                "status": "failed",
                "reason": (
                    f"lab/{name} has Cargo.toml and no Cargo.lock, "
                    "so the unlocked build was refused"
                ),
                "commands": [],
            }
        commands.append(
            {
                "argv": [
                    "cargo",
                    "test",
                    "--locked",
                    "--manifest-path",
                    str(cargo),
                    "--",
                    "--nocapture",
                ],
                "cwd": lane,
                "kind": "cargo",
            }
        )
    tests = python_tests(lane)
    # discover inserts its top directory on sys.path, including under python -I.
    # A directory without __init__.py is not walked, so target/ stays out.
    if any(path.parent == lane for path in tests):
        commands.append(
            {
                "argv": [
                    sys.executable,
                    "-I",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(lane),
                    "-t",
                    str(lane),
                    "-p",
                    "test_*.py",
                ],
                "cwd": lane,
                "kind": "unittest",
            }
        )
    if any(path.parent != lane for path in tests):
        tests_dir = lane / "tests"
        commands.append(
            {
                "argv": [
                    sys.executable,
                    "-I",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(tests_dir),
                    "-t",
                    str(tests_dir),
                    "-p",
                    "test_*.py",
                ],
                "cwd": tests_dir,
                "kind": "unittest",
            }
        )
    if not commands:
        return {
            "name": name,
            "status": "failed",
            "reason": (
                f"folder lab/{name} is present and has no run-ci-linux.sh, "
                "Cargo.toml, or test_*.py"
            ),
            "commands": [],
        }
    return {"name": name, "status": "run", "reason": "", "commands": commands}


def short_reason(reason: str) -> str:
    text = " ".join(reason.split())
    if len(text) > 300:
        return text[:300] + " [truncated]"
    return text


def parse_rows(text: str) -> tuple[list[dict[str, str]], list[str]]:
    rows = []
    errors = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("CI-LINUX-ROW"):
            continue
        match = ROW_LINE.fullmatch(line)
        if match is None:
            errors.append(short_reason(line))
            continue
        check = match.group("check")
        suffix = match.group("suffix")
        if suffix:
            check = f"{check}.{suffix}"
        rows.append(
            {
                "check": check,
                "result": match.group("result"),
                "reason": short_reason(match.group("reason")),
            }
        )
    return rows, errors


def count_passed(kind: str, stdout: str, stderr: str) -> int | None:
    text = stdout + "\n" + stderr
    if kind == "cargo":
        numbers = [int(item) for item in CARGO_PASSED.findall(text)]
    elif kind == "unittest":
        numbers = [int(item) for item in UNITTEST_RAN.findall(text)]
    else:
        return None
    if not numbers:
        return None
    return sum(numbers)


def excerpt(stdout: str, stderr: str) -> list[str]:
    lines = [line for line in (stdout + "\n" + stderr).splitlines() if line.strip()]
    clipped = []
    for line in lines[-12:]:
        text = " ".join(line.split())
        if len(text) > 200:
            text = text[:200] + " [truncated]"
        clipped.append(text)
    return clipped


def command_env(lane: str, platform: str, rows_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["CI_LINUX_LANE"] = lane
    env["CI_LINUX_PLATFORM"] = platform
    env["CI_LINUX_ROWS"] = str(rows_path)
    env.setdefault("RUST_TEST_THREADS", "2")
    env.setdefault("CARGO_TERM_COLOR", "never")
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def default_runner(argv: list[str], cwd: Path, env: dict[str, str], timeout: int) -> CommandResult:
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return CommandResult(124, stdout, stderr + "\ncommand timed out")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def family(check: str) -> str:
    return check.split(".", 1)[0]


def dedupe(rows: list[dict]) -> list[dict]:
    seen = set()
    chosen = []
    for row in rows:
        key = (row["lane"], row["check"], row["result"], row["reason"])
        if key in seen:
            continue
        seen.add(key)
        chosen.append(row)
    return chosen


def run_plan(plan: dict, platform: str, rows_dir: Path, runner: Runner, timeout: int) -> tuple[dict, list[dict]]:
    """Run a planned lane. Rows from a failed lane stay in the file and do not count."""
    name = plan["name"]
    if plan["status"] != "run":
        return (
            {
                "name": name,
                "status": plan["status"],
                "reason": plan["reason"],
                "commands": [],
                "exit": None,
                "tests_passed": None,
                "excerpt": [],
            },
            [],
        )
    rows_path = rows_dir / f"{name}.rows"
    rows_path.write_text("", encoding="utf-8")
    collected = []
    errors = []
    passed_total = 0
    saw_count = False
    displays = []
    for command in plan["commands"]:
        argv = command["argv"]
        displays.append(shlex.join(argv))
        result = runner(argv, command["cwd"], command_env(name, platform, rows_path), timeout)
        parsed, bad = parse_rows(result.stdout + "\n" + result.stderr)
        file_rows, file_bad = parse_rows(rows_path.read_text(encoding="utf-8", errors="replace"))
        collected.extend(parsed)
        collected.extend(file_rows)
        errors.extend(bad)
        errors.extend(file_bad)
        count = count_passed(command["kind"], result.stdout, result.stderr)
        if count is not None:
            saw_count = True
            passed_total += count
        if result.returncode != 0:
            reason = f"command exited {result.returncode}: {displays[-1]}"
            if result.returncode == 124:
                reason = f"command timed out after {timeout} seconds: {displays[-1]}"
            return (
                {
                    "name": name,
                    "status": "failed",
                    "reason": reason,
                    "commands": displays,
                    "exit": result.returncode,
                    "tests_passed": passed_total if saw_count else None,
                    "excerpt": excerpt(result.stdout, result.stderr),
                },
                stamp(collected, name, False),
            )
        if errors:
            return (
                {
                    "name": name,
                    "status": "failed",
                    "reason": f"a CI-LINUX-ROW line is malformed: {errors[0]}",
                    "commands": displays,
                    "exit": 0,
                    "tests_passed": passed_total if saw_count else None,
                    "excerpt": errors[:5],
                },
                stamp(collected, name, False),
            )
        if count == 0:
            return (
                {
                    "name": name,
                    "status": "failed",
                    "reason": f"{command['kind']} reported 0 passed tests: {displays[-1]}",
                    "commands": displays,
                    "exit": 0,
                    "tests_passed": 0,
                    "excerpt": excerpt(result.stdout, result.stderr),
                },
                stamp(collected, name, False),
            )
    return (
        {
            "name": name,
            "status": "passed",
            "reason": "",
            "commands": displays,
            "exit": 0,
            "tests_passed": passed_total if saw_count else None,
            "excerpt": [],
        },
        stamp(collected, name, True),
    )


def stamp(rows: list[dict], lane: str, passing: bool) -> list[dict]:
    stamped = []
    for row in rows:
        stamped.append(
            {
                "lane": lane,
                "check": row["check"],
                "result": row["result"],
                "reason": row["reason"],
                "from_passing_lane": passing,
            }
        )
    return dedupe(stamped)


def lanes_result(lanes: list[dict]) -> str:
    if any(lane["status"] in ("failed", "not-run") for lane in lanes):
        return "failed"
    if any(lane["status"] == "passed" for lane in lanes):
        return "passed"
    return "skipped"


def verdict_for(check: str, rows: list[dict], result: str) -> dict[str, str]:
    if result != "passed":
        if result == "skipped":
            reason = "no passing lane recorded a row"
        else:
            reason = "a lane failed, so its rows are not a pass"
        return {"status": "not proven", "reason": reason}
    permitted = [
        row
        for row in rows
        if family(row["check"]) == check and row["result"] == "permitted" and row["from_passing_lane"]
    ]
    refused = [
        row
        for row in rows
        if family(row["check"]) == check and row["result"] == "refused" and row["from_passing_lane"]
    ]
    if permitted and refused:
        return {
            "status": "proven",
            "reason": f"{len(permitted)} permitted, {len(refused)} refused",
        }
    missing = []
    if not permitted:
        missing.append("no permitted row")
    if not refused:
        missing.append("no refused row")
    return {"status": "not proven", "reason": " and ".join(missing) + " from a passing lane"}


def claim_for(platform: str, result: str, checks: dict[str, dict[str, str]], machine: str | None) -> str:
    if machine is not None:
        return (
            f"This runner is {machine}, not the {platform} machine. "
            f"This run did not prove B4 or C9 on {platform}."
        )
    if result == "failed":
        return f"A confinement lane failed on {platform}. This run did not prove B4 or C9."
    proven = [check for check in CHECKS if checks[check]["status"] == "proven"]
    if result == "skipped" or not proven:
        if result == "skipped":
            return (
                f"No confinement lane is on this branch. "
                f"This run did not prove B4 or C9 on {platform}."
            )
        return (
            f"The confinement lanes on this branch exited 0. "
            f"This run did not prove B4 or C9 on {platform}."
        )
    if proven == list(CHECKS):
        return (
            f"B4 and C9 are proven on {platform}. Each check has a permitted row "
            "and a refused row from a passing lane."
        )
    done = proven[0]
    other = "C9" if done == "B4" else "B4"
    return f"{done} is proven on {platform}. {other} is not proven on {platform}."


def not_run_lanes(platform: str) -> list[dict]:
    reason = f"not run because the runner machine does not match {platform}"
    return [
        {
            "name": name,
            "status": "not-run",
            "reason": reason,
            "commands": [],
            "exit": None,
            "tests_passed": None,
            "excerpt": [],
        }
        for name in LANES
    ]


def evaluate(
    root: Path,
    platform: str,
    facts: dict[str, str],
    runner: Runner,
    rows_dir: Path,
    timeout: int = 1200,
) -> dict:
    """Build the evidence report. The runner is called only for a matching machine."""
    if platform not in EXPECTED:
        raise ValueError(f"unknown platform {platform}")
    timeout = max(1, timeout)
    matched = machine_matches(platform, facts)
    lanes = []
    rows: list[dict] = []
    if not matched:
        lanes = not_run_lanes(platform)
    else:
        rows_dir.mkdir(parents=True, exist_ok=True)
        for name in LANES:
            lane, lane_rows = run_plan(plan_lane(root, name), platform, rows_dir, runner, timeout)
            lanes.append(lane)
            rows.extend(lane_rows)
    result = lanes_result(lanes)
    checks = {check: verdict_for(check, rows, result) for check in CHECKS}
    proven = "yes" if all(item["status"] == "proven" for item in checks.values()) else "no"
    machine_note = None if matched else facts.get("machine", "unknown")
    report = {
        "platform": platform,
        "requested_machine": EXPECTED[platform]["machine"],
        "machine_matches": "yes" if matched else "no",
        "facts": facts,
        "lanes": lanes,
        "rows": rows,
        "checks": checks,
        "lanes_result": result,
        "confinement_proven": proven,
        "claim": claim_for(platform, result, checks, machine_note),
    }
    if proven == "yes" and result != "passed":
        raise RuntimeError("refusing to mark confinement proven without a passing run")
    return report


def render(report: dict) -> str:
    """Render the short evidence file. A false yes raises instead of being written."""
    if report["confinement_proven"] not in ("yes", "no"):
        raise RuntimeError("confinement_proven must be yes or no")
    for check in CHECKS:
        if report["checks"][check]["status"] not in ("proven", "not proven"):
            raise RuntimeError("a check status is not proven or not proven")
    both = all(report["checks"][check]["status"] == "proven" for check in CHECKS)
    if report["confinement_proven"] == "yes" and not both:
        raise RuntimeError("refusing to claim confinement without both checks")
    if report["confinement_proven"] == "no" and "are proven" in report["claim"]:
        raise RuntimeError("claim says proven while confinement_proven is no")
    if report["lanes_result"] != "passed" and report["confinement_proven"] == "yes":
        raise RuntimeError("refusing to claim confinement without a passing run")
    facts = report["facts"]
    lines = [
        "schema: lab-linux-evidence/v1",
        f"platform: {report['platform']}",
        f"runs_on: {facts.get('runs_on', 'absent')}",
        f"machine: {facts.get('machine', 'unknown')}",
        f"requested_machine: {report['requested_machine']}",
        f"machine_matches: {report['machine_matches']}",
        f"runner_arch: {facts.get('runner_arch', 'absent')}",
        f"kernel: {facts.get('kernel', 'unknown')}",
        f"landlock_abi: {facts.get('landlock_abi', 'unknown')}",
        f"seccomp: {facts.get('seccomp', 'unknown')}",
        f"user_namespaces: {facts.get('user_namespaces', 'unknown')}",
        f"user_namespace_sysctls: {facts.get('user_namespace_sysctls', 'unknown')}",
        f"commit: {facts.get('commit', 'unknown')}",
    ]
    github_sha = facts.get("github_sha", "")
    if github_sha and github_sha != facts.get("commit"):
        lines.append(f"github_sha: {github_sha}")
    lines.append("lanes:")
    for lane in report["lanes"]:
        lines.append(f"- {lane['name']}: {lane['status']}")
        if lane["reason"]:
            lines.append(f"  reason: {lane['reason']}")
        for command in lane["commands"]:
            lines.append(f"  command: {command}")
        if lane["tests_passed"] is not None:
            lines.append(f"  tests_passed: {lane['tests_passed']}")
        if lane["exit"] not in (None, 0):
            lines.append(f"  exit: {lane['exit']}")
        for line in lane["excerpt"]:
            lines.append(f"  excerpt: {line}")
    lines.append("rows:")
    if report["rows"]:
        for row in report["rows"]:
            source = "passing-lane" if row["from_passing_lane"] else "failed-lane"
            lines.append(
                f"- {row['check']} {row['result']} [{row['lane']}, {source}] {row['reason']}"
            )
    else:
        lines.append("- (none)")
    lines.append("checks:")
    for check in CHECKS:
        item = report["checks"][check]
        lines.append(f"- {check}: {item['status']} — {item['reason']}")
    lines.append(f"lanes_result: {report['lanes_result']}")
    lines.append(f"confinement_proven: {report['confinement_proven']}")
    lines.append(f"claim: {report['claim']}")
    return "\n".join(lines) + "\n"


def fallback_evidence(platform: str, facts: dict[str, str], exc: BaseException) -> str:
    message = " ".join(str(exc).split())[:300] or exc.__class__.__name__
    lines = [
        "schema: lab-linux-evidence/v1",
        f"platform: {platform}",
        f"runs_on: {facts.get('runs_on', 'absent')}",
        f"machine: {facts.get('machine', 'unknown')}",
        f"kernel: {facts.get('kernel', 'unknown')}",
        f"landlock_abi: {facts.get('landlock_abi', 'unknown')}",
        f"seccomp: {facts.get('seccomp', 'unknown')}",
        f"user_namespaces: {facts.get('user_namespaces', 'unknown')}",
        f"user_namespace_sysctls: {facts.get('user_namespace_sysctls', 'unknown')}",
        "lanes:",
        "- (helper failed before the lane results were ready)",
        "rows:",
        "- (none)",
        "checks:",
        "- B4: not proven — the helper failed before it could record a row",
        "- C9: not proven — the helper failed before it could record a row",
        "lanes_result: failed",
        "confinement_proven: no",
        f"claim: The evidence helper failed on {platform}. This run did not prove B4 or C9. {message}",
    ]
    return "\n".join(lines) + "\n"


def announce(report: dict) -> None:
    for lane in report["lanes"]:
        if lane["status"] == "skipped":
            message = f"{lane['name']}: {lane['reason']}"
            print(f"skip: {message}", file=sys.stderr)
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::notice::{message}", file=sys.stderr)
        elif lane["status"] in ("failed", "not-run"):
            message = f"{lane['name']}: {lane['reason']}"
            print(f"fail: {message}", file=sys.stderr)
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::error::{message}", file=sys.stderr)
    print(report["claim"], file=sys.stderr)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record lab Linux confinement evidence.")
    parser.add_argument("--platform", required=True, choices=sorted(EXPECTED))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--command-timeout", type=int, default=1200)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["--probe-user-namespace"]:
        return probe_user_namespace_child()
    args = parse_args(argv)
    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    script = Path(__file__).resolve()
    evidence_dir = args.evidence_dir
    evidence_dir.mkdir(parents=True, exist_ok=True)
    facts = collect_facts(root, script)
    report = None
    try:
        with tempfile.TemporaryDirectory(prefix="lab-linux-rows-") as raw:
            report = evaluate(
                root,
                args.platform,
                facts,
                default_runner,
                Path(raw),
                args.command_timeout,
            )
        text = render(report)
        code = 0 if report["lanes_result"] != "failed" else 1
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        text = fallback_evidence(args.platform, facts, exc)
        code = 1
        report = None
    path = evidence_dir / "evidence.txt"
    path.write_text(text, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    if report is not None:
        announce(report)
    print(text, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
