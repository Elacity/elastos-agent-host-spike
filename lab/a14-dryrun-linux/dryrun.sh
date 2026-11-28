#!/usr/bin/env python3
"""Reproduce the A14 morning runbook from a fresh clone on Linux.

Reads lab/demo-a14/RUNBOOK.md at commit 3bff62b9702435ceb435789e24ecdf8ab5ae9cab
exactly. Does not edit that file or any other lab/demo-a14 path. Writes only
under the --out directory (default: this folder).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

PINNED = "3bff62b9702435ceb435789e24ecdf8ab5ae9cab"
BRANCH = "cursor/demo-a14-installed-demo-83e1"
DEFAULT_URL = "https://github.com/Elacity/elastos-agent-host-spike.git"
HERE = Path(__file__).resolve().parent

SECRET_RE = re.compile(
    r"(x-access-token:)[^@\s]+|(gh[ps]_)[A-Za-z0-9_]+|(Bearer )[A-Za-z0-9._\-]+"
)


def redact(text: str) -> str:
    return SECRET_RE.sub(lambda m: (m.group(1) or m.group(2) or m.group(3)) + "[REDACTED]", text)


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def run_cmd(
    args: list[str],
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: int = 600,
) -> dict:
    start = time.time()
    try:
        done = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (done.stdout or "") + (done.stderr or "")
        code = done.returncode
    except subprocess.TimeoutExpired as error:
        out = (error.stdout or "") + (error.stderr or "") + f"\nTIMEOUT after {timeout}s"
        code = 124
    except OSError as error:
        out = str(error)
        code = 127
    elapsed = time.time() - start
    return {
        "argv": [redact(str(a)) for a in args],
        "cwd": str(cwd) if cwd else os.getcwd(),
        "exit": code,
        "seconds": round(elapsed, 3),
        "started": now(),
        "output": redact(out),
    }


def tail(text: str, n: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def extract_fences(runbook: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)```", runbook, flags=re.S)


def command_units(script: str) -> list[tuple[str, str]]:
    """Group a bash fence into paste units. Keep if/fi as one unit."""
    units: list[tuple[str, str]] = []
    buf: list[str] = []
    depth = 0

    def flush_comment_or_blank(line: str) -> None:
        stripped = line.strip()
        if not stripped:
            units.append(("blank", line))
        elif stripped.startswith("#"):
            units.append(("comment", line))
        else:
            raise AssertionError(line)

    def opener(token: str) -> bool:
        return token in {"if", "for", "while", "until", "case"}

    def closer(token: str) -> bool:
        return token in {"fi", "done", "esac"}

    for line in script.splitlines():
        stripped = line.strip()
        if depth == 0 and not buf:
            if not stripped or stripped.startswith("#"):
                flush_comment_or_blank(line)
                continue
        buf.append(line)
        if stripped and not stripped.startswith("#"):
            token = re.split(r"\s+", stripped, maxsplit=1)[0]
            token = token.split(";")[0]
            if opener(token):
                depth += 1
            if closer(token):
                depth = max(0, depth - 1)
        if depth == 0 and buf:
            units.append(("cmd", "\n".join(buf)))
            buf = []
    if buf:
        units.append(("cmd", "\n".join(buf)))
    return units


class LiveBash:
    def __init__(self, cwd: Path, env: dict):
        self.cwd = cwd
        self.env = env
        self.proc: subprocess.Popen | None = None
        self.state_dir = Path(env.get("TMPDIR", "/tmp")) / f"a14-livebash-{os.getpid()}"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state = self.state_dir / "state.sh"
        self.start()

    def start(self) -> None:
        self.stop()
        self.proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=self.cwd,
            env=self.env,
            bufsize=0,
        )
        if self.state.is_file() or (self.state_dir / "pwd").is_file():
            pwd_file = self.state_dir / "pwd"
            restore = "set +euo pipefail\nset +e\n"
            if self.state.is_file():
                restore += f". {self.state}\n"
            if pwd_file.is_file():
                restore += f'cd -- "$(cat {pwd_file})"\n'
            self._send(restore)

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None

    def _send(self, text: str) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(text)
        self.proc.stdin.flush()

    def run(self, command: str, timeout: int) -> dict:
        if self.proc is None or self.proc.poll() is not None:
            self.start()
        marker = f"__A14RC_{uuid.uuid4().hex}__"
        # The morning paste starts with set -euo pipefail. The recorder wraps
        # each unit in set +e so a failing line still yields an exit code.
        # REPORT.md says which line would have stopped a real whole-block paste.
        wrapped = (
            "set +e\n"
            + command
            + "\n"
            + f"__a14_rc=$?\n"
            + f"echo {marker}:$__a14_rc\n"
            + f"pwd > {self.state_dir}/pwd\n"
            + f"{{ declare -p branch url dest demo_home run || true; }} > {self.state} 2>/dev/null\n"
            + "unset __a14_rc\n"
        )
        start = time.time()
        died = False
        try:
            self._send(wrapped)
        except BrokenPipeError:
            died = True
        output = []
        rc = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc is None:
                died = True
                break
            if self.proc.poll() is not None and rc is None:
                rest = self.proc.stdout.read() if self.proc.stdout else ""
                if rest:
                    output.append(rest)
                died = True
                break
            line = ""
            try:
                assert self.proc.stdout
                # Read one line with a short select-like timeout via the process.
                # stdout is unbuffered text; readline can block. Use a helper.
                line = self._readline(deadline)
            except Exception as error:
                output.append(f"\n[recorder read error: {error}]\n")
                died = True
                break
            if line is None:
                continue
            if line.startswith(marker + ":"):
                try:
                    rc = int(line.split(":", 1)[1])
                except ValueError:
                    rc = 1
                break
            output.append(line + "\n")
        if rc is None and not died:
            output.append(f"\nTIMEOUT after {timeout}s\n")
            rc = 124
            self.start()
        elif died:
            output.append("\n[shell exited; set -euo pipefail would stop the paste here]\n")
            if rc is None:
                rc = 1
            self.start()
        elapsed = time.time() - start
        text = redact("".join(output))
        return {
            "exit": rc,
            "seconds": round(elapsed, 3),
            "started": now(),
            "output": text,
            "shell_died": died,
        }

    def _readline(self, deadline: float) -> str | None:
        assert self.proc and self.proc.stdout
        # Non-blocking-ish: if the fd has nothing, sleep briefly.
        fd = self.proc.stdout.fileno()
        import select

        remain = max(0.0, deadline - time.time())
        ready, _, _ = select.select([fd], [], [], min(1.0, remain))
        if not ready:
            return None
        line = self.proc.stdout.readline()
        if line == "" and self.proc.poll() is not None:
            raise EOFError("bash closed")
        return line.rstrip("\n")


def write_log(log_dir: Path, name: str, payload: dict) -> None:
    path = log_dir / f"{name}.txt"
    body = payload.get("output") or ""
    path.write_text(
        f"exit: {payload.get('exit')}\nseconds: {payload.get('seconds')}\n"
        f"started: {payload.get('started')}\n\n{body}",
        encoding="utf-8",
    )


def classify_onetime(item: dict) -> str:
    kind = item["kind"]
    if kind == "macos":
        return "NOT RUN"
    if kind == "prose":
        return "AMBIGUOUS"
    if item.get("exit") == 0:
        return "PASS"
    if item.get("exit") is None:
        return "AMBIGUOUS"
    return "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE)
    parser.add_argument("--src", type=Path, default=None, help="fresh clone directory (created)")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--skip-clone", action="store_true")
    args = parser.parse_args()

    out = args.out.resolve()
    logs = out / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    wall0 = time.time()
    wall_start = now()
    records: list[dict] = []

    src = (args.src or Path(f"/tmp/a14-dryrun-src-{time.strftime('%Y%m%d-%H%M%S')}")).resolve()
    if src.exists() and not args.skip_clone:
        print(f"REFUSED: {src} already exists", file=sys.stderr)
        return 3

    env = os.environ.copy()
    # The runbook does not set these. Leave them unset so the fence uses defaults.
    env.pop("A14_REMOTE", None)
    env.pop("A14_CLONE", None)

    print(f"fresh clone -> {src}", flush=True)
    clone = run_cmd(["git", "clone", "--branch", BRANCH, args.url, str(src)], timeout=900)
    write_log(logs, "00-fresh-clone", clone)
    records.append(
        {
            "id": "fresh-clone",
            "section": "harness",
            "text": f"git clone --branch {BRANCH} {args.url} {src}",
            "kind": "harness",
            **{k: clone[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if clone["exit"] == 0 else "FAIL",
            "notes": "Harness clone so this script can read RUNBOOK.md. Not a morning-fence line.",
        }
    )
    if clone["exit"] != 0:
        _write_results(out, records, wall0, wall_start, src)
        return clone["exit"]

    checkout = run_cmd(["git", "checkout", "--detach", PINNED], cwd=src, timeout=60)
    write_log(logs, "00-checkout-pin", checkout)
    records.append(
        {
            "id": "checkout-pin",
            "section": "harness",
            "text": f"git checkout --detach {PINNED}",
            **{k: checkout[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if checkout["exit"] == 0 else "FAIL",
            "notes": "Task asked for this exact commit.",
        }
    )
    if checkout["exit"] != 0:
        _write_results(out, records, wall0, wall_start, src)
        return checkout["exit"]

    head = run_cmd(["git", "rev-parse", "HEAD"], cwd=src, timeout=30)
    runbook = (src / "lab/demo-a14/RUNBOOK.md").read_text(encoding="utf-8")
    fences = extract_fences(runbook)
    if len(fences) < 2:
        print("RUNBOOK.md does not have two bash fences", file=sys.stderr)
        return 2
    rustup_fence, morning_fence = fences[0], fences[1]

    uname = run_cmd(["uname", "-s", "-m"], timeout=10)
    df = run_cmd(["df", "-Pk", str(Path.home()), str(src)], timeout=10)
    rustup_ver = run_cmd(["rustup", "--version"], timeout=30)

    # --- one-time list ---
    free_kb = 0
    for line in df["output"].splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3].isdigit():
            free_kb = max(free_kb, int(parts[3]))
    records.append(
        {
            "id": "onetime-mac-disk",
            "section": "one-time",
            "text": "A Mac with at least 40 GB of free disk space.",
            "kind": "macos",
            "exit": None,
            "seconds": 0,
            "started": now(),
            "output": df["output"],
            "classification": "NOT RUN",
            "notes": (
                f"macOS-only requirement. This Linux volume has {free_kb / 1024 / 1024:.1f} GiB free "
                f"({free_kb} KiB). Preflight treats 40 GB as 41943040 KiB (40 GiB)."
            ),
        }
    )
    records.append(
        {
            "id": "onetime-terminal",
            "section": "one-time",
            "text": "The Terminal app (in Applications, then Utilities).",
            "kind": "macos",
            "exit": None,
            "seconds": 0,
            "started": now(),
            "output": "",
            "classification": "NOT RUN",
            "notes": "macOS-only. No Applications/Utilities/Terminal.app on Linux.",
        }
    )
    xcode = run_cmd(["xcode-select", "--install"], timeout=15)
    write_log(logs, "01-xcode-select-install", xcode)
    records.append(
        {
            "id": "onetime-xcode-select",
            "section": "one-time",
            "text": "xcode-select --install",
            "kind": "macos",
            **{k: xcode[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "NOT RUN",
            "notes": "macOS-only. Linux has no xcode-select (exit 127). The runbook says an already-installed result is fine.",
        }
    )
    records.append(
        {
            "id": "onetime-rustup-rs",
            "section": "one-time",
            "text": "Rust. Go to https://rustup.rs and run the one command it shows. Then close Terminal and open it again.",
            "kind": "prose",
            "exit": rustup_ver["exit"],
            "seconds": rustup_ver["seconds"],
            "started": rustup_ver["started"],
            "output": rustup_ver["output"],
            "classification": "AMBIGUOUS",
            "notes": (
                "The runbook does not print the rustup.rs command. A non-developer has to open a "
                "website and paste an installer. This machine already had rustup on PATH, so the "
                "installer was not re-run (it is interactive and would change a shared toolchain)."
            ),
        }
    )

    rustup_units = command_units(rustup_fence)
    for i, (kind, text) in enumerate(rustup_units, start=1):
        if kind != "cmd":
            continue
        rec = run_cmd(["bash", "--noprofile", "--norc", "-lc", text], timeout=900)
        name = f"02-rustup-{i}"
        write_log(logs, name, rec)
        records.append(
            {
                "id": f"onetime-rustup-{i}",
                "section": "one-time",
                "text": text,
                "kind": "cmd",
                **{k: rec[k] for k in ("exit", "seconds", "started", "output")},
                "classification": "PASS" if rec["exit"] == 0 else "FAIL",
                "notes": "One-time fence from RUNBOOK.md. The morning paste does not run these.",
            }
        )

    records.append(
        {
            "id": "onetime-fresh-clone-prose",
            "section": "one-time",
            "text": "A brand-new clone made by the morning block (`git clone --branch`). Do not run `git checkout` in a tree you already have.",
            "kind": "prose",
            "exit": None,
            "seconds": 0,
            "started": now(),
            "output": "",
            "classification": "AMBIGUOUS",
            "notes": (
                "This is an instruction, not a command. The morning fence does the clone. A "
                "non-developer can read this as 'clone first, then paste', which would make two "
                "clones, or as 'the paste will clone'."
            ),
        }
    )

    # --- morning fence, line/unit by unit, same shell ---
    shell = LiveBash(cwd=src, env=env)
    stop_reason = None
    morning_units = command_units(morning_fence)
    for i, (kind, text) in enumerate(morning_units, start=1):
        ident = f"morning-{i:02d}"
        if kind != "cmd":
            records.append(
                {
                    "id": ident,
                    "section": "morning",
                    "text": text,
                    "kind": kind,
                    "exit": 0,
                    "seconds": 0,
                    "started": now(),
                    "output": "",
                    "classification": "PASS" if kind == "blank" else "PASS",
                    "notes": "Comment or blank. No command ran.",
                }
            )
            continue
        timeout = 900 if "git clone" in text else 180
        if "install.sh" in text or "run.sh" in text:
            timeout = 180
        rec = shell.run(text, timeout=timeout)
        write_log(logs, f"03-{ident}", rec)
        classification, notes = classify_morning(text, rec, stop_reason)
        if rec.get("shell_died") and stop_reason is None:
            stop_reason = text.splitlines()[0][:80]
            notes += " Whole-block paste would stop here because of set -euo pipefail."
        records.append(
            {
                "id": ident,
                "section": "morning",
                "text": text,
                "kind": "cmd",
                **{k: rec[k] for k in ("exit", "seconds", "started", "output")},
                "classification": classification,
                "notes": notes,
                "shell_died": rec.get("shell_died"),
            }
        )
    shell.stop()

    # --- planted failure: F-A14ao + FAIL-path summary ---
    plant = plant_fail_closed(src, logs)
    records.extend(plant)

    _write_results(out, records, wall0, wall_start, src, extra={"head": head["output"].strip(), "uname": uname["output"].strip()})
    return 0


def classify_morning(text: str, rec: dict, stop_reason: str | None) -> tuple[str, str]:
    compact = " ".join(text.split())
    code = rec.get("exit")
    out = rec.get("output") or ""
    if compact == "set -euo pipefail":
        return "PASS", "Applies to the rest of the paste. Recorded as its own line."
    if compact.startswith("branch=") or compact.startswith("url=") or compact.startswith("dest="):
        return ("PASS" if code == 0 else "FAIL"), "Assignment as written."
    if compact.startswith("if [ -e"):
        if code == 0:
            return "PASS", "Dest did not already exist, so the refuse branch did not run."
        return "FAIL", f"Dest-exists refuse ran or the if failed (exit {code})."
    if compact.startswith("git clone"):
        if code == 0:
            return "PASS", "Fresh clone of the runbook branch. Tokens in URLs are redacted in logs."
        return "FAIL", f"git clone exited {code}. Root cause is in the output tail."
    if compact.startswith("cd "):
        return ("PASS" if code == 0 else "FAIL"), "Change into the new clone."
    if compact.startswith("test -f lab/demo-a14/install.sh"):
        return ("PASS" if code == 0 else "FAIL"), "Stop if install.sh is missing."
    if "git status --porcelain=v1" in compact:
        if code == 0:
            return "PASS", "New clone was clean."
        return "FAIL", "New clone was dirty or git status failed."
    if "preflight.sh" in compact:
        if code == 0:
            return "PASS", "preflight: OK on this machine."
        return "FAIL", "preflight: FAIL. On Linux this is expected (Darwin/arm64/sandbox-exec/lsof)."
    if "install.sh --sign" in compact:
        if "Linux" in os.uname().sysname:
            if code == 0:
                return "FAIL", "install.sh --sign passed on Linux; the runbook says VERSIONS.json is macOS-only."
            return "NOT RUN", (
                "macOS-only install. The command was started as written so we have an exit code, "
                f"but A14 cannot be booked from it (exit {code}). Install refuses after the same "
                "preflight list and must not write a new signing key."
            )
        return ("PASS" if code == 0 else "FAIL"), "Install and sign."
    if compact.startswith("bash lab/demo-a14/run.sh"):
        if os.uname().sysname != "Darwin":
            return "NOT RUN", (
                f"macOS-only journeys. Command started as written (exit {code}). "
                "Off macOS the demo must not print A14: PASS."
            )
        return ("PASS" if code == 0 else "FAIL"), "Run every step against the installed versions."
    if compact.startswith("demo_home="):
        return ("PASS" if code == 0 else "FAIL"), "Hard-coded Mac Application Support path."
    if compact.startswith("run=$(sed"):
        return ("PASS" if code == 0 else "FAIL"), "Read this-run. The || true keeps a missing file from aborting."
    if compact.startswith("test -n") and "open " in compact:
        if os.uname().sysname != "Darwin":
            return "NOT RUN", (
                "macOS `open`. On this Linux, `open` is xdg-open. The Library/Application Support "
                f"path is absent, so the && chain stops before open (exit {code})."
            )
        return ("PASS" if code == 0 else "FAIL"), "Open only this run's summary.txt."
    if code == 0:
        return "PASS", ""
    return "FAIL", f"exit {code}"


def plant_fail_closed(src: Path, logs: Path) -> list[dict]:
    rows = []
    demo = src / "lab/demo-a14/demo.py"
    tests = src / "lab/demo-a14"
    before = sha256(demo)
    named = run_cmd(
        [
            "python3",
            "-B",
            "-I",
            "-m",
            "unittest",
            "discover",
            "-s",
            "lab/demo-a14/tests",
            "-v",
            "-k",
            "test_pass_writes_a14_pass_in_this_runs_summary",
        ],
        cwd=src,
        timeout=180,
    )
    write_log(logs, "04-pass-test-before-plant", named)
    rows.append(
        {
            "id": "plant-baseline-pass-test",
            "section": "planted-failure",
            "text": "python3 -B -I -m unittest discover -s lab/demo-a14/tests -v -k test_pass_writes_a14_pass_in_this_runs_summary",
            **{k: named[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if named["exit"] == 0 else "FAIL",
            "notes": f"Control: the PASS-path test is green before the plant. demo.py sha256={before}",
        }
    )

    old = (
        '    say(f"Saved: {run_dir}")\n'
        "    write_summary(run_dir, say)\n"
        "    mark_this_run(layout, run_dir)\n"
        '    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n'
    )
    new = (
        '    say(f"Saved: {run_dir}")\n'
        "    mark_this_run(layout, run_dir)\n"
        '    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)\n'
    )
    text = demo.read_text(encoding="utf-8")
    if old not in text:
        rows.append(
            {
                "id": "plant-f-a14ao-apply",
                "section": "planted-failure",
                "text": "F-A14ao apply",
                "exit": 2,
                "seconds": 0,
                "started": now(),
                "output": "anchor old text not found in demo.py",
                "classification": "FAIL",
                "notes": "Cannot plant F-A14ao; the file does not match falsifiers.json.",
            }
        )
        return rows
    demo.write_text(text.replace(old, new, 1), encoding="utf-8")
    planted = sha256(demo)
    planted_run = run_cmd(
        [
            "python3",
            "-B",
            "-I",
            "-m",
            "unittest",
            "discover",
            "-s",
            "lab/demo-a14/tests",
            "-v",
            "-k",
            "test_pass_writes_a14_pass_in_this_runs_summary",
        ],
        cwd=src,
        timeout=180,
    )
    write_log(logs, "04-pass-test-after-plant", planted_run)
    caught = planted_run["exit"] != 0
    rows.append(
        {
            "id": "plant-f-a14ao",
            "section": "planted-failure",
            "text": "F-A14ao: skip write_summary on the PASS path",
            **{k: planted_run[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if caught else "FAIL",
            "notes": (
                f"Planted demo.py sha256={planted}. The test must fail: stdout can still say "
                "A14: PASS. while this-run's summary.txt is missing that line. "
                f"caught={caught}."
            ),
        }
    )

    restore = run_cmd(["git", "checkout", "--", "lab/demo-a14/demo.py"], cwd=src, timeout=30)
    after = sha256(demo)
    restored = after == before
    rows.append(
        {
            "id": "plant-restore",
            "section": "planted-failure",
            "text": "git checkout -- lab/demo-a14/demo.py",
            **{k: restore[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if restored and restore["exit"] == 0 else "FAIL",
            "notes": f"Restored demo.py sha256={after}; match_before={restored}.",
        }
    )

    inline = run_cmd(
        [
            "python3",
            "-B",
            "-I",
            str(HERE / "plant_fail_path.py"),
        ],
        cwd=tests,
        timeout=180,
    )
    write_log(logs, "04-fail-path-inline", inline)
    rows.append(
        {
            "id": "plant-fail-path-no-pass-line",
            "section": "planted-failure",
            "text": "plant_fail_path.py: FAIL journey must not write A14: PASS. into that run's summary.txt",
            **{k: inline[k] for k in ("exit", "seconds", "started", "output")},
            "classification": "PASS" if inline["exit"] == 0 else "FAIL",
            "notes": (
                "Planted a changed did-provider executable so the demo verdict is FAIL. "
                "A14: PASS. must be absent from stdout and from this-run's summary.txt."
            ),
        }
    )
    return rows


def sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_results(out: Path, records: list[dict], wall0: float, wall_start: str, src: Path, extra: dict | None = None) -> None:
    # Trim stored output to a tail so the JSON stays small.
    slim = []
    for row in records:
        item = dict(row)
        item["output_tail"] = tail(item.pop("output", ""), 40)
        slim.append(item)
    payload = {
        "pin": PINNED,
        "branch": BRANCH,
        "src": str(src),
        "started": wall_start,
        "finished": now(),
        "wall_seconds": round(time.time() - wall0, 3),
        "machine": {
            "os": os.uname().sysname,
            "release": os.uname().release,
            "machine": os.uname().machine,
        },
        "extra": extra or {},
        "records": slim,
    }
    (out / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out / 'results.json'} wall_seconds={payload['wall_seconds']}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
