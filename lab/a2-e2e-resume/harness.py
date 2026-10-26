#!/usr/bin/env python3
"""A2 resume journey: write, stale refuse, stop, start, resume, write again."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LANE = Path(__file__).resolve().parent
REPO = LANE.parent.parent
EVIDENCE = LANE / "evidence.txt"
DRIVER_BIN = LANE / "target/debug/a2-resume-driver"
GUEST_PIN = LANE / "guest.sha256"
JOURNEY = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")
EXPECTED_STOP_EXIT = 0
EXPECTED_SECOND_EXIT = 0
STATE_FILE = "a2-resume-state.json"


class Proof:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.steps: dict[str, str] = {}
        self.details: dict[str, str] = {}

    def log(self, text: str) -> None:
        self.lines.append(text)
        print(text, flush=True)

    def row(self, name: str, result: str, detail: str) -> None:
        if name not in JOURNEY:
            raise SystemExit(f"unknown row {name}")
        if result == "PASS":
            raise SystemExit(f"{name} PASS must be computed from evidence, not assigned")
        if result not in {"FAIL", "NOT RUN"}:
            raise SystemExit(f"bad result {result} for {name}")
        if result == "PASS" and name in self.steps and self.steps[name] == "NOT RUN":
            raise SystemExit(f"{name} was NOT RUN; it cannot become PASS")
        self.steps[name] = result
        self.details[name] = detail
        self.log(f"STEP {name}: {result} — {detail}")

    def accept(self, name: str, detail: str) -> None:
        if name not in JOURNEY:
            raise SystemExit(f"unknown row {name}")
        if name in self.steps and self.steps[name] == "NOT RUN":
            raise SystemExit(f"{name} was NOT RUN; it cannot become PASS")
        self.steps[name] = "PASS"
        self.details[name] = detail
        self.log(f"STEP {name}: PASS — {detail}")


def run(
    args: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    merged.setdefault("RUST_TEST_THREADS", "2")
    return subprocess.run(
        args,
        cwd=cwd,
        env=merged,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_guest_sha256() -> str:
    text = GUEST_PIN.read_text(encoding="utf-8").strip()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise SystemExit(f"{GUEST_PIN.name} is not a 64-char hex sha256")
    return text


def parse_evidence(output: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("EVIDENCE "):
            continue
        for part in line[len("EVIDENCE ") :].split():
            if "=" in part:
                key, value = part.split("=", 1)
                found[key] = value
    return found


def parse_driver_rows(output: str) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for line in output.splitlines():
        if not line.startswith("ROW "):
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        name, result = parts[1], parts[2]
        detail = parts[3] if len(parts) > 3 else ""
        if result not in {"PASS", "FAIL"}:
            continue
        found[name] = (result, detail)
    return found


def parse_pid(output: str, phase: str) -> str | None:
    marker = f"PROCESS {phase} pid="
    for line in output.splitlines():
        if line.startswith(marker):
            return line[len(marker) :].strip()
    return None


def journal_files(store: Path) -> list[Path]:
    runtime = store / "runtime-data"
    if not runtime.is_dir():
        return []
    found: list[Path] = []
    for path in runtime.rglob("*"):
        if path.is_file() and path.name == "journal":
            found.append(path)
    return found


def read_state(store: Path) -> dict:
    path = store / STATE_FILE
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def record_versions(proof: Proof) -> dict[str, str]:
    commit = run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip()
    parent = run(["git", "rev-parse", "HEAD^"], cwd=REPO).stdout.strip()
    rustc = run(["rustc", "--version"], cwd=REPO).stdout.strip()
    uname = run(["uname", "-sm"], cwd=REPO).stdout.strip()
    versions = {
        "commit": commit,
        "parent": parent,
        "rustc": rustc,
        "machine": uname,
        "python": sys.version.split()[0],
        "when": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    for key, value in versions.items():
        proof.log(f"VERSION {key}: {value}")
    return versions


def ensure_wasm_target(proof: Proof) -> None:
    result = run(
        ["rustup", "target", "add", "wasm32-unknown-unknown", "--toolchain", "1.91.0"],
        cwd=REPO,
    )
    proof.log(f"CMD rustup target add wasm32-unknown-unknown -> {result.returncode}")
    if result.returncode != 0:
        raise SystemExit(result.stderr or result.stdout)


def build_guest(proof: Proof) -> Path:
    script = REPO / "examples/agent-host/build.sh"
    result = run([str(script)], cwd=REPO)
    proof.log(f"CMD {script.relative_to(REPO)} -> {result.returncode}")
    if result.returncode != 0:
        proof.log((result.stderr or result.stdout)[-4000:])
        raise SystemExit("guest wasm build failed")
    wasm = REPO / "examples/agent-host/agent-host.component.wasm"
    if not wasm.is_file():
        raise SystemExit("guest wasm missing after build")
    digest = sha256_file(wasm)
    proof.log(f"GUEST_WASM sha256:{digest} bytes:{wasm.stat().st_size}")
    return wasm


def build_driver(proof: Proof) -> Path:
    result = run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(LANE / "Cargo.toml"),
            "--bin",
            "a2-resume-driver",
        ],
        cwd=REPO,
        env={"CARGO_INCREMENTAL": "0"},
    )
    proof.log(f"CMD cargo build a2-resume-driver -> {result.returncode}")
    if result.returncode != 0:
        proof.log((result.stderr or result.stdout)[-4000:])
        raise SystemExit("resume driver build failed")
    if not DRIVER_BIN.is_file():
        raise SystemExit("resume driver missing after build")
    proof.log(f"DRIVER sha256:{sha256_file(DRIVER_BIN)}")
    return DRIVER_BIN


def mark_not_run(proof: Proof, names: tuple[str, ...], reason: str) -> None:
    for name in names:
        if name not in proof.steps:
            proof.row(name, "NOT RUN", reason)


def run_phase(proof: Proof, phase: str, store: Path) -> subprocess.CompletedProcess[str]:
    result = run([str(DRIVER_BIN), phase, str(store)], cwd=REPO, timeout=180)
    output = result.stdout + result.stderr
    proof.log(f"CMD a2-resume-driver {phase} -> {result.returncode}")
    for line in output.splitlines():
        if (
            line.startswith("ROW ")
            or line.startswith("PROCESS ")
            or line.startswith("EVIDENCE ")
            or line.startswith("DRIVER_ERROR")
        ):
            proof.log(line)
    return result


def compute_write(
    proof: Proof,
    first: subprocess.CompletedProcess[str],
    store: Path,
    wasm: Path,
    expected_guest: str,
) -> None:
    output = first.stdout + first.stderr
    evidence = parse_evidence(output)
    journals = journal_files(store)
    state = read_state(store)
    live_guest = sha256_file(wasm) if wasm.is_file() else ""
    guest_ok = (
        live_guest == expected_guest
        and evidence.get("guest_sha256") == expected_guest
        and evidence.get("pinned") == expected_guest
    )
    format2 = evidence.get("format2") == "true"
    wrote = "write:ok" in evidence.get("invokes", "").split(",")
    has_journal = bool(journals) and all(path.stat().st_size > 0 for path in journals)
    has_state = bool(state.get("sha256")) and state.get("sha256") == evidence.get("journal_sha256")
    if guest_ok and format2 and wrote and has_journal and has_state:
        proof.accept(
            "WRITE",
            (
                f"journal on disk; format2; write:ok; sha256={state['sha256']} "
                f"guest={live_guest}"
            ),
        )
        return
    proof.row(
        "WRITE",
        "FAIL",
        (
            f"guest_ok={guest_ok} format2={format2} write:ok={wrote} "
            f"journal={has_journal} state={has_state} live_guest={live_guest}"
        ),
    )


def compute_stale(
    proof: Proof,
    first: subprocess.CompletedProcess[str],
    store: Path,
) -> None:
    output = first.stdout + first.stderr
    evidence = parse_evidence(output)
    state = read_state(store)
    conflict = "write:conflict" in evidence.get("invokes", "").split(",")
    same = state.get("sha256") == evidence.get("journal_sha256") and bool(state.get("sha256"))
    if proof.steps.get("WRITE") != "PASS":
        if "STALE" not in proof.steps:
            proof.row("STALE", "NOT RUN", "WRITE did not pass; stale was not counted")
        return
    if conflict and same:
        proof.accept(
            "STALE",
            f"guest write/conflict audited; stored sha256={state['sha256']}",
        )
        return
    rows = parse_driver_rows(output)
    if "STALE" in rows and rows["STALE"][0] == "FAIL":
        proof.row("STALE", "FAIL", rows["STALE"][1])
        return
    proof.row("STALE", "NOT RUN", "first process printed no STALE row")


def compute_stop(proof: Proof, first: subprocess.CompletedProcess[str], store: Path) -> None:
    if proof.steps.get("WRITE") != "PASS":
        mark_not_run(proof, ("STOP",), "first process did not complete a write")
        return
    if first.returncode == EXPECTED_STOP_EXIT:
        proof.accept(
            "STOP",
            f"first Runtime process exited {first.returncode}; store kept at {store.name}",
        )
        return
    proof.row(
        "STOP",
        "FAIL",
        f"first process exited {first.returncode}; expected {EXPECTED_STOP_EXIT}",
    )


def compute_start(
    proof: Proof,
    first: subprocess.CompletedProcess[str],
    second: subprocess.CompletedProcess[str],
    store: Path,
) -> None:
    output = second.stdout + second.stderr
    first_pid = parse_pid(first.stdout + first.stderr, "first")
    second_pid = parse_pid(output, "second")
    journals = journal_files(store)
    opened_store = bool(journals) and (store / STATE_FILE).is_file()
    if (
        second_pid
        and first_pid
        and second_pid != first_pid
        and opened_store
        and "DRIVER_ERROR" not in output.splitlines()[0:1]
        and "PROCESS second" in output
    ):
        proof.accept(
            "START",
            (
                f"fresh Runtime process pid={second_pid} opened store {store.name}; "
                f"first_pid={first_pid}"
            ),
        )
        return
    proof.row(
        "START",
        "FAIL",
        (
            f"second_pid={second_pid} first_pid={first_pid} "
            f"store_open={opened_store} exit={second.returncode}"
        ),
    )


def compute_resume(proof: Proof, second: subprocess.CompletedProcess[str], store: Path) -> None:
    output = second.stdout + second.stderr
    evidence = parse_evidence(output)
    state = read_state(store)
    rows = parse_driver_rows(output)
    loaded = "read:ok" in evidence.get("invokes", "").split(",")
    if proof.steps.get("START") != "PASS":
        if "RESUME" not in proof.steps:
            proof.row("RESUME", "NOT RUN", "START did not pass; resume was not counted")
        return
    if loaded and "RESUME" in rows and rows["RESUME"][0] == "PASS" and state.get("sha256"):
        proof.accept(
            "RESUME",
            f"guest read:ok on the stored journal; first sha256={state['sha256']}",
        )
        return
    if "RESUME" not in rows:
        proof.row("RESUME", "NOT RUN", "second process printed no RESUME row")
        return
    proof.row("RESUME", "FAIL", rows["RESUME"][1] or "resume evidence was missing")


def compute_write2(proof: Proof, second: subprocess.CompletedProcess[str]) -> None:
    output = second.stdout + second.stderr
    evidence = parse_evidence(output)
    rows = parse_driver_rows(output)
    wrote = "write:ok" in evidence.get("invokes", "").split(",")
    format2 = evidence.get("format2") == "true"
    if proof.steps.get("RESUME") != "PASS":
        if "WRITE2" not in proof.steps:
            proof.row("WRITE2", "NOT RUN", "resume did not pass; write-again was not started")
        return
    if wrote and format2 and "WRITE2" in rows and rows["WRITE2"][0] == "PASS":
        proof.accept("WRITE2", rows["WRITE2"][1] or "guest wrote a new format-2 revision")
        return
    if "WRITE2" not in rows:
        proof.row("WRITE2", "NOT RUN", "second process printed no WRITE2 row")
        return
    proof.row("WRITE2", "FAIL", rows["WRITE2"][1] or f"write:ok={wrote} format2={format2}")


def write_evidence(proof: Proof, versions: dict[str, str]) -> None:
    counted = all(proof.steps.get(name) == "PASS" for name in JOURNEY)
    skipped = [name for name in JOURNEY if proof.steps.get(name) == "NOT RUN"]
    blocks = [
        "A2 e2e resume proof",
        f"when: {versions['when']}",
        f"commit: {versions['commit']}",
        f"parent: {versions['parent']}",
        f"machine: {versions['machine']}",
        f"rustc: {versions['rustc']}",
        f"python: {versions['python']}",
        "",
        "Every row is computed from journal files, guest hash, audit invokes, and exit codes.",
        "Proof.row never accepts PASS. A skip is NOT RUN.",
        "",
        *[f"{name}: {proof.steps.get(name, 'NOT RUN')} — {proof.details.get(name, '')}" for name in JOURNEY],
        f"A2_counted: {'yes' if counted else 'no'}",
        f"skipped: {', '.join(skipped) if skipped else 'none'}",
        "",
        "log:",
        *proof.lines,
    ]
    EVIDENCE.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    proof.log(f"WROTE {EVIDENCE.relative_to(REPO)}")
    proof.log(f"A2_COUNTED: {'yes' if counted else 'no'}")


def main() -> int:
    proof = Proof()
    versions = record_versions(proof)
    ensure_wasm_target(proof)
    wasm = build_guest(proof)
    expected_guest = pinned_guest_sha256()
    live_guest = sha256_file(wasm)
    if live_guest != expected_guest:
        proof.row(
            "WRITE",
            "FAIL",
            f"built guest {live_guest} does not match {GUEST_PIN.name} {expected_guest}",
        )
        mark_not_run(proof, JOURNEY[1:], "guest hash mismatch; later rows were not started")
        write_evidence(proof, versions)
        return 1
    build_driver(proof)
    store = LANE / "homes" / f"store-{os.getpid()}"
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    proof.log(f"STORE {store.relative_to(REPO)}")

    first = run_phase(proof, "first", store)
    compute_write(proof, first, store, wasm, expected_guest)
    compute_stale(proof, first, store)
    compute_stop(proof, first, store)

    can_resume = (
        proof.steps.get("WRITE") == "PASS"
        and proof.steps.get("STALE") == "PASS"
        and proof.steps.get("STOP") == "PASS"
    )
    if not can_resume:
        mark_not_run(
            proof,
            ("START", "RESUME", "WRITE2"),
            "write, stale, or stop did not pass; later rows were not started",
        )
        write_evidence(proof, versions)
        return 1

    second = run_phase(proof, "second", store)
    compute_start(proof, first, second, store)
    compute_resume(proof, second, store)
    compute_write2(proof, second)
    if second.returncode != EXPECTED_SECOND_EXIT and proof.steps.get("WRITE2") == "PASS":
        proof.row(
            "WRITE2",
            "FAIL",
            f"second process exited {second.returncode}; expected {EXPECTED_SECOND_EXIT}",
        )

    write_evidence(proof, versions)
    if all(proof.steps.get(name) == "PASS" for name in JOURNEY):
        return 0
    proof.log("A2 at risk: the complete journey did not pass")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
