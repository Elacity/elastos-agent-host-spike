#!/usr/bin/env python3
"""A2 resume journey: write, stale refuse, stop, start, resume, write again."""

from __future__ import annotations

import hashlib
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
JOURNEY = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")


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
        if result not in {"PASS", "FAIL", "NOT RUN"}:
            raise SystemExit(f"bad result {result} for {name}")
        if result == "PASS" and name in self.steps and self.steps[name] == "NOT RUN":
            raise SystemExit(f"{name} was NOT RUN; it cannot become PASS")
        self.steps[name] = result
        self.details[name] = detail
        self.log(f"STEP {name}: {result} — {detail}")


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
    proof.log(f"GUEST_WASM sha256:{sha256_file(wasm)} bytes:{wasm.stat().st_size}")
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


def apply_driver_rows(proof: Proof, output: str, expected: tuple[str, ...]) -> None:
    found = parse_driver_rows(output)
    for name in expected:
        if name in found:
            result, detail = found[name]
            proof.row(name, result, detail)
        else:
            proof.row(name, "NOT RUN", "driver did not print this row")


def run_phase(proof: Proof, phase: str, store: Path) -> subprocess.CompletedProcess[str]:
    result = run([str(DRIVER_BIN), phase, str(store)], cwd=REPO, timeout=180)
    output = result.stdout + result.stderr
    proof.log(f"CMD a2-resume-driver {phase} -> {result.returncode}")
    for line in output.splitlines():
        if line.startswith("ROW ") or line.startswith("PROCESS ") or line.startswith("DRIVER_ERROR"):
            proof.log(line)
    return result


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
        "Every row is derived from driver or process output. A skip is NOT RUN.",
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
    build_guest(proof)
    build_driver(proof)
    store = LANE / "homes" / f"store-{os.getpid()}"
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    proof.log(f"STORE {store.relative_to(REPO)}")

    first = run_phase(proof, "first", store)
    apply_driver_rows(proof, first.stdout + first.stderr, ("WRITE", "STALE"))
    if "WRITE" not in proof.steps:
        proof.row(
            "WRITE",
            "FAIL" if first.returncode != 0 else "NOT RUN",
            f"first process exited {first.returncode} with no WRITE row",
        )
    if "STALE" not in proof.steps:
        proof.row("STALE", "NOT RUN", "first process printed no STALE row")

    if proof.steps.get("WRITE") == "PASS":
        proof.row(
            "STOP",
            "PASS" if first.returncode is not None else "FAIL",
            f"first Runtime process exited {first.returncode}; store kept at {store.name}",
        )
    else:
        mark_not_run(proof, ("STOP",), "first process did not complete a write")

    can_resume = proof.steps.get("WRITE") == "PASS" and proof.steps.get("STALE") == "PASS"
    if not can_resume:
        mark_not_run(
            proof,
            ("START", "RESUME", "WRITE2"),
            "write or stale did not pass; later rows were not started",
        )
        write_evidence(proof, versions)
        return 1

    second = run_phase(proof, "second", store)
    if "PROCESS second" in (second.stdout + second.stderr):
        proof.row(
            "START",
            "PASS",
            f"fresh Runtime process started on the same store; exit={second.returncode}",
        )
    else:
        proof.row("START", "FAIL", "second process printed no PROCESS second line")
    apply_driver_rows(proof, second.stdout + second.stderr, ("RESUME", "WRITE2"))
    if "RESUME" not in proof.steps:
        proof.row("RESUME", "NOT RUN", "second process printed no RESUME row")
    if proof.steps.get("RESUME") != "PASS":
        if "WRITE2" not in proof.steps:
            proof.row("WRITE2", "NOT RUN", "resume did not pass; write-again was not started")
    elif "WRITE2" not in proof.steps:
        proof.row("WRITE2", "NOT RUN", "second process printed no WRITE2 row")

    write_evidence(proof, versions)
    if all(proof.steps.get(name) == "PASS" for name in JOURNEY):
        return 0
    proof.log("A2 at risk: the complete journey did not pass")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
