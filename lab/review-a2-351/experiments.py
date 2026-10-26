#!/usr/bin/env python3
"""Adversarial plants against PR #351's A2 resume lab. Does not keep edits."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
REPO = REVIEW.parent.parent
LANE = REPO / "lab/a2-e2e-resume"
DRIVER = LANE / "target/debug/a2-resume-driver"
DRIVER_SRC = LANE / "src/main.rs"
HARNESS = LANE / "harness.py"
WASM = REPO / "examples/agent-host/agent-host.component.wasm"
SCRATCH = REVIEW / "scratch"
EVIDENCE = REVIEW / "experiments.log"

sys.path.insert(0, str(LANE))
import harness as a2  # noqa: E402


def log(lines: list[str], text: str) -> None:
    lines.append(text)
    print(text, flush=True)


def run(args: list[str], cwd: Path = REPO, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("RUST_TEST_THREADS", "2")
    env["CARGO_INCREMENTAL"] = "0"
    return subprocess.run(
        args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rebuild_driver() -> None:
    result = run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(LANE / "Cargo.toml"),
            "--bin",
            "a2-resume-driver",
        ]
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr[-4000:] or result.stdout[-4000:])


def plant_text(path: Path, old: str, new: str) -> tuple[str, str]:
    original = path.read_text(encoding="utf-8")
    if original.count(old) != 1:
        raise SystemExit(f"plant text not unique in {path}: count={original.count(old)}")
    before = sha256_file(path)
    path.write_text(original.replace(old, new, 1), encoding="utf-8")
    return original, before


def restore_text(path: Path, original: str, before: str) -> None:
    path.write_text(original, encoding="utf-8")
    if sha256_file(path) != before:
        raise SystemExit(f"restore hash mismatch for {path}")


def parse_rows(output: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("ROW "):
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        found[parts[1]] = parts[2]
    return found


def fresh_store(name: str) -> Path:
    store = SCRATCH / name
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    return store


def run_driver(phase: str, store: Path) -> subprocess.CompletedProcess[str]:
    return run([str(DRIVER), phase, str(store)])


def record_result(lines: list[str], name: str, caught: bool, detail: str) -> None:
    verdict = "CAUGHT" if caught else "MISSED"
    log(lines, f"PLANT {name}: {verdict} — {detail}")


def plant_hardcoded_driver_pass(lines: list[str]) -> None:
    """Driver prints WRITE PASS without writing. Harness must not count A2."""
    old = '    println!("PROCESS first pid={}", std::process::id());\n    let host = setup(store, true).await?;'
    new = (
        '    println!("PROCESS first pid={}", std::process::id());\n'
        '    row("WRITE", "PASS", "hardcoded plant");\n'
        '    row("STALE", "PASS", "hardcoded plant");\n'
        "    return Ok(());\n"
        "    let host = setup(store, true).await?;"
    )
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("hardcoded-driver")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.apply_driver_rows(proof, first.stdout + first.stderr, ("WRITE", "STALE"))
        if proof.steps.get("WRITE") == "PASS":
            proof.row(
                "STOP",
                "PASS" if first.returncode is not None else "FAIL",
                f"returncode={first.returncode}",
            )
        journal = list(store.rglob("*"))
        has_journal = any(
            p.is_file() and p.name not in {"a2-resume-state.json"} for p in journal
        )
        counted = all(proof.steps.get(name) == "PASS" for name in a2.JOURNEY)
        write_believed = proof.steps.get("WRITE") == "PASS"
        record_result(
            lines,
            "F-REV-HARDCODED-DRIVER-PASS",
            not write_believed,
            (
                f"WRITE={proof.steps.get('WRITE')} STALE={proof.steps.get('STALE')} "
                f"STOP={proof.steps.get('STOP')} counted={counted} "
                f"journal_on_disk={has_journal} first_exit={first.returncode}"
            ),
        )
        if write_believed:
            log(
                lines,
                "  note: harness treated a hardcoded ROW WRITE PASS as a real PASS",
            )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_skipped_stale(lines: list[str]) -> None:
    """First process writes but never prints STALE. That row must be NOT RUN."""
    old = "            stale_write(&host, &plain, &revision).await?;"
    new = "            // skipped stale_write plant"
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("skip-stale")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.apply_driver_rows(proof, first.stdout + first.stderr, ("WRITE", "STALE"))
        if "STALE" not in proof.steps:
            proof.row("STALE", "NOT RUN", "first process printed no STALE row")
        can_resume = proof.steps.get("WRITE") == "PASS" and proof.steps.get("STALE") == "PASS"
        record_result(
            lines,
            "F-REV-SKIPPED-STALE",
            proof.steps.get("STALE") == "NOT RUN" and not can_resume,
            f"WRITE={proof.steps.get('WRITE')} STALE={proof.steps.get('STALE')} can_resume={can_resume}",
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_harness_hardcoded_pass(lines: list[str]) -> None:
    """If the harness itself writes PASS without driver output, A2 would be counted."""
    proof = a2.Proof()
    try:
        proof.row("WRITE", "PASS", "hardcoded harness plant")
        proof.row("STALE", "PASS", "hardcoded harness plant")
        proof.row("STOP", "PASS", "hardcoded harness plant")
        proof.row("START", "PASS", "hardcoded harness plant")
        proof.row("RESUME", "PASS", "hardcoded harness plant")
        proof.row("WRITE2", "PASS", "hardcoded harness plant")
        counted = all(proof.steps.get(name) == "PASS" for name in a2.JOURNEY)
        record_result(
            lines,
            "F-REV-HARDCODED-HARNESS-PASS",
            not counted,
            f"Proof.row accepted six hardcoded PASSes; A2_counted={counted}",
        )
    except SystemExit as error:
        record_result(lines, "F-REV-HARDCODED-HARNESS-PASS", True, str(error))


def plant_harness_not_run_upgrade(lines: list[str]) -> None:
    """NOT RUN must not become PASS."""
    proof = a2.Proof()
    proof.row("RESUME", "NOT RUN", "skipped")
    try:
        proof.row("RESUME", "PASS", "upgrade plant")
        record_result(lines, "F-REV-NOT-RUN-UPGRADE", False, "NOT RUN was upgraded to PASS")
    except SystemExit as error:
        record_result(lines, "F-REV-NOT-RUN-UPGRADE", True, str(error))


def plant_stop_nonzero(lines: list[str]) -> None:
    """First process exits 1 after WRITE+STALE. STOP must not stay PASS."""
    old = "            stale_write(&host, &plain, &revision).await?;\n        }"
    new = (
        "            stale_write(&host, &plain, &revision).await?;\n"
        "            bail!(\"planted crash after stale\");\n"
        "        }"
    )
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("stop-nonzero")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.apply_driver_rows(proof, first.stdout + first.stderr, ("WRITE", "STALE"))
        if proof.steps.get("WRITE") == "PASS":
            proof.row(
                "STOP",
                "PASS" if first.returncode is not None else "FAIL",
                f"first Runtime process exited {first.returncode}",
            )
        stop_pass = proof.steps.get("STOP") == "PASS"
        record_result(
            lines,
            "F-REV-STOP-NONZERO",
            not stop_pass and first.returncode != 0,
            f"first_exit={first.returncode} STOP={proof.steps.get('STOP')} WRITE={proof.steps.get('WRITE')}",
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_second_stale_write(lines: list[str]) -> None:
    """Second process writes with a stale if_revision. WRITE2 must fail."""
    old = '    let reply = bridge_write(host, &next, serde_json::json!({ "if_revision": revision })).await?;'
    new = '    let reply = bridge_write(host, &next, serde_json::json!({ "if_revision": "stale-not-current" })).await?;'
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("second-stale")
        first = run_driver("first", store)
        second = run_driver("second", store)
        rows = parse_rows(first.stdout + first.stderr)
        rows.update(parse_rows(second.stdout + second.stderr))
        record_result(
            lines,
            "F-REV-SECOND-STALE-WRITE",
            rows.get("WRITE2") == "FAIL" and rows.get("RESUME") == "PASS",
            f"WRITE={rows.get('WRITE')} RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')}",
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_older_journal(lines: list[str]) -> None:
    """Second process sees an older journal than the first process recorded."""
    store_a = fresh_store("older-a")
    first_a = run_driver("first", store_a)
    if "ROW WRITE PASS" not in (first_a.stdout + first_a.stderr):
        record_result(lines, "F-REV-OLDER-JOURNAL", False, "first process did not WRITE PASS")
        return
    older = fresh_store("older-snap")
    shutil.rmtree(older)
    shutil.copytree(store_a, older)
    store_b = fresh_store("older-b")
    shutil.rmtree(store_b)
    shutil.copytree(store_a, store_b)
    second_b = run_driver("second", store_b)
    if "ROW WRITE2 PASS" not in (second_b.stdout + second_b.stderr):
        record_result(
            lines,
            "F-REV-OLDER-JOURNAL",
            False,
            f"could not create a newer journal; second exit={second_b.returncode}",
        )
        return
    # Put the older journal bytes back, keep the first-process state (sha of older).
    # Then also try: keep WRITE2 store but restore older journal only.
    newer_state = json.loads((store_b / "a2-resume-state.json").read_text(encoding="utf-8"))
    shutil.rmtree(store_b)
    shutil.copytree(older, store_b)
    (store_b / "a2-resume-state.json").write_text(
        json.dumps(
            {
                "revision": "forged-newer-revision",
                "sha256": "0" * 64,
                "bytes": 1,
                "first_pid": newer_state.get("first_pid"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    second = run_driver("second", store_b)
    rows = parse_rows(second.stdout + second.stderr)
    output = second.stdout + second.stderr
    record_result(
        lines,
        "F-REV-OLDER-JOURNAL",
        rows.get("RESUME") == "FAIL" or "DRIVER_ERROR" in output,
        f"RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')} exit={second.returncode}",
    )


def plant_store_wipe(lines: list[str]) -> None:
    """Wipe the store between processes. Second process must not RESUME PASS."""
    store = fresh_store("wipe")
    first = run_driver("first", store)
    if "ROW WRITE PASS" not in (first.stdout + first.stderr):
        record_result(lines, "F-REV-STORE-WIPE", False, "first process did not WRITE PASS")
        return
    shutil.rmtree(store)
    store.mkdir(parents=True)
    second = run_driver("second", store)
    rows = parse_rows(second.stdout + second.stderr)
    output = second.stdout + second.stderr
    started = "PROCESS second" in output
    record_result(
        lines,
        "F-REV-STORE-WIPE",
        rows.get("RESUME") != "PASS" and rows.get("WRITE2") != "PASS",
        (
            f"started={started} RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')} "
            f"exit={second.returncode} error={'DRIVER_ERROR' in output}"
        ),
    )


def plant_guest_hash(lines: list[str]) -> None:
    """Change the guest wasm. The lab must not still count a silent hash change."""
    if not WASM.is_file():
        record_result(lines, "F-REV-GUEST-HASH", False, "guest wasm missing")
        return
    original = WASM.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    try:
        mutated = bytearray(original)
        mutated[-1] ^= 0xFF
        WASM.write_bytes(mutated)
        after = hashlib.sha256(mutated).hexdigest()
        proof = a2.Proof()
        # The published harness only logs the hash. It never compares it.
        logged = f"GUEST_WASM sha256:{after} bytes:{len(mutated)}"
        proof.log(logged)
        record_result(
            lines,
            "F-REV-GUEST-HASH",
            False,
            (
                f"before={before} after={after}; harness logs the hash and never "
                "compares it, so a changed guest still proceeds"
            ),
        )
        # Also run first process against the mutated wasm to see if WRITE fails closed.
        store = fresh_store("guest-hash")
        first = run_driver("first", store)
        rows = parse_rows(first.stdout + first.stderr)
        log(
            lines,
            f"  mutated-guest first WRITE={rows.get('WRITE')} STALE={rows.get('STALE')} exit={first.returncode}",
        )
        if rows.get("WRITE") == "PASS":
            log(lines, "  note: mutated guest still produced WRITE PASS")
    finally:
        WASM.write_bytes(original)
        if hashlib.sha256(WASM.read_bytes()).hexdigest() != before:
            raise SystemExit("guest wasm restore failed")


def inspect_two_processes(lines: list[str]) -> None:
    store = fresh_store("two-proc")
    first = run_driver("first", store)
    first_out = first.stdout + first.stderr
    second = run_driver("second", store)
    second_out = second.stdout + second.stderr
    first_pid = next((line for line in first_out.splitlines() if line.startswith("PROCESS first")), "")
    second_pid = next((line for line in second_out.splitlines() if line.startswith("PROCESS second")), "")
    state = json.loads((store / "a2-resume-state.json").read_text(encoding="utf-8"))
    runtime_data = store / "runtime-data"
    journal_files = [p for p in runtime_data.rglob("*") if p.is_file()]
    log(lines, f"TWO-PROC first_exit={first.returncode} {first_pid}")
    log(lines, f"TWO-PROC second_exit={second.returncode} {second_pid}")
    log(lines, f"TWO-PROC first_rows={parse_rows(first_out)}")
    log(lines, f"TWO-PROC second_rows={parse_rows(second_out)}")
    log(lines, f"TWO-PROC state_keys={sorted(state)} first_pid={state.get('first_pid')}")
    log(lines, f"TWO-PROC runtime-data files={len(journal_files)} store_exists_after_first_exit=yes")
    same_pid = first_pid.split("pid=")[-1:] == second_pid.split("pid=")[-1:]
    log(lines, f"TWO-PROC same_printed_pid={same_pid}")


def main() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    log(lines, "A2 #351 adversarial review experiments")
    log(lines, f"HEAD {run(['git', 'rev-parse', 'HEAD']).stdout.strip()}")
    log(lines, f"DRIVER {sha256_file(DRIVER)}")
    log(lines, f"GUEST {sha256_file(WASM)}")
    inspect_two_processes(lines)
    plant_harness_hardcoded_pass(lines)
    plant_harness_not_run_upgrade(lines)
    plant_hardcoded_driver_pass(lines)
    plant_skipped_stale(lines)
    plant_stop_nonzero(lines)
    plant_second_stale_write(lines)
    plant_older_journal(lines)
    plant_store_wipe(lines)
    plant_guest_hash(lines)
    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    missed = [line for line in lines if line.startswith("PLANT ") and ": MISSED" in line]
    log(lines, f"MISSED {len(missed)}")
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
