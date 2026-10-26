#!/usr/bin/env python3
"""Plant one A2 resume bug, rerun the affected phases, restore, print CAUGHT."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

LANE = Path(__file__).resolve().parent
REPO = LANE.parent.parent
JOURNEY_ROWS = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")
DRIVER = LANE / "target/debug/a2-resume-driver"
DRIVER_SRC = LANE / "src/main.rs"
GUEST_SRC = REPO / "examples/agent-host/src/lib.rs"
WASM = REPO / "examples/agent-host/agent-host.component.wasm"
GUEST_PIN = LANE / "guest.sha256"
SCRATCH = LANE / "scratch"

sys.path.insert(0, str(LANE))
import harness as a2  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_plants() -> list[dict]:
    catalog = json.loads((LANE / "falsifiers.json").read_text(encoding="utf-8"))
    return list(catalog["falsifiers"])


def run_cmd(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("RUST_TEST_THREADS", "2")
    env["CARGO_INCREMENTAL"] = "0"
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)


def rebuild(kind: str) -> subprocess.CompletedProcess[str]:
    if kind == "guest":
        return run_cmd([str(REPO / "examples/agent-host/build.sh")], cwd=REPO)
    if kind == "driver":
        return run_cmd(
            ["cargo", "build", "--manifest-path", str(LANE / "Cargo.toml"), "--bin", "a2-resume-driver"],
            cwd=REPO,
        )
    raise SystemExit(f"unknown rebuild {kind}")


def parse_rows(output: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("ROW "):
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        name, result = parts[1], parts[2]
        if name in JOURNEY_ROWS:
            found[name] = result
    return found


def run_phases(phases: list[str], store: Path) -> tuple[dict[str, str], str]:
    driver = DRIVER
    if not driver.is_file():
        built = rebuild("driver")
        if built.returncode != 0:
            return {}, built.stdout + built.stderr
    rows: dict[str, str] = {}
    log = []
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    for index, phase in enumerate(phases):
        result = run_cmd([str(driver), phase, str(store)], cwd=REPO)
        output = result.stdout + result.stderr
        log.append(f"PHASE {phase} exit={result.returncode}\n{output}")
        parsed = parse_rows(output)
        rows.update(parsed)
        if phase == "first":
            rows["STOP"] = "PASS" if result.returncode == 0 else "FAIL"
        if phase == "second":
            rows["START"] = (
                "PASS"
                if result.returncode == 0 and "PROCESS second" in output
                else "FAIL"
            )
        needed = {"first": ("WRITE", "STALE"), "second": ("RESUME",)}[phase]
        if any(rows.get(name) != "PASS" for name in needed) and index + 1 < len(phases):
            break
    return rows, "\n".join(log)


def apply_plant(plant: dict) -> tuple[Path, str, str]:
    target = REPO / plant["path"]
    original = target.read_text(encoding="utf-8")
    before = sha256_file(target)
    if original.count(plant["old"]) != 1:
        raise SystemExit(f"{plant['id']}: plant text is missing or not unique in {plant['path']}")
    target.write_text(original.replace(plant["old"], plant["new"], 1), encoding="utf-8")
    return target, original, before


def restore(target: Path, original: str, before: str, plant_id: str) -> None:
    target.write_text(original, encoding="utf-8")
    if sha256_file(target) != before:
        raise SystemExit(f"{plant_id}: restore hash mismatch")


def run_one(plant: dict) -> int:
    target, original, before = apply_plant(plant)
    store = LANE / "scratch" / f"falsify-{plant['id']}"
    pin_original = pin_before = None
    try:
        built = rebuild(plant["rebuild"])
        if built.returncode != 0:
            print(f"{plant['id']} MISSED")
            print((built.stderr or built.stdout)[-4000:])
            return 1
        if plant["rebuild"] == "guest" and WASM.is_file():
            pin_original, pin_before = retarget_pin()
        rows, log = run_phases(plant["phases"], store)
        caught_row = plant["catch_row"]
        result = rows.get(caught_row)
        if result == "PASS":
            print(f"{plant['id']} MISSED")
            print(f"{caught_row} stayed PASS under the plant")
            print(log[-4000:])
            return 1
        if result is None:
            print(f"{plant['id']} CAUGHT")
            print(plant["why"])
            print(f"{caught_row}: NOT RUN")
            return 0
        print(f"{plant['id']} CAUGHT")
        print(plant["why"])
        print(f"{caught_row}: {result}")
        return 0
    finally:
        restore(target, original, before, plant["id"])
        if plant["rebuild"] == "guest":
            rebuilt = rebuild("guest")
            if rebuilt.returncode != 0:
                print(f"{plant['id']}: guest restore rebuild failed", file=sys.stderr)
            if pin_original is not None and pin_before is not None:
                restore_pin(pin_original, pin_before)
        if plant["rebuild"] == "driver":
            rebuilt = rebuild("driver")
            if rebuilt.returncode != 0:
                print(f"{plant['id']}: driver restore rebuild failed", file=sys.stderr)


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


def retarget_pin() -> tuple[str, str]:
    original = GUEST_PIN.read_text(encoding="utf-8")
    before = sha256_file(GUEST_PIN)
    GUEST_PIN.write_text(sha256_file(WASM) + "\n", encoding="utf-8")
    return original, before


def restore_pin(original: str, before: str) -> None:
    GUEST_PIN.write_text(original, encoding="utf-8")
    if sha256_file(GUEST_PIN) != before:
        raise SystemExit("guest.sha256 restore hash mismatch")


def fresh_store(name: str) -> Path:
    store = SCRATCH / name
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    return store


def run_driver(phase: str, store: Path) -> subprocess.CompletedProcess[str]:
    return run_cmd([str(DRIVER), phase, str(store)], cwd=REPO)


def print_caught(name: str, caught: bool, detail: str) -> int:
    verdict = "CAUGHT" if caught else "MISSED"
    print(f"{name} {verdict}")
    print(detail)
    return 0 if caught else 1


def plant_hardcoded_row_pass() -> int:
    proof = a2.Proof()
    try:
        proof.row("WRITE", "PASS", "hardcoded harness plant")
        proof.row("STALE", "PASS", "hardcoded harness plant")
        proof.row("STOP", "PASS", "hardcoded harness plant")
        proof.row("START", "PASS", "hardcoded harness plant")
        proof.row("RESUME", "PASS", "hardcoded harness plant")
        proof.row("WRITE2", "PASS", "hardcoded harness plant")
        counted = all(proof.steps.get(name) == "PASS" for name in a2.JOURNEY)
        return print_caught(
            "F-REV-HARDCODED-HARNESS-PASS",
            not counted,
            f"Proof.row accepted six hardcoded PASSes; A2_counted={counted}",
        )
    except SystemExit as error:
        return print_caught("F-REV-HARDCODED-HARNESS-PASS", True, str(error))


def plant_skipped_stale() -> int:
    old = (
        "                probe_stale_write(&mut WasmBus, &cursor, grants.write.as_ref())\n"
        "                    .map_err(|reason| elastos::bus::types::BusError::Invalid(reason.to_string()))?;"
    )
    new = "                // skipped probe_stale_write plant"
    original, before = plant_text(GUEST_SRC, old, new)
    pin_original = pin_before = None
    try:
        built = rebuild("guest")
        if built.returncode != 0:
            return print_caught("F-REV-SKIPPED-STALE", False, built.stderr[-2000:] or built.stdout[-2000:])
        pin_original, pin_before = retarget_pin()
        store = fresh_store("skip-stale")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        can_resume = proof.steps.get("WRITE") == "PASS" and proof.steps.get("STALE") == "PASS"
        return print_caught(
            "F-REV-SKIPPED-STALE",
            proof.steps.get("STALE") == "NOT RUN" and not can_resume,
            f"WRITE={proof.steps.get('WRITE')} STALE={proof.steps.get('STALE')} can_resume={can_resume}",
        )
    finally:
        restore_text(GUEST_SRC, original, before)
        rebuild("guest")
        if pin_original is not None and pin_before is not None:
            restore_pin(pin_original, pin_before)


def plant_stop_nonzero() -> int:
    old = (
        "            if stale {\n"
        "                row(\n"
        '                    "STALE",\n'
        '                    "PASS",\n'
        "                    &format!(\n"
        '                        "guest stale if_revision refused with revision_conflict; stored sha256={sha}"\n'
        "                    ),\n"
        "                );\n"
        "            }"
    )
    new = old + '\n            bail!("planted crash after stale");'
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        built = rebuild("driver")
        if built.returncode != 0:
            return print_caught("F-REV-STOP-NONZERO", False, built.stderr[-2000:] or built.stdout[-2000:])
        store = fresh_store("stop-nonzero")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        a2.compute_stop(proof, first, store)
        return print_caught(
            "F-REV-STOP-NONZERO",
            proof.steps.get("STOP") != "PASS" and first.returncode != 0,
            f"first_exit={first.returncode} STOP={proof.steps.get('STOP')} WRITE={proof.steps.get('WRITE')}",
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild("driver")


def plant_second_stale_write() -> int:
    old = '    let body = journal_write_body(&bytes, Some(&revision));'
    new = '    let body = journal_write_body(&bytes, Some("stale-not-current"));'
    original, before = plant_text(GUEST_SRC, old, new)
    pin_original = pin_before = None
    try:
        built = rebuild("guest")
        if built.returncode != 0:
            return print_caught(
                "F-REV-SECOND-STALE-WRITE",
                False,
                built.stderr[-2000:] or built.stdout[-2000:],
            )
        pin_original, pin_before = retarget_pin()
        store = fresh_store("second-stale")
        first = run_driver("first", store)
        second = run_driver("second", store)
        rows = parse_rows(first.stdout + first.stderr)
        rows.update(parse_rows(second.stdout + second.stderr))
        return print_caught(
            "F-REV-SECOND-STALE-WRITE",
            rows.get("WRITE2") == "FAIL" and rows.get("RESUME") == "PASS",
            f"WRITE={rows.get('WRITE')} RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')}",
        )
    finally:
        restore_text(GUEST_SRC, original, before)
        rebuild("guest")
        if pin_original is not None and pin_before is not None:
            restore_pin(pin_original, pin_before)


def plant_older_journal() -> int:
    store_a = fresh_store("older-a")
    first_a = run_driver("first", store_a)
    if "ROW WRITE PASS" not in (first_a.stdout + first_a.stderr):
        return print_caught("F-REV-OLDER-JOURNAL", False, "first process did not WRITE PASS")
    older = fresh_store("older-snap")
    shutil.rmtree(older)
    shutil.copytree(store_a, older)
    store_b = fresh_store("older-b")
    shutil.rmtree(store_b)
    shutil.copytree(store_a, store_b)
    second_b = run_driver("second", store_b)
    if "ROW WRITE2 PASS" not in (second_b.stdout + second_b.stderr):
        return print_caught(
            "F-REV-OLDER-JOURNAL",
            False,
            f"could not create a newer journal; second exit={second_b.returncode}",
        )
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
    return print_caught(
        "F-REV-OLDER-JOURNAL",
        rows.get("RESUME") == "FAIL" or "DRIVER_ERROR" in output,
        f"RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')} exit={second.returncode}",
    )


def plant_store_wipe() -> int:
    store = fresh_store("wipe")
    first = run_driver("first", store)
    if "ROW WRITE PASS" not in (first.stdout + first.stderr):
        return print_caught("F-REV-STORE-WIPE", False, "first process did not WRITE PASS")
    shutil.rmtree(store)
    store.mkdir(parents=True)
    second = run_driver("second", store)
    rows = parse_rows(second.stdout + second.stderr)
    output = second.stdout + second.stderr
    started = "PROCESS second" in output
    return print_caught(
        "F-REV-STORE-WIPE",
        rows.get("RESUME") != "PASS" and rows.get("WRITE2") != "PASS",
        (
            f"started={started} RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')} "
            f"exit={second.returncode} error={'DRIVER_ERROR' in output}"
        ),
    )


def plant_guest_byte_flip() -> int:
    if not WASM.is_file():
        return print_caught("F-REV-GUEST-HASH", False, "guest wasm missing")
    original = WASM.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    try:
        mutated = bytearray(original)
        mutated[-1] ^= 0xFF
        WASM.write_bytes(mutated)
        after = hashlib.sha256(mutated).hexdigest()
        store = fresh_store("guest-hash")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        write_pass = proof.steps.get("WRITE") == "PASS"
        return print_caught(
            "F-REV-GUEST-HASH",
            not write_pass and before != after,
            (
                f"before={before} after={after} WRITE={proof.steps.get('WRITE')} "
                f"exit={first.returncode}"
            ),
        )
    finally:
        WASM.write_bytes(original)
        if hashlib.sha256(WASM.read_bytes()).hexdigest() != before:
            raise SystemExit("guest wasm restore failed")


REVIEW_PLANTS = (
    plant_hardcoded_row_pass,
    plant_skipped_stale,
    plant_stop_nonzero,
    plant_second_stale_write,
    plant_older_journal,
    plant_store_wipe,
    plant_guest_byte_flip,
)


def main(argv: list[str]) -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    plants = load_plants()
    review_names = {
        "F-REV-HARDCODED-HARNESS-PASS": plant_hardcoded_row_pass,
        "F-REV-SKIPPED-STALE": plant_skipped_stale,
        "F-REV-STOP-NONZERO": plant_stop_nonzero,
        "F-REV-SECOND-STALE-WRITE": plant_second_stale_write,
        "F-REV-OLDER-JOURNAL": plant_older_journal,
        "F-REV-STORE-WIPE": plant_store_wipe,
        "F-REV-GUEST-HASH": plant_guest_byte_flip,
    }
    wanted = argv[1:]
    failed = 0
    if wanted:
        json_wanted = [plant for plant in plants if plant["id"] in wanted]
        review_wanted = [review_names[name] for name in wanted if name in review_names]
        if len(json_wanted) + len(review_wanted) != len(wanted):
            sys.stderr.write("unknown falsifier id\n")
            return 2
        for plant in json_wanted:
            failed += run_one(plant)
        for runner in review_wanted:
            failed += runner()
        return 0 if failed == 0 else 1
    for plant in plants:
        failed += run_one(plant)
    for runner in REVIEW_PLANTS:
        failed += runner()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
