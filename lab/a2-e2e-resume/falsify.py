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
    driver = LANE / "target/debug/a2-resume-driver"
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
            rows["STOP"] = "PASS" if result.returncode == 0 or parsed else "FAIL"
        if phase == "second":
            rows["START"] = "PASS" if result.returncode in (0, 1) and "PROCESS second" in output else "FAIL"
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
    try:
        built = rebuild(plant["rebuild"])
        if built.returncode != 0:
            print(f"{plant['id']} MISSED")
            print((built.stderr or built.stdout)[-4000:])
            return 1
        rows, log = run_phases(plant["phases"], store)
        caught_row = plant["catch_row"]
        result = rows.get(caught_row)
        if result == "PASS":
            print(f"{plant['id']} MISSED")
            print(f"{caught_row} stayed PASS under the plant")
            print(log[-4000:])
            return 1
        if result is None:
            print(f"{plant['id']} MISSED")
            print(f"{caught_row} was NOT RUN under the plant")
            print(log[-4000:])
            return 1
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
        if plant["rebuild"] == "driver":
            rebuilt = rebuild("driver")
            if rebuilt.returncode != 0:
                print(f"{plant['id']}: driver restore rebuild failed", file=sys.stderr)


def main(argv: list[str]) -> int:
    plants = load_plants()
    wanted = argv[1:]
    if wanted:
        plants = [plant for plant in plants if plant["id"] in wanted]
        if len(plants) != len(wanted):
            sys.stderr.write("unknown falsifier id\n")
            return 2
    failed = 0
    for plant in plants:
        failed += run_one(plant)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
