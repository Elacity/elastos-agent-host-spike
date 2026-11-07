#!/usr/bin/env python3
"""Apply one A2 plant, run its named test, restore the file, print CAUGHT."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

LANE = Path(__file__).resolve().parent
REPO = LANE.parent.parent


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_plant(plant_id: str) -> dict:
    catalog = json.loads((LANE / "falsifiers.json").read_text(encoding="utf-8"))
    for plant in catalog["falsifiers"]:
        if plant["id"] == plant_id:
            return plant
    raise SystemExit(f"unknown falsifier {plant_id}")


def run_named_test(name: str, ignored: bool) -> subprocess.CompletedProcess[str]:
    extra = ["--ignored"] if ignored else []
    env = os.environ.copy()
    env.setdefault("RUST_TEST_THREADS", "2")
    env["CARGO_INCREMENTAL"] = "0"
    return subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "elastos-server",
            "--lib",
            name,
            "--",
            *extra,
            "--exact",
            "--nocapture",
        ],
        cwd=REPO / "elastos",
        env=env,
        text=True,
        capture_output=True,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: falsify.py F-A2-REVISION\n")
        return 2
    plant = load_plant(argv[1])
    target = REPO / plant["path"]
    original = target.read_text(encoding="utf-8")
    before = sha256_file(target)
    if plant["old"] not in original:
        sys.stderr.write(f"{plant['id']}: plant text is missing from {plant['path']}\n")
        return 1
    if original.count(plant["old"]) != 1:
        sys.stderr.write(f"{plant['id']}: plant text is not unique in {plant['path']}\n")
        return 1
    target.write_text(original.replace(plant["old"], plant["new"], 1), encoding="utf-8")
    try:
        result = run_named_test(plant["test"], plant.get("ignored", False))
    finally:
        target.write_text(original, encoding="utf-8")
    after = sha256_file(target)
    if after != before:
        sys.stderr.write(f"{plant['id']}: restore hash mismatch\n")
        return 1
    output = result.stdout + result.stderr
    failed = result.returncode != 0 and (
        "FAILED" in output or "assert" in output.lower()
    )
    if failed:
        print(f"{plant['id']} CAUGHT")
        print(plant["why"])
        return 0
    print(f"{plant['id']} MISSED")
    print(output[-4000:])
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
