#!/usr/bin/env python3
"""Replay the ten plants in lab/a5-binding-harness/falsifiers.json on a copy."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def run_exact(manifest: Path, name: str) -> tuple[int, float, str]:
    started = time.monotonic()
    proc = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            str(manifest),
            name,
            "--",
            "--nocapture",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, time.monotonic() - started, proc.stdout


def main() -> int:
    harness = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = harness / "Cargo.toml"
    plants = json.loads((harness / "falsifiers.json").read_text())
    os.environ.setdefault("RUST_TEST_THREADS", "2")
    os.environ.setdefault("CARGO_INCREMENTAL", "0")
    os.environ["CARGO_TARGET_DIR"] = str(harness / "target/host")

    lines = [f"harness={harness}"]
    caught = 0
    for item in plants["falsifiers"]:
        fid = item["id"]
        applied = []
        miss = False
        for edit in item["edits"]:
            rel = edit["file"]
            tail = rel.split("lab/a5-binding-harness/", 1)[-1]
            path = harness / tail
            text = path.read_text()
            count = text.count(edit["old"])
            if count != 1:
                lines.append(f"{fid} PLANT-MISS {path} count={count}")
                miss = True
                break
            applied.append((path, text, sha256(path)))
            path.write_text(text.replace(edit["old"], edit["new"], 1))
        if miss:
            for path, text, _ in applied:
                path.write_text(text)
            continue

        results = []
        timeout = False
        for name in item["tests"]:
            code, elapsed, log = run_exact(manifest, name)
            (out_dir / f"{fid}-{name}.log").write_text(log)
            kind = (
                "TIMEOUT"
                if ("timed out" in log.lower() or "timeout" in log.lower())
                else "ASSERT"
            )
            if kind == "TIMEOUT":
                timeout = True
            status = "FAILED" if code != 0 else "PASSED"
            fail = next(
                (
                    row
                    for row in log.splitlines()
                    if "panicked" in row or "assertion" in row
                ),
                "",
            )
            results.append((name, status, code, elapsed, kind, fail[:240]))
        all_failed = all(status == "FAILED" for _, status, *_ in results)
        if all_failed and not timeout:
            caught += 1
            verdict = "CAUGHT"
        elif timeout:
            verdict = "TIMEOUT"
        else:
            verdict = "SURVIVED"
        lines.append(f"{fid} {verdict}")
        for name, status, code, elapsed, kind, fail in results:
            lines.append(
                f"  {name} {status} exit={code} {kind} {elapsed:.2f}s {fail}"
            )
        for path, text, before in applied:
            path.write_text(text)
            after = sha256(path)
            lines.append(
                f"  restore {path.relative_to(harness)} "
                f"{'IDENTICAL' if after == before else 'DRIFT'} {after}"
            )

    lines.append(f"official {caught} CAUGHT of {len(plants['falsifiers'])}")
    (out_dir / "official-plants.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if caught == len(plants["falsifiers"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
