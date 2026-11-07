#!/usr/bin/env python3
"""R2 attacks on a copy of the A5 harness. Does not touch PR #334's branch."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


HARNESS = Path(os.environ.get("A5_COPY", "/tmp/a5-review-r2-copy/lab/a5-binding-harness"))
SRC = Path(os.environ.get("A5_SRC", "/tmp/a5-334-wt/lab/a5-binding-harness"))
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "results").resolve()
REVIEW = Path(__file__).resolve().parent
MANIFEST = HARNESS / "Cargo.toml"
CAP = HARNESS / "src/capability.rs"
LIB = HARNESS / "src/lib.rs"
HTTP = HARNESS / "src/http.rs"

os.environ.setdefault("RUST_TEST_THREADS", "2")
os.environ.setdefault("CARGO_INCREMENTAL", "0")
os.environ["CARGO_TARGET_DIR"] = str(HARNESS / "target/host")


def restore_sources() -> None:
    for name in (
        "src/capability.rs",
        "src/lib.rs",
        "src/http.rs",
        "src/contract.rs",
        "src/journey.rs",
    ):
        shutil.copy2(SRC / name, HARNESS / name)


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1))


def run_acceptance(env: dict[str, str] | None, dest: Path) -> str:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    # Drop coords unless the attack sets it.
    if env is None or "A5_RUNTIME_COORDS" not in env:
        merged.pop("A5_RUNTIME_COORDS", None)
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "acceptance",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=merged,
    )
    dest.write_text(proc.stdout + f"\nexit={proc.returncode}\n")
    return proc.stdout


def start_stub(mode: str) -> tuple[subprocess.Popen, int]:
    err = (OUT / f"stub-{mode}.err").open("w")
    proc = subprocess.Popen(
        [sys.executable, str(REVIEW / "stub_operator.py")],
        stdout=subprocess.PIPE,
        stderr=err,
        env={**os.environ, "A5_STUB_MODE": mode, "A5_STUB_PORT": "0"},
        text=True,
    )
    line = proc.stdout.readline() if proc.stdout else ""
    port = int(line.strip())
    return proc, port


def stop_stub(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def write_coords(path: Path, port: int, **extra: object) -> None:
    body = {
        "api_url": f"http://127.0.0.1:{port}",
        "runtime_kind": "operator",
        "attach_secret": "forged-attach-secret",
    }
    body.update(extra)
    path.write_text(json.dumps(body))


def summarize(text: str) -> str:
    rows = [
        line
        for line in text.splitlines()
        if " | " in line and line.startswith("A5-")
    ]
    tail = next(
        (line for line in text.splitlines() if line.startswith("A5 binding:")),
        "",
    )
    return "\n".join(rows + [tail])


def record(name: str, note: str, text: str) -> None:
    (OUT / f"{name}.txt").write_text(note + "\n" + text)
    print(f"=== {name} ===")
    print(note)
    print(summarize(text))
    print()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    restore_sources()

    # --- #372 replays on today's code ---

    # M-FORGE-TODAY: forged coords + theatre stub, no source edit.
    proc, port = start_stub("theatre")
    coords = OUT / "forged-coords.json"
    write_coords(coords, port)
    text = run_acceptance({"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-FORGE-TODAY.raw")
    stop_stub(proc)
    record(
        "M-FORGE-TODAY",
        "forged coords + theatre stub, guest_measured still None, gap() unedited",
        text,
    )

    # M-372-GAP-NONE: exact #372 "asks landed" edit (gap() returns None).
    restore_sources()
    replace_once(
        CAP,
        """        if holds {
            Some(pins)
        } else if self.guest_measured() {
            None
        } else {
            Some(pins)
        }
""",
        """        let _ = (holds, pins);
        None
""",
        "M-372-GAP-NONE",
    )
    text = run_acceptance(None, OUT / "M-372-GAP-NONE.raw")
    record(
        "M-372-GAP-NONE",
        "#372 attack: gap() forced to None, no coords",
        text,
    )

    proc, port = start_stub("theatre")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-372-GAP-NONE-STUB.raw"
    )
    stop_stub(proc)
    record(
        "M-372-GAP-NONE-STUB",
        "#372 attack: gap() None + forged coords + theatre stub",
        text,
    )

    # --- New ways to reach ACCEPTED ---

    # Forge measurement files the gate might read.
    restore_sources()
    measure_files = [
        HARNESS / "guest-measurement.json",
        HARNESS / "MEASURED",
        HARNESS / "src/guest-measurement.json",
        Path("/tmp/a5-guest-measurement.json"),
        OUT / "guest-measurement.json",
    ]
    payload = json.dumps(
        {
            "asks": ["RA-1", "RA-2", "RA-3", "RA-5", "RA-6"],
            "guest_handle": "forged-handle",
            "measured": True,
            "operator": "forged",
        }
    )
    for path in measure_files:
        path.write_text(payload)
    text = run_acceptance(
        {
            "A5_GUEST_MEASURED": "1",
            "A5_MEASURED": "1",
            "A5_ACCEPT": "1",
            "A5_GUEST_MEASUREMENT": str(measure_files[-1]),
            "A5_MEASUREMENT_FILE": str(measure_files[-1]),
        },
        OUT / "M-FORGE-MEASUREMENT.raw",
    )
    record(
        "M-FORGE-MEASUREMENT",
        "forged measurement JSON files + env vars the gate might trust",
        text,
    )
    for path in measure_files:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    # Spoof operator identity / host.
    restore_sources()
    bad_coords = OUT / "spoof-coords.json"
    bad_coords.write_text(
        json.dumps(
            {
                "api_url": "http://10.0.0.1:80",
                "runtime_kind": "home",
                "attach_secret": "forged",
            }
        )
    )
    # Still blocked today; also try after skipping blockers below.

    # Replay a recorded guest transcript: write a transcript file.
    transcript = OUT / "guest-transcript.json"
    transcript.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "id": "A5-ID-POS",
                        "grade": "PASS",
                        "handle": "replay-handle",
                        "bytes": "a5-identity-agent-a-seed\\n",
                    }
                ]
            }
        )
    )
    text = run_acceptance(
        {"A5_TRANSCRIPT": str(transcript), "A5_RUNTIME_COORDS": str(bad_coords)},
        OUT / "M-REPLAY-TRANSCRIPT.raw",
    )
    record(
        "M-REPLAY-TRANSCRIPT",
        "recorded guest transcript + spoofed non-loopback coords; no source edit",
        text,
    )

    # Flip guest_measured() to always true (single-function bool).
    restore_sources()
    replace_once(
        CAP,
        """    pub fn guest_measured(self) -> bool {
        GuestMeasurement::from_operator().is_some_and(|m| m.includes(self))
    }
""",
        """    pub fn guest_measured(self) -> bool {
        true
    }
""",
        "M-FLIP-GUEST-TRUE",
    )
    text = run_acceptance(None, OUT / "M-FLIP-GUEST-TRUE.raw")
    record(
        "M-FLIP-GUEST-TRUE",
        "single-fn flip: guest_measured() always true, no coords",
        text,
    )

    proc, port = start_stub("theatre")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-FLIP-GUEST-TRUE-STUB.raw"
    )
    stop_stub(proc)
    record(
        "M-FLIP-GUEST-TRUE-STUB",
        "guest_measured() true + #372 theatre stub",
        text,
    )

    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-FLIP-GUEST-TRUE-MEASURED.raw"
    )
    stop_stub(proc)
    record(
        "M-FLIP-GUEST-TRUE-MEASURED",
        "guest_measured() true + stub that returns handle and measured shape",
        text,
    )

    # from_operator() returns Some(all asks) — the intended later edit.
    restore_sources()
    replace_once(
        CAP,
        """    pub fn from_operator() -> Option<Self> {
        let _ = std::env::var_os("A5_RUNTIME_COORDS");
        None
    }
""",
        """    pub fn from_operator() -> Option<Self> {
        Some(Self { asks: Capability::ALL.to_vec() })
    }
""",
        "M-FROM-OPERATOR-SOME",
    )
    text = run_acceptance(None, OUT / "M-FROM-OPERATOR-SOME.raw")
    record(
        "M-FROM-OPERATOR-SOME",
        "from_operator() returns Some(all asks), no coords",
        text,
    )
    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-FROM-OPERATOR-SOME-STUB.raw"
    )
    stop_stub(proc)
    record(
        "M-FROM-OPERATOR-SOME-STUB",
        "from_operator() Some(all) + measured stub",
        text,
    )

    # Delete blockers from needs() for A5-PUB only.
    restore_sources()
    replace_once(
        CAP,
        "            Check::PublicNotBinding => &[ResidentCore],\n",
        "            Check::PublicNotBinding => &[],\n",
        "M-DELETE-PUB-NEEDS",
    )
    text = run_acceptance(None, OUT / "M-DELETE-PUB-NEEDS.raw")
    record(
        "M-DELETE-PUB-NEEDS",
        "A5-PUB needs() emptied, no coords",
        text,
    )
    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-DELETE-PUB-NEEDS-STUB.raw"
    )
    stop_stub(proc)
    record(
        "M-DELETE-PUB-NEEDS-STUB",
        "A5-PUB needs() emptied + measured stub (handle + Public bytes)",
        text,
    )

    # Empty every needs() list.
    restore_sources()
    old_needs = CAP.read_text()
    start = old_needs.find("    pub fn needs(self) -> &'static [Capability] {")
    end = old_needs.find("    /// A row stays blocked", start)
    if start < 0 or end < 0:
        raise SystemExit("needs() block not found")
    new_needs = old_needs[start:end].replace(
        "&[LiveGrantView, UsersAiAlias, ResidentCore]",
        "&[]",
    )
    new_needs = new_needs.replace("&[LiveGrantView, ResidentCore]", "&[]")
    new_needs = new_needs.replace(
        "&[LiveGrantView, Settlement, ResidentCore]", "&[]"
    )
    new_needs = new_needs.replace(
        "&[LiveGrantView, HomeStorage, UsersAiAlias, ResidentCore]", "&[]"
    )
    new_needs = new_needs.replace("&[ResidentCore]", "&[]")
    CAP.write_text(old_needs[:start] + new_needs + old_needs[end:])
    text = run_acceptance(None, OUT / "M-DELETE-ALL-NEEDS.raw")
    record(
        "M-DELETE-ALL-NEEDS",
        "every needs() list emptied, no coords",
        text,
    )
    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-DELETE-ALL-NEEDS-STUB.raw"
    )
    stop_stub(proc)
    record(
        "M-DELETE-ALL-NEEDS-STUB",
        "every needs() list emptied + measured stub",
        text,
    )

    # Flip blocked() to always empty.
    restore_sources()
    replace_once(
        CAP,
        """    pub fn blocked(self) -> Vec<Capability> {
        self.needs()
            .iter()
            .copied()
            .filter(|capability| !capability.guest_measured())
            .collect()
    }
""",
        """    pub fn blocked(self) -> Vec<Capability> {
        Vec::new()
    }
""",
        "M-FLIP-BLOCKED-EMPTY",
    )
    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)}, OUT / "M-FLIP-BLOCKED-EMPTY.raw"
    )
    stop_stub(proc)
    record(
        "M-FLIP-BLOCKED-EMPTY",
        "blocked() always empty + measured stub",
        text,
    )

    # Accept journey Ok without evidence (the remaining live-path lock).
    restore_sources()
    replace_once(
        CAP,
        """    pub fn from_operator() -> Option<Self> {
        let _ = std::env::var_os("A5_RUNTIME_COORDS");
        None
    }
""",
        """    pub fn from_operator() -> Option<Self> {
        Some(Self { asks: Capability::ALL.to_vec() })
    }
""",
        "M-ACCEPT-WITHOUT-EVIDENCE/from_operator",
    )
    replace_once(
        LIB,
        """            None => Grade::Fail(
                "journey returned ok without live operator evidence; PASS requires a Runtime response"
                    .to_owned(),
            ),
""",
        """            None => Grade::Pass(
                "journey ok; evidence missing".to_owned(),
            ),
""",
        "M-ACCEPT-WITHOUT-EVIDENCE/lib",
    )
    proc, port = start_stub("measured")
    write_coords(coords, port)
    text = run_acceptance(
        {"A5_RUNTIME_COORDS": str(coords)},
        OUT / "M-ACCEPT-WITHOUT-EVIDENCE.raw",
    )
    stop_stub(proc)
    record(
        "M-ACCEPT-WITHOUT-EVIDENCE",
        "from_operator Some(all) + accept journey Ok without evidence + measured stub",
        text,
    )

    restore_sources()
    print("sources restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
