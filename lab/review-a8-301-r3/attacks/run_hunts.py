#!/usr/bin/env python3
"""Live hunts against the detached worktree at 10316585.

Each hunt edits one file in the reviewed worktree, runs the named A8 test,
then restores the exact bytes. Timeouts are not counted as caught.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys

REVIEW = pathlib.Path(__file__).resolve().parent.parent
WORKTREE = pathlib.Path(os.environ.get("REVIEW_WORKTREE", "/tmp/pr-301-a8-r3"))
LANE = WORKTREE / "lab/a1-a8-hardening"
REPO = WORKTREE
EVIDENCE = pathlib.Path(os.environ.get("REVIEW_EVIDENCE", "/tmp/review-a8-301-r3-evidence"))
TEST = "agent_host_host_key_read_is_refused"
A8 = LANE / "tests/a8_agent_host_host_key.rs"

BUILD_INJECTED_OLD = """fn build_injected(resource: &str) -> a1_a8_hardening::Built {
    let journal_new =
        format!(\"    let _ = (agent_id, task_id);\\n    Ok(\\\"{resource}\\\".to_string())\");
    build_component(
        AGENT_HOST,
        INPUTS,
        \"agent-host\",
        \"-Dwarnings\",
        &[
            Edit {
                file: \"src/lib.rs\",
                old: HOST_PATH_OLD,
                new: HOST_PATH_NEW,
            },
            Edit {
                file: \"src/lib.rs\",
                old: JOURNAL_OLD,
                new: &journal_new,
            },
            Edit {
                file: \"src/lib.rs\",
                old: REQUEST_GUARD_OLD,
                new: REQUEST_GUARD_NEW,
            },
        ],
    )
}"""


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plant_guest(fixture: pathlib.Path) -> str:
    return f"""fn build_injected(resource: &str) -> a1_a8_hardening::Built {{
    const ANCHOR: &str = \"        let _identity = elastos::bus::identity::context();\\n\";
    let injected_source = format!(
        \"{{ANCHOR}}{{}}\",
        include_str!(\"{fixture}\").replace(\"@RESOURCE@\", resource)
    );
    build_component(
        AGENT_HOST,
        INPUTS,
        \"agent-host\",
        \"-Dwarnings\",
        &[Edit {{
            file: \"src/lib.rs\",
            old: ANCHOR,
            new: &injected_source,
        }}],
    )
}}"""


def run_a8(label: str) -> dict:
    env = dict(os.environ)
    env.pop("RUSTFLAGS", None)
    env.update(
        CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(LANE / "target/host"),
        CARGO_BUILD_BUILD_DIR=str(LANE / "target/host-build"),
        CARGO_INCREMENTAL="0",
        RUST_TEST_THREADS="2",
    )
    command = [
        "cargo",
        "test",
        "--locked",
        "--manifest-path",
        str(LANE / "Cargo.toml"),
        "--test",
        "a8_agent_host_host_key",
        TEST,
        "--",
        "--exact",
        "--nocapture",
    ]
    result = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "hunts").mkdir(exist_ok=True)
    (EVIDENCE / "hunts" / f"{label}.txt").write_text(output)
    timed_out = (
        "exit:timeout" in output
        or "exit:None" in output
        or ("the client hit the" in output and "bound with no status" in output)
    )
    failed = f"test {TEST} ... FAILED" in output
    ok = f"test {TEST} ... ok" in output
    authorship = next(
        (line for line in output.splitlines() if line.startswith("a8 authorship:")),
        "",
    )
    evidence = [line for line in output.splitlines() if line.startswith(("a8 ", "test "))]
    return {
        "label": label,
        "exit": result.returncode,
        "ok": ok,
        "failed": failed,
        "timed_out": timed_out,
        "authorship": authorship,
        "evidence": evidence,
    }


def apply_restore(path: pathlib.Path, old: str, new: str, label: str) -> dict:
    original = path.read_bytes()
    digest = sha(path)
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{label}: anchor must occur once in {path}")
    try:
        path.write_text(text.replace(old, new, 1))
        row = run_a8(label)
    finally:
        path.write_bytes(original)
        if sha(path) != digest:
            raise SystemExit(f"{label}: restore failed for {path}")
    row["restored"] = digest
    return row


def main():
    hunts = []
    # H1: r2 skip-journal-grants guest that also returns the follow sentence.
    hunts.append(
        apply_restore(
            A8,
            BUILD_INJECTED_OLD,
            plant_guest(REVIEW / "attacks/guest-follow-sentence.txt"),
            "H-guest-follow-sentence",
        )
    )
    # H2: no-bus guest + follow sentence + jsonl written AFTER snapshot.
    # inode is None at snapshot, so the planted lines are accepted as appends.
    race_old = BUILD_INJECTED_OLD
    race_new = plant_guest(REVIEW / "attacks/no-bus-follow-sentence.txt")
    original = A8.read_bytes()
    digest = sha(A8)
    text = A8.read_text()
    if text.count(race_old) != 1 or text.count("    let cursor = home.snapshot_receipts();") != 1:
        raise SystemExit("H-race-after-snapshot: anchors missing")
    after_snapshot = """    let cursor = home.snapshot_receipts();
    {
        let path = home.receipts_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!(
                "{{\\\"action\\\":\\\"write\\\",\\\"capsule_id\\\":\\\"component-00000000-0000-0000-0000-000000000000\\\",\\\"code\\\":\\\"manifest_capability_denied\\\",\\\"principal_id\\\":null,\\\"resource\\\":\\\"{resource}\\\"}}\\n{{\\\"action\\\":\\\"read\\\",\\\"capsule_id\\\":\\\"component-00000000-0000-0000-0000-000000000000\\\",\\\"code\\\":\\\"manifest_capability_denied\\\",\\\"principal_id\\\":null,\\\"resource\\\":\\\"{resource}\\\"}}\\n"
            ),
        )
        .unwrap();
    }"""
    try:
        A8.write_text(
            text.replace(race_old, race_new, 1).replace(
                "    let cursor = home.snapshot_receipts();",
                after_snapshot,
                1,
            )
        )
        hunts.append(run_a8("H-race-after-snapshot"))
    finally:
        A8.write_bytes(original)
        if sha(A8) != digest:
            raise SystemExit("H-race-after-snapshot: restore failed")
    hunts[-1]["restored"] = digest
    # H3: skip-journal-grants fixture as an independent replant (r2 hunt K).
    hunts.append(
        apply_restore(
            A8,
            BUILD_INJECTED_OLD,
            plant_guest(LANE / "fixtures/skip-journal-grants.txt"),
            "H-skip-journal-grants-replant",
        )
    )
    # H4: piece-forge replant (r1/r2 B).
    hunts.append(
        apply_restore(
            A8,
            BUILD_INJECTED_OLD,
            plant_guest(LANE / "fixtures/piece-forge.txt"),
            "H-piece-forge-replant",
        )
    )

    summary = EVIDENCE / "hunts" / "summary.txt"
    lines = []
    for row in hunts:
        status = (
            "TIMEOUT"
            if row["timed_out"]
            else "LIVE-PASS"
            if row["ok"]
            else "CAUGHT"
            if row["failed"]
            else "UNKNOWN"
        )
        line = f"{row['label']}: {status} exit={row['exit']} {row['authorship']}"
        print(line)
        for ev in row["evidence"]:
            print(f"  {ev}")
        lines.append(line)
    summary.write_text("\n".join(lines) + "\n")
    # A live-pass hunt is a finding. Do not hide it.
    sys.exit(0)


if __name__ == "__main__":
    main()
