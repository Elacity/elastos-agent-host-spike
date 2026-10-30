#!/usr/bin/env python3
"""Honest A8 run, keep the raw jsonl. Scratch edit, then restore."""

import hashlib
import pathlib
import subprocess
import sys

REPO = pathlib.Path("/tmp/pr-301-a8-r2")
LANE = REPO / "lab/a1-a8-hardening"
TEST = LANE / "tests/a8_agent_host_host_key.rs"
EV = pathlib.Path(__file__).resolve().parent.parent / "evidence/hunts"
ORIGINAL = TEST.read_bytes()
ORIGINAL_SHA = hashlib.sha256(ORIGINAL).hexdigest()

DUMP = '''    let raw_path = home.data().join("runtime/capability-requests.jsonl");
    let raw = std::fs::read_to_string(&raw_path).unwrap_or_default();
    println!("a8 raw jsonl path: {}", raw_path.display());
    println!("a8 raw jsonl bytes: {}", raw.len());
    for (i, line) in raw.lines().enumerate() {
        println!("a8 raw jsonl[{i}]: {line}");
    }
'''


def main():
    EV.mkdir(parents=True, exist_ok=True)
    text = ORIGINAL.decode()
    old = "    let records = home.capability_requests();\n"
    if text.count(old) != 1:
        raise SystemExit("records read not unique")
    TEST.write_text(text.replace(old, old + DUMP, 1))
    env = dict(__import__("os").environ)
    env.pop("RUSTFLAGS", None)
    env.update(
        CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(LANE / "target/host"),
        CARGO_BUILD_BUILD_DIR=str(LANE / "target/host-build"),
        CARGO_INCREMENTAL="0",
        RUST_TEST_THREADS="2",
    )
    try:
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                str(LANE / "Cargo.toml"),
                "--test",
                "a8_agent_host_host_key",
                "agent_host_host_key_read_is_refused",
                "--",
                "--exact",
                "--nocapture",
            ],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        (EV / "dump-jsonl.txt").write_text(output)
        print(f"dump cargo_exit={result.returncode}")
        for line in output.splitlines():
            if line.startswith("a8 ") or line.startswith("test "):
                print(line)
    finally:
        TEST.write_bytes(ORIGINAL)
        digest = hashlib.sha256(TEST.read_bytes()).hexdigest()
        if digest != ORIGINAL_SHA:
            raise SystemExit(f"restore failed: {digest}")
        print("restored", digest)


if __name__ == "__main__":
    sys.exit(main())
