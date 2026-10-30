#!/usr/bin/env python3
"""K: write then read without request_journal_grants, continuing after the first denial."""

import hashlib
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path("/tmp/pr-301-a8-r2")
LANE = REPO / "lab/a1-a8-hardening"
TEST = LANE / "tests/a8_agent_host_host_key.rs"
HERE = pathlib.Path(__file__).resolve().parent
EV = HERE.parent / "evidence/hunts"
ORIGINAL = TEST.read_bytes()
ORIGINAL_SHA = hashlib.sha256(ORIGINAL).hexdigest()


def exact_build_injected():
    text = ORIGINAL.decode()
    start = text.index("fn build_injected(resource: &str)")
    end = text.index("\nfn denied_actions", start)
    return text[start:end].rstrip()


def main():
    EV.mkdir(parents=True, exist_ok=True)
    dest = LANE / "fixtures/write-then-read-continue.txt"
    shutil.copyfile(HERE / "write-then-read-continue.txt", dest)
    replacement = '''fn build_injected(resource: &str) -> a1_a8_hardening::Built {
    const ANCHOR: &str = "        let _identity = elastos::bus::identity::context();\\n";
    let injected_source = format!(
        "{ANCHOR}{}",
        include_str!("../fixtures/write-then-read-continue.txt").replace("@RESOURCE@", resource)
    );
    build_component(
        AGENT_HOST,
        INPUTS,
        "agent-host",
        "-Dwarnings",
        &[Edit {
            file: "src/lib.rs",
            old: ANCHOR,
            new: &injected_source,
        }],
    )
}
'''
    text = ORIGINAL.decode()
    old = exact_build_injected()
    TEST.write_text(text.replace(old, replacement, 1))
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
        (EV / "K-write-then-read-continue.txt").write_text(output)
        print(f"K cargo_exit={result.returncode}")
        for line in output.splitlines():
            if (
                line.startswith("a8 ")
                or line.startswith("test ")
                or "panicked" in line
                or "assertion" in line.lower()
            ):
                print(line)
    finally:
        TEST.write_bytes(ORIGINAL)
        dest.unlink(missing_ok=True)
        digest = hashlib.sha256(TEST.read_bytes()).hexdigest()
        if digest != ORIGINAL_SHA:
            raise SystemExit(f"restore failed: {digest}")
        print("restored", digest)


if __name__ == "__main__":
    sys.exit(main())
