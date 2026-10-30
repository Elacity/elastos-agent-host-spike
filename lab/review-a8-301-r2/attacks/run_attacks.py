#!/usr/bin/env python3
"""Scratch attacks against #301 A8 at a2398b5d. Edit the detached worktree, then restore."""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path("/tmp/pr-301-a8-r2")
LANE = REPO / "lab/a1-a8-hardening"
TEST = LANE / "tests/a8_agent_host_host_key.rs"
HERE = pathlib.Path(__file__).resolve().parent
EV = HERE.parent / "evidence/attacks"

ORIGINAL = TEST.read_bytes()
ORIGINAL_SHA = hashlib.sha256(ORIGINAL).hexdigest()


def exact_build_injected():
    text = ORIGINAL.decode()
    start = text.index("fn build_injected(resource: &str)")
    end = text.index("\nfn denied_actions", start)
    return text[start:end].rstrip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def restore():
    TEST.write_bytes(ORIGINAL)
    if sha(TEST) != ORIGINAL_SHA:
        raise SystemExit(f"restore failed: {sha(TEST)}")
    subprocess.run(
        ["git", "checkout", "--", "lab/a1-a8-hardening/fixtures"],
        cwd=REPO,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for name in ("write-then-read.txt", "jsonl-path.txt"):
        (LANE / "fixtures" / name).unlink(missing_ok=True)


def run_test(name, ignored=False):
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
        name,
        "--",
        "--exact",
        "--nocapture",
    ]
    if ignored:
        command.insert(command.index("--"), "--ignored")
    return subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True)


def write_test(text):
    TEST.write_text(text)
    if sha(TEST) == ORIGINAL_SHA:
        raise SystemExit("edit did not change the test file")


def apply_anchor_fixture(fixture_name):
    dest = LANE / "fixtures" / fixture_name
    src = HERE / fixture_name
    shutil.copyfile(src, dest)
    replacement = f'''fn build_injected(resource: &str) -> a1_a8_hardening::Built {{
    const ANCHOR: &str = "        let _identity = elastos::bus::identity::context();\\n";
    let injected_source = format!(
        "{{ANCHOR}}{{}}",
        include_str!("../fixtures/{fixture_name}").replace("@RESOURCE@", resource)
    );
    build_component(
        AGENT_HOST,
        INPUTS,
        "agent-host",
        "-Dwarnings",
        &[Edit {{
            file: "src/lib.rs",
            old: ANCHOR,
            new: &injected_source,
        }}],
    )
}}
'''
    text = ORIGINAL.decode()
    old = exact_build_injected()
    if text.count(old) != 1:
        raise SystemExit("build_injected not unique")
    write_test(text.replace(old, replacement, 1))
    return dest


def summarize(name, result):
    output = result.stdout + result.stderr
    EV.mkdir(parents=True, exist_ok=True)
    (EV / f"{name}.txt").write_text(output)
    passed = f"test {name} ... ok" in output or "test agent_host_host_key_read_is_refused ... ok" in output
    failed = " ... FAILED" in output
    timed_out = "exit:timeout" in output or (
        "the client hit the" in output and "bound with no status" in output
    )
    print(f"{name}: cargo_exit={result.returncode} passed={passed} failed={failed} timed_out={timed_out}")
    for line in output.splitlines():
        if (
            line.startswith("a8 ")
            or line.startswith("test ")
            or "panicked" in line
            or "assertion" in line.lower()
            or line.startswith("error:")
        ):
            print(f"  {line}")
    return output


def main():
    EV.mkdir(parents=True, exist_ok=True)
    if sha(TEST) != ORIGINAL_SHA:
        raise SystemExit(f"worktree test file dirty: {sha(TEST)}")
    print("original", ORIGINAL_SHA)
    extras = []
    try:
        print("===== A-skip-guards =====", flush=True)
        text = ORIGINAL.decode()
        for chunk in (
            '            Edit {\n                file: "src/lib.rs",\n                old: HOST_PATH_OLD,\n                new: HOST_PATH_NEW,\n            },\n',
            '            Edit {\n                file: "src/lib.rs",\n                old: REQUEST_GUARD_OLD,\n                new: REQUEST_GUARD_NEW,\n            },\n',
        ):
            if text.count(chunk) != 1:
                raise SystemExit(f"A chunk missing:\n{chunk}")
            text = text.replace(chunk, "", 1)
        write_test(text)
        summarize("A-skip-guards", run_test("agent_host_host_key_read_is_refused"))
        restore()

        print("===== B-piece-forge =====", flush=True)
        extras.append(apply_anchor_fixture("piece-forge.txt"))
        summarize("B-piece-forge", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== C-wasm-bus-only =====", flush=True)
        text = ORIGINAL.decode()
        old = """    assert_eq!(
        actions,
        ["write".to_string(), "read".to_string()],
        "Runtime must record manifest_capability_denied for write and read on {resource} (request_journal_grants called the bus); host records: {records:?}"
    );"""
        new = """    let internal = format!(
        "Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\\"capsule manifest does not declare authority for {resource}\\")"
    );
    assert!(
        run.has_line(&internal),
        "expected the Runtime Internal sentence on stderr; stderr:\\n{}",
        run.stderr
    );
    assert_eq!(
        actions,
        ["write".to_string(), "read".to_string()],
        "Runtime must record manifest_capability_denied for write and read on {resource} (request_journal_grants called the bus); host records: {records:?}"
    );"""
        if text.count(old) != 1:
            raise SystemExit("C assertion chunk missing")
        write_test(text.replace(old, new, 1))
        summarize("C-wasm-bus-only", run_test("agent_host_host_key_read_is_refused"))
        restore()

        print("===== D-direct-request =====", flush=True)
        extras.append(apply_anchor_fixture("direct-request.txt"))
        summarize("D-direct-request", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== H-write-then-read-direct =====", flush=True)
        extras.append(apply_anchor_fixture("write-then-read.txt"))
        summarize("H-write-then-read-direct", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== I-jsonl-path =====", flush=True)
        extras.append(apply_anchor_fixture("jsonl-path.txt"))
        summarize("I-jsonl-path", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== J-preseed-jsonl =====", flush=True)
        extras.append(apply_anchor_fixture("piece-forge.txt"))
        text = TEST.read_text()
        seed = '''    let home = Home::new();
    let seeded = home.data().join("runtime");
    std::fs::create_dir_all(&seeded).unwrap();
    std::fs::write(
        seeded.join("capability-requests.jsonl"),
        format!(
            "{{\\"action\\":\\"write\\",\\"resource\\":\\"{resource}\\",\\"code\\":\\"manifest_capability_denied\\"}}\\n{{\\"action\\":\\"read\\",\\"resource\\":\\"{resource}\\",\\"code\\":\\"manifest_capability_denied\\"}}\\n"
        ),
    )
    .unwrap();
'''
        old_home = "    let home = Home::new();\n"
        if text.count(old_home) != 1:
            raise SystemExit("Home::new not unique")
        write_test(text.replace(old_home, seed, 1))
        summarize("J-preseed-jsonl", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== E-ignored-blocked =====", flush=True)
        summarize(
            "E-ignored-blocked",
            run_test("shipped_agent_host_bytes_read_host_key", ignored=True),
        )
        print("===== E-ignored-needs-runtime =====", flush=True)
        summarize(
            "E-ignored-needs-runtime",
            run_test("shipped_wasm_bus_prints_internal_sentence", ignored=True),
        )
    finally:
        restore()
        for path in extras:
            if path.exists() and path.name not in {
                "piece-forge.txt",
                "direct-request.txt",
            }:
                path.unlink()
        status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=REPO, text=True
        ).strip()
        print("final", sha(TEST), "status", status or "clean")


if __name__ == "__main__":
    sys.exit(main())
