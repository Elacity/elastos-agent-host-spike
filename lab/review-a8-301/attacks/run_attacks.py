#!/usr/bin/env python3
"""Scratch attacks against #301 A8. Edit the detached worktree, then restore."""

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path("/tmp/pr-301-a8")
LANE = REPO / "lab/a1-a8-hardening"
TEST = LANE / "tests/a8_agent_host_host_key.rs"
HERE = pathlib.Path(__file__).resolve().parent
EV = pathlib.Path("/workspace/lab/review-a8-301/evidence/attacks")

ORIGINAL = TEST.read_bytes()
ORIGINAL_SHA = hashlib.sha256(ORIGINAL).hexdigest()

HOST_PATH_EDIT = """            Edit {
                file: \"src/lib.rs\",
                old: HOST_PATH_OLD,
                new: HOST_PATH_NEW,
            },
            """
REQUEST_GUARD_EDIT = """            Edit {
                file: \"src/lib.rs\",
                old: REQUEST_GUARD_OLD,
                new: REQUEST_GUARD_NEW,
            },
            """
SURFACE_EDIT = """            Edit {
                file: \"src/lib.rs\",
                old: SURFACE_OLD,
                new: SURFACE_NEW,
            },
"""

ANCHOR_BUILD = """fn build_injected(resource: &str) -> a1_a8_hardening::Built {
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
            Edit {
                file: \"src/lib.rs\",
                old: SURFACE_OLD,
                new: SURFACE_NEW,
            },
        ],
    )
}"""

# Load the exact bytes from the live file instead of reconstructing escapes.
def exact_build_injected():
    text = ORIGINAL.decode()
    start = text.index("fn build_injected(resource: &str)")
    end = text.index("\n#[test]", start)
    return text[start:end].rstrip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def restore():
    TEST.write_bytes(ORIGINAL)
    if sha(TEST) != ORIGINAL_SHA:
        raise SystemExit(f"restore failed: {sha(TEST)}")


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


def apply_remove(chunks):
    text = ORIGINAL.decode()
    for chunk in chunks:
        if text.count(chunk) != 1:
            raise SystemExit(f"chunk not unique:\n{chunk}")
        text = text.replace(chunk, "", 1)
    write_test(text)


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
    (EV / f"{name}.txt").write_text(output)
    passed = f"test agent_host_host_key_read_is_refused ... ok" in output or (
        f"test shipped_agent_host_bytes_read_host_key ... ok" in output
    )
    failed = " ... FAILED" in output
    print(f"{name}: cargo_exit={result.returncode} passed={passed} failed={failed}")
    for line in output.splitlines():
        if (
            line.startswith("a8 ")
            or line.startswith("test ")
            or "panicked" in line
            or "error[E" in line
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
        # Keep JOURNAL + SURFACE. Drop host_path special-case and grant-guard deletion.
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
        chunk = '            Edit {\n                file: "src/lib.rs",\n                old: SURFACE_OLD,\n                new: SURFACE_NEW,\n            },\n'
        if text.count(chunk) != 1:
            raise SystemExit("C surface chunk missing")
        write_test(text.replace(chunk, "", 1))
        summarize("C-wasm-bus-only", run_test("agent_host_host_key_read_is_refused"))
        restore()

        print("===== D-direct-request =====", flush=True)
        extras.append(apply_anchor_fixture("direct-request.txt"))
        summarize("D-direct-request", run_test("agent_host_host_key_read_is_refused"))
        restore()
        extras[-1].unlink(missing_ok=True)

        print("===== E-ignored-blocked =====", flush=True)
        summarize(
            "E-ignored-blocked",
            run_test("shipped_agent_host_bytes_read_host_key", ignored=True),
        )
    finally:
        restore()
        for path in extras:
            if path.exists():
                path.unlink()
        print("final", sha(TEST), "status", subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True).strip() or "clean")


if __name__ == "__main__":
    sys.exit(main())
