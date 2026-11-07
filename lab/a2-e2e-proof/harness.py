#!/usr/bin/env python3
"""Re-run the A2 journal journey against the pinned Runtime."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LANE = Path(__file__).resolve().parent
REPO = LANE.parent.parent
EVIDENCE = LANE / "evidence.txt"
WRITE_TEST = (
    "runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge"
)
STALE_TEST = (
    "resource_bridge::tests::a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept"
)
DENIED_TEST = (
    "runtime::tests::the_agent_host_stores_nothing_when_its_journal_grants_are_denied"
)
FORMAT1_TEST = (
    "runtime::tests::the_agent_host_refuses_a_format_1_journal_with_its_reason"
)
IGNORE_REASON = (
    '#[ignore = "loads examples/agent-host/agent-host.component.wasm; '
    'run examples/agent-host/run-e2e.sh"]'
)


class Proof:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.steps: dict[str, str] = {}
        self.notes: list[str] = []

    def log(self, text: str) -> None:
        self.lines.append(text)
        print(text, flush=True)

    def step(self, name: str, result: str, detail: str) -> None:
        self.steps[name] = result
        self.log(f"STEP {name}: {result} — {detail}")


def run(
    args: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    merged.setdefault("RUST_TEST_THREADS", "2")
    return subprocess.run(
        args,
        cwd=cwd,
        env=merged,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo_result(output: str, name: str) -> str:
    short = re.escape(name.split("::")[-1])
    match = re.search(
        rf"test (?:[^\n]*::)?{short}(?: \(.*?\) )? \.\.\. ([^\n]+)",
        output,
    )
    if match:
        return match.group(1).strip()
    return "not-run"


def cargo_tail(output: str) -> str:
    lines = [
        line
        for line in output.splitlines()
        if line.startswith("test ")
        or line.startswith("test result:")
        or line.startswith("error")
        or "FAILED" in line
        or "ignored" in line
    ]
    return "\n".join(lines[-20:])


def cargo_test(name: str, ignored: bool) -> tuple[subprocess.CompletedProcess[str], str]:
    extra = ["--ignored"] if ignored else []
    result = run(
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
        env={"CARGO_INCREMENTAL": "0"},
    )
    output = result.stdout + result.stderr
    return result, cargo_result(output, name)


def record_versions(proof: Proof) -> dict[str, str]:
    commit = run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip()
    parent = run(["git", "rev-parse", "HEAD^"], cwd=REPO).stdout.strip()
    rustc = run(["rustc", "--version"], cwd=REPO).stdout.strip()
    uname = run(["uname", "-sm"], cwd=REPO).stdout.strip()
    versions = {
        "commit": commit,
        "parent": parent,
        "rustc": rustc,
        "machine": uname,
        "python": sys.version.split()[0],
        "when": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    for key, value in versions.items():
        proof.log(f"VERSION {key}: {value}")
    return versions


def ensure_wasm_target(proof: Proof) -> None:
    result = run(
        ["rustup", "target", "add", "wasm32-unknown-unknown", "--toolchain", "1.91.0"],
        cwd=REPO,
    )
    proof.log(
        f"CMD rustup target add wasm32-unknown-unknown -> {result.returncode}"
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr or result.stdout)


def build_guest(proof: Proof) -> Path:
    script = REPO / "examples/agent-host/build.sh"
    result = run([str(script)], cwd=REPO)
    proof.log(f"CMD {script.relative_to(REPO)} -> {result.returncode}")
    if result.returncode != 0:
        proof.log(result.stderr[-4000:] or result.stdout[-4000:])
        raise SystemExit("guest wasm build failed")
    wasm = REPO / "examples/agent-host/agent-host.component.wasm"
    if not wasm.is_file():
        raise SystemExit("guest wasm missing after build")
    proof.log(f"GUEST_WASM sha256:{sha256_file(wasm)} bytes:{wasm.stat().st_size}")
    return wasm


def platform_key() -> str:
    system = platform.system()
    machine = platform.machine()
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-amd64"
    if system == "Linux" and machine in {"aarch64", "arm64"}:
        return "linux-arm64"
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "darwin-arm64"
    raise SystemExit(f"unsupported platform {system} {machine}")


def build_runtime(proof: Proof) -> tuple[Path, Path]:
    env = {
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_DEBUG": "0",
    }
    elastos = run(
        [
            "cargo",
            "build",
            "--manifest-path",
            "elastos/Cargo.toml",
            "-p",
            "elastos-server",
            "--bin",
            "elastos",
        ],
        cwd=REPO,
        env=env,
    )
    proof.log(f"CMD cargo build -p elastos-server --bin elastos -> {elastos.returncode}")
    if elastos.returncode != 0:
        proof.log((elastos.stderr or elastos.stdout)[-4000:])
        raise SystemExit("Runtime binary build failed")
    provider = run(
        [
            "cargo",
            "build",
            "--manifest-path",
            "elastos/Cargo.toml",
            "-p",
            "localhost-provider",
            "--bin",
            "localhost-provider",
        ],
        cwd=REPO,
        env=env,
    )
    proof.log(
        f"CMD cargo build -p localhost-provider --bin localhost-provider -> {provider.returncode}"
    )
    if provider.returncode != 0:
        proof.log((provider.stderr or provider.stdout)[-4000:])
        raise SystemExit("localhost-provider build failed")
    target = REPO / "elastos/target/debug"
    runtime = target / "elastos"
    localhost = target / "localhost-provider"
    proof.log(f"RUNTIME sha256:{sha256_file(runtime)}")
    proof.log(f"PROVIDER sha256:{sha256_file(localhost)}")
    return runtime, localhost


def health_ok(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2) as sock:
            sock.sendall(
                b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            sock.settimeout(0.4)
            data = sock.recv(32)
        return data.startswith(b"HTTP/1.1 200 ")
    except OSError:
        return False


def start_runtime(proof: Proof, runtime: Path, provider: Path) -> dict[str, object]:
    homes = LANE / "homes"
    homes.mkdir(parents=True, exist_ok=True)
    root = homes / f"home-{os.getpid()}"
    if root.exists():
        shutil.rmtree(root)
    home = root / "home"
    data = home / ".local/share/elastos"
    temp = root / "tmp"
    storage = root / "storage"
    for path in (home, data / "bin", temp, storage):
        path.mkdir(parents=True)
    installed = data / "bin/localhost-provider"
    shutil.copy2(provider, installed)
    installed.chmod(0o755)
    source = json.loads((REPO / "components.json").read_text(encoding="utf-8"))
    entry = source["external"]["localhost-provider"]
    entry["platforms"][platform_key()] = {
        "checksum": f"sha256:{sha256_file(installed)}",
        "size": installed.stat().st_size,
        "install_path": "bin/localhost-provider",
    }
    (data / "components.json").write_text(
        json.dumps({"external": {"localhost-provider": entry}, "profiles": {}}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (data / "config.toml").write_text(
        'dev_mode = true\ncarrier_bind_addr = "127.0.0.1:0"\n',
        encoding="utf-8",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env.clear()
    env.update(
        {
            "HOME": str(home),
            "XDG_DATA_HOME": str(home / ".local/share"),
            "TMPDIR": str(temp),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "ELASTOS_CARRIER_MDNS": "0",
        }
    )
    stdout = (root / "serve.stdout").open("w", encoding="utf-8")
    stderr = (root / "serve.stderr").open("w", encoding="utf-8")
    child = subprocess.Popen(
        [
            str(runtime),
            "serve",
            "--addr",
            f"127.0.0.1:{port}",
            "--storage-path",
            str(storage),
        ],
        cwd=home,
        env=env,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    started = time.time()
    ready = False
    while time.time() - started < 90:
        if child.poll() is not None:
            break
        if (data / "runtime-coords.json").exists() and health_ok(port):
            ready = True
            break
        time.sleep(0.1)
    proof.log(
        f"CMD elastos serve --addr 127.0.0.1:{port} pid={child.pid} ready={ready}"
    )
    if not ready:
        stderr.flush()
        proof.log((root / "serve.stderr").read_text(encoding="utf-8")[-2000:])
    return {
        "child": child,
        "port": port,
        "root": root,
        "data": data,
        "ready": ready,
        "stdout": stdout,
        "stderr": stderr,
    }


def stop_runtime(handle: dict[str, object]) -> None:
    child: subprocess.Popen[str] = handle["child"]  # type: ignore[assignment]
    if child.poll() is None:
        try:
            os.killpg(child.pid, 15)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, 9)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
    for stream in (handle.get("stdout"), handle.get("stderr")):
        if stream:
            stream.close()


def inspect_ignore_reason(proof: Proof) -> None:
    source = (REPO / "elastos/crates/elastos-server/src/runtime.rs").read_text(
        encoding="utf-8"
    )
    count = source.count(IGNORE_REASON)
    proof.log(f"IGNORE_MARKER count={count}")
    if count < 1:
        raise SystemExit("A2 ignore marker missing from runtime.rs")
    guest = REPO / "examples/agent-host/src/lib.rs"
    text = guest.read_text(encoding="utf-8")
    uses_create_only = '"create_only": true' in text
    resume_fn = "fn resume_journal(" in text
    proof.log(f"GUEST journal_write_body uses_create_only={uses_create_only}")
    proof.log(f"GUEST resume_journal present={resume_fn}")


def confirm_ci_skips_write(proof: Proof) -> None:
    result, status = cargo_test(WRITE_TEST, ignored=False)
    output = result.stdout + result.stderr
    proof.log(f"CMD cargo test {WRITE_TEST} (no --ignored) -> {status}")
    proof.log(cargo_tail(output))
    if not status.startswith("ignored"):
        proof.step(
            "WRITE",
            "FAIL",
            f"without --ignored the e2e reported {status!r}, not ignored",
        )
        return
    proof.notes.append(
        "Default cargo test reports the A2 e2e as ignored. That skip is not a pass."
    )


def run_write(proof: Proof) -> None:
    result, status = cargo_test(WRITE_TEST, ignored=True)
    output = result.stdout + result.stderr
    proof.log(f"CMD cargo test {WRITE_TEST} --ignored --exact -> {status}")
    proof.log(cargo_tail(output))
    if status.startswith("ignored"):
        proof.step("WRITE", "FAIL", "still ignored after --ignored; skip is not a pass")
        return
    if status == "ok" and result.returncode == 0:
        proof.step(
            "WRITE",
            "PASS",
            "guest wrote and read the journal through the in-process real bridge",
        )
        return
    proof.step("WRITE", "FAIL", f"cargo reported {status!r}")


def run_siblings(proof: Proof) -> None:
    for name in (DENIED_TEST, FORMAT1_TEST):
        result, status = cargo_test(name, ignored=True)
        proof.log(f"CMD cargo test {name} --ignored --exact -> {status}")
        proof.log(cargo_tail(result.stdout + result.stderr))


def run_stale(proof: Proof) -> None:
    result, status = cargo_test(STALE_TEST, ignored=False)
    output = result.stdout + result.stderr
    proof.log(f"CMD cargo test {STALE_TEST} --exact -> {status}")
    proof.log(cargo_tail(output))
    if status.startswith("ignored"):
        proof.step("STALE", "FAIL", "stale-revision test was ignored; skip is not a pass")
        return
    has_reason = "revision_conflict" in (
        REPO / "elastos/crates/elastos-server/src/resource_bridge.rs"
    ).read_text(encoding="utf-8")
    if status == "ok" and result.returncode == 0 and has_reason:
        proof.step(
            "STALE",
            "PASS",
            "stale if_revision write refused with revision_conflict; stored journal kept",
        )
        return
    proof.step("STALE", "FAIL", f"cargo reported {status!r}")


def run_resume(proof: Proof) -> None:
    runtime_src = (REPO / "elastos/crates/elastos-server/src/runtime.rs").read_text(
        encoding="utf-8"
    )
    guest_src = (REPO / "examples/agent-host/src/lib.rs").read_text(encoding="utf-8")
    e2e = "the_agent_host_writes_and_reads_its_journal_through_the_real_bridge"
    e2e_body_start = runtime_src.find(f"async fn {e2e}")
    e2e_body = runtime_src[e2e_body_start : e2e_body_start + 2500] if e2e_body_start >= 0 else ""
    restarts = "restart" in e2e_body.lower() or "drop" in e2e_body and "agent_host_runtime" in e2e_body
    run_uses_create_only = "create_only" in guest_src and "fn journal_write_body" in guest_src
    proof.log(f"RESUME e2e_restarts_runtime={bool(restarts)}")
    proof.log(f"RESUME guest_first_write_is_create_only={run_uses_create_only}")
    proof.step(
        "RESUME",
        "FAIL",
        "the ignored e2e reads back in the same process; shipped run() starts a "
        "fresh journal with create_only and does not load a stored format-2 "
        "journal after a new launch. Resume after restart is not proven.",
    )


def write_evidence(proof: Proof, versions: dict[str, str], serve_ready: bool) -> None:
    counted = (
        proof.steps.get("WRITE") == "PASS"
        and proof.steps.get("STALE") == "PASS"
        and proof.steps.get("RESUME") == "PASS"
    )
    blocks = [
        "A2 e2e proof",
        f"when: {versions['when']}",
        f"commit: {versions['commit']}",
        f"parent: {versions['parent']}",
        f"machine: {versions['machine']}",
        f"rustc: {versions['rustc']}",
        f"python: {versions['python']}",
        f"runtime_serve_ready: {serve_ready}",
        "",
        "why_ignored: loads examples/agent-host/agent-host.component.wasm; "
        "CI does not build that guest, so the test is #[ignore] and points at "
        "examples/agent-host/run-e2e.sh. Not flaky. Not marked broken.",
        "",
        f"WRITE: {proof.steps.get('WRITE', 'NOT RUN')}",
        f"STALE: {proof.steps.get('STALE', 'NOT RUN')}",
        f"RESUME: {proof.steps.get('RESUME', 'NOT RUN')}",
        f"A2_counted: {'yes' if counted else 'no'}",
        "",
        "log:",
        *proof.lines,
    ]
    EVIDENCE.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    proof.log(f"WROTE {EVIDENCE.relative_to(REPO)}")
    proof.log(f"A2_COUNTED: {'yes' if counted else 'no'}")


def main() -> int:
    proof = Proof()
    versions = record_versions(proof)
    inspect_ignore_reason(proof)
    ensure_wasm_target(proof)
    build_guest(proof)
    runtime, provider = build_runtime(proof)
    handle = start_runtime(proof, runtime, provider)
    try:
        confirm_ci_skips_write(proof)
        run_write(proof)
        run_siblings(proof)
        run_stale(proof)
        run_resume(proof)
    finally:
        stop_runtime(handle)
        if handle.get("ready"):
            proof.log("RUNTIME stopped after health 200")
        else:
            proof.log("RUNTIME serve did not become ready; cargo tests still ran")
    write_evidence(proof, versions, bool(handle.get("ready")))
    if proof.steps.get("WRITE") == "PASS" and proof.steps.get("STALE") == "PASS":
        if proof.steps.get("RESUME") == "PASS":
            return 0
        proof.log("A2 at risk: resume after restart is not proven")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
