#!/usr/bin/env python3
"""Independent r2 plants against draft PR #351. Does not keep edits."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
REPO = Path(os.environ.get("A2_REPO", REVIEW.parent.parent)).resolve()
LANE = REPO / "lab/a2-e2e-resume"
DRIVER = LANE / "target/debug/a2-resume-driver"
DRIVER_SRC = LANE / "src/main.rs"
GUEST_SRC = REPO / "examples/agent-host/src/lib.rs"
HARNESS = LANE / "harness.py"
WASM = REPO / "examples/agent-host/agent-host.component.wasm"
GUEST_PIN = LANE / "guest.sha256"
SCRATCH = REVIEW / "scratch"
EVIDENCE = REVIEW / "experiments.log"
PHRASE = "aaaa-bbbb-cccc-dddd-eeee-ffff-1111-2222"
HELPER = "store_test_principal_root_protection"

sys.path.insert(0, str(LANE))
import harness as a2  # noqa: E402


def log(lines: list[str], text: str) -> None:
    lines.append(text)
    print(text, flush=True)


def run(
    args: list[str],
    cwd: Path = REPO,
    timeout: int = 300,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("RUST_TEST_THREADS", "2")
    env["CARGO_INCREMENTAL"] = "0"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rebuild_driver() -> None:
    result = run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(LANE / "Cargo.toml"),
            "--bin",
            "a2-resume-driver",
        ]
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr[-4000:] or result.stdout[-4000:])


def rebuild_guest() -> None:
    result = run([str(REPO / "examples/agent-host/build.sh")])
    if result.returncode != 0:
        raise SystemExit(result.stderr[-4000:] or result.stdout[-4000:])


def plant_text(path: Path, old: str, new: str) -> tuple[str, str]:
    original = path.read_text(encoding="utf-8")
    if original.count(old) != 1:
        raise SystemExit(f"plant text not unique in {path}: count={original.count(old)}")
    before = sha256_file(path)
    path.write_text(original.replace(old, new, 1), encoding="utf-8")
    return original, before


def restore_text(path: Path, original: str, before: str) -> None:
    path.write_text(original, encoding="utf-8")
    if sha256_file(path) != before:
        raise SystemExit(f"restore hash mismatch for {path}")


def parse_rows(output: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("ROW "):
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        found[parts[1]] = parts[2]
    return found


def fresh_store(name: str) -> Path:
    store = SCRATCH / name
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    return store


def run_driver(phase: str, store: Path) -> subprocess.CompletedProcess[str]:
    return run([str(DRIVER), phase, str(store)])


def record_result(lines: list[str], name: str, caught: bool, detail: str) -> None:
    verdict = "CAUGHT" if caught else "MISSED"
    log(lines, f"PLANT {name}: {verdict} — {detail}")


def record_hunt(lines: list[str], name: str, holds: bool, detail: str) -> None:
    verdict = "HOLD" if holds else "LEAK"
    log(lines, f"HUNT {name}: {verdict} — {detail}")


def source_has(path: Path, text: str) -> int:
    return path.read_text(encoding="utf-8").count(text)


def plant_absent_old_bypass(lines: list[str]) -> None:
    """#368 driver bypass strings must be gone."""
    checks = {
        "stale_write(&host, &plain, &revision)": DRIVER_SRC,
        "bridge_write(host, &next,": DRIVER_SRC,
        "handle_component_resource_request": DRIVER_SRC,
        "capability_manager.grant(\n            pending.session_id": DRIVER_SRC,
    }
    stale = source_has(DRIVER_SRC, "stale_write(&host, &plain, &revision)")
    bridge = source_has(DRIVER_SRC, "bridge_write(host, &next,")
    hook = source_has(DRIVER_SRC, "handle_component_resource_request(")
    # The driver still grants the guest's two pending journal asks. That is
    # Home's role. The #368 bypass was a minted token on the public hook.
    grant_pending = "pending.session_id" in DRIVER_SRC.read_text(encoding="utf-8")
    record_hunt(
        lines,
        "F-R2-OLD-DRIVER-BYPASS-ABSENT",
        stale == 0 and bridge == 0 and hook == 0,
        (
            f"stale_write={stale} bridge_write={bridge} "
            f"handle_component_resource_request={hook} "
            f"still_grants_pending={grant_pending} checks={list(checks)}"
        ),
    )


def plant_hardcoded_harness_pass(lines: list[str]) -> None:
    proof = a2.Proof()
    try:
        proof.row("WRITE", "PASS", "hardcoded harness plant")
        proof.row("STALE", "PASS", "hardcoded harness plant")
        proof.row("STOP", "PASS", "hardcoded harness plant")
        proof.row("START", "PASS", "hardcoded harness plant")
        proof.row("RESUME", "PASS", "hardcoded harness plant")
        proof.row("WRITE2", "PASS", "hardcoded harness plant")
        counted = all(proof.steps.get(name) == "PASS" for name in a2.JOURNEY)
        record_result(
            lines,
            "F-REV-HARDCODED-HARNESS-PASS",
            not counted,
            f"Proof.row accepted six hardcoded PASSes; A2_counted={counted}",
        )
    except SystemExit as error:
        record_result(lines, "F-REV-HARDCODED-HARNESS-PASS", True, str(error))


def plant_not_run_upgrade(lines: list[str]) -> None:
    proof = a2.Proof()
    proof.row("RESUME", "NOT RUN", "skipped")
    try:
        proof.row("RESUME", "PASS", "upgrade plant")
        record_result(lines, "F-REV-NOT-RUN-UPGRADE", False, "NOT RUN was upgraded to PASS")
    except SystemExit as error:
        record_result(lines, "F-REV-NOT-RUN-UPGRADE", True, str(error))


def plant_hardcoded_driver_pass(lines: list[str]) -> None:
    """Driver prints WRITE/STALE PASS and returns. Harness must not WRITE PASS."""
    old = (
        '    println!("PROCESS first pid={}", std::process::id());\n'
        "    let guest_sha = guest_sha256()?;"
    )
    new = (
        '    println!("PROCESS first pid={}", std::process::id());\n'
        '    row("WRITE", "PASS", "hardcoded plant");\n'
        '    row("STALE", "PASS", "hardcoded plant");\n'
        "    return Ok(());\n"
        "    let guest_sha = guest_sha256()?;"
    )
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("hardcoded-driver")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        if proof.steps.get("WRITE") == "PASS":
            a2.compute_stop(proof, first, store)
        journals = list((store / "runtime-data").rglob("journal")) if (store / "runtime-data").exists() else []
        write_believed = proof.steps.get("WRITE") == "PASS"
        record_result(
            lines,
            "F-REV-HARDCODED-DRIVER-PASS",
            not write_believed,
            (
                f"WRITE={proof.steps.get('WRITE')} STALE={proof.steps.get('STALE')} "
                f"STOP={proof.steps.get('STOP')} journals={len(journals)} "
                f"first_exit={first.returncode}"
            ),
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_skipped_stale(lines: list[str]) -> None:
    old = (
        "                probe_stale_write(&mut WasmBus, &cursor, grants.write.as_ref())\n"
        "                    .map_err(|reason| elastos::bus::types::BusError::Invalid(reason.to_string()))?;"
    )
    new = "                // skipped probe_stale_write plant"
    original, before = plant_text(GUEST_SRC, old, new)
    pin_original = GUEST_PIN.read_text(encoding="utf-8")
    pin_before = sha256_file(GUEST_PIN)
    try:
        rebuild_guest()
        GUEST_PIN.write_text(sha256_file(WASM) + "\n", encoding="utf-8")
        store = fresh_store("skip-stale")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        can_resume = proof.steps.get("WRITE") == "PASS" and proof.steps.get("STALE") == "PASS"
        record_result(
            lines,
            "F-REV-SKIPPED-STALE",
            proof.steps.get("STALE") == "NOT RUN" and not can_resume,
            f"WRITE={proof.steps.get('WRITE')} STALE={proof.steps.get('STALE')} can_resume={can_resume}",
        )
    finally:
        restore_text(GUEST_SRC, original, before)
        rebuild_guest()
        GUEST_PIN.write_text(pin_original, encoding="utf-8")
        if sha256_file(GUEST_PIN) != pin_before:
            raise SystemExit("guest.sha256 restore hash mismatch")


def plant_stop_nonzero(lines: list[str]) -> None:
    old = (
        "            if stale {\n"
        "                row(\n"
        '                    "STALE",\n'
        '                    "PASS",\n'
        "                    &format!(\n"
        '                        "guest stale if_revision refused with revision_conflict; stored sha256={sha}"\n'
        "                    ),\n"
        "                );\n"
        "            }"
    )
    new = old + '\n            bail!("planted crash after stale");'
    original, before = plant_text(DRIVER_SRC, old, new)
    try:
        rebuild_driver()
        store = fresh_store("stop-nonzero")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        a2.compute_stop(proof, first, store)
        record_result(
            lines,
            "F-REV-STOP-NONZERO",
            proof.steps.get("STOP") != "PASS" and first.returncode != 0,
            f"first_exit={first.returncode} STOP={proof.steps.get('STOP')} WRITE={proof.steps.get('WRITE')}",
        )
    finally:
        restore_text(DRIVER_SRC, original, before)
        rebuild_driver()


def plant_second_stale_write(lines: list[str]) -> None:
    old = "    let body = journal_write_body(&bytes, Some(&revision));"
    new = '    let body = journal_write_body(&bytes, Some("stale-not-current"));'
    original, before = plant_text(GUEST_SRC, old, new)
    pin_original = GUEST_PIN.read_text(encoding="utf-8")
    pin_before = sha256_file(GUEST_PIN)
    try:
        rebuild_guest()
        GUEST_PIN.write_text(sha256_file(WASM) + "\n", encoding="utf-8")
        store = fresh_store("second-stale")
        first = run_driver("first", store)
        second = run_driver("second", store)
        first_out = first.stdout + first.stderr
        second_out = second.stdout + second.stderr
        rows = parse_rows(first_out)
        rows.update(parse_rows(second_out))
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        a2.compute_stale(proof, first, store)
        a2.compute_stop(proof, first, store)
        a2.compute_start(proof, first, second, store)
        a2.compute_resume(proof, second, store)
        a2.compute_write2(proof, second)
        record_result(
            lines,
            "F-REV-SECOND-STALE-WRITE",
            proof.steps.get("WRITE2") == "FAIL" and proof.steps.get("RESUME") == "PASS",
            (
                f"driver WRITE2={rows.get('WRITE2')} RESUME={rows.get('RESUME')} "
                f"computed WRITE2={proof.steps.get('WRITE2')} RESUME={proof.steps.get('RESUME')}"
            ),
        )
    finally:
        restore_text(GUEST_SRC, original, before)
        rebuild_guest()
        GUEST_PIN.write_text(pin_original, encoding="utf-8")
        if sha256_file(GUEST_PIN) != pin_before:
            raise SystemExit("guest.sha256 restore hash mismatch")


def plant_older_journal(lines: list[str]) -> None:
    store_a = fresh_store("older-a")
    first_a = run_driver("first", store_a)
    if "ROW WRITE PASS" not in (first_a.stdout + first_a.stderr):
        record_result(lines, "F-REV-OLDER-JOURNAL", False, "first process did not WRITE PASS")
        return
    older = fresh_store("older-snap")
    shutil.rmtree(older)
    shutil.copytree(store_a, older)
    store_b = fresh_store("older-b")
    shutil.rmtree(store_b)
    shutil.copytree(store_a, store_b)
    second_b = run_driver("second", store_b)
    if "ROW WRITE2 PASS" not in (second_b.stdout + second_b.stderr):
        record_result(
            lines,
            "F-REV-OLDER-JOURNAL",
            False,
            f"could not create a newer journal; second exit={second_b.returncode}",
        )
        return
    newer_state = json.loads((store_b / "a2-resume-state.json").read_text(encoding="utf-8"))
    shutil.rmtree(store_b)
    shutil.copytree(older, store_b)
    (store_b / "a2-resume-state.json").write_text(
        json.dumps(
            {
                "revision": "forged-newer-revision",
                "sha256": "0" * 64,
                "bytes": 1,
                "first_pid": newer_state.get("first_pid"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    second = run_driver("second", store_b)
    rows = parse_rows(second.stdout + second.stderr)
    output = second.stdout + second.stderr
    record_result(
        lines,
        "F-REV-OLDER-JOURNAL",
        rows.get("RESUME") == "FAIL" or "DRIVER_ERROR" in output,
        f"RESUME={rows.get('RESUME')} WRITE2={rows.get('WRITE2')} exit={second.returncode}",
    )


def plant_store_wipe(lines: list[str]) -> None:
    store = fresh_store("wipe")
    first = run_driver("first", store)
    if "ROW WRITE PASS" not in (first.stdout + first.stderr):
        record_result(lines, "F-REV-STORE-WIPE", False, "first process did not WRITE PASS")
        return
    shutil.rmtree(store)
    store.mkdir(parents=True)
    second = run_driver("second", store)
    rows = parse_rows(second.stdout + second.stderr)
    output = second.stdout + second.stderr
    proof = a2.Proof()
    # START must not PASS on a wiped store.
    dummy_first = first
    a2.compute_start(proof, dummy_first, second, store)
    started = "PROCESS second" in output
    record_result(
        lines,
        "F-REV-STORE-WIPE",
        rows.get("RESUME") != "PASS"
        and rows.get("WRITE2") != "PASS"
        and proof.steps.get("START") != "PASS",
        (
            f"started={started} driver_RESUME={rows.get('RESUME')} "
            f"computed_START={proof.steps.get('START')} exit={second.returncode} "
            f"error={'DRIVER_ERROR' in output}"
        ),
    )


def plant_guest_hash(lines: list[str]) -> None:
    if not WASM.is_file():
        record_result(lines, "F-REV-GUEST-HASH", False, "guest wasm missing")
        return
    original = WASM.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    try:
        mutated = bytearray(original)
        mutated[-1] ^= 0xFF
        WASM.write_bytes(mutated)
        after = hashlib.sha256(mutated).hexdigest()
        store = fresh_store("guest-hash")
        first = run_driver("first", store)
        proof = a2.Proof()
        a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
        write_pass = proof.steps.get("WRITE") == "PASS"
        record_result(
            lines,
            "F-REV-GUEST-HASH",
            not write_pass and before != after,
            (
                f"before={before} after={after} WRITE={proof.steps.get('WRITE')} "
                f"exit={first.returncode}"
            ),
        )
    finally:
        WASM.write_bytes(original)
        if hashlib.sha256(WASM.read_bytes()).hexdigest() != before:
            raise SystemExit("guest wasm restore failed")


def hunt_lab_protection(lines: list[str]) -> None:
    tomls = list(REPO.rglob("Cargo.toml"))
    enablers = []
    for path in tomls:
        text = path.read_text(encoding="utf-8")
        if 'features = ["lab-protection"]' in text or "features = ['lab-protection']" in text:
            enablers.append(str(path.relative_to(REPO)))
    default_on = []
    server = REPO / "elastos/crates/elastos-server/Cargo.toml"
    server_text = server.read_text(encoding="utf-8")
    if "lab-protection" in server_text and "default = []" in server_text:
        default_empty = True
    else:
        default_empty = False
        default_on.append("elastos-server default is not empty")
    workspace = (REPO / "elastos/Cargo.toml").read_text(encoding="utf-8")
    lab_is_member = "a2-e2e-resume" in workspace
    ci_hits = []
    for path in list((REPO / ".github").rglob("*")) + list((REPO / "scripts").rglob("*")) + [
        REPO / "justfile"
    ]:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "all-features" in text or "all_features" in text:
            ci_hits.append(str(path.relative_to(REPO)))
        if "lab-protection" in text and path.suffix in {".yml", ".yaml", ".sh"}:
            ci_hits.append(f"{path.relative_to(REPO)}:lab-protection")
    record_hunt(
        lines,
        "F-R2-LAB-PROTECTION-UNIFICATION",
        enablers == ["lab/a2-e2e-resume/Cargo.toml"]
        and default_empty
        and not lab_is_member
        and not ci_hits,
        (
            f"enablers={enablers} default_empty={default_empty} "
            f"lab_workspace_member={lab_is_member} all_features_or_ci={ci_hits}"
        ),
    )


def hunt_release_artifacts(lines: list[str]) -> None:
    """Build default release rlib + elastos binary; grep phrase and helper."""
    result = run(
        ["cargo", "build", "-p", "elastos-server", "--release"],
        cwd=REPO / "elastos",
        timeout=3600,
    )
    if result.returncode != 0:
        record_hunt(
            lines,
            "F-R2-RELEASE-GREP",
            False,
            f"release build failed: {(result.stderr or result.stdout)[-1500:]}",
        )
        return
    target = REPO / "elastos/target/release"
    deps = target / "deps"
    rlibs = sorted(deps.glob("libelastos_server-*.rlib")) if deps.is_dir() else []
    binary = target / "elastos"
    scanned: list[Path] = list(rlibs)
    if binary.is_file():
        scanned.append(binary)
    phrase_hits = []
    helper_hits = []
    for path in scanned:
        data = path.read_bytes()
        if PHRASE.encode() in data:
            phrase_hits.append(str(path.relative_to(REPO)))
        if HELPER.encode() in data:
            helper_hits.append(str(path.relative_to(REPO)))
    # Probe crate without the feature must not see the helper.
    probe_dir = REVIEW / "probe"
    if probe_dir.exists():
        shutil.rmtree(probe_dir)
    probe_dir.mkdir()
    (probe_dir / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "a2-r2-probe"',
                'version = "0.0.0"',
                'edition = "2021"',
                "publish = false",
                "[dependencies]",
                'elastos-server = { path = "../../elastos/crates/elastos-server" }',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (probe_dir / "src").mkdir()
    (probe_dir / "src/lib.rs").write_text(
        "pub fn probe() { let _ = elastos_server::auth::store_test_principal_root_protection; }\n",
        encoding="utf-8",
    )
    probe = run(
        ["cargo", "check", "--manifest-path", str(probe_dir / "Cargo.toml")],
        timeout=3600,
    )
    probe_out = probe.stderr + probe.stdout
    hidden = probe.returncode != 0 and "E0425" in probe_out and HELPER in probe_out
    # Contrast: --all-features should compile the phrase into the rlib.
    featured = run(
        ["cargo", "build", "-p", "elastos-server", "--release", "--features", "lab-protection"],
        cwd=REPO / "elastos",
        timeout=3600,
    )
    featured_rlibs = sorted((REPO / "elastos/target/release/deps").glob("libelastos_server-*.rlib"))
    featured_phrase = any(PHRASE.encode() in path.read_bytes() for path in featured_rlibs)
    record_hunt(
        lines,
        "F-R2-RELEASE-GREP",
        not phrase_hits and hidden and featured.returncode == 0,
        (
            f"default_phrase_hits={phrase_hits} default_helper_hits={helper_hits} "
            f"probe_hidden={hidden} probe_exit={probe.returncode} "
            f"all_features_build={featured.returncode} "
            f"all_features_rlib_has_phrase={featured_phrase} "
            f"scanned={[str(p.relative_to(REPO)) for p in scanned]}"
        ),
    )


def hunt_process_isolation(lines: list[str]) -> None:
    store = fresh_store("two-proc")
    first = run_driver("first", store)
    first_out = first.stdout + first.stderr
    first_pid = a2.parse_pid(first_out, "first")
    alive_after_first = False
    if first_pid and first_pid.isdigit():
        alive_after_first = Path(f"/proc/{first_pid}").exists()
    second_env_leak = False
    second = run(
        [str(DRIVER), "second", str(store)],
        extra_env={
            "A2_REVIEW_MARKER": "should-not-be-required",
        },
    )
    second_out = second.stdout + second.stderr
    second_pid = a2.parse_pid(second_out, "second")
    same_pid = bool(first_pid) and first_pid == second_pid
    journals = a2.journal_files(store)
    record_hunt(
        lines,
        "F-R2-PROCESS-ISOLATION",
        first.returncode == 0
        and second.returncode == 0
        and not alive_after_first
        and not same_pid
        and bool(journals)
        and not second_env_leak,
        (
            f"first_pid={first_pid} second_pid={second_pid} first_exit={first.returncode} "
            f"second_exit={second.returncode} first_alive_after_wait={alive_after_first} "
            f"same_pid={same_pid} journals={len(journals)}"
        ),
    )


def hunt_driver_opens(lines: list[str]) -> None:
    """Trace the first process. The driver must not open the journal for write."""
    if shutil.which("strace") is None:
        record_hunt(lines, "F-R2-DRIVER-STRACE", False, "strace not installed")
        return
    store = fresh_store("strace")
    trace = REVIEW / "strace-first.log"
    if trace.exists():
        trace.unlink()
    traced = run(
        [
            "strace",
            "-f",
            "-e",
            "trace=openat,open,write",
            "-o",
            str(trace),
            str(DRIVER),
            "first",
            str(store),
        ],
        timeout=180,
    )
    text = trace.read_text(encoding="utf-8", errors="replace") if trace.is_file() else ""
    journal_writes = []
    token_writes = []
    for line in text.splitlines():
        lower = line.lower()
        if "journal" in lower and ("O_WRONLY" in line or "O_RDWR" in line):
            journal_writes.append(line)
        if "a2-resume-state.json" in line:
            continue
        if "token" in lower and ("O_WRONLY" in line or "O_RDWR" in line):
            token_writes.append(line)
    # Guest hostcall writes the journal through the Runtime. Those opens
    # belong to the same OS process. Count them, but require the driver
    # source itself has no write of the journal path.
    src = DRIVER_SRC.read_text(encoding="utf-8")
    driver_writes_journal = "write_principal_root_object" in src
    sidecar_only = "write_state" in src and "a2-resume-state.json" in src
    record_hunt(
        lines,
        "F-R2-DRIVER-STRACE",
        traced.returncode == 0 and sidecar_only and not token_writes and "write_principal_root_object" not in src,
        (
            f"exit={traced.returncode} journal_open_write_lines={len(journal_writes)} "
            f"token_writes={len(token_writes)} driver_writes_journal={driver_writes_journal} "
            f"sidecar_only={sidecar_only} sample={journal_writes[:3]}"
        ),
    )


def hunt_guest_bytes_loaded(lines: list[str]) -> None:
    """Pin must match the file Component::from_file loads (capsule entrypoint)."""
    capsule = json.loads((REPO / "examples/agent-host/capsule.json").read_text(encoding="utf-8"))
    entry = capsule.get("entrypoint")
    wasm = REPO / "examples/agent-host" / str(entry)
    pin = a2.pinned_guest_sha256()
    live = sha256_file(wasm) if wasm.is_file() else ""
    loader = (REPO / "elastos/crates/elastos-compute/src/providers/component.rs").read_text(
        encoding="utf-8"
    )
    loads_entrypoint = "path.join(&manifest.entrypoint)" in loader and "Component::from_file" in loader
    record_hunt(
        lines,
        "F-R2-GUEST-BYTES-LOADED",
        entry == "agent-host.component.wasm"
        and live == pin
        and loads_entrypoint
        and wasm.resolve() == WASM.resolve(),
        f"entrypoint={entry} live={live} pin={pin} loads_entrypoint={loads_entrypoint}",
    )


def hunt_stale_runtime_refusal(lines: list[str]) -> None:
    """STALE must be a hostcall conflict, not a guest-printed word."""
    store = fresh_store("stale-audit")
    first = run_driver("first", store)
    evidence = a2.parse_evidence(first.stdout + first.stderr)
    invokes = evidence.get("invokes", "")
    conflict = "write:conflict" in invokes.split(",")
    proof = a2.Proof()
    a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
    a2.compute_stale(proof, first, store)
    guest_src = GUEST_SRC.read_text(encoding="utf-8")
    probe_uses_hostcall = (
        'Some("stale-not-current")' in guest_src
        and "bus.invoke(&cursor.resource, \"write\"" in guest_src
        and 'code == "revision_conflict"' in guest_src
    )
    # A guest that only printed the word "conflict" would not create an
    # audited write:conflict. The audit is host-side.
    record_hunt(
        lines,
        "F-R2-STALE-RUNTIME-REFUSAL",
        conflict
        and proof.steps.get("STALE") == "PASS"
        and probe_uses_hostcall
        and "write:conflict" in invokes,
        (
            f"invokes={invokes} STALE={proof.steps.get('STALE')} "
            f"probe_uses_hostcall={probe_uses_hostcall}"
        ),
    )


def two_proc_baseline(lines: list[str]) -> None:
    store = fresh_store("baseline")
    first = run_driver("first", store)
    second = run_driver("second", store)
    first_out = first.stdout + first.stderr
    second_out = second.stdout + second.stderr
    log(lines, f"TWO-PROC first_exit={first.returncode} {a2.parse_pid(first_out, 'first')}")
    log(lines, f"TWO-PROC second_exit={second.returncode} {a2.parse_pid(second_out, 'second')}")
    log(lines, f"TWO-PROC first_rows={parse_rows(first_out)}")
    log(lines, f"TWO-PROC second_rows={parse_rows(second_out)}")
    proof = a2.Proof()
    a2.compute_write(proof, first, store, WASM, a2.pinned_guest_sha256())
    a2.compute_stale(proof, first, store)
    a2.compute_stop(proof, first, store)
    a2.compute_start(proof, first, second, store)
    a2.compute_resume(proof, second, store)
    a2.compute_write2(proof, second)
    log(lines, f"TWO-PROC computed={proof.steps}")
    log(lines, f"TWO-PROC details={proof.details}")


def main() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "A2 #351 r2 adversarial review experiments",
        f"REPO {REPO}",
        f"HEAD {run(['git', 'rev-parse', 'HEAD']).stdout.strip()}",
    ]
    if DRIVER.is_file():
        lines.append(f"DRIVER {sha256_file(DRIVER)}")
    if WASM.is_file():
        lines.append(f"GUEST {sha256_file(WASM)}")
    if GUEST_PIN.is_file():
        lines.append(f"PIN {GUEST_PIN.read_text(encoding='utf-8').strip()}")

    two_proc_baseline(lines)
    plant_absent_old_bypass(lines)
    plant_hardcoded_harness_pass(lines)
    plant_not_run_upgrade(lines)
    plant_hardcoded_driver_pass(lines)
    plant_skipped_stale(lines)
    plant_stop_nonzero(lines)
    plant_second_stale_write(lines)
    plant_older_journal(lines)
    plant_store_wipe(lines)
    plant_guest_hash(lines)
    hunt_lab_protection(lines)
    hunt_guest_bytes_loaded(lines)
    hunt_stale_runtime_refusal(lines)
    hunt_process_isolation(lines)
    hunt_driver_opens(lines)
    if os.environ.get("A2_SKIP_RELEASE") != "1":
        hunt_release_artifacts(lines)

    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WROTE {EVIDENCE}")
    missed = [line for line in lines if line.startswith("PLANT ") and ": MISSED" in line]
    leaks = [line for line in lines if line.startswith("HUNT ") and ": LEAK" in line]
    return 1 if missed or leaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
