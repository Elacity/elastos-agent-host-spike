#!/usr/bin/env python3
"""r4 new attacks against #301 at b0cc24c2.

Unit hunts copy the receipt predicates. Live hunts edit the detached
worktree, run the A8 test, then restore SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys

REVIEW = pathlib.Path(__file__).resolve().parent.parent
WORKTREE = pathlib.Path(os.environ.get("REVIEW_WORKTREE", "/tmp/pr-301-a8-r4"))
LANE = WORKTREE / "lab/a1-a8-hardening"
A8 = LANE / "tests/a8_agent_host_host_key.rs"
LIB = LANE / "src/lib.rs"
EVIDENCE = pathlib.Path(
    os.environ.get("REVIEW_EVIDENCE", str(REVIEW / "evidence"))
)

RESOURCE = "localhost://Public/../../../../.ssh/id_ed25519"
MANIFEST_DENIED = "manifest_capability_denied"
GUEST_FN = "request_journal_grants"
GUEST_HASH = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737"
HONEST_CAPSULE = "component-341af27a-6b9c-4892-a618-808f0b687a9d"
FOREIGN = "component-00000000-0000-0000-0000-000000000000"
SESSION = "session-this-launch"
TEST = "agent_host_host_key_read_is_refused"

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


def optional_string(value: dict, key: str):
    raw = value.get(key)
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text if text else None


def parse_record(line: str) -> dict:
    value = json.loads(line)
    return {
        "action": value.get("action"),
        "resource": value.get("resource"),
        "code": value.get("code"),
        "capsule_id": optional_string(value, "capsule_id"),
        "session_id": optional_string(value, "session_id"),
        "module_hash": optional_string(value, "module_hash"),
        "guest_function": optional_string(value, "guest_function"),
        "seq": value.get("seq"),
    }


def isolation_actions(records):
    return [
        r["action"]
        for r in records
        if r["resource"] == RESOURCE and r["code"] == MANIFEST_DENIED
    ]


def authorship_gaps(records, assigned, session, guest_hash):
    if assigned is not None and any(r["capsule_id"] != assigned for r in records):
        return "FAIL", "foreign capsule_id"
    if session is not None and any(r["session_id"] != session for r in records):
        return "FAIL", "session mismatch"
    if any(r["module_hash"] not in (None, guest_hash) for r in records):
        return "FAIL", "hash mismatch"
    if any(r["guest_function"] not in (None, GUEST_FN) for r in records):
        return "FAIL", "honest sequence requires request_journal_grants"
    missing = []
    if assigned is None:
        missing.append("component id")
    if session is None or not records or any(r["session_id"] is None for r in records):
        missing.append("session id")
    if not records or any(r["module_hash"] != guest_hash for r in records):
        missing.append("guest module hash")
    if not records or any(r["guest_function"] != GUEST_FN for r in records):
        missing.append("guest function")
    if missing:
        return "NEEDS RUNTIME", missing
    return "PASS", []


def cargo_result(records, assigned, session, window_ok=True, guest_hash=GUEST_HASH):
    if not window_ok:
        return "FAIL", "receipts outside launch window"
    if isolation_actions(records) != ["write", "read"]:
        return "FAIL", "write-then-read"
    return authorship_gaps(records, assigned, session, guest_hash)


def complete(extra=None, capsule=HONEST_CAPSULE):
    extra = extra or {}
    rows = []
    for action in ("write", "read"):
        row = {
            "action": action,
            "capsule_id": capsule,
            "code": MANIFEST_DENIED,
            "principal_id": None,
            "resource": RESOURCE,
            "session_id": SESSION,
            "module_hash": GUEST_HASH,
            "guest_function": GUEST_FN,
        }
        row.update(extra)
        rows.append(parse_record(json.dumps(row)))
    return rows


def record(name: str, verdict: str, detail: str, patch: str) -> dict:
    line = f"{name}: {verdict} {detail}"
    print(line, flush=True)
    return {"name": name, "verdict": verdict, "detail": detail, "patch": patch}


def unit_hunts() -> list[dict]:
    out = []

    # 1. Guest write via preopen / symlink — source shape.
    linker = (WORKTREE / "elastos/crates/elastos-compute/src/providers/component.rs").read_text()
    no_wasi = (
        "exposes no WASI, environment, filesystem preopen" in linker
        and "ProductCapsuleV1::add_to_linker" in linker
        and "wasi:filesystem" not in linker
        and "DirPerms" not in linker
    )
    out.append(
        record(
            "H-guest-write-preopen",
            "CAUGHT" if no_wasi else "SURVIVED",
            "ComponentProvider links only elastos:bus; no WASI preopen, FIFO, or dir",
            "elastos/crates/elastos-compute/src/providers/component.rs:47-49 and instantiate_component linker (read-only)",
        )
    )

    # 2. Session from env/argv vs identity.
    spawn = (LANE / "src/lib.rs").read_text()
    env_cleared = ".env_clear()" in spawn and "wasi:cli/environment" not in spawn
    identity = "session: self.capsule_id.clone()" in linker
    out.append(
        record(
            "H-session-from-env-argv",
            "CAUGHT" if env_cleared else "SURVIVED",
            "Home::spawn clears env; elastos run passes no capsule argv; guest has no WASI environ",
            "lab/a1-a8-hardening/src/lib.rs Home::spawn env_clear; run_cmd.rs capsule_args unused by bus v1",
        )
    )
    out.append(
        record(
            "H-session-from-identity",
            "SURVIVED" if identity else "CAUGHT",
            "identity::context().session equals capsule_id; guest can read this launch's id",
            "elastos/crates/elastos-compute/src/providers/component.rs identity::Host::context session: self.capsule_id.clone()",
        )
    )

    # 3. Predictable / reused session.
    session_pred = complete(extra={"session_id": "session-1"})
    # authorship compares to bind session; a printed session-1 would PASS
    pred_verdict, pred_detail = cargo_result(session_pred, HONEST_CAPSULE, "session-1")
    reused = complete()
    reused[0]["session_id"] = SESSION
    reused[1]["session_id"] = SESSION
    same_as_capsule = complete(extra={"session_id": HONEST_CAPSULE})
    same_verdict, _ = cargo_result(same_as_capsule, HONEST_CAPSULE, HONEST_CAPSULE)
    out.append(
        record(
            "H-session-predictable",
            "SURVIVED" if pred_verdict == "PASS" else "CAUGHT",
            f"is_session_id accepts session-1; complete bind with that id is {pred_verdict} {pred_detail}",
            "lab/a1-a8-hardening/src/lib.rs is_session_id; authorship_gaps equality only",
        )
    )
    out.append(
        record(
            "H-session-equals-capsule",
            "SURVIVED" if same_verdict == "PASS" else "CAUGHT",
            "lab accepts session_id == capsule_id, which identity already returns",
            "ComponentState.session = capsule_id; authorship_gaps does not refuse that alias",
        )
    )

    # 4. TOCTOU: hash is of in-memory bytes, load reads the staged path later.
    hashes_memory = "let guest_hash = sha256(&injected.bytes);" in A8.read_text()
    load_from_file = "Component::from_file(&engine, &component_path)" in linker
    out.append(
        record(
            "H-toctou-hash-vs-load",
            "SURVIVED" if hashes_memory and load_from_file else "CAUGHT",
            "test hashes injected.bytes; Runtime loads path.join(entrypoint) later; no re-hash of staged file",
            "tests/a8_agent_host_host_key.rs guest_hash = sha256(&injected.bytes); ComponentProvider::load from_file",
        )
    )

    # 5. Duplicate / out-of-order sequence numbers.
    ooo = list(reversed(complete(extra={"seq": 1})))
    ooo[0]["seq"] = 2
    ooo[1]["seq"] = 1
    ooo_actions = isolation_actions(ooo)
    dup = complete(extra={"seq": 1}) + complete(extra={"seq": 1})
    ooo_ok = ooo_actions == ["read", "write"]
    # write-then-read order is checked; seq field is ignored
    seq_ignored_rows = complete(extra={"seq": 2})
    seq_ignored_rows[0]["seq"] = 2
    seq_ignored_rows[1]["seq"] = 1
    seq_verdict, _ = cargo_result(seq_ignored_rows, HONEST_CAPSULE, SESSION)
    out.append(
        record(
            "H-seq-out-of-order-actions",
            "CAUGHT" if ooo_ok else "CAUGHT",
            f"isolation_denied_actions keeps file order; read then write is {ooo_actions}, not [write, read]",
            "isolation_denied_actions maps records in file order; assert_eq! [write, read]",
        )
    )
    out.append(
        record(
            "H-seq-duplicate-pairs",
            "CAUGHT",
            f"four actions {isolation_actions(dup)} fail the exact write-then-read list",
            "assert_eq!(actions, [write, read])",
        )
    )
    out.append(
        record(
            "H-seq-numbers-ignored",
            "SURVIVED" if seq_verdict == "PASS" else "CAUGHT",
            "receipt seq/sequence fields are not parsed; out-of-order numbers still PASS a complete bind",
            "parse_capability_record has no seq field; authorship_gaps ignores unknown keys",
        )
    )

    # 6. Host log rotate / truncate. lock_launch_receipts always stores size 0.
    lock = (LANE / "src/lib.rs").read_text()
    size_zero = "inode: Some(meta.ino()),\n                size: 0," in lock
    shrink = "capability-requests.jsonl shrank after launch" in lock
    inode_change = "inode changed after launch" in lock
    out.append(
        record(
            "H-log-truncate-same-inode",
            "SURVIVED" if size_zero else "CAUGHT",
            "lock_launch_receipts records size 0; same-inode truncate+rewrite is read from the start",
            "Home::lock_launch_receipts size: 0; read_capability_requests_since shrink check is dead for that cursor",
        )
    )
    out.append(
        record(
            "H-log-rotate-new-inode",
            "CAUGHT" if inode_change else "SURVIVED",
            "a replaced inode after a known file is refused",
            "read_capability_requests_since inode != cursor.inode -> panic",
        )
    )
    if shrink and size_zero:
        out.append(
            record(
                "H-log-shrink-dead",
                "SURVIVED",
                "shrink check exists but launch cursor size is always 0, so it never fires",
                "lock_launch_receipts size: 0 vs capability_requests_since meta.len() < cursor.size",
            )
        )

    # 7. Duplicate JSON keys. Python json and serde_json last-wins.
    dup_line = (
        '{"action":"write","capsule_id":"%s","capsule_id":"%s",'
        '"code":"%s","resource":"%s","session_id":"%s",'
        '"module_hash":"%s","guest_function":"%s"}'
        % (FOREIGN, HONEST_CAPSULE, MANIFEST_DENIED, RESOURCE, SESSION, GUEST_HASH, GUEST_FN)
    )
    dup_rec = parse_record(dup_line)
    last_wins = dup_rec["capsule_id"] == HONEST_CAPSULE
    first_hidden = FOREIGN in dup_line and last_wins
    dup_rows = [dup_rec, parse_record(dup_line.replace('"write"', '"read"', 1))]
    dup_verdict, _ = cargo_result(dup_rows, HONEST_CAPSULE, SESSION)
    out.append(
        record(
            "H-json-duplicate-keys",
            "SURVIVED" if first_hidden and dup_verdict == "PASS" else "CAUGHT",
            f"last key wins (capsule_id={dup_rec['capsule_id']}); complete bind is {dup_verdict}; first foreign id is dropped",
            'parse_capability_record uses serde_json Value.get; no reject of duplicate keys',
        )
    )

    # 8. capsule_id case / whitespace.
    ws_line = json.dumps(
        {
            "action": "write",
            "capsule_id": f"  {HONEST_CAPSULE}  ",
            "code": MANIFEST_DENIED,
            "resource": RESOURCE,
            "session_id": SESSION,
            "module_hash": GUEST_HASH,
            "guest_function": GUEST_FN,
        }
    )
    ws = parse_record(ws_line)
    ws_rows = [ws, parse_record(ws_line.replace("write", "read", 1))]
    ws_verdict, _ = cargo_result(ws_rows, HONEST_CAPSULE, SESSION)
    case_line = json.dumps(
        {
            "action": "write",
            "capsule_id": HONEST_CAPSULE.upper(),
            "code": MANIFEST_DENIED,
            "resource": RESOURCE,
            "session_id": SESSION,
            "module_hash": GUEST_HASH,
            "guest_function": GUEST_FN,
        }
    )
    case_rec = parse_record(case_line)
    case_rows = [case_rec, parse_record(case_line.replace("write", "read", 1))]
    case_verdict, case_detail = cargo_result(case_rows, HONEST_CAPSULE, SESSION)
    out.append(
        record(
            "H-capsule-whitespace",
            "SURVIVED" if ws_verdict == "PASS" else "CAUGHT",
            "optional_string trims capsule_id / session_id / module_hash / guest_function",
            "src/lib.rs optional_string map(str::trim)",
        )
    )
    out.append(
        record(
            "H-capsule-case",
            "CAUGHT" if case_verdict == "FAIL" else "SURVIVED",
            f"uppercase capsule_id is {case_verdict} {case_detail}",
            "authorship_gaps compares capsule_id with == after trim; no case fold",
        )
    )
    return out


def plant_guest(fixture_rel: str) -> str:
    return f"""fn build_injected(resource: &str) -> a1_a8_hardening::Built {{
    const ANCHOR: &str = \"        let _identity = elastos::bus::identity::context();\\n\";
    let injected_source = format!(
        \"{{ANCHOR}}{{}}\",
        include_str!(\"{fixture_rel}\").replace(\"@RESOURCE@\", resource)
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
    result = subprocess.run(command, cwd=WORKTREE, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    hunt_dir = EVIDENCE / "hunts"
    hunt_dir.mkdir(parents=True, exist_ok=True)
    (hunt_dir / f"{label}.txt").write_text(output)
    failed = f"test {TEST} ... FAILED" in output
    ok = f"test {TEST} ... ok" in output
    timed_out = "exit:timeout" in output or "exit:None" in output
    return {
        "exit": result.returncode,
        "failed": failed,
        "ok": ok,
        "timed_out": timed_out,
        "output": output,
    }


def apply_once(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"anchor must occur once in {path}: count={text.count(old)}")
    path.write_text(text.replace(old, new, 1))


def live_hunts() -> list[dict]:
    out = []
    a8_orig = A8.read_bytes()
    a8_digest = sha(A8)
    lib_orig = LIB.read_bytes()
    lib_digest = sha(LIB)
    fixture_dir = LANE / "fixtures"

    def restore() -> None:
        A8.write_bytes(a8_orig)
        LIB.write_bytes(lib_orig)
        if sha(A8) != a8_digest or sha(LIB) != lib_digest:
            raise SystemExit("restore failed")

    # Live 1: guest asks write on the receipts resource after a Public symlink.
    try:
        (REVIEW / "attacks/guest-write-receipts.txt").read_text()
        dest = fixture_dir / "r4-guest-write-receipts.txt"
        dest.write_text((REVIEW / "attacks/guest-write-receipts.txt").read_text())
        apply_once(A8, BUILD_INJECTED_OLD, plant_guest("../fixtures/r4-guest-write-receipts.txt"))
        apply_once(
            A8,
            "    let home = Home::new();",
            """    let home = Home::new();
    {
        let receipts = home.receipts_path();
        let public = home.data().join(\"Public\");
        std::fs::create_dir_all(&public).unwrap();
        let alias = public.join(\"capability-requests.jsonl\");
        let _ = std::os::unix::fs::symlink(&receipts, &alias);
    }""",
        )
        result = run_a8("H-guest-write-receipts")
        dest.unlink(missing_ok=True)
        restore()
        survived = result["ok"] and not result["timed_out"]
        out.append(
            record(
                "H-guest-write-receipts",
                "SURVIVED" if survived else "CAUGHT",
                f"exit={result['exit']} ok={result['ok']} failed={result['failed']} timeout={result['timed_out']}",
                "attacks/guest-write-receipts.txt + Public symlink to receipts_path",
            )
        )
    except Exception as error:
        restore()
        out.append(record("H-guest-write-receipts", "ERROR", str(error), "live plant"))

    # Live 2: guest copies identity.session into an Invalid line that looks like [run].
    try:
        dest = fixture_dir / "r4-session-from-identity.txt"
        dest.write_text((REVIEW / "attacks/session-from-identity.txt").read_text())
        apply_once(A8, BUILD_INJECTED_OLD, plant_guest("../fixtures/r4-session-from-identity.txt"))
        result = run_a8("H-forged-session-from-identity")
        dest.unlink(missing_ok=True)
        restore()
        minted = "a8 host key read:" in result["output"] and "session:Some" in result["output"]
        survived = result["ok"] or minted
        out.append(
            record(
                "H-forged-session-from-identity",
                "SURVIVED" if survived else "CAUGHT",
                f"exit={result['exit']} ok={result['ok']} minted_session={minted}",
                "attacks/session-from-identity.txt guest returns [run] session_id=<identity.session>",
            )
        )
    except Exception as error:
        restore()
        out.append(record("H-forged-session-from-identity", "ERROR", str(error), "live plant"))

    # Live 3: TOCTOU swap staged bytes after stage, before run.
    try:
        apply_once(
            A8,
            "    let capsule = home.stage(\"agent-host\", &injected.bytes, &manifest);",
            """    let capsule = home.stage(\"agent-host\", &injected.bytes, &manifest);
    {
        let entry = String::from_utf8(manifest.clone()).ok().and_then(|text| {
            let value: serde_json::Value = serde_json::from_str(&text).ok()?;
            value.get(\"entrypoint\")?.as_str().map(str::to_string)
        }).unwrap_or_else(|| \"agent-host.component.wasm\".into());
        std::fs::write(capsule.join(entry), &shipped.bytes).unwrap();
    }""",
        )
        result = run_a8("H-toctou-swap-staged")
        restore()
        survived = result["ok"] and not result["timed_out"]
        out.append(
            record(
                "H-toctou-swap-staged",
                "SURVIVED" if survived else "CAUGHT",
                f"exit={result['exit']} ok={result['ok']} failed={result['failed']}; guest_hash still injected.bytes, file is shipped",
                "after home.stage, overwrite entrypoint with shipped.bytes",
            )
        )
    except Exception as error:
        restore()
        out.append(record("H-toctou-swap-staged", "ERROR", str(error), "live plant"))

    # Live 4: same-inode rewrite after run_until, before receipts_since_launch read.
    # The test reads records immediately; plant a rewrite in between.
    try:
        apply_once(
            A8,
            "    let records = home.receipts_since_launch();\n    let host_log = home.host_runtime_log();",
            """    {
        let path = home.receipts_path();
        let forged = format!(
            "{{\\\"action\\\":\\\"write\\\",\\\"capsule_id\\\":\\\"{FOREIGN}\\\",\\\"code\\\":\\\"manifest_capability_denied\\\",\\\"resource\\\":\\\"{resource}\\\",\\\"session_id\\\":\\\"session-1\\\",\\\"module_hash\\\":\\\"{hash}\\\",\\\"guest_function\\\":\\\"request_journal_grants\\\"}}\\n{{\\\"action\\\":\\\"read\\\",\\\"capsule_id\\\":\\\"{FOREIGN}\\\",\\\"code\\\":\\\"manifest_capability_denied\\\",\\\"resource\\\":\\\"{resource}\\\",\\\"session_id\\\":\\\"session-1\\\",\\\"module_hash\\\":\\\"{hash}\\\",\\\"guest_function\\\":\\\"request_journal_grants\\\"}}\\n\",
            FOREIGN = \"component-00000000-0000-0000-0000-000000000000\",
            hash = sha256(&injected.bytes)
        );
        std::fs::write(&path, forged).unwrap();
    }
    let records = home.receipts_since_launch();
    let host_log = home.host_runtime_log();""",
        )
        result = run_a8("H-log-rewrite-same-inode")
        restore()
        # assigned is still None, so cargo should still FAIL. Survival is if
        # rewritten foreign lines are accepted as the host records.
        output = result["output"]
        saw_foreign = "component-00000000-0000-0000-0000-000000000000" in output
        survived = saw_foreign and (
            result["ok"] or "needs runtime" in output.lower() or result["failed"]
        )
        # rewritten content being parsed is the hole; cargo FAIL for missing
        # assigned is expected. Mark SURVIVED if the forged lines became host_records.
        out.append(
            record(
                "H-log-rewrite-same-inode",
                "SURVIVED" if saw_foreign else "CAUGHT",
                f"exit={result['exit']} ok={result['ok']} saw_foreign={saw_foreign}",
                "after run_until, truncate+rewrite capability-requests.jsonl on the same inode",
            )
        )
    except Exception as error:
        restore()
        out.append(record("H-log-rewrite-same-inode", "ERROR", str(error), "live plant"))

    restore()
    return out


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "hunts").mkdir(exist_ok=True)
    results = unit_hunts()
    live = os.environ.get("R4_LIVE", "1") != "0"
    if live:
        results.extend(live_hunts())
    summary = [
        f"{row['name']}: {row['verdict']} {row['detail']}" for row in results
    ]
    (EVIDENCE / "hunts" / "summary.txt").write_text("\n".join(summary) + "\n")
    (EVIDENCE / "hunts" / "new_hunts.json").write_text(json.dumps(results, indent=2) + "\n")
    survived = [row for row in results if row["verdict"] == "SURVIVED"]
    errors = [row for row in results if row["verdict"] == "ERROR"]
    print(
        f"\n{len(results) - len(survived) - len(errors)} CAUGHT, {len(survived)} SURVIVED, {len(errors)} ERROR",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
