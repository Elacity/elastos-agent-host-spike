//! M1 A8: the agent-host component asks the Runtime to read a fake host key,
//! and the Runtime refuses before any provider or operator decision.

use a1_a8_hardening::{
    assigned_component_id, build_component, component_imports, contains_bytes, repository, sha256,
};
use a1_a8_hardening::{runtime, CapabilityRequestRecord, Edit, Home, Operator, RUNTIME_ALLOWLIST};
use std::fs;
use std::time::Duration;

const AGENT_HOST: &str = "examples/agent-host";
const INPUTS: &[&str] = &["Cargo.toml", "Cargo.lock", "capsule.json", "src"];
const RESOURCE: &str = include_str!("../fixtures/host-key-read.txt");
const FAKE: &[u8] = include_bytes!("../fixtures/fake-ssh/id_ed25519");
const BOUND: Duration = Duration::from_secs(60);
const RUNTIME_REFUSAL_PREFIX: &[u8] = b"capsule manifest does not declare authority";
const EARLY_INJECTION_MARKER: &[u8] = b"agent-host read the host key";
const HOST_KEY_MARKER: &[u8] = b".ssh/id_ed25519";
const MANIFEST_DENIED: &str = "manifest_capability_denied";
const JOURNAL_FOLLOW: &str = "the journal append did not follow its grants";

const HOST_PATH_OLD: &str = "fn host_path(text: &str) -> bool {\n    text.starts_with('/') || text.contains('\\\\') || text.split('/').any(|part| part == \"..\")\n}";
const HOST_PATH_NEW: &str = "fn host_path(text: &str) -> bool {\n    if text == \"localhost://Public/../../../../.ssh/id_ed25519\" {\n        return false;\n    }\n    text.starts_with('/') || text.contains('\\\\') || text.split('/').any(|part| part == \"..\")\n}";
const JOURNAL_OLD: &str = "    Ok(format!(\"{JOURNAL_ROOT}{agent_id}/tasks/{task_id}/journal\"))";
const REQUEST_GUARD_OLD: &str = "fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {\n    if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {\n        return JournalGrants {\n            write: None,\n            read: None,\n        };\n    }\n";
const REQUEST_GUARD_NEW: &str = "fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {\n";

fn build_injected(resource: &str) -> a1_a8_hardening::Built {
    let journal_new =
        format!("    let _ = (agent_id, task_id);\n    Ok(\"{resource}\".to_string())");
    build_component(
        AGENT_HOST,
        INPUTS,
        "agent-host",
        "-Dwarnings",
        &[
            Edit {
                file: "src/lib.rs",
                old: HOST_PATH_OLD,
                new: HOST_PATH_NEW,
            },
            Edit {
                file: "src/lib.rs",
                old: JOURNAL_OLD,
                new: &journal_new,
            },
            Edit {
                file: "src/lib.rs",
                old: REQUEST_GUARD_OLD,
                new: REQUEST_GUARD_NEW,
            },
        ],
    )
}

fn denied_actions(
    records: &[CapabilityRequestRecord],
    resource: &str,
    assigned: Option<&str>,
) -> Vec<String> {
    records
        .iter()
        .filter(|record| {
            record.resource == resource
                && record.code == MANIFEST_DENIED
                && assigned
                    .map(|id| record.capsule_id.as_deref() == Some(id))
                    .unwrap_or(true)
        })
        .map(|record| record.action.clone())
        .collect()
}

fn this_run_component_id(run: &a1_a8_hardening::Run) -> Option<String> {
    assigned_component_id(&run.stdout).or_else(|| assigned_component_id(&run.stderr))
}

#[test]
fn agent_host_host_key_read_is_refused() {
    let resource = RESOURCE.trim();
    let shipped = build_component(AGENT_HOST, INPUTS, "agent-host", "-Dwarnings", &[]);
    let injected = build_injected(resource);
    let real_manifest = fs::read(repository().join("examples/agent-host/capsule.json")).unwrap();
    let shipped_imports = component_imports(&shipped.bytes);
    let injected_imports = component_imports(&injected.bytes);
    let guest_has_refusal = contains_bytes(&injected.bytes, RUNTIME_REFUSAL_PREFIX);
    let guest_has_early = contains_bytes(&injected.bytes, EARLY_INJECTION_MARKER);
    let guest_has_host_key = contains_bytes(&injected.bytes, HOST_KEY_MARKER);
    println!("a8 runtime: elastos sha256 {}", runtime().sha256);
    println!(
        "a8 shipped agent-host: sha256 {} imports {shipped_imports:?}",
        sha256(&shipped.bytes)
    );
    println!(
        "a8 injected agent-host: sha256 {} imports {injected_imports:?}",
        sha256(&injected.bytes)
    );
    println!(
        "a8 origin: guest_has_refusal_sentence:{guest_has_refusal} guest_has_early_injection:{guest_has_early} guest_has_host_key:{guest_has_host_key}"
    );
    assert_ne!(
        shipped.bytes, injected.bytes,
        "the injection must change the build"
    );
    assert_eq!(
        injected_imports, shipped_imports,
        "the injection must keep the shipped import list"
    );
    assert!(injected_imports
        .iter()
        .all(|name| RUNTIME_ALLOWLIST.contains(&name.as_str())));
    assert!(
        !contains_bytes(&shipped.bytes, HOST_KEY_MARKER),
        "the shipped guest must not name the fake host key"
    );
    assert!(
        guest_has_host_key,
        "the injected guest must name the fake host key"
    );
    assert!(
        !guest_has_refusal,
        "the guest bytes must not contain the Runtime refusal sentence"
    );
    assert!(
        !guest_has_early,
        "the injected guest must not be the early-return host-key injection"
    );
    assert!(
        HOST_PATH_NEW.contains("text.split('/').any(|part| part == \"..\")"),
        "the injection must keep the .. check for every other path"
    );
    assert_eq!(
        HOST_PATH_NEW.matches("return false").count(),
        1,
        "host_path may fail closed only for the fake key"
    );
    assert!(
        HOST_PATH_NEW.contains(&format!("if text == \"{resource}\"")),
        "host_path may fail closed only for the fake key path"
    );

    let home = Home::new();
    // Lexical check only: from a file-backed Public root under the data dir,
    // this many parent segments name <home>/.ssh/id_ed25519.
    let depth = home
        .data()
        .strip_prefix(home.home())
        .unwrap()
        .components()
        .count()
        + 1;
    assert_eq!(
        resource,
        format!("localhost://Public/{}.ssh/id_ed25519", "../".repeat(depth))
    );
    let key = home.seed(".ssh/id_ed25519", FAKE);
    let manifest = injected.manifest.clone();
    let capsule = home.stage("agent-host", &injected.bytes, &manifest);
    let operator = Operator::start(&home);
    home.assert_receipts_absent();
    let cursor = home.snapshot_receipts();
    println!(
        "a8 receipt cursor: size:{} inode:{:?} path:{}",
        cursor.size,
        cursor.inode,
        home.receipts_path().display()
    );
    let run = home.run_until(&capsule, BOUND, |home| {
        home.capability_requests_since(&cursor)
            .iter()
            .any(|record| record.resource == resource && record.code != MANIFEST_DENIED)
    });
    let records = home.capability_requests_since(&cursor);
    operator.stop();

    let marker = &FAKE[..FAKE.len() - 1];
    let marker_absent = home
        .captures()
        .iter()
        .all(|capture| !contains_bytes(capture, marker));
    let unchanged = fs::read(&key).unwrap() == FAKE;
    let assigned = this_run_component_id(&run);
    let guest_hash = sha256(&injected.bytes);
    let actions = denied_actions(&records, resource, assigned.as_deref());
    let exit = match run.status {
        None => "timeout".to_string(),
        Some(status) => match status.code() {
            Some(code) => format!("Some({code})"),
            None => "signaled".to_string(),
        },
    };
    println!(
        "a8 host key read: exit:{exit} assigned:{assigned:?} guest_hash:{guest_hash} host_records:{records:?} marker_absent:{marker_absent} unchanged:{unchanged}"
    );
    assert!(marker_absent, "the fake key marker reached a capture");
    assert!(unchanged, "the fake key bytes changed");
    assert!(
        run.status.is_some(),
        "the client hit the {BOUND:?} bound with no status (timeout is not a catch); stderr:\n{}",
        run.stderr
    );
    assert!(
        !run.exited_ok(),
        "the guest must not exit 0 after the host-key ask; stderr:\n{}",
        run.stderr
    );
    if let Some(id) = assigned.as_deref() {
        assert!(
            records
                .iter()
                .all(|record| record.capsule_id.as_deref() == Some(id)),
            "receipt capsule_id must match this launch {id}; host records: {records:?}"
        );
    }
    assert_eq!(
        actions,
        ["write".to_string(), "read".to_string()],
        "Runtime must record manifest_capability_denied for write and read on {resource} (request_journal_grants called the bus); host records: {records:?}"
    );
    assert!(
        run.stderr.contains(JOURNAL_FOLLOW),
        "honest sequence requires request_journal_grants, then write refused, then read refused; stderr:\n{}",
        run.stderr
    );
    assert!(
        records
            .iter()
            .all(|record| record.resource == resource || record.code != MANIFEST_DENIED),
        "the injection must fail only the fake key; host records: {records:?}"
    );
    assert_eq!(
        manifest, real_manifest,
        "the staged manifest must be the shipped agent-host manifest"
    );
    let mut missing = Vec::new();
    if assigned.is_none() {
        missing.push("component id from Runtime [run] output or API");
    }
    if records.iter().any(|record| record.session_id.is_none()) {
        missing.push("session id");
    }
    if records
        .iter()
        .any(|record| record.module_hash.as_deref() != Some(guest_hash.as_str()))
    {
        missing.push("guest module hash");
    }
    if missing.is_empty() {
        println!("a8 authorship: bound to this launch");
    } else {
        println!(
            "a8 authorship: needs runtime: capability-requests.jsonl omits {}",
            missing.join(", ")
        );
    }
    home.finish();
}

#[test]
#[ignore = "needs runtime: WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible"]
fn shipped_wasm_bus_prints_internal_sentence() {
    panic!(
        "needs runtime: request_journal_grants uses WasmBus, which maps BusError::Internal to \
         BusFailure::Other; the guest then fails closed as Invalid(\"the journal append did not \
         follow its grants\"). The Runtime authorship proof is the host-side \
         manifest_capability_denied record, not this sentence"
    );
}

#[test]
#[ignore = "blocked: AC-002-ARGS; the shipped agent-host names only its own journal"]
fn shipped_agent_host_bytes_read_host_key() {
    panic!(
        "blocked: elastos:bus@v1 has no launch-argument channel (AC-002-ARGS), and the shipped \
         agent-host asks only for localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal \
         and refuses '..' itself, so its unmodified bytes cannot ask for a host key"
    );
}
