//! M1 A8: the agent-host component asks the Runtime to read a fake host key,
//! and the Runtime refuses before any provider or operator decision.

use a1_a8_hardening::{build_component, component_imports, contains_bytes, repository, sha256};
use a1_a8_hardening::{runtime, Edit, Home, Operator, RUNTIME_ALLOWLIST};
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

const HOST_PATH_OLD: &str = "fn host_path(text: &str) -> bool {\n    text.starts_with('/') || text.contains('\\\\') || text.split('/').any(|part| part == \"..\")\n}";
const HOST_PATH_NEW: &str = "fn host_path(text: &str) -> bool {\n    let _ = text;\n    false\n}";
const JOURNAL_OLD: &str = "    Ok(format!(\"{JOURNAL_ROOT}{agent_id}/tasks/{task_id}/journal\"))";
const REQUEST_GUARD_OLD: &str = "fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {\n    if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {\n        return JournalGrants {\n            write: None,\n            read: None,\n        };\n    }\n";
const REQUEST_GUARD_NEW: &str = "fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {\n";
const SURFACE_OLD: &str = "        let grants = request_journal_grants(&mut WasmBus, &cursor);\n";
const SURFACE_NEW: &str = "        let grants = request_journal_grants(&mut WasmBus, &cursor);\n        {\n            use elastos::bus::capabilities;\n            use elastos::bus::types::CapabilityRequest;\n            capabilities::request(&CapabilityRequest {\n                resource: cursor.resource.clone(),\n                actions: vec![\"read\".into()],\n                reason: \"Agent Host task journal\".into(),\n            })?;\n        }\n";

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
            Edit {
                file: "src/lib.rs",
                old: SURFACE_OLD,
                new: SURFACE_NEW,
            },
        ],
    )
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
    let run = home.run(&capsule, BOUND);
    operator.stop();

    let refusal = format!(
        "Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for {resource}\")"
    );
    let marker = &FAKE[..FAKE.len() - 1];
    let marker_absent = home
        .captures()
        .iter()
        .all(|capture| !contains_bytes(capture, marker));
    let unchanged = fs::read(&key).unwrap() == FAKE;
    println!(
        "a8 host key read: exit:{:?} refusal_line:{:?} marker_absent:{marker_absent} unchanged:{unchanged}",
        run.status.and_then(|status| status.code()),
        run.line_with("Error:")
    );
    assert!(marker_absent, "the fake key marker reached a capture");
    assert!(unchanged, "the fake key bytes changed");
    assert!(
        run.status.is_some() && !run.exited_ok() && run.has_line(&refusal),
        "expected nonzero exit and the exact manifest-bound refusal; stderr:\n{}",
        run.stderr
    );
    assert_eq!(
        manifest, real_manifest,
        "the staged manifest must be the shipped agent-host manifest"
    );
    home.finish();
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
