//! M1 A8: the agent-host component asks the Runtime to read a fake host key,
//! and the Runtime refuses before any provider or operator decision.

use a1_a8_hardening::{build_component, component_imports, repository, sha256, Edit};
use a1_a8_hardening::{runtime, Home, Operator, RUNTIME_ALLOWLIST};
use std::fs;
use std::time::Duration;

const AGENT_HOST: &str = "examples/agent-host";
const INPUTS: &[&str] = &["Cargo.toml", "Cargo.lock", "capsule.json", "src"];
const RESOURCE: &str = include_str!("../fixtures/host-key-read.txt");
const FAKE: &[u8] = include_bytes!("../fixtures/fake-ssh/id_ed25519");
const ANCHOR: &str = "        let _identity = elastos::bus::identity::context();\n";
const INJECTION: &str = include_str!("../fixtures/agent-host-injection.txt");
const BOUND: Duration = Duration::from_secs(60);

#[test]
fn agent_host_host_key_read_is_refused() {
    let resource = RESOURCE.trim();
    let shipped = build_component(AGENT_HOST, INPUTS, "agent-host", "-Dwarnings", &[]);
    let injected_source = format!("{ANCHOR}{}", INJECTION.replace("@RESOURCE@", resource));
    let injected = build_component(
        AGENT_HOST,
        INPUTS,
        "agent-host",
        "-Dwarnings",
        &[Edit {
            file: "src/lib.rs",
            old: ANCHOR,
            new: &injected_source,
        }],
    );
    let real_manifest = fs::read(repository().join("examples/agent-host/capsule.json")).unwrap();
    let shipped_imports = component_imports(&shipped.bytes);
    let injected_imports = component_imports(&injected.bytes);
    println!("a8 runtime: elastos sha256 {}", runtime().sha256);
    println!(
        "a8 shipped agent-host: sha256 {} imports {shipped_imports:?}",
        sha256(&shipped.bytes)
    );
    println!(
        "a8 injected agent-host: sha256 {} imports {injected_imports:?}",
        sha256(&injected.bytes)
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
        .all(|capture| !capture.windows(marker.len()).any(|part| part == marker));
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
