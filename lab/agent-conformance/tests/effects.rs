mod common;
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::runtime_under_test;
use probe::{build_probe, Effect};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// The repository build script writes one probe entrypoint. Keep builds and
// native build preparation sequential even with RUST_TEST_THREADS=2.
static EFFECT_RUN: Mutex<()> = Mutex::new(());

fn assert_refusal(effect: Effect, bus_error: &str) {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    let home = ThrowawayHome::new().unwrap();
    home.guard(home.home(), home.data()).unwrap();
    // The hash identifies these exact bytes; the directory only locates them.
    // Bundle-CID admission remains a separate grade point.
    let capsule = home.root().join(format!("sha256-{hash}"));
    fs::create_dir(&capsule).unwrap();
    fs::write(
        capsule.join("capsule.json"),
        include_bytes!("../probe/capsule.json"),
    )
    .unwrap();
    fs::write(
        capsule.join("agent-conformance-probe.component.wasm"),
        bytes,
    )
    .unwrap();
    println!("probe component sha256:{hash} effect:{}", effect.name());

    let mut operator = common::operator::Operator::start(&home).expect("start fixture operator");
    operator.ready().expect("operator readiness");
    let first = operator.census().expect("ready operator socket census");
    let sampled = Instant::now();
    let output = home
        .launch(
            &runtime.binary,
            &["run", capsule.to_str().unwrap()],
            Duration::from_secs(10),
        )
        .expect("bounded probe launch through the existing primitive");
    while sampled.elapsed() < Duration::from_secs(3) {
        operator.require_alive().expect("operator stays alive");
        std::thread::sleep(Duration::from_millis(50));
    }
    let second = operator.census().expect("final operator socket census");
    operator.child.stop().expect("stop operator and its group");
    drop(operator);
    println!(
        "operator census: {first} then {second} loopback sockets for {}; group stopped",
        effect.name()
    );

    // Report only the expected public refusal and booleans, never raw Runtime
    // output or operator attach data. Both checks observe the guest lifecycle.
    let stderr = std::str::from_utf8(&output.stderr).expect("Runtime stderr is UTF-8");
    let reason_present = stderr.contains("Component capsule failed:")
        && stderr.contains(&format!("Component capsule denied: BusError::{bus_error}"));
    println!(
        "probe refusal effect:{} exit:{:?} reason_present:{reason_present}",
        effect.name(),
        output.status.code()
    );
    assert!(
        !output.status.success() && reason_present,
        "expected nonzero exit and lifecycle refusal {bus_error}; exit:{:?} reason_present:{reason_present}",
        output.status.code()
    );
    home.finish().unwrap();
}

#[test]
fn ungranted_effect_is_refused() {
    let resource = include_str!("../fixtures/ungranted-read.txt").trim();
    assert_refusal(
        Effect::Read,
        &format!("Internal(\"capsule manifest does not declare authority for {resource}\")"),
    );
}

#[test]
fn ungranted_network_is_refused() {
    let resource = include_str!("../fixtures/ungranted-network.txt").trim();
    assert_refusal(
        Effect::Network,
        &format!("Internal(\"capsule manifest does not declare authority for {resource}\")"),
    );
}

#[test]
fn default_activation_refuses_without_selector() {
    assert_refusal(
        Effect::Default,
        "Unavailable(\"probe launch arguments are unavailable in elastos:bus@v1\")",
    );
}

#[test]
#[ignore = "blocked: RT3"]
fn ungranted_model_call_is_refused() {
    panic!("blocked: RT3 — Runtime model-call grant acceptance is required");
}

#[test]
#[ignore = "blocked: AC-006-STORAGE"]
fn operator_storage_is_under_throwaway_home() {
    panic!("blocked: AC-006-STORAGE — Runtime must derive run storage from the selected Home");
}
