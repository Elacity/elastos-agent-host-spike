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

#[path = "common/parallel.rs"]
mod process_isolation;

#[test]
#[ignore = "blocked: RT4"]
fn parallel_capsules_complete_independently() {
    panic!("blocked: RT4 — resident instances in one Runtime need Bus v2 lifecycle support");
}

#[test]
#[ignore = "blocked: AC-002-ARGS"]
fn parallel_instances_return_success_payloads() {
    panic!("blocked: AC-002-ARGS — Bus lifecycle needs a success payload and CLI forwarding");
}

fn stage_probe(home: &ThrowawayHome, bytes: &[u8], effect: Effect) -> std::path::PathBuf {
    let hash = format!("{:x}", Sha256::digest(bytes));
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

    capsule
}

fn assert_refusal(effect: Effect, bus_error: &str) {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test()
        .unwrap_or_else(|_| probe::skipped("Runtime build failed before launch"));
    let home = ThrowawayHome::new().unwrap();
    let capsule = stage_probe(&home, &bytes, effect);

    let mut operator = common::operator::Operator::start(&home).unwrap_or_else(|_| {
        probe::skipped("operator setup or loopback bind failed before probe launch")
    });
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

#[path = "common/grants.rs"]
mod grants;

fn exercise_fixture_read(effect: Effect, granted: bool) {
    use agent_conformance::harness::{Launch, RunningInstances};
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test()
        .unwrap_or_else(|_| probe::skipped("Runtime build failed before launch"));
    let home =
        ThrowawayHome::new().unwrap_or_else(|_| probe::skipped("could not prepare fixture Home"));
    let capsule = stage_probe(&home, &bytes, effect);
    let fixture = grants::Fixture::committed().expect("valid committed grant fixture");
    let mut operator = common::operator::Operator::start(&home).unwrap_or_else(|_| {
        probe::skipped("operator setup or loopback bind failed before probe launch")
    });
    // A refusal from the Runtime under test remains FAIL, even before run.
    operator.ready().expect("operator readiness");
    let first = operator.census().expect("ready operator socket census");
    let sampled = Instant::now();
    let mut controller = grants::Controller::attach(&home, operator.port, fixture)
        .expect("fixture shell controller attaches once");
    controller
        .seed_read_files()
        .expect("seed fixture files through Runtime");
    let running = RunningInstances::start(
        &[Launch {
            home: &home,
            program: &runtime.binary,
            args: vec!["run", capsule.to_str().unwrap()],
        }],
        Some(&home),
    )
    .unwrap_or_else(|_| probe::skipped("could not start probe child"));
    let collected = running.collect_with(Duration::from_secs(10), || controller.poll());
    while sampled.elapsed() < Duration::from_secs(3) {
        operator.require_alive().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    let second = operator.census().expect("final operator socket census");
    operator.child.stop().expect("stop operator and its group");
    drop(operator);
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    println!(
        "operator census: {first} then {second} loopback sockets; fixture read; group stopped"
    );
    let completions = collected.expect("controller and probe finish within their bounds");
    assert_eq!(completions.len(), 1);
    let output = &completions[0].output;
    let stderr = std::str::from_utf8(&output.stderr).expect("Runtime stderr is UTF-8");
    let stdout = std::str::from_utf8(&output.stdout).expect("Runtime stdout is UTF-8");
    for reason in [
        "fixture provider parse error",
        "fixture provider file read error",
        "fixture provider read failed",
    ] {
        assert!(!stderr.contains(reason), "{reason}");
    }
    let content_error = stderr.contains("granted file bytes differ from guest expectation");
    println!(
        "fixture read: exit:{:?} matched:{} granted:{} denied:{} content_error:{content_error}",
        output.status.code(),
        controller.decisions.matched,
        controller.decisions.granted,
        controller.decisions.denied
    );
    // A denial or a content error is never reported as an environmental skip.
    if granted {
        assert_eq!(controller.decisions.matched, 1);
        assert_eq!(controller.decisions.granted, 1);
        assert_eq!(controller.decisions.denied, 0);
        assert!(
            !content_error,
            "guest content check failed after the observed grant"
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "granted guest must read and check all file bytes"
        );
    } else {
        // Check natural success first so F-ac1a proves the sibling became readable.
        assert_eq!(
            output.status.code(),
            Some(1),
            "ungranted sibling must be refused; zero means its bytes were read"
        );
        assert_eq!(controller.decisions.matched, 0);
        assert_eq!(controller.decisions.granted, 0);
        assert_eq!(controller.decisions.denied, 1);
        let denial = format!(
            "Component capsule denied: BusError::Denied(\"{}\")",
            controller.deny_reason()
        );
        assert!(
            stderr.contains("Component capsule failed:") && stderr.contains(&denial),
            "Runtime must deliver the fixture denial reason"
        );
    }
    let seeded = std::str::from_utf8(include_bytes!("../fixtures/granted-bytes.txt")).unwrap();
    assert!(
        !stdout.contains(seeded) && !stderr.contains(seeded),
        "file bytes must stay inside the guest"
    );
    home.finish().unwrap();
}

#[test]
fn granted_read_succeeds() {
    exercise_fixture_read(Effect::GrantedRead, true);
}

#[test]
fn ungranted_sibling_read_is_refused() {
    exercise_fixture_read(Effect::SiblingRead, false);
}
