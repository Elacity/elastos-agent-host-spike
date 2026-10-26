mod common;
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::{Observation, StagedProbe, MANIFEST};
use agent_conformance::runtime::runtime_under_test;
use probe::{build_probe, Effect};
use std::sync::Mutex;
use std::time::Duration;

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

fn stage_probe(home: &ThrowawayHome, bytes: &[u8], effect: Effect) -> StagedProbe {
    agent_conformance::identity::stage_probe(home, bytes, MANIFEST, effect.name())
        .expect("name the exact staged probe bundle")
}

fn assert_refusal(effect: Effect, bus_error: &str) {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap();
    let capsule = stage_probe(&home, &bytes, effect);

    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let output = home
        .launch(
            &runtime.binary,
            &["run", capsule.path.to_str().unwrap()],
            Duration::from_secs(10),
        )
        .expect("bounded probe launch through the existing primitive");
    Observation::Launched {
        probe: capsule.identity,
    }
    .emit();
    println!(
        "{}",
        operator
            .finish_check(sampled)
            .expect("final census and operator group stop")
    );
    assert_output_refusal(&output, effect, bus_error);
    home.finish().unwrap();
}

fn refusal_evidence(
    output: &std::process::Output,
    effect: Effect,
    bus_error: &str,
) -> (String, bool) {
    let stderr = std::str::from_utf8(&output.stderr).expect("Runtime stderr is UTF-8");
    let reason_present = stderr.contains("Component capsule failed:")
        && stderr.contains(&format!("Component capsule denied: BusError::{bus_error}"));
    (
        format!(
            "probe refusal effect:{} exit:{:?} reason_present:{reason_present}",
            effect.name(),
            output.status.code()
        ),
        !output.status.success() && reason_present,
    )
}

fn assert_output_refusal(output: &std::process::Output, effect: Effect, bus_error: &str) {
    let (line, refused) = refusal_evidence(output, effect, bus_error);
    println!("{line}");
    assert!(
        refused,
        "expected nonzero exit and lifecycle refusal {bus_error}"
    );
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadOutcome {
    Granted,
    Denied,
    NoPolicy,
}

fn exercise_fixture_read(effect: Effect, granted: bool) {
    exercise_read(
        effect,
        if granted {
            ReadOutcome::Granted
        } else {
            ReadOutcome::Denied
        },
    );
}

fn exercise_read(effect: Effect, outcome: ReadOutcome) {
    use agent_conformance::harness::{Launch, RunningInstances};
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    let capsule = stage_probe(&home, &bytes, effect);
    let (fixture, apply_policy) = if outcome == ReadOutcome::NoPolicy {
        grants::Fixture::no_policy().expect("valid optional fixture policy")
    } else {
        (
            grants::Fixture::committed().expect("valid committed grant fixture"),
            true,
        )
    };
    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    // A refusal from the Runtime under test remains FAIL, even before run.
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let mut controller = grants::Controller::attach(&home, operator.port, fixture)
        .expect("fixture shell controller attaches once");
    controller
        .seed_read_files()
        .expect("seed fixture files through Runtime");
    let running = RunningInstances::start(
        &[Launch {
            home: &home,
            program: &runtime.binary,
            args: vec!["run", capsule.path.to_str().unwrap()],
        }],
        Some(&home),
    )
    .unwrap_or_else(|reason| probe::skipped(reason));
    Observation::Launched {
        probe: capsule.identity.clone(),
    }
    .emit();
    let bound = if outcome == ReadOutcome::NoPolicy {
        40
    } else {
        10
    };
    let collected = running.collect_with(Duration::from_secs(bound), || {
        if apply_policy {
            controller.poll()
        } else {
            // Seeding uses the shell fixture. This client receives no approval
            // or denial from it; only Runtime can settle the pending request.
            Ok(())
        }
    });
    println!(
        "{}",
        operator
            .finish_check(sampled)
            .expect("final census and operator group stop")
    );
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
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
    controller
        .print_checked(&format!(
            "fixture read: exit:{:?} matched:{} granted:{} denied:{} content_error:{content_error}",
            output.status.code(),
            controller.decisions.matched,
            controller.decisions.granted,
            controller.decisions.denied
        ))
        .expect("printed result excludes fixture credentials");
    // A denial or a content error is never reported as an environmental skip.
    if outcome == ReadOutcome::NoPolicy {
        assert_eq!(
            output.status.code(),
            Some(1),
            "no-policy acceptance failed; private triage required"
        );
        assert_output_refusal(
            output,
            effect,
            "Internal(\"capability request still pending after 30s\")",
        );
        assert_eq!(controller.decisions.granted, 0);
        assert_eq!(controller.decisions.denied, 0);
        assert_eq!(controller.decisions.matched, 0);
    } else if outcome == ReadOutcome::Granted {
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
        assert_output_refusal(
            output,
            effect,
            &format!("Denied(\"{}\")", controller.deny_reason()),
        );
    }
    let seeded = std::str::from_utf8(include_bytes!("../fixtures/granted-bytes.txt")).unwrap();
    assert!(
        !stdout.contains(seeded) && !stderr.contains(seeded),
        "file bytes must stay inside the guest"
    );
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    let observations = [
        Observation::Native {
            role: "elastos".into(),
            sha256: runtime.sha256.clone(),
        },
        Observation::Native {
            role: "localhost-provider".into(),
            sha256: agent_conformance::runtime::localhost_provider_under_test()
                .unwrap()
                .sha256
                .clone(),
        },
        Observation::Launched {
            probe: capsule.identity,
        },
    ];
    controller
        .check_report(
            match outcome {
                ReadOutcome::Granted => "granted_read_succeeds",
                ReadOutcome::Denied => "ungranted_sibling_read_is_refused",
                ReadOutcome::NoPolicy => "no_policy_file_does_not_mean_allow",
            },
            &observations,
        )
        .expect("report and receipt exclude fixture credentials");
    home.finish().unwrap();
}

#[test]
fn attach_secret_stays_in_memory() {
    grants::assert_memory_surfaces();
    exercise_fixture_read(Effect::GrantedRead, true);
    exercise_fixture_read(Effect::SiblingRead, false);
    host_key::exercise();
}

#[test]
fn granted_read_succeeds() {
    exercise_fixture_read(Effect::GrantedRead, true);
}

#[test]
fn ungranted_sibling_read_is_refused() {
    exercise_fixture_read(Effect::SiblingRead, false);
}

#[test]
fn no_policy_file_does_not_mean_allow() {
    // One activation attempts one read. A natural Runtime refusal is required;
    // the harness timeout is an error, never refusal evidence.
    exercise_read(Effect::GrantedRead, ReadOutcome::NoPolicy);
}

#[test]
fn agent_cannot_read_human_space_without_grant() {
    assert_refusal(
        Effect::HumanRead,
        "Internal(\"localhost://Users/self requires a principal-scoped launch context\")",
    );
}

#[test]
fn ungranted_memory_write_is_refused() {
    let resource = include_str!("../fixtures/memory-write.txt").trim();
    assert_refusal(
        Effect::MemoryWrite,
        &format!("Internal(\"capsule manifest does not declare authority for {resource}\")"),
    );
}

// The fixture describes intended principals only. Runtime must verify and bind
// them before the launch primitive can exercise these journeys. A fixture label
// or a second Home is never treated as a verified principal.
#[test]
#[ignore = "blocked: UsersAI binding; AC-002-ARGS"]
fn agent_memory_under_own_principal() {
    panic!("blocked: UsersAI binding; AC-002-ARGS — Runtime must bind verified agent principals and return resolved object ownership");
}

#[test]
#[ignore = "blocked: UsersAI binding; AC-002-ARGS"]
fn agent_cannot_read_other_agent_memory() {
    panic!("blocked: UsersAI binding; AC-002-ARGS — Runtime must enforce agent roots and carry the target selector and result");
}

#[test]
#[ignore = "blocked: UsersAI binding; AC-002-ARGS"]
fn agent_can_read_human_space_with_grant() {
    panic!("blocked: UsersAI binding; AC-002-ARGS — Runtime must bind the agent launch; reuse the fixture Controller for its human-space grant");
}

#[path = "common/host_key.rs"]
mod host_key;

#[test]
fn host_key_read_is_refused() {
    host_key::exercise();
}
