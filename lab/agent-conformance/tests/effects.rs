mod common;
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::census;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::{Observation, StagedProbe, MANIFEST};
use agent_conformance::runtime::runtime_under_test;
use agent_conformance::standin_runtime::{Caller as StandInCaller, StandIn, Start};
use probe::{build_probe, Effect};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};
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

fn assert_refusal(effect: Effect, manifest: &[u8], bus_error: &str) -> std::process::Output {
    assert_refusal_as(effect, effect.name(), manifest, bus_error)
}

// The label names the staged bundle in the version identity record. A staged
// manifest other than MANIFEST is a distinct bundle with its own label.
fn assert_refusal_as(
    effect: Effect,
    label: &str,
    manifest: &[u8],
    bus_error: &str,
) -> std::process::Output {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap();
    let capsule = agent_conformance::identity::stage_probe(&home, &bytes, manifest, label)
        .expect("name the exact staged probe bundle");

    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let output = home
        .launch(
            &runtime.binary,
            &["run", capsule.path.to_str().unwrap()],
            // A refusal returns at once. The bound passes the probe's own
            // 30-second pending wait, so a declared request still reports its
            // refusal reason instead of the harness bound.
            Duration::from_secs(40),
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
    output
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
        MANIFEST,
        &format!("Internal(\"capsule manifest does not declare authority for {resource}\")"),
    );
}

#[test]
fn ungranted_network_is_refused() {
    exercise_fixture_read(Effect::Network, false);
}

#[test]
fn undeclared_network_manifest_is_refused() {
    // The same probe bundle, with the network capability removed from its
    // manifest. The public read capability stays.
    let mut manifest: serde_json::Value =
        serde_json::from_slice(MANIFEST).expect("probe manifest is JSON");
    let capabilities = manifest["capabilities"]
        .as_array_mut()
        .expect("probe manifest lists capabilities");
    capabilities.retain(|capability| capability.as_str() != Some("elastos://net/stream"));
    assert_eq!(capabilities.len(), 1, "the public read capability stays");
    let output = assert_refusal_as(
        Effect::Network,
        "undeclared-network",
        &serde_json::to_vec(&manifest).expect("stripped manifest is JSON"),
        "Internal(\"capsule manifest does not declare authority for elastos://net/stream\")",
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "the manifest refusal exits 1"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("Runtime stderr is UTF-8");
    assert!(
        !stderr.contains("fixture denies"),
        "the manifest refusal involves no fixture denial"
    );
}

#[test]
fn default_activation_refuses_without_selector() {
    assert_refusal(
        Effect::Default,
        MANIFEST,
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
    Instances,
    Cancel,
    Kill,
}

fn exercise_fixture_read(effect: Effect, granted: bool) {
    exercise_read(
        effect,
        if granted {
            ReadOutcome::Granted
        } else {
            ReadOutcome::Denied
        },
        false,
    );
}

fn exercise_read(effect: Effect, outcome: ReadOutcome, require_live_grants: bool) {
    use agent_conformance::harness::{Launch, RunningInstances};
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let instances = matches!(
        outcome,
        ReadOutcome::Instances | ReadOutcome::Cancel | ReadOutcome::Kill
    );
    let effects = if instances {
        vec![Effect::Instance1, Effect::Instance2]
    } else {
        vec![effect]
    };
    // Reuse the two existing builds once per test process, including the
    // cancel journey and credential check. Artifact reproducibility stays separate.
    static INSTANCE_BUILDS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    let builds = if instances {
        INSTANCE_BUILDS
            .get_or_init(|| {
                effects
                    .iter()
                    .map(|effect| build_probe(*effect, 1))
                    .collect()
            })
            .clone()
    } else {
        vec![build_probe(effect, 1)]
    };
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    // As in the existing parallel journey, each client owns its local Home
    // state and borrows only the operator's coordinates through the spawn site.
    let client_homes: Vec<_> = if instances {
        (0..2)
            .map(|_| {
                let client = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
                client.guard(client.home(), client.data()).unwrap();
                std::fs::write(
                    client.data().join("config.toml"),
                    include_bytes!("../fixtures/operator-config.toml"),
                )
                .unwrap();
                client
            })
            .collect()
    } else {
        Vec::new()
    };
    let launch_homes: Vec<_> = if client_homes.is_empty() {
        vec![&home]
    } else {
        client_homes.iter().collect()
    };
    let capsules: Vec<_> = effects
        .iter()
        .zip(&builds)
        .zip(&launch_homes)
        .map(|((effect, bytes), home)| stage_probe(home, bytes, *effect))
        .collect();
    let (fixture, apply_policy) = if outcome == ReadOutcome::NoPolicy {
        grants::Fixture::no_policy().expect("valid optional fixture policy")
    } else {
        (
            if instances {
                grants::Fixture::instances().expect("valid instance grant fixture")
            } else {
                grants::Fixture::committed().expect("valid committed grant fixture")
            },
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
    if outcome == ReadOutcome::Instances {
        controller.require_overlap();
    } else if outcome == ReadOutcome::Cancel {
        controller.require_cancel();
    } else if outcome == ReadOutcome::Kill {
        controller.require_kill();
    }
    let launches: Vec<_> = capsules
        .iter()
        .zip(&launch_homes)
        .map(|(capsule, home)| Launch {
            home,
            program: &runtime.binary,
            args: vec!["run", capsule.path.to_str().unwrap()],
        })
        .collect();
    let running = RunningInstances::start(&launches, Some(&home))
        .unwrap_or_else(|reason| probe::skipped(reason));
    for capsule in &capsules {
        controller
            .print_checked(
                &Observation::Launched {
                    probe: capsule.identity.clone(),
                }
                .line(),
            )
            .expect("printed identity excludes fixture credentials");
    }
    let bound = match outcome {
        ReadOutcome::NoPolicy => 40,
        ReadOutcome::Instances | ReadOutcome::Cancel | ReadOutcome::Kill => 25,
        _ => 10,
    };
    let mut unapproved = None;
    let collected = running.collect_with(Duration::from_secs(bound), |running| {
        if apply_policy {
            controller.poll(running)?;
            if outcome == ReadOutcome::Kill
                && running.kill_recorded(0)
                && launch_homes[0].run_starts() != 1
            {
                return Err("no-retry check: instance-1 must start exactly once");
            }
            Ok(())
        } else {
            // Observe without a grant or denial until the client exits.
            controller.observe_unapproved(&mut unapproved)
        }
    });
    let settlement = match outcome {
        ReadOutcome::Kill => controller
            .killed_request()
            .and_then(|original| controller.settle_orphan(&original, grants::KILL_REASON))
            .map(Some),
        ReadOutcome::NoPolicy => unapproved
            .as_ref()
            .ok_or("no-policy: original pending evidence is missing")
            .and_then(|original| controller.settle_orphan(original, grants::NO_POLICY_REASON))
            .map(Some),
        _ => Ok(None),
    };
    let quiet = if outcome == ReadOutcome::Kill && collected.is_ok() && settlement.is_ok() {
        controller.quiet_after_kill().map(Some)
    } else {
        Ok(None)
    };
    let cleanup_state = controller.check_cleanup_wiring(|controller| controller.cleanup_state());
    let mut finished = operator.finish_check(sampled);
    if outcome == ReadOutcome::Kill {
        // Reuse 021's root census for both client roots after the quiet window.
        // The existing path checks process holders, the API port and TMPDIR.
        for client in &client_homes {
            let census = agent_conformance::census::cleanup(client, controller.port());
            controller
                .print_checked(match &census {
                    Ok(line) | Err(line) => line,
                })
                .expect("client census excludes fixture credentials");
            if let Err(reason) = census {
                finished = Err(reason);
            }
        }
    }
    let line = match &finished {
        Ok(line) | Err(line) => line,
    };
    let state = match cleanup_state {
        Ok(state) => state.to_owned(),
        Err(reason) => format!(
            "FAIL {reason}; retained:target/{}",
            home.root().file_name().unwrap().to_string_lossy()
        ),
    };
    controller
        .print_checked(&format!("{line}; {state}"))
        .expect("cleanup evidence excludes fixture credentials");
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    for client in &client_homes {
        controller
            .check_captures(client)
            .expect("client captures exclude fixture credentials");
    }
    let observations: Vec<_> = [
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
    ]
    .into_iter()
    .chain(capsules.iter().map(|capsule| Observation::Launched {
        probe: capsule.identity.clone(),
    }))
    .collect();
    if instances {
        let overlap = if outcome == ReadOutcome::Cancel {
            controller.check_cancel(collected.as_ref().ok().map(Vec::as_slice))
        } else if outcome == ReadOutcome::Kill {
            controller.check_kill(
                collected.as_ref().ok().map(Vec::as_slice),
                settlement.as_ref().ok().and_then(Option::as_ref),
                quiet.as_ref().ok().copied().flatten(),
            )
        } else {
            controller.check_overlap()
        };
        // Real output lines and captures are checked even when a barrier fails.
        for index in 0..2 {
            let completion = collected.as_ref().ok().and_then(|items| items.get(index));
            controller
                .print_checked(&format!(
                    "fixture read: instance-{} captured:{} exit:{:?}",
                    index + 1,
                    completion.is_some(),
                    completion.and_then(|item| item.output.status.code())
                ))
                .expect("printed instance result excludes fixture credentials");
        }
        controller
            .check_sources()
            .expect("lane sources exclude fixture credentials");
        if collected.is_err() {
            controller
                .print_checked("fixture controller: overlap failed before completion")
                .unwrap();
        }
        let reads = collected
            .as_ref()
            .map_err(|_| "overlap collection failed")
            .and_then(|completions| instance_read_result(completions, &controller, outcome));
        let passed = reads.is_ok()
            && overlap.is_ok()
            && finished.is_ok()
            && cleanup_state.is_ok()
            && settlement.is_ok()
            && quiet.is_ok();
        let names = if outcome == ReadOutcome::Cancel {
            vec!["cancelled_instance_settles_with_reason_sibling_completes"]
        } else if outcome == ReadOutcome::Kill {
            vec!["killed_worker_settlement_recorded_without_retry"]
        } else {
            vec![
                "two_instances_overlap_with_separate_grants",
                "instance_grant_does_not_authorise_sibling",
            ]
        };
        for name in names {
            controller
                .check_journey(name, &observations, passed)
                .expect("instance report and receipt exclude fixture credentials");
        }
        collected.expect("overlap journey failed");
        reads.expect("instance read acceptance failed");
        overlap.expect("required instance settlement evidence");
        settlement.expect("orphan settlement failed");
        quiet.expect("no-retry check: quiet window failed");
        if outcome == ReadOutcome::Kill {
            assert_eq!(
                launch_homes[0].run_starts(),
                1,
                "no-retry check: instance-1 must start exactly once"
            );
            assert_eq!(
                launch_homes[1].run_starts(),
                1,
                "sibling must start exactly once"
            );
        }
        assert!(
            finished.is_ok(),
            "cleanup census refused leftovers; see checked reason"
        );
        assert!(
            cleanup_state.is_ok(),
            "cleanup grant census failed; see checked reason"
        );
        for client in client_homes {
            client.finish().unwrap();
        }
        home.finish().unwrap();
        return;
    }
    assert!(
        finished.is_ok(),
        "cleanup census refused leftovers; see checked reason"
    );
    assert!(
        cleanup_state.is_ok(),
        "cleanup grant census failed; see checked reason"
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
        let (line, refused) = refusal_evidence(
            output,
            effect,
            "Internal(\"capability request still pending after 30s\")",
        );
        controller
            .print_checked(&line)
            .expect("no-policy refusal excludes fixture credentials");
        assert!(
            refused,
            "no-policy client must report its 30 second wait refusal"
        );
        let orphan = settlement
            .as_ref()
            .expect("no-policy orphan measurement failed")
            .as_ref()
            .expect("no-policy settlement evidence is missing");
        controller
            .print_settlement(
                "absent-policy",
                Some(&completions),
                &format!("reason:{}; {}", grants::NO_POLICY_REASON, orphan.line()),
            )
            .expect("no-policy settlement excludes fixture credentials");
        orphan.check().expect("no-policy orphan settlement failed");
        assert_eq!(controller.decisions.granted, 0);
        assert_eq!(controller.decisions.denied, orphan.before);
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
            "ungranted {} must be refused; exit 0 means the fixture granted it",
            effect.name()
        );
        assert_eq!(controller.decisions.matched, 0);
        assert_eq!(controller.decisions.granted, 0);
        assert_eq!(controller.decisions.denied, 1);
        assert!(
            !stderr.contains("capsule manifest does not declare authority"),
            "the pending request is refused by the fixture"
        );
        // The declared network row is denied by the fixture, and its reason
        // names that request. Read rows keep the fixture's read reason.
        let reason = match effect {
            Effect::Network => "fixture denies unlisted elastos://net/stream",
            _ => controller.deny_reason(),
        };
        if matches!(effect, Effect::Network) {
            assert!(
                !stderr.contains("fixture denies unlisted read"),
                "the network denial names the network resource"
            );
        }
        assert_output_refusal(output, effect, &format!("Denied(\"{reason}\")"));
    }
    let seeded = std::str::from_utf8(include_bytes!("../fixtures/granted-bytes.txt")).unwrap();
    assert!(
        !stdout.contains(seeded) && !stderr.contains(seeded),
        "file bytes must stay inside the guest"
    );
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    controller
        .check_report(
            match outcome {
                ReadOutcome::Granted => "granted_read_succeeds",
                ReadOutcome::Denied => match effect {
                    Effect::SiblingRead => "ungranted_sibling_read_is_refused",
                    Effect::Network => "ungranted_network_is_refused",
                    _ => unreachable!("denied report name follows the effect"),
                },
                ReadOutcome::NoPolicy => "no_policy_file_does_not_mean_allow",
                ReadOutcome::Instances | ReadOutcome::Cancel | ReadOutcome::Kill => {
                    unreachable!("instances checked above")
                }
            },
            &observations,
        )
        .expect("report and receipt exclude fixture credentials");
    if require_live_grants {
        assert_eq!(
            cleanup_state,
            Ok("pending:0 grants:0"),
            "blocked: AC-021-GRANTS"
        );
    }
    home.finish().unwrap();
}

fn instance_read_result(
    completions: &[agent_conformance::harness::Completion],
    controller: &grants::Controller,
    outcome: ReadOutcome,
) -> Result<(), &'static str> {
    if completions.len() != 2 {
        return Err("both clients must be collected");
    }
    // Check the sibling first: cancelling every first request must fail here.
    for index in [1, 0] {
        let completion = &completions[index];
        if outcome == ReadOutcome::Kill && index == 0 {
            continue;
        }
        let stderr = std::str::from_utf8(&completion.output.stderr)
            .map_err(|_| "client stderr requires UTF-8")?;
        if stderr.contains("fixture provider")
            || stderr.contains("granted file bytes differ")
            || stderr.contains("fixture grant scope differs")
        {
            return Err("instance own read failed before its sibling request");
        }
        let (_, refused) = refusal_evidence(
            &completion.output,
            Effect::Instance1,
            &format!(
                "Denied(\"{}\")",
                if outcome == ReadOutcome::Cancel && index == 0 {
                    grants::CANCEL_REASON
                } else {
                    controller.deny_reason()
                }
            ),
        );
        if !refused {
            return Err(if index == 1 {
                "sibling check: instance-2 must finish its own read and receive its sibling denial"
            } else {
                "instance-1 must receive its exact denial status and reason"
            });
        }
    }
    let grants = if matches!(outcome, ReadOutcome::Cancel | ReadOutcome::Kill) {
        1
    } else {
        2
    };
    // Two denials: the sibling refusal and one other refusal. Kill's orphan
    // count stays in Settlement::check, so 0 or 2 orphans deny 1 or 3 times.
    if controller.decisions.matched != grants
        || controller.decisions.granted != grants
        || controller.decisions.denied != 2
    {
        return Err("expected own session grants and two denials are required");
    }
    Ok(())
}

#[test]
fn killed_worker_settlement_recorded_without_retry() {
    exercise_read(Effect::Instance1, ReadOutcome::Kill, false);
}

#[test]
fn cancelled_instance_settles_with_reason_sibling_completes() {
    exercise_read(Effect::Instance1, ReadOutcome::Cancel, false);
}

#[test]
fn two_instances_overlap_with_separate_grants() {
    exercise_read(Effect::Instance1, ReadOutcome::Instances, false);
}

#[test]
fn instance_grant_does_not_authorise_sibling() {
    exercise_read(Effect::Instance1, ReadOutcome::Instances, false);
}

#[test]
fn attach_secret_stays_in_memory() {
    grants::assert_memory_surfaces();
    exercise_fixture_read(Effect::GrantedRead, true);
    exercise_fixture_read(Effect::SiblingRead, false);
    host_key::exercise();
    exercise_read(Effect::Instance1, ReadOutcome::Instances, false);
}

#[test]
#[ignore = "blocked: AC-021-GRANTS"]
fn run_leaves_no_live_grant() {
    exercise_read(Effect::GrantedRead, ReadOutcome::Granted, true);
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
    exercise_read(Effect::GrantedRead, ReadOutcome::NoPolicy, false);
}

#[test]
fn agent_cannot_read_human_space_without_grant() {
    assert_refusal(
        Effect::HumanRead,
        MANIFEST,
        "Internal(\"localhost://Users/self requires a principal-scoped launch context\")",
    );
}

#[test]
fn ungranted_memory_write_is_refused() {
    let resource = include_str!("../fixtures/memory-write.txt").trim();
    assert_refusal(
        Effect::MemoryWrite,
        MANIFEST,
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
#[ignore = "blocked: UsersAI binding"]
fn real_agent_host_journal_under_usersai_principal() {
    let path = agent_conformance::build::repository().join("examples/agent-host/capsule.json");
    assert!(
        std::fs::symlink_metadata(&path)
            .expect("agent-host manifest metadata")
            .is_file(),
        "agent-host manifest must be a regular file without symlinks"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("read agent-host manifest"))
            .expect("agent-host manifest JSON");
    for entry in manifest["capabilities"]
        .as_array()
        .expect("agent-host manifest capabilities array")
    {
        let entry = entry.as_str().expect("agent-host capability string");
        assert!(
            entry.starts_with("localhost://UsersAI/self/"),
            "P7 gap: agent-host journal bound {entry} is not under UsersAI/self"
        );
    }
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

// Lab client sessions on the run client's attach and provider routes.
// A Public read is the positive control and earns no A5 credit.
#[derive(Clone, Copy)]
enum SessionBinding {
    OtherSession,
    NewSession,
    AgentRecord,
}

impl SessionBinding {
    fn name(self) -> &'static str {
        match self {
            Self::OtherSession => "grant_refused_from_another_session",
            Self::NewSession => "grant_refused_from_a_new_session",
            Self::AgentRecord => "grant_record_names_agent_identity",
        }
    }
}

fn exercise_session_binding(
    binding: SessionBinding,
) -> Result<Option<grants::AgentRecord>, &'static str> {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let provider = agent_conformance::runtime::localhost_provider_under_test()
        .unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let mut controller = grants::Controller::attach(
        &home,
        operator.port,
        grants::Fixture::committed().expect("valid committed grant fixture"),
    )
    .expect("fixture shell controller attaches once");
    controller
        .seed_read_files()
        .expect("seed fixture files through Runtime");
    let outcome = bind_client_sessions(&mut controller, binding);
    let cleanup_state = controller.check_cleanup_wiring(|controller| controller.cleanup_state());
    let finished = operator.finish_check(sampled);
    let line = match &finished {
        Ok(line) | Err(line) => line.clone(),
    };
    let state = match &cleanup_state {
        Ok(state) => (*state).to_owned(),
        Err(reason) => format!("FAIL {reason}"),
    };
    controller
        .print_checked(&format!("{line}; {state}"))
        .expect("cleanup evidence excludes fixture credentials");
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    if outcome.is_ok() {
        let observations = [
            Observation::Native {
                role: "elastos".into(),
                sha256: runtime.sha256.clone(),
            },
            Observation::Native {
                role: "localhost-provider".into(),
                sha256: provider.sha256.clone(),
            },
        ];
        controller
            .check_journey(
                binding.name(),
                &observations,
                !matches!(binding, SessionBinding::AgentRecord),
            )
            .expect("report and receipt exclude fixture credentials");
    }
    finished.expect("cleanup census refused leftovers; see checked reason");
    cleanup_state.expect("cleanup grant census failed; see checked reason");
    let removed = home.finish();
    let outcome = outcome?;
    removed?;
    Ok(outcome)
}

fn bind_client_sessions(
    controller: &mut grants::Controller,
    binding: SessionBinding,
) -> Result<Option<grants::AgentRecord>, &'static str> {
    let owner = controller.client_session()?;
    let grant = controller.open_session_read(
        &owner,
        grants::GRANTED_READ_RESOURCE,
        "agent conformance: session binding read",
    )?;
    controller.read_seeded(&owner, grants::GRANTED_READ_RESOURCE, &grant)?;
    controller.note_seeded_read(
        grants::GRANTED_READ_RESOURCE,
        "positive control; a Public read earns no A5 credit",
    )?;
    let other = match binding {
        SessionBinding::OtherSession | SessionBinding::AgentRecord => {
            Some(controller.client_session()?)
        }
        SessionBinding::NewSession => None,
    };
    let renewed = match binding {
        SessionBinding::NewSession => Some(controller.client_session()?),
        SessionBinding::OtherSession | SessionBinding::AgentRecord => None,
    };
    let (got_session, got_label) = match binding {
        SessionBinding::OtherSession => {
            let other = other.as_ref().unwrap();
            if other.session_id() == owner.session_id() {
                return Err("another session reused the granting session");
            }
            let other_grant = controller.open_session_read(
                other,
                grants::SIBLING_READ_RESOURCE,
                "agent conformance: session binding sibling",
            )?;
            controller.read_seeded(other, grants::SIBLING_READ_RESOURCE, &other_grant)?;
            controller.note_seeded_read(
                grants::SIBLING_READ_RESOURCE,
                "presenting session read its own file",
            )?;
            (other_grant.session_id().to_owned(), "<session-B>")
        }
        SessionBinding::NewSession => {
            let renewed = renewed.as_ref().unwrap();
            if renewed.session_id() == owner.session_id() {
                return Err("new session reused the granting session");
            }
            (renewed.session_id().to_owned(), "<session-A2>")
        }
        SessionBinding::AgentRecord => {
            let other = other.as_ref().unwrap();
            if other.session_id() == owner.session_id() {
                return Err("another session reused the granting session");
            }
            (other.session_id().to_owned(), "<session-B>")
        }
    };
    // The presented session is the only input to the Runtime refusal.
    // F-a5-other-session replaces `SessionBinding::OtherSession => other.as_ref().unwrap(),` with `SessionBinding::OtherSession => &owner,`.
    // F-a5-new-session replaces `SessionBinding::NewSession => renewed.as_ref().unwrap(),` with `SessionBinding::NewSession => &owner,`.
    let presenting = match binding {
        SessionBinding::OtherSession => other.as_ref().unwrap(),
        SessionBinding::NewSession => renewed.as_ref().unwrap(),
        SessionBinding::AgentRecord => other.as_ref().unwrap(),
    };
    let text = controller.present_grant(presenting, grants::GRANTED_READ_RESOURCE, &grant)?;
    let checked = grants::check_wrong_capsule(&text, grant.session_id(), &got_session)?;
    controller.print_checked(&grants::redact_refusal(&checked, got_label)?)?;
    controller.read_seeded(&owner, grants::GRANTED_READ_RESOURCE, &grant)?;
    controller.note_seeded_read(
        grants::GRANTED_READ_RESOURCE,
        "same token after the presenting session was refused",
    )?;
    if matches!(binding, SessionBinding::AgentRecord) {
        let (capsule_id, principal) = controller.grant_record(grants::GRANTED_READ_RESOURCE)?;
        return Ok(Some(grants::AgentRecord {
            session_id: grant.session_id().to_owned(),
            capsule_id,
            principal,
            refusal_expected: checked.expected().to_owned(),
        }));
    }
    Ok(None)
}

#[test]
fn grant_refused_from_another_session() {
    assert!(exercise_session_binding(SessionBinding::OtherSession)
        .expect("another session cannot present the grant")
        .is_none());
}

#[test]
fn grant_refused_from_a_new_session() {
    assert!(exercise_session_binding(SessionBinding::NewSession)
        .expect("a new session cannot present the grant")
        .is_none());
}

#[test]
#[ignore = "blocked: AC-038-GRANT-PRINCIPAL"]
fn grant_record_names_agent_identity() {
    let record = exercise_session_binding(SessionBinding::AgentRecord)
        .expect("session binding journey")
        .expect("grant record");
    let named = grants::grant_names_verified_agent(
        &record.capsule_id,
        record.principal.as_deref(),
        &record.session_id,
        // This attach route has no independently verified agent evidence yet.
        None,
    );
    assert!(
        named.is_ok(),
        "{}; 403 expected ID equals A's session ID: {}; audit capsule_id equals A's session ID: {}",
        named.unwrap_err(),
        record.refusal_expected == record.session_id,
        record.capsule_id == record.session_id
    );
}

fn bind_owned_roots(controller: &mut grants::Controller) -> Result<(), &'static str> {
    let session_a = controller.client_session()?;
    let session_b = controller.client_session()?;
    if session_a.session_id() == session_b.session_id() {
        return Err("owned roots reused one client session");
    }
    let grant_a = controller.open_session_write(
        &session_a,
        grants::INSTANCE_A_FILE,
        "agent conformance: instance-a own root",
    )?;
    controller.write_granted(&session_a, grants::INSTANCE_A_FILE, &grant_a, b"instance-a")?;
    let grant_b = controller.open_session_write(
        &session_b,
        grants::INSTANCE_B_FILE,
        "agent conformance: instance-b own root",
    )?;
    controller.write_granted(&session_b, grants::INSTANCE_B_FILE, &grant_b, b"instance-b")?;
    controller.settle_sibling_root_request(
        &session_b,
        grants::INSTANCE_A_SIBLING_FILE,
        "agent conformance: sibling root",
    )
}

fn exercise_owned_roots() -> Result<(), &'static str> {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let provider = agent_conformance::runtime::localhost_provider_under_test()
        .unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let mut controller = grants::Controller::attach(
        &home,
        operator.port,
        grants::Fixture::committed().expect("valid committed grant fixture"),
    )
    .expect("fixture shell controller attaches once");
    let outcome = bind_owned_roots(&mut controller);
    let cleanup_state = controller.check_cleanup_wiring(|controller| controller.cleanup_state());
    let finished = operator.finish_check(sampled);
    let line = match &finished {
        Ok(line) | Err(line) => line.clone(),
    };
    let state = match &cleanup_state {
        Ok(state) => (*state).to_owned(),
        Err(reason) => format!("FAIL {reason}"),
    };
    controller
        .print_checked(&format!("{line}; {state}"))
        .expect("cleanup evidence excludes fixture credentials");
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    if outcome.is_ok() {
        let observations = [
            Observation::Native {
                role: "elastos".into(),
                sha256: runtime.sha256.clone(),
            },
            Observation::Native {
                role: "localhost-provider".into(),
                sha256: provider.sha256.clone(),
            },
        ];
        controller
            .check_journey(
                "instance_writes_only_under_own_storage_root",
                &observations,
                true,
            )
            .expect("report and receipt exclude fixture credentials");
    }
    finished.expect("cleanup census refused leftovers; see checked reason");
    cleanup_state.expect("cleanup grant census failed; see checked reason");
    let removed = home.finish();
    outcome?;
    removed?;
    Ok(())
}

#[test]
#[ignore = "blocked: AC-039-OWNED-ROOT"]
fn instance_writes_only_under_own_storage_root() {
    exercise_owned_roots().expect("Runtime refuses a sibling write under the other owned root");
}

/// The one shell request route. Both a live and a stopped stand-in answer it.
fn standin_request_route(standin: &StandIn, session_id: &str) -> Result<serde_json::Value, String> {
    standin
        .get_capability_requests(StandInCaller::Shell, Some(session_id))
        .map_err(|(_, reason)| reason)
}

/// The census reads every listed session's request record through
/// `standin_request_route` and refuses a `pending` one before it reads any
/// entry's status. It then refuses a `starting`, `running` or `stopping` entry,
/// refuses a live grant, and finishes with the physical root and temp census.
fn standin_a12_census(standin: &StandIn, home: &ThrowawayHome, port: u16) -> Result<(), String> {
    let listed = standin
        .get_capsules(StandInCaller::Shell)
        .map_err(|(_, reason)| reason)?;
    let capsules = listed["capsules"]
        .as_array()
        .ok_or("capsule list requires a capsule array")?;
    for capsule in capsules {
        let session_id = capsule["session_id"]
            .as_str()
            .ok_or("capsule entry requires a session")?;
        let pending = standin_request_route(standin, session_id)?;
        let requests = pending["requests"]
            .as_array()
            .ok_or("request list requires a request array")?;
        for request in requests {
            if request["status"] == "pending" {
                return Err("pending request leftover".to_owned());
            }
        }
    }
    for capsule in capsules {
        let status = capsule["status"]
            .as_str()
            .ok_or("capsule entry requires a status")?;
        if status == "starting" || status == "running" || status == "stopping" {
            return Err(format!("instance still live: {status}"));
        }
    }
    let view = standin
        .get_capability_list(StandInCaller::Shell, Some("all_sessions_live"))
        .map_err(|(_, reason)| reason)?;
    match grants::live_grant_state(&view) {
        Ok("pending:0 grants:0") => {}
        Ok(state) => return Err(state.to_owned()),
        Err(reason) => return Err(reason.to_owned()),
    }
    match census::cleanup(home, port) {
        Ok(line) if line.contains("root checks PASS") => Ok(()),
        Ok(line) => Err(line),
        Err(line) => Err(line),
    }
}

#[test]
fn standin_stopped_run_leaves_no_live_grant() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("the stand-in run binds one loopback port");
    let port = listener
        .local_addr()
        .expect("the stand-in run reads its port")
        .port();
    drop(listener);
    let home = ThrowawayHome::new().expect("the stand-in run uses one throwaway home");
    let launch_two = |standin: &mut StandIn| -> Vec<String> {
        standin
            .admit_resident("/capsules/read-shared", "read-shared", Start::Ok)
            .expect("the stand-in admits read-shared");
        let mut ids = Vec::new();
        for _ in 0..2 {
            let launch = standin
                .post_capsules(
                    StandInCaller::Shell,
                    &json!({"path": "/capsules/read-shared"}),
                )
                .expect("the stand-in launches the admitted path");
            let id = launch["id"]
                .as_str()
                .expect("the stand-in names the launched instance")
                .to_owned();
            standin
                .finish_start(&id)
                .expect("the stand-in finishes start");
            ids.push(id);
        }
        ids
    };
    let mut stopped_run = StandIn::new();
    assert_eq!(
        launch_two(&mut stopped_run),
        vec!["component-1".to_owned(), "component-2".to_owned()],
        "the stand-in numbers the two launches"
    );
    for session_id in ["component-1", "component-2"] {
        let pending = stopped_run
            .post_capability_request(
                StandInCaller::Client { session_id },
                &json!({
                    "resource": "localhost://Public/resident-instances/shared.txt",
                    "action": "read",
                    "reason": "read shared",
                }),
            )
            .expect("the stand-in stores the client's request");
        let request_id = pending["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        let granted = stopped_run
            .post_capability_grant(
                StandInCaller::Shell,
                &json!({"request_id": request_id, "duration": "session"}),
            )
            .expect("the stand-in's shell grants the request");
        assert_eq!(
            granted,
            json!({"success": true}),
            "the stand-in's client approval carries no token"
        );
    }
    let view = stopped_run
        .get_capability_list(StandInCaller::Shell, Some("all_sessions_live"))
        .expect("the stand-in returns the shell live view");
    let requests: BTreeSet<&str> = view["capabilities"]
        .as_array()
        .expect("the stand-in returns a capability list")
        .iter()
        .map(|grant| {
            grant["request_id"]
                .as_str()
                .expect("the stand-in names each live grant")
        })
        .collect();
    assert_eq!(
        requests,
        BTreeSet::from(["request-1", "request-2"]),
        "the stand-in lists exactly the two grants the shell granted from the clients' requests"
    );
    let census = standin_a12_census(&stopped_run, &home, port);
    assert!(
        matches!(&census, Err(reason) if reason == "instance still live: running"),
        "the stand-in's census refuses the live pair on its status row before the grant row: {census:?}"
    );
    let grants: BTreeSet<&str> = view["capabilities"]
        .as_array()
        .expect("the stand-in returns a capability list")
        .iter()
        .map(|grant| {
            grant["request_id"]
                .as_str()
                .expect("the stand-in names each live grant")
        })
        .collect();
    assert_eq!(
        grants,
        BTreeSet::from(["request-1", "request-2"]),
        "the stand-in keeps the granted requests live before the stops"
    );
    for session_id in ["component-1", "component-2"] {
        let pending = stopped_run
            .post_capability_request(
                StandInCaller::Client { session_id },
                &json!({
                    "resource": "localhost://Public/resident-instances/shared.txt",
                    "action": "read",
                    "reason": "read shared again",
                }),
            )
            .expect("the stand-in stores the client's second request while it runs");
        assert_eq!(
            pending["status"], "pending",
            "the stand-in leaves the second request pending for the shell to answer"
        );
        let self_approval = stopped_run.post_capability_grant(
            StandInCaller::Client { session_id },
            &json!({"request_id": pending["request_id"]}),
        );
        assert!(
            matches!(&self_approval, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
            "the stand-in refuses the client approving its own request: {self_approval:?}"
        );
    }
    stopped_run
        .delete_capsule(
            StandInCaller::Shell,
            "component-1",
            &json!({"reason": "stop one"}),
        )
        .expect("the stand-in stops component-1");
    stopped_run
        .delete_capsule(
            StandInCaller::Shell,
            "component-2",
            &json!({"reason": "stop two"}),
        )
        .expect("the stand-in stops component-2");
    let listed = stopped_run
        .get_capsules(StandInCaller::Shell)
        .expect("the stand-in lists the stopped pair");
    let capsules = listed["capsules"]
        .as_array()
        .expect("the stand-in returns a capsule list");
    assert_eq!(
        capsules.len(),
        2,
        "the stand-in keeps both stopped entries after the stops"
    );
    for capsule in capsules {
        assert_eq!(
            capsule["status"], "stopped",
            "the stand-in reports a stopped entry as not live"
        );
    }
    for (overseer, session_id, decision_reason) in [
        (1, "component-1", "stopped: stop one"),
        (2, "component-2", "stopped: stop two"),
    ] {
        let pending = stopped_run
            .get_capability_requests(StandInCaller::Shell, Some(session_id))
            .expect("the stand-in returns the stopped session's requests");
        let requests = pending["requests"]
            .as_array()
            .expect("the stand-in returns a request list");
        assert_eq!(
            requests.len(),
            2,
            "the stand-in keeps the granted request and the second request for {session_id}"
        );
        assert_eq!(
            requests[0]["request_id"],
            format!("request-{overseer}"),
            "the stand-in keeps the request the client made and the shell granted"
        );
        assert_eq!(
            requests[0]["status"], "granted",
            "the stand-in keeps the shell's client approval after the stop"
        );
        assert_eq!(
            requests[0]["settled_by"], "shell",
            "the stand-in keeps the shell as the grant's settler"
        );
        assert_eq!(
            requests[1]["request_id"],
            format!("request-{}", overseer + 2),
            "the stand-in keeps the second request the client made"
        );
        assert_eq!(
            requests[1]["status"], "denied",
            "the stand-in denies the second request when the session stops"
        );
        assert_eq!(
            requests[1]["settled_by"], "runtime",
            "the stand-in settles the second request as the runtime"
        );
        assert_eq!(
            requests[1]["decision_reason"], decision_reason,
            "the stand-in names the stop cause"
        );
    }
    // Both stops settled the second requests. The census's physical row needs
    // the census module's own host tools, so this row reads the two stand-in
    // routes instead: no live grant and no pending request after both stops.
    let view = stopped_run
        .get_capability_list(StandInCaller::Shell, Some("all_sessions_live"))
        .expect("the stand-in returns the shell live view");
    assert_eq!(
        view,
        json!({"scope": "all_sessions_live", "capabilities": []}),
        "both stops revoked every live grant"
    );
    for session_id in ["component-1", "component-2"] {
        assert!(
            !standin_requests(&stopped_run, session_id)
                .iter()
                .any(|request| request["status"] == "pending"),
            "both stops settled {session_id}'s pending request"
        );
    }
    // A completed run passes every census row: no pending request, no live
    // entry, no live grant and no physical leftover.
    let clean = standin_a12_census(&stopped_run, &home, port);
    assert!(
        clean.is_ok(),
        "the two stopped entries leave no live grant, live entry, pending request or physical leftover: {clean:?}"
    );
    // Negative control for the physical census: a planted temp file in the
    // same home must reach `census::cleanup` and be refused there.
    let leftover_file = home.temp().join("a12-temp-leftover");
    std::fs::write(&leftover_file, b"leftover").expect("the stand-in run plants one temp file");
    let planted = standin_a12_census(&stopped_run, &home, port);
    assert!(
        matches!(&planted, Err(reason) if reason.contains("temp leftover")),
        "the stand-in refuses the planted temp leftover: {planted:?}"
    );
    assert!(
        leftover_file.exists(),
        "the refused census leaves the planted temp file in place"
    );
    std::fs::remove_file(&leftover_file).expect("the stand-in run removes its temp file");
    let restored = standin_a12_census(&stopped_run, &home, port);
    assert!(
        restored.is_ok(),
        "the stand-in returns to a clean physical census after the temp file is removed: {restored:?}"
    );
    let mut fresh_run = StandIn::new();
    assert_eq!(
        launch_two(&mut fresh_run),
        vec!["component-1".to_owned(), "component-2".to_owned()],
        "the stand-in numbers the third run's launches"
    );
    // Negative control for the status guard: both entries are running through
    // the launch and start routes and store no request, so only the status
    // check can refuse this census.
    let live_census = standin_a12_census(&fresh_run, &home, port);
    assert!(
        matches!(&live_census, Err(reason) if reason == "instance still live: running"),
        "the stand-in refuses a run that is still live: {live_census:?}"
    );
    assert_eq!(
        fresh_run
            .get_capsules(StandInCaller::Shell)
            .expect("the stand-in lists the live pair")["capsules"],
        json!([
            standin_capsule_record("component-1", "read-shared", "running", ""),
            standin_capsule_record("component-2", "read-shared", "running", ""),
        ]),
        "the refused census leaves both live entries unchanged"
    );
    let leftover = fresh_run
        .post_capability_request(
            StandInCaller::Client {
                session_id: "component-1",
            },
            &json!({
                "resource": STANDIN_RESOURCE,
                "action": "read",
                "reason": "read shared",
            }),
        )
        .expect("the stand-in stores the client's request while it runs");
    assert_eq!(
        (leftover["request_id"].clone(), leftover["status"].clone()),
        (json!("request-1"), json!("pending")),
        "the stand-in keeps the third run's one request pending"
    );
    // Negative control for the pending-request guard: one request reaches the
    // census through the route while both entries read starting, which the
    // census does not refuse. The stops that follow settle it.
    let pending_census = standin_a12_census(&fresh_run, &home, port);
    assert!(
        matches!(&pending_census, Err(reason) if reason == "pending request leftover"),
        "the stand-in refuses the request the run has not settled: {pending_census:?}"
    );
    assert_eq!(
        fresh_run.get_capability_requests(StandInCaller::Shell, Some("component-1")),
        Ok(json!({"requests": [standin_request_record(
            "request-1",
            "component-1",
            "pending",
            "",
            None
        )]})),
        "the refused census leaves the pending request unchanged"
    );
    fresh_run
        .delete_capsule(
            StandInCaller::Shell,
            "component-1",
            &json!({"reason": "stop one"}),
        )
        .expect("the stand-in stops the third run's component-1");
    fresh_run
        .delete_capsule(
            StandInCaller::Shell,
            "component-2",
            &json!({"reason": "stop two"}),
        )
        .expect("the stand-in stops the third run's component-2");
    for session_id in ["component-1", "component-2"] {
        assert!(
            !standin_requests(&fresh_run, session_id)
                .iter()
                .any(|request| request["status"] == "pending"),
            "both stops settled {session_id}'s pending request"
        );
    }
    let left = fresh_run
        .get_capability_requests(StandInCaller::Shell, Some("component-1"))
        .expect("the stand-in returns the fourth run's request record");
    assert_eq!(
        left["requests"],
        json!([standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "stopped: stop one",
            Some("runtime")
        )]),
        "the stand-in denies the fourth run's request at its stop"
    );
    home.finish()
        .expect("the stand-in run removes its throwaway home");
}

const STANDIN_SHARED_PATH: &str = "/capsules/read-shared";
const STANDIN_SHARED_NAME: &str = "read-shared";
const STANDIN_FAILED_PATH: &str = "/capsules/fail-after-submit";
const STANDIN_FAILED_NAME: &str = "fail-after-submit";
const STANDIN_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";

fn standin_launch(standin: &mut StandIn, path: &str) -> String {
    let launched = standin
        .post_capsules(StandInCaller::Shell, &json!({"path": path}))
        .expect("the stand-in launches the admitted path");
    launched["id"]
        .as_str()
        .expect("the stand-in names the launched instance")
        .to_owned()
}

fn standin_capsule(standin: &StandIn, id: &str) -> serde_json::Value {
    let listed = standin
        .get_capsules(StandInCaller::Shell)
        .expect("the stand-in returns the shell capsule list");
    listed["capsules"]
        .as_array()
        .expect("the stand-in returns a capsule list")
        .iter()
        .find(|entry| entry["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("the stand-in lists {id}"))
}

fn standin_capsule_record(id: &str, name: &str, status: &str, cause: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "status": status,
        "session_id": id,
        "cause": cause,
    })
}

fn standin_requests(standin: &StandIn, session: &str) -> Vec<serde_json::Value> {
    let listed = standin
        .get_capability_requests(StandInCaller::Shell, Some(session))
        .expect("the stand-in returns the shell request records");
    listed["requests"]
        .as_array()
        .expect("the stand-in returns a request list")
        .clone()
}

fn standin_request_record(
    request_id: &str,
    session_id: &str,
    status: &str,
    decision_reason: &str,
    settled_by: Option<&str>,
) -> serde_json::Value {
    json!({
        "request_id": request_id,
        "session_id": session_id,
        "resource": STANDIN_RESOURCE,
        "action": "read",
        "reason": "read shared",
        "status": status,
        "decision_reason": decision_reason,
        "settled_by": settled_by,
    })
}

fn standin_live_grants(standin: &StandIn) -> Vec<serde_json::Value> {
    standin
        .get_capability_list(StandInCaller::Shell, Some("all_sessions_live"))
        .expect("the stand-in returns the shell live view")["capabilities"]
        .as_array()
        .expect("the stand-in returns a capability list")
        .clone()
}

/// One client request through `post_capability_request`. The stand-in numbers
/// the id, so a journey reaches both requests the same way.
fn standin_shared_request(standin: &mut StandIn, session_id: &str) -> String {
    let pending = standin
        .post_capability_request(
            StandInCaller::Client { session_id },
            &json!({
                "resource": STANDIN_RESOURCE,
                "action": "read",
                "reason": "read shared",
            }),
        )
        .expect("the stand-in stores the client's request");
    assert_eq!(
        pending["status"], "pending",
        "the stand-in leaves the client's request pending for the shell"
    );
    pending["request_id"]
        .as_str()
        .expect("the stand-in names the request")
        .to_owned()
}

#[test]
fn standin_cancel_survivor_reaches_running() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("the stand-in survivor run binds one loopback port");
    drop(listener);
    let home = ThrowawayHome::new().expect("the stand-in survivor run uses one throwaway home");

    let mut standin = StandIn::new();
    standin
        .admit_resident(STANDIN_SHARED_PATH, STANDIN_SHARED_NAME, Start::Ok)
        .expect("the stand-in admits read-shared");
    assert_eq!(
        (
            standin_launch(&mut standin, STANDIN_SHARED_PATH),
            standin_launch(&mut standin, STANDIN_SHARED_PATH),
        ),
        ("component-1".to_owned(), "component-2".to_owned()),
        "the stand-in numbers the two launches component-1 and component-2"
    );
    assert_eq!(
        (
            standin_capsule(&standin, "component-1"),
            standin_capsule(&standin, "component-2"),
        ),
        (
            standin_capsule_record("component-1", STANDIN_SHARED_NAME, "starting", ""),
            standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
        ),
        "the stand-in keeps both launches starting before the start returns"
    );
    assert_eq!(
        (
            standin_shared_request(&mut standin, "component-1"),
            standin_shared_request(&mut standin, "component-2"),
        ),
        ("request-1".to_owned(), "request-2".to_owned()),
        "the stand-in numbers the two requests through the one request route"
    );

    standin
        .delete_capsule(
            StandInCaller::Shell,
            "component-1",
            &json!({"reason": "stop one"}),
        )
        .expect("the stand-in stops component-1");
    assert_eq!(
        standin_capsule(&standin, "component-1"),
        standin_capsule_record(
            "component-1",
            STANDIN_SHARED_NAME,
            "stopped",
            "stopped: stop one"
        ),
        "the stand-in stops component-1 with the stop cause"
    );
    assert_eq!(
        standin_requests(&standin, "component-1"),
        vec![standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "stopped: stop one",
            Some("runtime")
        )],
        "the stand-in denies component-1's request as the runtime with the stop cause"
    );
    assert_eq!(
        (
            standin_capsule(&standin, "component-2"),
            standin_requests(&standin, "component-2"),
        ),
        (
            standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
            vec![standin_request_record(
                "request-2",
                "component-2",
                "pending",
                "",
                None
            )],
        ),
        "the stand-in keeps component-2 starting with its request pending and no settler"
    );

    standin.set_instant(4);
    let granted = standin
        .post_capability_grant(
            StandInCaller::Shell,
            &json!({
                "request_id": "request-2",
                "duration": "session",
                "rationale": "grant shared read",
            }),
        )
        .expect("the stand-in grants the survivor's pending request");
    assert_eq!(
        granted,
        json!({"success": true}),
        "the stand-in answers success true for the survivor grant and stores no token"
    );
    assert_eq!(
        standin_capsule(&standin, "component-2"),
        standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
        "the stand-in keeps the granted survivor starting"
    );
    assert_eq!(
        standin_requests(&standin, "component-2"),
        vec![standin_request_record(
            "request-2",
            "component-2",
            "granted",
            "grant shared read",
            Some("shell")
        )],
        "the stand-in grants request-2 with the shell as settler and the rationale as decision"
    );
    assert_eq!(
        standin_requests(&standin, "component-1"),
        vec![standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "stopped: stop one",
            Some("runtime")
        )],
        "the stand-in leaves the ended instance's denied record unchanged"
    );
    let live = standin_live_grants(&standin);
    let live_ids: BTreeSet<&str> = live
        .iter()
        .map(|grant| {
            grant["request_id"]
                .as_str()
                .expect("the stand-in names each live grant")
        })
        .collect();
    assert_eq!(
        live_ids,
        BTreeSet::from(["request-2"]),
        "the stand-in shows exactly the survivor's request as live"
    );
    assert_eq!(
        live,
        vec![json!({
            "request_id": "request-2",
            "session_id": "component-2",
            "resource": STANDIN_RESOURCE,
            "action": "read",
            "duration": "session",
            "granted_at": 4,
        })],
        "the stand-in stores the one live grant for the survivor's session at the test instant"
    );
    standin
        .authorise(
            StandInCaller::Client {
                session_id: "component-2",
            },
            "request-2",
        )
        .expect("the stand-in authorises the survivor's presentation");
    let ended_presentation = standin.authorise(
        StandInCaller::Client {
            session_id: "component-1",
        },
        "request-2",
    );
    assert!(
        matches!(&ended_presentation, Err((403, reason)) if reason.contains("wrong capsule")),
        "the stand-in refuses the ended instance's presentation: {ended_presentation:?}"
    );

    standin
        .finish_start("component-2")
        .expect("the stand-in finishes the survivor's start");
    assert_eq!(
        standin_capsule(&standin, "component-2"),
        standin_capsule_record("component-2", STANDIN_SHARED_NAME, "running", ""),
        "the stand-in runs the granted survivor after its start returns"
    );
    assert_eq!(
        standin_requests(&standin, "component-2"),
        vec![standin_request_record(
            "request-2",
            "component-2",
            "granted",
            "grant shared read",
            Some("shell")
        )],
        "the stand-in keeps the granted record after the survivor start returns"
    );
    assert_eq!(
        standin_live_grants(&standin),
        vec![json!({
            "request_id": "request-2",
            "session_id": "component-2",
            "resource": STANDIN_RESOURCE,
            "action": "read",
            "duration": "session",
            "granted_at": 4,
        })],
        "the stand-in keeps exactly the survivor grant after the start returns"
    );
    // The census refuses this live pair on its status row before it reads the
    // grant row. The survivor's live grant itself is the subject here, so this
    // row reads the shell live view through the route.
    assert_eq!(
        standin_live_grants(&standin),
        vec![json!({
            "request_id": "request-2",
            "session_id": "component-2",
            "resource": STANDIN_RESOURCE,
            "action": "read",
            "duration": "session",
            "granted_at": 4,
        })],
        "the stand-in keeps exactly the survivor grant live while the survivor runs"
    );

    standin
        .delete_capsule(
            StandInCaller::Shell,
            "component-2",
            &json!({"reason": "stop two"}),
        )
        .expect("the stand-in stops component-2");
    assert_eq!(
        standin_capsule(&standin, "component-2"),
        standin_capsule_record(
            "component-2",
            STANDIN_SHARED_NAME,
            "stopped",
            "stopped: stop two"
        ),
        "the stand-in stops component-2 with the stop cause"
    );
    assert_eq!(
        standin_requests(&standin, "component-2"),
        vec![standin_request_record(
            "request-2",
            "component-2",
            "granted",
            "grant shared read",
            Some("shell")
        )],
        "the stand-in keeps the survivor's granted record after the stop"
    );
    assert!(
        standin_live_grants(&standin).is_empty(),
        "the stand-in leaves no live grant after the survivor stop"
    );
    let revoked = standin.authorise(
        StandInCaller::Client {
            session_id: "component-2",
        },
        "request-2",
    );
    assert!(
        matches!(&revoked, Err((400, reason)) if reason.starts_with("grant is not live:") && reason.contains("Revoked")),
        "the stand-in refuses the stopped survivor's presentation as revoked: {revoked:?}"
    );
    // The census's physical row needs the census module's own host tools, so
    // this row reads the two stand-in routes: no live grant, no pending request.
    assert_eq!(
        standin_live_grants(&standin),
        Vec::<serde_json::Value>::new(),
        "both ends revoked every live grant"
    );
    assert!(
        !standin_requests(&standin, "component-2")
            .iter()
            .any(|request| request["status"] == "pending"),
        "both ends settled the survivor's pending request"
    );
    home.finish()
        .expect("the stand-in survivor run removes its throwaway home");
}

#[test]
fn standin_failed_survivor_reaches_running() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("the stand-in failed-survivor run has a free loopback port");
    drop(listener);
    let home =
        ThrowawayHome::new().expect("the stand-in failed-survivor run uses one throwaway home");

    let mut standin = StandIn::new();
    standin
        .admit_resident(
            STANDIN_FAILED_PATH,
            STANDIN_FAILED_NAME,
            Start::Error("start refused".to_owned()),
        )
        .expect("the stand-in admits fail-after-submit");
    standin
        .admit_resident(STANDIN_SHARED_PATH, STANDIN_SHARED_NAME, Start::Ok)
        .expect("the stand-in admits read-shared");
    assert_eq!(
        (
            standin_launch(&mut standin, STANDIN_FAILED_PATH),
            standin_launch(&mut standin, STANDIN_SHARED_PATH),
        ),
        ("component-1".to_owned(), "component-2".to_owned()),
        "the stand-in numbers the failing launch first and the shared launch second"
    );
    assert_eq!(
        (
            standin_capsule(&standin, "component-1"),
            standin_capsule(&standin, "component-2"),
        ),
        (
            standin_capsule_record("component-1", STANDIN_FAILED_NAME, "starting", ""),
            standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
        ),
        "the stand-in keeps both launches starting before the start returns"
    );
    assert_eq!(
        (
            standin_shared_request(&mut standin, "component-1"),
            standin_shared_request(&mut standin, "component-2"),
        ),
        ("request-1".to_owned(), "request-2".to_owned()),
        "the stand-in numbers the two requests through the one request route"
    );

    standin
        .finish_start("component-1")
        .expect("the stand-in returns the failing start");
    assert_eq!(
        standin_capsule(&standin, "component-1"),
        standin_capsule_record(
            "component-1",
            STANDIN_FAILED_NAME,
            "failed",
            "start refused"
        ),
        "the stand-in fails component-1 with the start cause"
    );
    assert_eq!(
        standin_requests(&standin, "component-1"),
        vec![standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "start refused",
            Some("runtime")
        )],
        "the stand-in denies component-1's request as the runtime with the failure cause"
    );
    assert_eq!(
        (
            standin_capsule(&standin, "component-2"),
            standin_requests(&standin, "component-2"),
        ),
        (
            standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
            vec![standin_request_record(
                "request-2",
                "component-2",
                "pending",
                "",
                None
            )],
        ),
        "the stand-in keeps the failed instance's sibling starting with its request pending"
    );

    standin.set_instant(4);
    let granted = standin
        .post_capability_grant(
            StandInCaller::Shell,
            &json!({
                "request_id": "request-2",
                "duration": "session",
                "rationale": "grant shared read",
            }),
        )
        .expect("the stand-in grants the survivor's pending request");
    assert_eq!(
        granted,
        json!({"success": true}),
        "the stand-in answers success true for the survivor grant and stores no token"
    );
    assert_eq!(
        standin_capsule(&standin, "component-1"),
        standin_capsule_record(
            "component-1",
            STANDIN_FAILED_NAME,
            "failed",
            "start refused"
        ),
        "the stand-in keeps the failed instance failed after the survivor grant"
    );
    assert_eq!(
        standin_requests(&standin, "component-1"),
        vec![standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "start refused",
            Some("runtime")
        )],
        "the stand-in leaves the failed instance's denied record unchanged"
    );
    assert_eq!(
        standin_capsule(&standin, "component-2"),
        standin_capsule_record("component-2", STANDIN_SHARED_NAME, "starting", ""),
        "the stand-in keeps the granted survivor starting"
    );
    let live = standin_live_grants(&standin);
    let live_ids: BTreeSet<&str> = live
        .iter()
        .map(|grant| {
            grant["request_id"]
                .as_str()
                .expect("the stand-in names each live grant")
        })
        .collect();
    assert_eq!(
        live_ids,
        BTreeSet::from(["request-2"]),
        "the stand-in shows exactly the survivor's request as live"
    );
    assert_eq!(
        live[0]["session_id"], "component-2",
        "the stand-in binds the survivor grant to the survivor's session"
    );

    standin
        .finish_start("component-2")
        .expect("the stand-in finishes the survivor's start");
    assert_eq!(
        standin_capsule(&standin, "component-2"),
        standin_capsule_record("component-2", STANDIN_SHARED_NAME, "running", ""),
        "the stand-in runs the granted survivor after its start returns"
    );
    // The census refuses this live pair on its status row before it reads the
    // grant row. The survivor's live grant itself is the subject here, so this
    // row reads the shell live view through the route.
    assert_eq!(
        standin_live_grants(&standin),
        vec![json!({
            "request_id": "request-2",
            "session_id": "component-2",
            "resource": STANDIN_RESOURCE,
            "action": "read",
            "duration": "session",
            "granted_at": 4,
        })],
        "the stand-in keeps exactly the survivor grant live while the survivor runs"
    );

    standin
        .delete_capsule(
            StandInCaller::Shell,
            "component-2",
            &json!({"reason": "stop two"}),
        )
        .expect("the stand-in stops component-2");
    // As in the cancel run, the census's physical row needs the census module's
    // own host tools. The two stand-in routes carry the surviving rows.
    assert_eq!(
        standin_live_grants(&standin),
        Vec::<serde_json::Value>::new(),
        "the survivor stop revoked the last live grant"
    );
    assert!(
        !standin_requests(&standin, "component-2")
            .iter()
            .any(|request| request["status"] == "pending"),
        "the survivor stop settled the survivor's pending request"
    );
    assert_eq!(
        standin_requests(&standin, "component-1"),
        vec![standin_request_record(
            "request-1",
            "component-1",
            "denied",
            "start refused",
            Some("runtime")
        )],
        "the stand-in keeps the failed instance's denied record after the survivor stop"
    );
    home.finish()
        .expect("the stand-in failed-survivor run removes its throwaway home");
}
