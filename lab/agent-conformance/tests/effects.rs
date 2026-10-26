mod common;
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::{Observation, StagedProbe, MANIFEST};
use agent_conformance::runtime::runtime_under_test;
use probe::{build_probe, Effect};
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
            .and_then(|completions| {
                instance_read_result(
                    completions,
                    &controller,
                    outcome,
                    settlement.as_ref().ok().and_then(Option::as_ref),
                )
            });
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
    controller
        .check_report(
            match outcome {
                ReadOutcome::Granted => "granted_read_succeeds",
                ReadOutcome::Denied => "ungranted_sibling_read_is_refused",
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
    settlement: Option<&grants::Settlement>,
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
    let denials = if outcome == ReadOutcome::Kill {
        1 + settlement
            .ok_or("kill: orphan measurement is missing")?
            .before
    } else {
        2
    };
    if controller.decisions.matched != grants
        || controller.decisions.granted != grants
        || controller.decisions.denied != denials
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
