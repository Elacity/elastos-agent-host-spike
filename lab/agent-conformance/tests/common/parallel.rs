//! Process-isolation fallback: diagnostic completions, not Bus success payloads.

use super::{build_probe, common, stage_probe, Effect, EFFECT_RUN};
use agent_conformance::harness::{Completion, Launch, RunningInstances, ThrowawayHome};
use agent_conformance::runtime::runtime_under_test;
use std::fs;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const BOUND: Duration = Duration::from_secs(10);
const RESULTS: [&str; 4] = [
    "conformance completed task-a result:40",
    "conformance completed task-b result:66",
    "conformance completed task-c result:94",
    "conformance completed task-d result:140",
];

fn artifacts() -> &'static [Vec<u8>; 5] {
    static BUILDS: OnceLock<[Vec<u8>; 5]> = OnceLock::new();
    BUILDS.get_or_init(|| {
        [
            Effect::Task(0),
            Effect::Task(1),
            Effect::Task(2),
            Effect::Task(3),
            Effect::Runaway,
        ]
        .map(|effect| build_probe(effect, 1))
    })
}

fn exercise(runaway: bool, require_reason: bool) -> Vec<Completion> {
    // Share task 003's build lock and Runtime cache, including when two tests run.
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let builds = artifacts();
    let runtime = runtime_under_test()
        .unwrap_or_else(|_| super::probe::skipped("Runtime build failed before launch"));
    let operator_home = ThrowawayHome::new().unwrap();
    let homes = [(); 4].map(|_| ThrowawayHome::new().unwrap());
    let capsules: Vec<_> = homes
        .iter()
        .enumerate()
        .map(|(index, home)| {
            home.guard(home.home(), home.data()).unwrap();
            fs::write(
                home.data().join("config.toml"),
                include_bytes!("../../fixtures/operator-config.toml"),
            )
            .unwrap();
            let selected = if runaway && index == 0 { 4 } else { index };
            let effect = if selected == 4 {
                Effect::Runaway
            } else {
                Effect::Task(selected as u8)
            };
            stage_probe(home, &builds[selected], effect)
        })
        .collect();

    let mut operator = common::operator::Operator::start(&operator_home).unwrap_or_else(|_| {
        super::probe::skipped("operator setup or loopback bind failed before probe launch")
    });
    operator.ready().expect("operator ready");
    let first = operator.census().expect("ready socket census");
    let sampled = Instant::now();
    let launches: Vec<_> = homes
        .iter()
        .zip(&capsules)
        .map(|(home, capsule)| Launch {
            home,
            program: &runtime.binary,
            args: vec!["run", capsule.to_str().unwrap()],
        })
        .collect();
    let running = RunningInstances::start(&launches, Some(&operator_home))
        .expect("start all four clients before collection");
    let collected = running.collect(BOUND);
    while sampled.elapsed() < Duration::from_secs(3) {
        operator.require_alive().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    let second = operator.census().expect("final socket census");
    operator.child.stop().expect("stop operator group");
    drop(operator);
    println!("operator census: {first} then {second} loopback sockets; four clients, one operator; group stopped");
    let completions =
        collected.expect("natural client exits within shared bound; harness kills cannot pass");
    assert_results(&completions, runaway, require_reason);
    for home in homes {
        home.finish().unwrap();
    }
    operator_home.finish().unwrap();
    completions
}

fn assert_results(completions: &[Completion], runaway: bool, require_reason: bool) {
    assert_eq!(completions.len(), 4);
    for (index, completion) in completions.iter().enumerate() {
        assert!(completion.elapsed < BOUND);
        let output = &completion.output;
        let stderr = std::str::from_utf8(&output.stderr).expect("client stderr UTF-8");
        let stdout = std::str::from_utf8(&output.stdout).expect("client stdout UTF-8");
        let result = if runaway && index == 0 {
            let reason = stderr.contains("Component lifecycle run failed:")
                && stderr.contains("all fuel consumed");
            println!(
                "parallel process isolation: runaway exit:{:?} fuel_reason:{reason} elapsed:{:.3}s",
                output.status.code(),
                completion.elapsed.as_secs_f64()
            );
            assert_eq!(
                output.status.code(),
                Some(1),
                "Runtime must report a failure, not a signal"
            );
            assert!(
                stderr.contains("Component capsule failed:")
                    && stderr.contains("Component lifecycle run failed:")
                    && stderr.contains("error while executing at wasm backtrace:"),
                "Runtime must report a lifecycle trap, not admission or attach failure"
            );
            if require_reason {
                assert!(reason, "Runtime must expose the fuel exhaustion reason");
            }
            None
        } else {
            let expected = format!(
                "Component capsule denied: BusError::Unavailable(\"{}\")",
                RESULTS[index]
            );
            let observed = stderr.contains("Component capsule failed:")
                && stderr.matches(&expected).count() == 1;
            println!("parallel process isolation: task:{index} exit:{:?} own_result:{observed} elapsed:{:.3}s", output.status.code(), completion.elapsed.as_secs_f64());
            assert_eq!(
                output.status.code(),
                Some(1),
                "diagnostic completion uses the Bus error channel"
            );
            assert!(observed, "expected exactly this task's computed diagnostic");
            Some(index)
        };
        for (other, marker) in RESULTS.iter().enumerate() {
            if Some(other) != result {
                assert!(
                    !stderr.contains(marker) && !stdout.contains(marker),
                    "a sibling result reached this client"
                );
            }
        }
    }
}

#[test]
fn parallel_instances_complete_independently() {
    exercise(false, false);
}

#[test]
fn runaway_trap_is_bounded_while_siblings_finish() {
    exercise(true, false);
}

#[test]
#[ignore = "blocked: AC-005-REASON"]
fn runaway_is_stopped_with_reason() {
    exercise(true, true);
}
