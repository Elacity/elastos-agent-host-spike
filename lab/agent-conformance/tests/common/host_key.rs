//! A fake host file, outside every Home root, through the existing Bus journey.

use super::{common, grants, probe, refusal_evidence, stage_probe, EFFECT_RUN};
use agent_conformance::harness::{Launch, RunningInstances, ThrowawayHome};
use agent_conformance::identity::Observation;
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use probe::{build_probe, Effect};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

const RESOURCE: &str = include_str!("../../fixtures/host-key-read.txt");
const FAKE: &[u8] = include_bytes!("../../fixtures/fake-ssh/id_ed25519");

fn seed(home: &ThrowawayHome) -> Result<PathBuf, Box<dyn std::error::Error>> {
    home.guard(home.home(), home.data())?;
    // Exclusive creation refuses an existing directory or symlink. The fixture
    // path is fixed inside the guarded home; the resource is never a host path.
    let directory = home.home().join(".ssh");
    fs::create_dir(&directory)?;
    let path = directory.join("id_ed25519");
    File::create_new(&path)?.write_all(FAKE)?;
    Ok(path)
}

fn unchanged(home: &ThrowawayHome, path: &std::path::Path) -> bool {
    home.guard(home.home(), home.data()).unwrap();
    let directory = fs::symlink_metadata(home.home().join(".ssh")).unwrap();
    let file = fs::symlink_metadata(path).unwrap();
    assert!(directory.is_dir() && !directory.file_type().is_symlink());
    assert!(file.is_file() && !file.file_type().is_symlink());
    fs::read(path).unwrap() == FAKE
}

#[test]
fn fixture_path_uses_the_guarded_home_rule() {
    let home = ThrowawayHome::new().unwrap();
    let path = seed(&home).unwrap();
    assert!(unchanged(&home, &path));
    assert!(seed(&home).is_err(), "existing fixture must be preserved");
    // Derive the relative depth from the one data-dir rule, without resolving
    // or reading any candidate target. This is a lexical fixture check only.
    let depth = home
        .data()
        .strip_prefix(home.home())
        .unwrap()
        .components()
        .count()
        + 1;
    assert_eq!(
        RESOURCE.trim(),
        format!("localhost://Public/{}.ssh/id_ed25519", "../".repeat(depth))
    );
    assert!(!path.starts_with(home.data()));
    home.finish().unwrap();
}

pub fn exercise() {
    let _serial = EFFECT_RUN.lock().unwrap_or_else(|error| error.into_inner());
    let effect = Effect::HostKeyRead;
    let bytes = build_probe(effect, 1);
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    let fake_path = seed(&home).expect("seed only the fake host fixture");
    let capsule = stage_probe(&home, &bytes, effect);
    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    let mut controller =
        grants::Controller::attach(&home, operator.port, grants::Fixture::committed().unwrap())
            .expect("fixture shell controller attaches once");
    let running = RunningInstances::start(
        &[Launch {
            home: &home,
            program: &runtime.binary,
            args: vec!["run", capsule.path.to_str().unwrap()],
        }],
        Some(&home),
    )
    .unwrap_or_else(|reason| probe::skipped(reason));
    let launched = Observation::Launched {
        probe: capsule.identity,
    };
    controller.print_checked(&launched.line()).unwrap();
    let collected =
        running.collect_with(Duration::from_secs(10), |running| controller.poll(running));
    let census = operator
        .finish_check(sampled)
        .expect("final census and operator group stop");
    controller.print_checked(&census).unwrap();
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    let completions = collected.expect("controller and probe finish within their bounds");
    assert_eq!(completions.len(), 1);
    let output = &completions[0].output;
    let reason = format!(
        "Internal(\"capsule manifest does not declare authority for {}\")",
        RESOURCE.trim()
    );
    let (line, refused) = refusal_evidence(output, effect, &reason);
    controller.print_checked(&line).unwrap();
    let marker_absent = [&output.stdout, &output.stderr].iter().all(|capture| {
        // Exclude the complete marker even if the output strips its newline.
        !capture
            .windows(FAKE.len() - 1)
            .any(|part| part == &FAKE[..FAKE.len() - 1])
    });
    let provider_refusal =
        String::from_utf8_lossy(&output.stderr).contains("Path traversal not allowed");
    let intact = unchanged(&home, &fake_path);
    let decisions = &controller.decisions;
    let no_decision = decisions.matched == 0 && decisions.granted == 0 && decisions.denied == 0;
    let passed = refused && marker_absent && intact && no_decision;
    controller.print_checked(&format!(
        "host key read: exit:{:?} matched:{} granted:{} denied:{} marker_absent:{marker_absent} unchanged:{intact} provider_traversal_refusal:{provider_refusal}",
        output.status.code(), decisions.matched, decisions.granted, decisions.denied,
    )).unwrap();
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    controller
        .check_journey(
            "host_key_read_is_refused",
            &[
                Observation::Native {
                    role: "elastos".into(),
                    sha256: runtime.sha256.clone(),
                },
                Observation::Native {
                    role: "localhost-provider".into(),
                    sha256: localhost_provider_under_test().unwrap().sha256.clone(),
                },
                launched,
            ],
            passed,
        )
        .expect("printed journey, report and receipt exclude fixture credentials");
    // These checks also run after a planted grant. Its changed refusal must
    // fail only after all credential surfaces and receipt identities are checked.
    assert!(marker_absent, "fake fixture output requires private triage");
    assert!(intact, "fake host fixture bytes changed");
    assert!(refused, "expected exact manifest-bound lifecycle refusal");
    assert!(
        no_decision,
        "manifest refusal must precede operator decisions"
    );
    home.finish().unwrap();
}
