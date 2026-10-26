#[allow(dead_code)]
#[path = "common/grants.rs"]
mod agent_host_grants;
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::build::{copy_agent_host, lane, offline_build, repository};
use agent_conformance::harness::{Launch, RunningInstances, ThrowawayHome};
use agent_conformance::identity::{stage_probe, Observation};
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const TEST: &str = "real_agent_host_gets_no_ungranted_authority";
const JOURNAL: &str = "localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal";

fn build_agent_host(home: &ThrowawayHome) -> (Vec<u8>, Vec<u8>) {
    let tree = home.root().join("build-inputs");
    fs::create_dir_all(tree.join("examples")).unwrap();
    let copy = tree.join("examples/agent-host");
    copy_agent_host(&repository().join("examples/agent-host"), &copy)
        .expect("copy the real capsule's listed inputs");
    // Preserve the guest's relative WIT lookup without editing its source or
    // writing into the repository contract. The contract is outside the copy.
    fs::create_dir_all(tree.join("elastos/wit")).unwrap();
    let wit = repository().join("elastos/wit/elastos-bus-v1.wit");
    assert!(fs::symlink_metadata(&wit).unwrap().is_file());
    fs::copy(wit, tree.join("elastos/wit/elastos-bus-v1.wit")).unwrap();
    let started = Instant::now();
    let output = offline_build("bash", &lane().join("target/real-agent-host-build"))
        .expect("prepare lane-owned build output")
        .arg(repository().join("scripts/build-component-capsule.sh"))
        .arg(&copy)
        .env("RUSTFLAGS", "-Dwarnings")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .expect("start the offline component build");
    println!("agent-host build: {:.3}s", started.elapsed().as_secs_f64());
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("attempting to make an HTTP request, but --offline was specified")
            || (stderr.contains("no matching package named") && stderr.contains("offline"))
        {
            probe::skipped("agent-host offline build prerequisite: cached crate unavailable");
        }
        panic!(
            "agent-host source/build failure ({}): {stderr}",
            output.status
        );
    }
    (
        fs::read(copy.join("agent-host.component.wasm")).expect("built real component"),
        fs::read(copy.join("capsule.json")).expect("copied real manifest"),
    )
}

// Inspect names and metadata only, including the Runtime's data directories.
fn no_journal(path: &Path) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|_| "journal census could not list a directory")? {
        let entry = entry.map_err(|_| "journal census could not inspect an entry")?;
        let path = entry.path();
        if entry.file_name() == "journal"
            || (entry.file_name() == "Agents"
                && path.parent().and_then(Path::file_name) == Some(".AppData".as_ref()))
        {
            return Err("agent-host journal census: journal or .AppData/Agents path exists".into());
        }
        let kind = entry
            .file_type()
            .map_err(|_| "journal census could not read entry type")?;
        if kind.is_symlink() {
            return Err("agent-host journal census refuses a symlink".into());
        }
        if kind.is_dir() {
            no_journal(&path)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "blocked: UsersAI binding"]
fn real_agent_host_gets_no_ungranted_authority() {
    let home = ThrowawayHome::new().unwrap_or_else(|reason| probe::skipped(reason));
    let (bytes, manifest) = build_agent_host(&home);
    let capsule = stage_probe(&home, &bytes, &manifest, "agent-host")
        .expect("name the real capsule through the shared bundle stager");
    let runtime = runtime_under_test().unwrap_or_else(|reason| probe::skipped(reason));
    let mut operator = common::operator::Operator::start(&home)
        .unwrap_or_else(|reason| probe::skipped(&format!("operator prerequisite: {reason}")));
    let sampled = operator
        .begin_check()
        .expect("ready offline operator and first census");
    let mut controller = agent_host_grants::Controller::attach(
        &home,
        operator.port,
        agent_host_grants::Fixture::committed().unwrap(),
    )
    .expect("attach the existing fixture controller");
    controller
        .cleanup_state()
        .expect("empty pending list before this run");
    let launches = [Launch {
        home: &home,
        program: &runtime.binary,
        args: vec!["run", capsule.path.to_str().unwrap()],
    }];
    let running = RunningInstances::start(&launches, Some(&home)).expect("launch the real capsule");
    let observation = Observation::Launched {
        probe: capsule.identity,
    };
    controller.print_checked(&observation.line()).unwrap();
    let collected =
        running.collect_with(Duration::from_secs(20), |running| controller.poll(running));
    let requests = controller.check_requests(&[
        (JOURNAL, "write", "Agent Host task journal"),
        (JOURNAL, "read", "Agent Host task journal"),
    ]);
    let cleanup = controller.cleanup_state();
    let finished = operator.finish_check(sampled);
    controller
        .check_captures(&home)
        .expect("captures exclude fixture credentials");
    controller
        .check_sources()
        .expect("lane sources exclude fixture credentials");
    let journal = no_journal(home.root());
    let decisions = &controller.decisions;
    controller
        .print_checked(&format!(
            "agent-host decisions: matched:{} granted:{} denied:{}; reason:{}",
            decisions.matched,
            decisions.granted,
            decisions.denied,
            controller.deny_reason(),
        ))
        .unwrap();
    controller
        .print_checked(match &finished {
            Ok(line) | Err(line) => line,
        })
        .unwrap();
    let result = (|| -> Result<(), String> {
        requests?;
        if (decisions.matched, decisions.granted, decisions.denied) != (0, 0, 2) {
            return Err("agent-host requires matched:0 granted:0 denied:2".into());
        }
        let completions = collected?;
        let output = &completions[0].output;
        if output.status.code() != Some(0) {
            let reason = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!(
                "agent-host expected exit 0, got {}; {reason}",
                output.status
            ));
        }
        journal?;
        cleanup?;
        finished?;
        Ok(())
    })();
    if let Err(reason) = &result {
        controller
            .print_checked(&format!("FAILURE {TEST}: {reason}"))
            .unwrap();
    }
    let observations = [
        Observation::Native {
            role: "elastos".into(),
            sha256: runtime.sha256.clone(),
        },
        Observation::Native {
            role: "localhost-provider".into(),
            sha256: localhost_provider_under_test().unwrap().sha256.clone(),
        },
        observation,
    ];
    controller
        .check_journey(TEST, &observations, result.is_ok())
        .expect("printed lines, report and receipt exclude fixture credentials");
    result.expect("real agent-host deny journey");
    home.finish().unwrap();
}

#[test]
fn agent_host_journal_census_detects_planted_paths() {
    let home = ThrowawayHome::new().unwrap();
    no_journal(home.root()).unwrap();
    let journal = home.data().join("journal");
    fs::write(&journal, b"synthetic journal").unwrap();
    assert!(
        no_journal(home.root()).is_err(),
        "journal file must fail the census"
    );
    fs::remove_file(journal).unwrap();
    let agents = home.data().join("Users/fixture/.AppData/Agents");
    fs::create_dir_all(&agents).unwrap();
    assert!(
        no_journal(home.root()).is_err(),
        "Agents directory must fail the census"
    );
    fs::remove_dir(agents).unwrap();
    no_journal(home.root()).unwrap();
    home.finish().unwrap();
}
