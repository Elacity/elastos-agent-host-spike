#[path = "common/probe.rs"]
mod probe;

use agent_conformance::build::{lane, offline_build, repository};
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::{stage_probe, Observation, MANIFEST};
use agent_conformance::report::{render_run, table, GitIdentity};
use probe::{build_probe, Effect};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Output;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use wasmparser::{Encoding, Parser, Payload, Validator};

static PROBE_BUILD: Mutex<()> = Mutex::new(());

const BUILD_FIXTURE: &str = "probe_build_result_fixture";
const TOOL_STDOUT: &str = "synthetic-probe-tool-stdout";
const TOOL_STDERR: &str = "synthetic-probe-tool-stderr";
const BUILD_CONTINUED: &str = "probe build fixture continued";

#[test]
fn probe_build_result_fixture() {
    let directory = std::env::current_dir().unwrap();
    if directory.file_name().and_then(|name| name.to_str()) != Some("home")
        || directory.parent().and_then(Path::parent) != Some(lane().join("target").as_path())
        || !directory.join("probe-build-fixture").is_file()
    {
        return;
    }
    let home = ThrowawayHome::new().unwrap();
    let result = home.launch(
        &directory.join("probe-build-tool"),
        &[],
        Duration::from_secs(5),
    );
    if let Ok(output) = &result {
        assert!(
            output.stdout == TOOL_STDOUT.as_bytes(),
            "fixture tool stdout"
        );
        assert!(
            output.stderr == TOOL_STDERR.as_bytes(),
            "fixture tool stderr"
        );
    }
    home.finish().unwrap();
    probe::probe_build_output(result);
    println!("{BUILD_CONTINUED}");
}

fn build_fixture_home() -> ThrowawayHome {
    let home = ThrowawayHome::new().unwrap();
    home.guard(home.home(), home.data()).unwrap();
    fs::write(home.home().join("probe-build-fixture"), b"").unwrap();
    home
}

fn write_build_tool(home: &ThrowawayHome, status: u8) {
    home.guard(home.home(), home.data()).unwrap();
    let executable = home.home().join("probe-build-tool");
    fs::write(
        &executable,
        format!("#!/bin/sh\nprintf '{TOOL_STDOUT}'\nprintf '{TOOL_STDERR}' >&2\nexit {status}\n"),
    )
    .unwrap();
    fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
}

fn launch_build_fixture(home: &ThrowawayHome) -> Output {
    home.launch(
        &std::env::current_exe().unwrap(),
        &[
            BUILD_FIXTURE,
            "--exact",
            "--show-output",
            "--color",
            "never",
        ],
        Duration::from_secs(10),
    )
    .unwrap()
}

fn build_fixture_report(output: &Output, grade: &str) -> String {
    let captured = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let listed = format!("{BUILD_FIXTURE}: test\n");
    let (row, success) = table(&listed, &captured, output.status.success(), Some(""));
    assert!(
        row.contains(&format!("{BUILD_FIXTURE} | {grade}\n")),
        "fixture observed grade"
    );
    assert!(!success, "fixture table command failed");
    let report = render_run(
        &listed,
        &captured,
        output.status.success(),
        Ok(GitIdentity {
            commit: "a".repeat(40),
            dirty: true,
        }),
        Some(""),
    );
    assert!(
        report
            .table
            .contains(&format!("{BUILD_FIXTURE} | {grade}\n")),
        "fixture receipt grade"
    );
    let receipt: serde_json::Value = serde_json::from_slice(&report.receipt_bytes).unwrap();
    assert!(!report.passed, "fixture report command failed");
    assert_eq!(
        receipt["cargo_success"], false,
        "fixture real command status"
    );
    assert_eq!(
        receipt["command_success"], false,
        "fixture receipt command failed"
    );
    assert_eq!(
        receipt["identity_status"], "incomplete",
        "fixture identity stays incomplete"
    );
    for reason in [
        "missing Runtime SHA-256",
        "missing localhost-provider SHA-256",
        "missing launched probe identity",
    ] {
        assert!(
            report.failures.iter().any(|failure| failure == reason),
            "fixture missing identity retained"
        );
    }
    let receipt_text = String::from_utf8_lossy(&report.receipt_bytes);
    for text in [
        captured.as_str(),
        report.table.as_str(),
        receipt_text.as_ref(),
    ] {
        assert!(
            !text.contains(TOOL_STDOUT) && !text.contains(TOOL_STDERR),
            "fixture tool output stays private"
        );
    }
    captured
}

fn assert_build_continues(home: &ThrowawayHome) {
    write_build_tool(home, 0);
    let output = launch_build_fixture(home);
    assert!(
        output.status.success(),
        "fixture success continues normally"
    );
    let captured = String::from_utf8_lossy(&output.stdout);
    assert!(
        captured.lines().any(|line| line == BUILD_CONTINUED),
        "fixture continuation reached"
    );
    assert!(
        !captured.contains("SKIPPED ") && !captured.contains("FAILURE "),
        "fixture success has no refusal"
    );
    assert!(
        captured.contains("test result: ok."),
        "fixture success libtest result"
    );
}

#[test]
fn probe_build_failure_stays_fail() {
    let home = build_fixture_home();
    write_build_tool(&home, 31);
    let output = launch_build_fixture(&home);
    assert!(!output.status.success(), "failed build keeps failure exit");
    let reason = "probe build failed: exit status: 31";
    let captured = build_fixture_report(&output, &format!("FAIL | {reason}"));
    let marker = format!("FAILURE {BUILD_FIXTURE}: {reason}");
    assert_eq!(
        captured.lines().filter(|line| *line == marker).count(),
        1,
        "failed build exact marker"
    );
    assert_eq!(
        captured
            .lines()
            .filter(|line| line.starts_with("FAILURE "))
            .count(),
        1,
        "failed build one failure marker"
    );
    assert!(
        !captured.contains("SKIPPED "),
        "failed build has zero skipped markers"
    );
    assert!(
        captured.contains("test result: FAILED."),
        "failed build libtest result"
    );
    assert!(
        !captured.contains(BUILD_CONTINUED),
        "failed build returns no artifact continuation"
    );
    assert_build_continues(&home);
    home.finish().unwrap();
}

#[test]
fn probe_start_failure_stays_skipped() {
    let home = build_fixture_home();
    assert!(
        !home.home().join("probe-build-tool").exists(),
        "fixture executable is absent"
    );
    let output = launch_build_fixture(&home);
    assert!(!output.status.success(), "start failure keeps failure exit");
    let reason = "start probe build: could not start child process";
    let captured = build_fixture_report(&output, &format!("SKIPPED ({reason})"));
    let marker = format!("SKIPPED {BUILD_FIXTURE}: {reason}");
    assert_eq!(
        captured.lines().filter(|line| *line == marker).count(),
        1,
        "start failure exact marker"
    );
    assert_eq!(
        captured
            .lines()
            .filter(|line| line.starts_with("SKIPPED "))
            .count(),
        1,
        "start failure one skipped marker"
    );
    assert!(!captured.contains("FAILURE "), "start failure stays setup");
    assert!(
        captured.contains("test result: FAILED."),
        "start failure libtest result"
    );
    assert!(
        !captured.contains(BUILD_CONTINUED),
        "start failure has no continuation"
    );
    assert_build_continues(&home);
    home.finish().unwrap();
}

fn builds() -> &'static [(Effect, [Vec<u8>; 2]); 15] {
    static BUILDS: OnceLock<[(Effect, [Vec<u8>; 2]); 15]> = OnceLock::new();
    BUILDS.get_or_init(|| {
        let _serial = PROBE_BUILD.lock().unwrap();
        [
            Effect::Default,
            Effect::Read,
            Effect::HumanRead,
            Effect::MemoryWrite,
            Effect::Network,
            Effect::GrantedRead,
            Effect::SiblingRead,
            Effect::HostKeyRead,
            Effect::Instance1,
            Effect::Instance2,
            Effect::Task(0),
            Effect::Task(1),
            Effect::Task(2),
            Effect::Task(3),
            Effect::Runaway,
        ]
        .map(|effect| (effect, [build_probe(effect, 1), build_probe(effect, 2)]))
    })
}

fn imports(bytes: &[u8]) -> Result<Vec<String>, &'static str> {
    if !Parser::is_component(bytes) {
        return Err("probe artifact is not a component");
    }
    Validator::new()
        .validate_all(bytes)
        .map_err(|_| "probe component is invalid")?;
    let mut depth = 0;
    let mut names = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("validated component must parse") {
            Payload::Version {
                encoding: Encoding::Component | Encoding::Module,
                ..
            } => depth += 1,
            Payload::End(_) => depth -= 1,
            Payload::ComponentImportSection(section) if depth == 1 => {
                for import in section {
                    names.push(
                        import
                            .expect("validated component import must parse")
                            .name
                            .0
                            .to_owned(),
                    );
                }
            }
            _ => {}
        }
    }
    Ok(names)
}

fn allowed_import(name: &str) -> Result<(), &'static str> {
    // Match the Bus v1 admission subset used by the effect builds.
    match name {
        "elastos:bus/types@1.0.0"
        | "elastos:bus/runtime@1.0.0"
        | "elastos:bus/identity@1.0.0"
        | "elastos:bus/capabilities@1.0.0"
        | "elastos:bus/providers@1.0.0" => Ok(()),
        _ => Err("probe import is outside the supported ElastOS Bus interfaces"),
    }
}

#[test]
fn probe_imports_only_the_bus() {
    for artifact in builds().iter().flat_map(|(_, pair)| pair) {
        let names = imports(artifact).unwrap();
        assert!(!names.is_empty(), "the component must import the Bus types");
        for name in names {
            assert_eq!(allowed_import(&name), Ok(()), "unexpected import {name}");
        }
    }
}

#[test]
fn foreign_and_wrong_version_imports_are_refused() {
    for name in [
        "elastos:bus/capabilities@1.0.0",
        "elastos:bus/providers@1.0.0",
    ] {
        assert_eq!(allowed_import(name), Ok(()));
    }
    for name in [
        "wasi:cli/environment@0.2.0",
        "host:files/read@1.0.0",
        "elastos:bus/capabilities@2.0.0",
        "elastos:bus/providers@2.0.0",
        "elastos:bus/unknown@1.0.0",
        "elastos:bus/providers@1.0.0/extra",
    ] {
        assert_eq!(
            allowed_import(name),
            Err("probe import is outside the supported ElastOS Bus interfaces")
        );
    }
}

#[test]
fn non_component_and_invalid_component_are_refused() {
    assert_eq!(
        imports(b"not wasm"),
        Err("probe artifact is not a component")
    );
    assert_eq!(
        imports(b"\0asm\x01\0\0\0"),
        Err("probe artifact is not a component")
    );
    assert_eq!(
        imports(b"\0asm\x0d\0\x01\0\xff"),
        Err("probe component is invalid")
    );
}

#[test]
fn probe_hash_is_stable() {
    // Same-machine artifact evidence only. Cargo symbol hashes vary by host;
    // this SHA-256 is neither a published bundle CID nor Runtime admission.
    let mut hashes = std::collections::BTreeSet::new();
    for (effect, [first, second]) in builds() {
        let first_hash = format!("{:x}", Sha256::digest(first));
        let second_hash = format!("{:x}", Sha256::digest(second));
        assert_eq!(
            first_hash, second_hash,
            "independent {effect:?} builds differ"
        );
        assert!(
            hashes.insert(first_hash.clone()),
            "effects must have distinct bytes"
        );
        let home = ThrowawayHome::new().unwrap();
        let staged = stage_probe(&home, first, MANIFEST, effect.name()).unwrap();
        assert_eq!(staged.identity.component_sha256, first_hash);
        Observation::BuildOnly {
            probe: staged.identity,
        }
        .emit();
        home.finish().unwrap();
    }
}

#[test]
fn probe_manifest_names_the_current_bus_world() {
    let lane = lane();
    let root = repository();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(lane.join("probe/capsule.json")).unwrap()).unwrap();
    let wit = fs::read(root.join("elastos/wit/elastos-bus-v1.wit")).unwrap();
    assert_eq!(
        manifest["wit_world_sha256"],
        format!("{:x}", Sha256::digest(wit))
    );
    assert_eq!(manifest["runtime_abi"], "elastos.component/v1");
    assert_eq!(manifest["bus_contract"], "elastos:bus@v1");
    assert_eq!(manifest["execution"], "component");
    let entrypoint = manifest["entrypoint"].as_str().unwrap();
    assert_eq!(Path::new(entrypoint).components().count(), 1);
    assert_eq!(entrypoint, "agent-conformance-probe.component.wasm");
    assert_eq!(
        manifest["capabilities"],
        serde_json::json!(["localhost://Public/agent-conformance-grants/*"])
    );
}

#[test]
fn probe_effects_are_exclusive() {
    let _serial = PROBE_BUILD.lock().unwrap();
    let features = [
        "read",
        "network",
        "task",
        "runaway",
        "granted-read",
        "sibling-read",
        "host-key-read",
        "memory-write",
    ];
    for (index, first) in features.iter().enumerate() {
        for second in &features[index + 1..] {
            let pair = format!("{first},{second}");
            let output = offline_build("cargo", &lane().join("target/probe-feature-check"))
                .unwrap()
                .args([
                    "check",
                    "--locked",
                    "--offline",
                    "--manifest-path",
                    "lab/agent-conformance/probe/Cargo.toml",
                    "--features",
                    &pair,
                ])
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .output()
                .unwrap();
            assert!(!output.status.success(), "two effects must be refused");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("select exactly one probe effect")
            );
        }
    }
}

#[test]
fn instance_subselectors_require_one_granted_read() {
    let _serial = PROBE_BUILD.lock().unwrap();
    for (flags, reason) in [
        ("--cfg feature=\"instance-1\"", "instance requires granted-read"),
        ("--cfg feature=\"instance-2\"", "instance requires granted-read"),
        ("--cfg feature=\"granted-read\" --cfg feature=\"instance-1\" --cfg feature=\"instance-2\"", "select exactly one instance"),
    ] {
        let output = offline_build("cargo", &lane().join("target/probe-feature-check"))
            .unwrap()
            .args(["check", "--locked", "--offline", "--manifest-path", "lab/agent-conformance/probe/Cargo.toml"])
            .env("RUSTFLAGS", flags)
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .output().unwrap();
        assert!(!output.status.success(), "invalid instance selector must be refused");
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
    }
}
