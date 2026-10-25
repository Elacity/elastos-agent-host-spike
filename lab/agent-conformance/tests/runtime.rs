mod common;

use agent_conformance::build::{lane, repository};
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

const REFUSAL: &str = "This command requires a running runtime.";

fn run_probe(home: &ThrowawayHome) -> String {
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    // Locate the same probe from the launch cwd without putting a private
    // checkout path into Runtime's stderr and the recorded test evidence.
    let probe: PathBuf = home
        .home()
        .strip_prefix(lane())
        .unwrap()
        .components()
        .map(|_| "..")
        .chain(["probe"])
        .collect();
    let output = home
        .launch(
            &runtime.binary,
            &["run", probe.to_str().unwrap()],
            Duration::from_secs(10),
        )
        .expect("launch through the throwaway Home primitive");
    let stderr = String::from_utf8(output.stderr).expect("Runtime stderr must be UTF-8");
    assert!(
        !output.status.success(),
        "Runtime must refuse without an operator"
    );
    assert!(
        stderr.contains(REFUSAL),
        "expected operator refusal; stderr:\n{stderr}"
    );
    stderr
}

#[test]
fn run_without_operator_is_refused_with_reason() {
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    // Identification only: compare the returned digest against the actual bytes
    // with the existing test dependency, and check repeated access shares it.
    assert!(runtime.binary.is_absolute());
    assert!(std::ptr::eq(runtime, runtime_under_test().unwrap()));
    assert_eq!(
        runtime.sha256,
        format!("{:x}", Sha256::digest(fs::read(&runtime.binary).unwrap()))
    );
    let home = ThrowawayHome::new().unwrap();
    let stderr = run_probe(&home);
    println!("Runtime refusal stderr: {stderr:?}");
    home.finish().unwrap();
}

#[test]
fn runtime_data_dir_is_under_throwaway_home() {
    let home = ThrowawayHome::new().unwrap();
    // The guard and decoy use the one data-dir rule. Runtime resolves its own
    // path; a wrong harness rule leaves this file behind (F-ac1f).
    let decoy = home.data().join("runtime-coords.json");
    fs::write(
        &decoy,
        br#"{"api_url":"http://192.0.2.1:9","attach_secret":"dummy-fixture","pid":0}"#,
    )
    .unwrap();
    run_probe(&home);
    assert!(
        !decoy.try_exists().unwrap(),
        "Runtime must remove the decoy from the guarded data directory"
    );
    home.finish().unwrap();
}

#[test]
fn serve_refuses_provider_whose_bytes_differ_from_its_hash() {
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    let home = ThrowawayHome::new().unwrap();
    let installed =
        common::write_operator_home(&home).expect("install the guarded operator fixture");
    let provider = localhost_provider_under_test().unwrap();
    assert!(provider.binary.is_absolute());
    assert!(std::ptr::eq(
        provider,
        localhost_provider_under_test().unwrap()
    ));
    assert_eq!(
        provider.sha256,
        format!("{:x}", Sha256::digest(fs::read(&installed).unwrap()))
    );
    fs::OpenOptions::new()
        .append(true)
        .open(installed)
        .unwrap()
        .write_all(&[0])
        .unwrap();

    let port = TcpListener::bind("127.0.0.1:0").expect("reserve a free loopback port");
    let addr = port.local_addr().unwrap().to_string();
    drop(port);
    let storage = home.root().join("storage");
    let output = home
        .launch(
            &runtime.binary,
            &[
                "serve",
                "--addr",
                &addr,
                "--storage-path",
                storage.to_str().unwrap(),
            ],
            Duration::from_secs(10),
        )
        .expect("serve must refuse within its time bound");
    let stderr = String::from_utf8(output.stderr)
        .expect("Runtime stderr must be UTF-8")
        .replace(repository().to_str().unwrap(), "<lane>");
    assert!(
        !output.status.success(),
        "serve must refuse changed provider bytes"
    );
    assert!(
        stderr.contains("localhost-provider") && stderr.contains("failed checksum verification"),
        "expected provider checksum refusal; stderr:\n{stderr}"
    );
    assert!(
        !home
            .data()
            .join("runtime-coords.json")
            .try_exists()
            .unwrap(),
        "serve must stop before readiness coordinates"
    );
    assert!(storage.is_dir(), "serve must use the in-root storage path");
    println!("Provider refusal stderr: {stderr:?}");
    home.finish().unwrap();
}
