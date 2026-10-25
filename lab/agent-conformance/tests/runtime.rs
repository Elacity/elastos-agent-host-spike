mod common;

use agent_conformance::build::lane;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
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
    let installed = common::write_operator_home(&home).expect("install the operator fixture");
    let provider = localhost_provider_under_test().unwrap();
    assert!(provider.binary.is_absolute());
    assert!(std::ptr::eq(
        provider,
        localhost_provider_under_test().unwrap()
    ));
    let bytes = fs::read(&installed).unwrap();
    assert_eq!(provider.sha256, format!("{:x}", Sha256::digest(&bytes)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o111,
            0o111
        );
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(home.data().join("components.json")).unwrap()).unwrap();
    assert_eq!(manifest.as_object().unwrap().len(), 2);
    assert_eq!(manifest["external"].as_object().unwrap().len(), 1);
    assert_eq!(manifest["profiles"], serde_json::json!({}));
    let info = &manifest["external"]["localhost-provider"]["platforms"]
        [common::operator_platform().unwrap()];
    assert_eq!(info["checksum"], format!("sha256:{}", provider.sha256));
    assert_eq!(info["size"], bytes.len());
    assert_eq!(info["install_path"], "bin/localhost-provider");
    OpenOptions::new()
        .append(true)
        .open(&installed)
        .unwrap()
        .write_all(&[0])
        .unwrap();

    // Select a free loopback port without connecting. Verification must refuse
    // before Runtime reaches either Carrier or the HTTP listener.
    let port = TcpListener::bind("127.0.0.1:0").unwrap();
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
        .expect("serve must return within its bound through the one launch primitive");
    let stderr = String::from_utf8(output.stderr)
        .expect("Runtime stderr must be UTF-8")
        .replace(lane().to_str().unwrap(), "<lane>");
    println!("Provider refusal stderr: {stderr:?}");
    assert!(
        !output.status.success(),
        "serve must refuse the changed provider"
    );
    assert!(
        stderr.contains("localhost-provider") && stderr.contains("failed checksum verification"),
        "expected provider checksum refusal; stderr:\n{stderr}"
    );
    assert!(!home
        .data()
        .join("runtime-coords.json")
        .try_exists()
        .unwrap());
    assert!(
        storage.is_dir(),
        "serve must create the in-root storage directory"
    );
    home.finish().unwrap();
}
