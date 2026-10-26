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

fn run_by_synthetic_cid(home: &ThrowawayHome) -> String {
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    // Provider resolution refuses before CID validation. These refusals give
    // no evidence that the CID itself was checked, and need no probe build.
    let cid = capsule_identity::encode_entries(&[capsule_identity::BundleEntry {
        path: "synthetic.bin".into(),
        content: b"CID launch refusal fixture".to_vec(),
    }])
    .unwrap()
    .to_string();
    let output = home
        .launch(
            &runtime.binary,
            &["run", "--cid", &cid],
            Duration::from_secs(10),
        )
        .expect("CID launch must return within its bound through the one primitive");
    assert!(!output.status.success(), "CID launch must be refused");
    String::from_utf8(output.stderr).expect("Runtime stderr must be UTF-8")
}

fn assert_no_materialized_capsule(home: &ThrowawayHome) {
    assert!(
        fs::read_dir(home.temp()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("elastos-capsule-")),
        "refused CID launch must leave no materialized capsule in TMPDIR"
    );
}

#[test]
fn run_by_cid_without_content_provider_is_refused() {
    let home = ThrowawayHome::new().unwrap();
    assert!(!home.data().join("components.json").try_exists().unwrap());
    let stderr = run_by_synthetic_cid(&home);
    assert!(
        stderr.contains("ipfs-provider not found"),
        "expected missing content provider refusal; stderr:\n{stderr}"
    );
    assert_no_materialized_capsule(&home);
    home.finish().unwrap();
}

#[test]
fn run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash() {
    let home = ThrowawayHome::new().unwrap();
    let script = b"#!/bin/sh\n: > \"$HOME/../cid-provider-started\"\nexit 1\n";
    let checksum = format!(
        "{:x}",
        Sha256::digest(b"uninstalled content provider fixture\n")
    );
    let installed = home.data().join("bin/ipfs-provider");
    common::write_component_home(&home, "ipfs-provider", &installed, script, &checksum)
        .expect("install the content provider refusal fixture");
    let stderr = run_by_synthetic_cid(&home);
    assert!(
        !home
            .root()
            .join("cid-provider-started")
            .try_exists()
            .unwrap(),
        "checksum refusal must happen before the content provider script is spawned"
    );
    let refusal = format!(
        "installed component 'ipfs-provider' at {} failed checksum verification against {}",
        installed.display(),
        home.data().join("components.json").display()
    );
    assert!(
        stderr.lines().any(|line| line.contains(&refusal)),
        "expected the complete content provider checksum refusal on one line; stderr:\n{stderr}"
    );
    assert_no_materialized_capsule(&home);
    home.finish().unwrap();
}

#[test]
#[ignore = "blocked: AC-025-CID"]
fn capsule_named_by_hash() {
    // Stage the probe, make its bundle CID available offline, run it by --cid,
    // and require the same activation result as the directory launch.
    panic!("blocked: AC-025-CID — requires a provider-resolvable bundle CID and an isolated offline content fixture");
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

#[test]
fn fixture_operator_starts_ready_and_stops_cleanly() {
    let home = ThrowawayHome::new().unwrap();
    let mut operator =
        common::operator::Operator::start(&home).expect("install and start operator");
    operator.ready().expect("operator readiness");
    assert_eq!(
        fs::read(home.data().join("config.toml")).unwrap(),
        include_bytes!("../fixtures/operator-config.toml")
    );
    assert!(home.root().join("storage").is_dir());
    // Also check this operator before retaining it for any later fixture work.
    let sampled = operator
        .begin_check()
        .expect("ready operator socket census");
    let pgid = operator.child.pgid();
    println!(
        "{}",
        operator
            .finish_check(sampled)
            .expect("operator stop and cleanup census")
    );
    assert!(!home.group_is_alive(pgid).unwrap());
    home.finish().unwrap();
}

#[test]
fn fixture_operator_sockets_are_loopback_only() {
    let home = ThrowawayHome::new().unwrap();
    let mut operator =
        common::operator::Operator::start(&home).expect("install and start operator");
    let sampled = operator
        .begin_check()
        .expect("operator ready and first census");
    println!(
        "{}",
        operator
            .finish_check(sampled)
            .expect("final census and operator group stop")
    );
    home.finish().unwrap();
}

#[test]
fn socket_census_requires_parseable_loopback_endpoints_and_api_listener() {
    use common::operator::loopback_socket_count;
    let api = "p123\nf12\ntIPv4\nPTCP\nn127.0.0.1:9000\nTST=LISTEN\n";
    let udp = "f13\ntIPv6\nPUDP\nn[::1]:4321\n";
    let connected = "f14\ntIPv4\nPTCP\nn127.0.0.1:12->127.0.0.1:13\nTST=ESTABLISHED\n";
    assert_eq!(
        loopback_socket_count(&format!("{api}{udp}{connected}"), 9000),
        Ok(3)
    );
    for invalid in [
        String::new(),
        "unparseable".into(),
        api.replace("9000", "9001"),
        api.replace("127.0.0.1", "*"),
        api.replace("127.0.0.1", "0.0.0.0"),
        api.replace("127.0.0.1", "127.0.0.2"),
        api.replace("TST=LISTEN", "TST=ESTABLISHED"),
        api.replace("tIPv4\n", ""),
        api.replace("n127.0.0.1:9000", "n127.0.0.1:9000\nn127.0.0.1:9000"),
        format!("{api}{}", connected.replace("->127.0.0.1", "->192.0.2.1")),
        format!("{api}{}", udp.replace("[::1]", "[::]")),
        format!("{api}f20\ntIPv4\nPUDP\nnunknown\n"),
    ] {
        assert!(
            loopback_socket_count(&invalid, 9000).is_err(),
            "census must refuse incomplete or non-loopback evidence"
        );
    }
}

#[test]
fn cleanup_census_refuses_each_leftover() {
    use agent_conformance::census::cleanup;
    let home = ThrowawayHome::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let reason = cleanup(&home, port).unwrap_err();
    assert!(reason.contains("API socket leftover"), "{reason}");
    let captures = home.capture_paths().unwrap();
    assert_eq!(
        captures.len(),
        1,
        "the census capture belongs to the same inventory"
    );
    assert!(captures[0].iter().all(|path| path.is_file()));
    drop(listener);

    let planted = home.temp().join("planted");
    fs::write(&planted, b"cleanup fixture").unwrap();
    let reason = cleanup(&home, port).unwrap_err();
    assert!(reason.contains("temp leftover"));
    assert!(reason.contains("tmp/planted"));
    assert!(reason.contains(home.root().file_name().unwrap().to_str().unwrap()));
    fs::remove_file(planted).unwrap();

    let mut child = home
        .start(
            std::path::Path::new("/bin/sh"),
            &["-c", "cd \"$HOME/..\"; exec /bin/sleep 20"],
        )
        .unwrap();
    let reason = cleanup(&home, port).unwrap_err();
    assert!(reason.contains("process leftover"));
    assert!(reason.contains("processes:1"));
    assert!(reason.contains("\".\""), "root cwd must be visible");
    child.stop().unwrap();
    drop(child);

    let line = cleanup(&home, port).unwrap();
    assert!(line.contains("processes:0 paths:[] API sockets:0 temp:0 paths:[]"));
    assert!(line.contains("excludes only test PID"));
    home.finish().unwrap();
}

#[test]
fn cleanup_root_selection_finds_other_groups() {
    use agent_conformance::census::root_holders;
    let first = ThrowawayHome::new().unwrap();
    let second = ThrowawayHome::new().unwrap();
    let mut a = first
        .start(std::path::Path::new("/bin/sleep"), &["20"])
        .unwrap();
    let mut b = second
        .start(std::path::Path::new("/bin/sleep"), &["20"])
        .unwrap();
    let roots = [first.root().to_owned(), second.root().to_owned()];
    let holders = root_holders(&first, &roots).unwrap();
    for (home, child) in [(&first, &a), (&second, &b)] {
        assert!(holders.iter().any(|holder| holder.pid == child.pgid()
            && holder.root == home.root().file_name().unwrap().to_str().unwrap()
            && holder.path == "home"));
    }
    assert!(a.is_alive().unwrap() && b.is_alive().unwrap());
    a.stop().unwrap();
    b.stop().unwrap();
    drop((a, b));
    assert!(root_holders(&first, &roots).unwrap().is_empty());
    first.finish().unwrap();
    second.finish().unwrap();
}
