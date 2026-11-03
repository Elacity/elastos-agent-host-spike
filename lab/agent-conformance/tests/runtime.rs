mod common;

use agent_conformance::build::lane;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use sha2::{Digest, Sha256};
use std::cell::Cell;
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
            runtime
                .verified_path()
                .expect("verify the recorded Runtime bytes"),
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
    assert!(runtime.verified_path().unwrap().is_absolute());
    assert!(std::ptr::eq(runtime, runtime_under_test().unwrap()));
    assert_eq!(
        runtime.sha256,
        format!(
            "{:x}",
            Sha256::digest(fs::read(runtime.verified_path().unwrap()).unwrap())
        )
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
            runtime
                .verified_path()
                .expect("verify the recorded Runtime bytes"),
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

fn assert_operator_home_bytes(home: &ThrowawayHome, installed: &std::path::Path, bytes: &[u8]) {
    assert_eq!(installed, home.data().join("bin/localhost-provider"));
    assert_eq!(fs::read(installed).unwrap(), bytes);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(home.data().join("components.json")).unwrap()).unwrap();
    let info = &manifest["external"]["localhost-provider"]["platforms"]
        [common::operator_platform().unwrap()];
    assert_eq!(
        info["checksum"],
        format!("sha256:{:x}", Sha256::digest(bytes))
    );
    assert_eq!(info["size"], bytes.len());
    assert_eq!(info["install_path"], "bin/localhost-provider");
    assert_eq!(
        fs::read(home.data().join("config.toml")).unwrap(),
        include_bytes!("../fixtures/operator-config.toml")
    );
}

#[test]
fn operator_home_guard_precedes_provider_load() {
    let home = ThrowawayHome::new().unwrap();
    let decoy = ThrowawayHome::new().unwrap();
    let marker = decoy.data().join("marker");
    let marker_bytes = b"keep the decoy Home bytes\n";
    fs::write(&marker, marker_bytes).unwrap();
    let bytes = b"synthetic operator provider\n";
    let calls = Cell::new(0);
    let load_provider = || {
        calls.set(calls.get() + 1);
        Ok(bytes.to_vec())
    };
    let saved_data = home.root().join("saved-data");
    fs::rename(home.data(), &saved_data).unwrap();
    std::os::unix::fs::symlink(decoy.data(), home.data()).unwrap();

    let result = common::write_operator_home_with_loader(&home, &load_provider)
        .map_err(|error| error.to_string());
    let outputs = [
        "bin",
        "bin/localhost-provider",
        "components.json",
        "config.toml",
    ]
    .map(|name| fs::symlink_metadata(home.data().join(name)));
    let saved_marker = fs::read(&marker);
    // Repair the selected Home before assertions, also under a compiling plant.
    fs::remove_file(home.data()).expect("remove the owned data-directory symlink");
    fs::rename(&saved_data, home.data()).expect("restore the selected Home directory");

    assert_eq!(calls.get(), 0, "Home guard must precede provider loading");
    assert_eq!(
        result,
        Err("data directory must use directories without symlinks".into()),
        "operator writer must return the existing guard refusal"
    );
    for output in outputs {
        assert!(
            output.is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "guard refusal must leave installed and config outputs absent"
        );
    }
    assert_eq!(saved_marker.unwrap(), marker_bytes, "keep the decoy bytes");
    let installed = common::write_operator_home_with_loader(&home, &load_provider)
        .expect("prepare the repaired Home through the same path");
    assert_eq!(
        calls.get(),
        1,
        "repaired Home loads the provider exactly once"
    );
    assert_operator_home_bytes(&home, &installed, bytes);
    assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
    home.finish().unwrap();
    decoy.finish().unwrap();
}

#[test]
fn operator_home_config_collision_is_reported() {
    let bytes = b"synthetic config-collision provider\n";
    let marker_bytes = b"keep the existing config destination\n";
    for symlink in [false, true] {
        let home = ThrowawayHome::new().unwrap();
        let config = home.data().join("config.toml");
        let marker = home.root().join("config-decoy");
        fs::write(&marker, marker_bytes).unwrap();
        if symlink {
            std::os::unix::fs::symlink(&marker, &config).unwrap();
        } else {
            fs::write(&config, marker_bytes).unwrap();
        }
        let result = common::write_operator_home_with_loader(&home, || Ok(bytes.to_vec()));
        let saved_config = fs::read(&config);
        let saved_marker = fs::read(&marker);
        let metadata = fs::symlink_metadata(&config).unwrap();
        let link = symlink.then(|| fs::read_link(&config).unwrap());
        fs::remove_file(&config).expect("repair the owned config collision");

        let error = result
            .expect_err("operator writer must refuse the existing config")
            .to_string();
        assert!(
            error.contains(config.to_str().unwrap()),
            "config refusal must name the selected config path; error: {error}"
        );
        assert!(
            error.starts_with("create operator config "),
            "config refusal must name the create operation; error: {error}"
        );
        let cause = std::io::Error::from_raw_os_error(17).to_string();
        assert!(
            error.ends_with(&format!(": {cause}")),
            "config refusal must keep the underlying I/O cause; error: {error}"
        );
        assert_eq!(saved_config.unwrap(), marker_bytes, "keep config bytes");
        assert_eq!(saved_marker.unwrap(), marker_bytes, "keep decoy bytes");
        if let Some(target) = link {
            assert!(metadata.file_type().is_symlink(), "keep the config symlink");
            assert_eq!(target, marker, "keep the config symlink target");
        } else {
            assert!(metadata.is_file(), "keep the regular config file");
        }
        // Completed component writes stay in this refused fixture until finish.
        assert_eq!(
            fs::read(home.data().join("bin/localhost-provider")).unwrap(),
            bytes
        );
        home.finish().unwrap();

        let fresh = ThrowawayHome::new().unwrap();
        let installed = common::write_operator_home_with_loader(&fresh, || Ok(bytes.to_vec()))
            .expect("prepare a fresh Home after repairing the collision");
        assert_operator_home_bytes(&fresh, &installed, bytes);
        fresh.finish().unwrap();
    }

    let home = ThrowawayHome::new().unwrap();
    let error = common::write_operator_home_with_loader(&home, || {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "synthetic provider load cause",
        )
        .into())
    })
    .expect_err("provider load failure must propagate before installation");
    assert_eq!(error.to_string(), "synthetic provider load cause");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound,
        "preserve the loader's underlying error"
    );
    for name in ["bin", "components.json", "config.toml"] {
        assert!(!home.data().join(name).try_exists().unwrap());
    }
    let installed = common::write_operator_home_with_loader(&home, || Ok(bytes.to_vec()))
        .expect("prepare the Home after repairing provider loading");
    assert_operator_home_bytes(&home, &installed, bytes);
    home.finish().unwrap();
}

#[test]
fn component_home_writer_checks_guard_before_writing() {
    let home = ThrowawayHome::new().unwrap();
    let bytes = b"component Home writer fixture\n";
    let checksum = format!("{:x}", Sha256::digest(bytes));
    let installed = home.data().join("bin/ipfs-provider");
    let moved_home = home.root().join("moved-home");
    let moved_data = moved_home.join(home.data().strip_prefix(home.home()).unwrap());
    fs::rename(home.home(), &moved_home).unwrap();
    std::os::unix::fs::symlink(&moved_home, home.home()).unwrap();

    let result = common::write_component_home(&home, "ipfs-provider", &installed, bytes, &checksum)
        .map_err(|error| error.to_string());
    let observations = [
        moved_data.join("bin"),
        moved_data.join("bin/ipfs-provider"),
        moved_data.join("components.json"),
    ]
    .map(fs::symlink_metadata);
    // Repair before assertions, including when a plant wrote through the link.
    fs::remove_file(home.home()).expect("remove the owned Home symlink");
    fs::rename(&moved_home, home.home()).expect("restore the owned Home directory");
    eprintln!("component writer fixture: owned Home repaired");

    assert_eq!(
        result,
        Err("home must use directories without symlinks".into()),
        "writer must return the existing Home-symlink refusal"
    );
    for (name, observed) in ["bin", "installed file", "components.json"]
        .into_iter()
        .zip(observations)
    {
        assert!(
            observed.is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "writer must guard before creating {name}"
        );
    }

    common::write_component_home(&home, "ipfs-provider", &installed, bytes, &checksum)
        .expect("writer must accept the repaired Home");
    assert_eq!(fs::read(&installed).unwrap(), bytes);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(home.data().join("components.json")).unwrap()).unwrap();
    assert_eq!(manifest.as_object().unwrap().len(), 2);
    assert_eq!(manifest["external"].as_object().unwrap().len(), 1);
    assert_eq!(manifest["profiles"], serde_json::json!({}));
    let info =
        &manifest["external"]["ipfs-provider"]["platforms"][common::operator_platform().unwrap()];
    assert_eq!(info["checksum"], format!("sha256:{checksum}"));
    assert_eq!(info["size"], bytes.len());
    assert_eq!(info["install_path"], "bin/ipfs-provider");
    home.finish().unwrap();
}

#[test]
fn component_home_writer_names_refused_destinations() {
    let bytes = b"component destination fixture\n";
    let checksum = format!("{:x}", Sha256::digest(bytes));
    let marker = b"keep the existing destination\n";
    for case in ["bin", "installed", "manifest", "manifest-symlink"] {
        let home = ThrowawayHome::new().unwrap();
        let bin = home.data().join("bin");
        let manifest = home.data().join("components.json");
        let installed = if case == "installed" {
            // Keep bin absent so its creation cannot mask this file refusal.
            home.root().join("installed-ipfs-provider")
        } else {
            bin.join("ipfs-provider")
        };
        let (refused, preserved, operation) = match case {
            "bin" => {
                fs::create_dir(&bin).unwrap();
                (
                    bin.clone(),
                    bin.join("marker"),
                    "create component directory",
                )
            }
            "installed" => (
                installed.clone(),
                installed.clone(),
                "create component file",
            ),
            "manifest" => (
                manifest.clone(),
                manifest.clone(),
                "create component manifest",
            ),
            "manifest-symlink" => {
                let target = home.root().join("manifest-marker");
                std::os::unix::fs::symlink(&target, &manifest).unwrap();
                (manifest.clone(), target, "create component manifest")
            }
            _ => unreachable!(),
        };
        fs::write(&preserved, marker).unwrap();
        if case == "installed" {
            assert!(!bin.try_exists().unwrap(), "fixture bin must start absent");
        }

        let result =
            common::write_component_home(&home, "ipfs-provider", &installed, bytes, &checksum)
                .map_err(|error| error.to_string());
        let saved_bytes = fs::read(&preserved);
        let saved_metadata = fs::symlink_metadata(&refused);
        let saved_link = (case == "manifest-symlink").then(|| fs::read_link(&refused));
        // Preserve observations before finish removes this case's owned root.
        let error = result.expect_err(&format!(
            "{case}: writer must refuse the existing destination"
        ));
        assert!(
            error.contains(refused.to_str().unwrap()),
            "{case}: refusal must name the exact destination {}; error: {error}",
            refused.display()
        );
        assert!(
            error.starts_with(&format!("{operation} ")),
            "{case}: refusal must name the operation; error: {error}"
        );
        let cause = std::io::Error::from_raw_os_error(17).to_string();
        assert!(
            error.ends_with(&format!(": {cause}")),
            "{case}: refusal must retain the underlying I/O cause; error: {error}"
        );
        assert_eq!(saved_bytes.unwrap(), marker, "{case}: keep marker bytes");
        let metadata = saved_metadata.unwrap();
        if let Some(link) = saved_link {
            assert!(
                metadata.file_type().is_symlink(),
                "keep the manifest symlink"
            );
            assert_eq!(link.unwrap(), preserved, "keep the manifest symlink target");
        } else if case == "bin" {
            assert!(metadata.is_dir(), "keep the existing bin directory");
        } else {
            assert!(metadata.is_file(), "{case}: keep the existing file");
        }
        home.finish().unwrap();
    }
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
    // Remaining, in order: a measured Kubo v0.40.1 match for the staged probe
    // bundle's lab CID; the offline content fixture; `--cid` reaching the
    // directory launch's activation.
    panic!("blocked: AC-025-CID — requires a measured Kubo v0.40.1 match for the staged probe bundle's lab CID, the offline content fixture (installed, checksum-verified ipfs-provider, a local-only Kubo policy and a socket census), and --cid reaching the directory launch's activation");
}

#[test]
#[ignore = "blocked: AC-040-RECORD-LAUNCH"]
fn launch_refuses_bytes_unlike_signed_record() {
    // `elastos run` finds an installed release capsule by name. It does not
    // compare the launched directory's bytes with the signed record sha256 or cid.
    panic!("blocked: AC-040-RECORD-LAUNCH — record-to-launch must compare the launched bytes with the signed record sha256 or cid and refuse a difference (https://github.com/Elacity/elastos-runtime/issues/274)");
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
    assert!(provider.verified_path().unwrap().is_absolute());
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
            runtime
                .verified_path()
                .expect("verify the recorded Runtime bytes"),
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

    // Bind by a relative path: the macOS sockaddr_un path limit is smaller
    // than this worktree's absolute throwaway-Home path.
    let mut socket_child = home.start(
        std::path::Path::new("/usr/bin/python3"),
        &["-c", "import socket,time; s=socket.socket(socket.AF_UNIX); s.bind('cleanup.sock'); s.listen(1); open('socket-ready','w').close(); time.sleep(20)"],
    ).unwrap();
    let started = std::time::Instant::now();
    while !home.home().join("socket-ready").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "Unix socket control readiness exceeded 5 seconds"
        );
        assert!(
            socket_child.is_alive().unwrap(),
            "Unix socket control exited before binding"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let socket_result = cleanup(&home, port);
    socket_child.stop().unwrap();
    drop(socket_child);
    fs::remove_file(home.home().join("cleanup.sock")).unwrap();
    fs::remove_file(home.home().join("socket-ready")).unwrap();
    let reason = socket_result.unwrap_err();
    // This Mac's +D census sees the holder through cwd/captures, but does
    // not select its relative-path Unix socket. Keep the scope explicit.
    assert!(reason.contains("process leftover"), "{reason}");
    assert!(
        !reason.contains("cleanup.sock"),
        "recheck the documented Unix socket visibility limit"
    );
    println!("cleanup socket control: bound Unix socket omitted by root selection; holder refused as process leftover; Unix socket absence unmeasured");

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
