mod common;
#[path = "common/probe.rs"]
#[allow(dead_code)]
mod probe;

use agent_conformance::build::lane;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::{localhost_provider_under_test, runtime_under_test};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REFUSAL: &str = "This command requires a running runtime.";

fn checksum_refusal_matches(
    stderr: &str,
    component: &str,
    installed: &Path,
    manifest: &Path,
) -> bool {
    let refusal = format!(
        "installed component '{component}' at {} failed checksum verification against {}",
        installed.display(),
        manifest.display()
    );
    stderr.lines().any(|line| line.contains(&refusal))
}

#[test]
fn checksum_refusal_requires_one_component_path_and_manifest() {
    // Synthetic diagnostics check the lab assertion, not Runtime acceptance.
    let root = Path::new("/fixture Home/Library/Application Support/elastos");
    let manifest = root.join("components.json");
    for component in ["localhost-provider", "ipfs-provider"] {
        let installed = root.join("bin").join(component);
        let valid = format!(
            "installed component '{component}' at {} failed checksum verification against {}",
            installed.display(),
            manifest.display()
        );
        let prefixed = format!("WARN runtime: {valid}\n");
        assert!(
            checksum_refusal_matches(&valid, component, &installed, &manifest),
            "complete checksum line must pass"
        );
        let other = format!(
            "installed component 'did-provider' at {} failed checksum verification against {}",
            root.join("bin/did-provider").display(),
            manifest.display()
        );
        let cases = [
            (
                "separate component and checksum lines must be refused",
                format!("checking {component}\n{other}\n"),
            ),
            (
                "split checksum message must be refused",
                valid.replace(" failed checksum", "\nfailed checksum"),
            ),
            (
                "split manifest fragment must be refused",
                valid.replace(" against ", " against\n"),
            ),
            (
                "missing provider beside another checksum error must be refused",
                format!("{component} not installed.\n{other}\n"),
            ),
            (
                "near-match component must be refused",
                valid.replace(component, &format!("{component}-copy")),
            ),
            (
                "wrong installed path must be refused",
                valid.replace(
                    installed.to_str().unwrap(),
                    root.join("other bin").join(component).to_str().unwrap(),
                ),
            ),
            (
                "wrong manifest path must be refused",
                valid.replace(
                    manifest.to_str().unwrap(),
                    root.join("other components.json").to_str().unwrap(),
                ),
            ),
            ("empty output must be refused", String::new()),
        ];
        for (label, stderr) in cases {
            assert!(
                !checksum_refusal_matches(&stderr, component, &installed, &manifest),
                "{label}"
            );
            assert!(
                checksum_refusal_matches(&prefixed, component, &installed, &manifest),
                "complete prefixed line with spaces must recover"
            );
        }
    }
}

fn assert_component_outputs_absent(home: &ThrowawayHome, component: &str) {
    for path in [
        home.data().join("bin"),
        home.data().join("bin").join(component),
        home.data().join("components.json"),
    ] {
        assert!(
            !path.try_exists().unwrap(),
            "metadata refusal must leave output absent: {}",
            path.display()
        );
    }
}

fn assert_component_install(
    home: &ThrowawayHome,
    component: &str,
    platform: &str,
    bytes: &[u8],
    source: &serde_json::Value,
) -> serde_json::Value {
    let installed = home.data().join("bin").join(component);
    assert_eq!(fs::read(&installed).unwrap(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755,
            "fixture bytes must be executable"
        );
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(home.data().join("components.json")).unwrap()).unwrap();
    let mut expected = source.clone();
    let info = &mut expected["platforms"][platform];
    info["checksum"] = serde_json::json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    info["size"] = serde_json::json!(bytes.len());
    info["install_path"] = serde_json::json!(format!("bin/{component}"));
    assert_eq!(
        manifest,
        serde_json::json!({"external": {component: expected}, "profiles": {}}),
        "recorded metadata and minimal manifest must survive installed-byte stamping"
    );
    manifest
}

#[test]
fn component_home_requires_recorded_platform() {
    use serde_json::json;
    const BYTES: &[u8] = b"harmless recorded-platform fixture\n";
    let checksum = format!("{:x}", Sha256::digest(BYTES));

    // The Home guard owns precedence, including over source loading.
    let home = ThrowawayHome::new().unwrap();
    let loaded = std::cell::Cell::new(false);
    fs::remove_dir(home.data()).unwrap();
    std::os::unix::fs::symlink(home.temp(), home.data()).unwrap();
    let reason = common::write_component_home_with_source(
        &home,
        "ipfs-provider",
        &home.data().join("bin/ipfs-provider"),
        BYTES,
        &checksum,
        || {
            loaded.set(true);
            Ok((json!({"platforms": {"darwin-arm64": {}}}), "darwin-amd64"))
        },
    )
    .unwrap_err();
    assert_eq!(
        reason.to_string(),
        "data directory must use directories without symlinks"
    );
    assert!(!loaded.get(), "guard refusal must precede source loading");
    assert_component_outputs_absent(&home, "ipfs-provider");
    fs::remove_file(home.data()).unwrap();
    fs::create_dir(home.data()).unwrap();
    common::write_component_home_with_source(
        &home,
        "ipfs-provider",
        &home.data().join("bin/ipfs-provider"),
        BYTES,
        &checksum,
        || {
            loaded.set(true);
            Ok((json!({"platforms": {"darwin-amd64": {}}}), "darwin-amd64"))
        },
    )
    .unwrap();
    assert!(loaded.get(), "repaired Home must load its source");
    assert_component_install(
        &home,
        "ipfs-provider",
        "darwin-amd64",
        BYTES,
        &json!({"platforms": {"darwin-amd64": {}}}),
    );
    home.finish().unwrap();

    for component in ["localhost-provider", "ipfs-provider"] {
        for (platform, row) in [
            ("darwin-amd64", None),
            ("fixture-absent", None),
            ("darwin-amd64", Some(json!(null))),
            ("darwin-amd64", Some(json!("fixture row"))),
            ("darwin-amd64", Some(json!([]))),
        ] {
            let home = ThrowawayHome::new().unwrap();
            let installed = home.data().join("bin").join(component);
            let mut source = json!({
                "fixture_component": "unchanged",
                "platforms": {"darwin-arm64": {"fixture_arm": true}}
            });
            let expected_reason = if let Some(row) = row {
                source["platforms"][platform] = row;
                format!("repository {component} {platform} platform must be an object")
            } else {
                format!("{component} has no {platform} platform entry in components.json")
            };
            let original = source.clone();
            let result = common::write_component_home_with_source(
                &home,
                component,
                &installed,
                BYTES,
                &checksum,
                || Ok((source.clone(), platform)),
            );
            assert_eq!(
                result.err().map(|error| error.to_string()),
                Some(expected_reason),
                "selected metadata must return its exact refusal"
            );
            assert_eq!(source, original, "refusal must preserve source metadata");
            assert_component_outputs_absent(&home, component);

            // Repair only the selected input; absent outputs need zero cleanup.
            source["platforms"][platform] = json!({"fixture_repaired": true});
            let repaired = source.clone();
            common::write_component_home_with_source(
                &home,
                component,
                &installed,
                BYTES,
                &checksum,
                || Ok((source.clone(), platform)),
            )
            .unwrap();
            assert_eq!(
                source, repaired,
                "installation must preserve source metadata"
            );
            assert_component_install(&home, component, platform, BYTES, &source);
            home.finish().unwrap();
        }
    }
}

#[test]
fn component_home_preserves_recorded_platform_metadata() {
    use serde_json::json;
    const BYTES: &[u8] = b"harmless metadata-preservation fixture\n";
    let checksum = format!("{:x}", Sha256::digest(BYTES));
    for component in ["localhost-provider", "ipfs-provider"] {
        let home = ThrowawayHome::new().unwrap();
        let source = json!({
            "fixture_component": {"keep": "component sentinel"},
            "platforms": {
                "darwin-arm64": {
                    "fixture_platform": {"keep": "selected sentinel"},
                    "release_path": "fixture release",
                    "checksum": "old fixture checksum", "size": 999,
                    "install_path": "old fixture path"
                },
                "fixture-other": {"keep": ["other platform sentinel"]}
            }
        });
        let original = source.clone();
        common::write_component_home_with_source(
            &home,
            component,
            &home.data().join("bin").join(component),
            BYTES,
            &checksum,
            || Ok((source.clone(), "darwin-arm64")),
        )
        .unwrap();
        assert_eq!(
            source, original,
            "installation must preserve source metadata"
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(home.data().join("components.json")).unwrap())
                .unwrap();
        let entry = &manifest["external"][component];
        assert_eq!(entry["fixture_component"], source["fixture_component"]);
        assert_eq!(
            entry["platforms"]["darwin-arm64"]["fixture_platform"],
            source["platforms"]["darwin-arm64"]["fixture_platform"],
            "selected platform sentinel must survive stamping"
        );
        assert_eq!(
            entry["platforms"]["fixture-other"],
            source["platforms"]["fixture-other"]
        );
        assert_component_install(&home, component, "darwin-arm64", BYTES, &source);
        home.finish().unwrap();
    }

    // Harmless bytes exercise repository loading without building or executing a provider.
    let home = ThrowawayHome::new().unwrap();
    let source: serde_json::Value = serde_json::from_slice(
        &fs::read(agent_conformance::build::repository().join("components.json")).unwrap(),
    )
    .unwrap();
    let component = "ipfs-provider";
    common::write_component_home(
        &home,
        component,
        &home.data().join("bin").join(component),
        BYTES,
        &checksum,
    )
    .unwrap();
    assert_component_install(
        &home,
        component,
        common::operator_platform().unwrap(),
        BYTES,
        &source["external"][component],
    );
    home.finish().unwrap();
}

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
    assert_eq!(
        runtime.binary,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/runtime/debug/elastos"),
        "cached Runtime must use the unchanged lane output path"
    );
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
    assert!(
        checksum_refusal_matches(
            &stderr,
            "ipfs-provider",
            &installed,
            &home.data().join("components.json")
        ),
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
    // Keep the provider first so a clean native target measures its cold build.
    let provider = localhost_provider_under_test().expect("build the checkout provider offline");
    let runtime = runtime_under_test().expect("build the checkout Runtime offline");
    let home = ThrowawayHome::new().unwrap();
    let installed = common::write_operator_home(&home).expect("install the operator fixture");
    assert!(provider.binary.is_absolute());
    assert_eq!(
        provider.binary,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/runtime/debug/localhost-provider"),
        "cached provider must use the unchanged lane output path"
    );
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
    let stderr = String::from_utf8(output.stderr).expect("Runtime stderr must be UTF-8");
    let checksum_refused = checksum_refusal_matches(
        &stderr,
        "localhost-provider",
        &installed,
        &home.data().join("components.json"),
    );
    let stderr = stderr.replace(lane().to_str().unwrap(), "<lane>");
    println!("Provider refusal stderr: {stderr:?}");
    assert!(
        !output.status.success(),
        "serve must refuse the changed provider"
    );
    assert!(
        checksum_refused,
        "expected the complete provider checksum refusal on one line; stderr:\n{stderr}"
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
    let observation = cleanup(&home, port);
    child.stop().unwrap();
    drop(child);
    let reason = observation.unwrap_err();
    assert!(reason.contains("process leftover"));
    assert!(reason.contains("processes:1"));
    assert!(reason.contains("\".\""), "root cwd must be visible");

    let line = cleanup(&home, port).unwrap();
    assert!(line.contains("processes:0 paths:[] API sockets:0 temp:0 paths:[]"));
    assert!(line.contains("excludes only test PID"));
    home.finish().unwrap();
}

// Setup is an unavailable control prerequisite. Every later refusal is a
// failed check, including guard, capture, timeout and managed-stop errors.
#[derive(Debug, PartialEq, Eq)]
enum UnixSocketFailure {
    Setup(String),
    Check(String),
}

impl UnixSocketFailure {
    fn check(reason: impl Into<String>) -> Self {
        Self::Check(reason.into())
    }
}

fn unix_socket_preflight(home: &ThrowawayHome, executable: &Path) -> Result<(), UnixSocketFailure> {
    home.guard(home.home(), home.data())
        .map_err(UnixSocketFailure::check)?;
    let output = match home.launch(
        executable,
        &["-I", "-S", "-B", "-c", "import socket"],
        Duration::from_secs(5),
    ) {
        Ok(output) => output,
        Err("could not start child process") => {
            return Err(UnixSocketFailure::Setup(
                "Unix socket control setup: interpreter could not start".into(),
            ));
        }
        Err(reason) => return Err(UnixSocketFailure::check(reason)),
    };
    if !output.status.success() {
        return Err(UnixSocketFailure::Setup(format!(
            "Unix socket control setup: socket import failed: {}",
            output.status
        )));
    }
    Ok(())
}

fn unix_socket_control(
    home: &ThrowawayHome,
    executable: &Path,
    port: u16,
) -> Result<(), UnixSocketFailure> {
    use agent_conformance::census::cleanup;
    use std::os::unix::fs::FileTypeExt;

    unix_socket_preflight(home, executable)?;
    // Bind by a relative path: macOS's sockaddr_un limit is smaller than
    // this worktree's absolute throwaway-Home path.
    let mut child = home.start(
        executable,
        &["-I", "-S", "-B", "-c", "import socket,time; s=socket.socket(socket.AF_UNIX); s.bind('cleanup.sock'); s.listen(1); open('socket-ready','w').close(); time.sleep(20)"],
    ).map_err(UnixSocketFailure::check)?;
    let pgid = child.pgid();
    let observed = (|| -> Result<_, String> {
        let started = std::time::Instant::now();
        while !home
            .home()
            .join("socket-ready")
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            if started.elapsed() >= Duration::from_secs(5) {
                return Err("Unix socket control readiness exceeded 5 seconds".into());
            }
            if !child.is_alive()? {
                return Err("Unix socket control exited before binding".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let metadata = fs::symlink_metadata(home.home().join("cleanup.sock"))
            .map_err(|error| format!("Unix socket control socket metadata: {error}"))?;
        if !metadata.file_type().is_socket() {
            return Err("Unix socket control path is not a Unix socket".into());
        }
        Ok(cleanup(home, port))
    })();
    // Always stop and reap before checking the saved observation, even when
    // readiness or the census failed. A failed stop keeps its Home and cause.
    let stopped = child.stop();
    drop(child);
    if let Err(reason) = stopped {
        return Err(UnixSocketFailure::check(match observed {
            Err(observed) => format!("{observed}; stop failed: {reason}"),
            Ok(_) => reason.into(),
        }));
    }
    if home
        .group_is_alive(pgid)
        .map_err(UnixSocketFailure::check)?
    {
        return Err(UnixSocketFailure::check(
            "Unix socket control group remains after stop",
        ));
    }
    let socket_result = observed.map_err(UnixSocketFailure::check)?;
    home.guard(home.home(), home.data())
        .map_err(UnixSocketFailure::check)?;
    for name in ["cleanup.sock", "socket-ready"] {
        fs::remove_file(home.home().join(name))
            .map_err(|error| UnixSocketFailure::check(format!("remove {name}: {error}")))?;
    }
    let reason = socket_result.err().ok_or_else(|| {
        UnixSocketFailure::check("Unix socket control holder was accepted by the census")
    })?;
    // This Mac's +D census sees cwd/captures, but omits the bound socket.
    if !reason.contains("process leftover") {
        return Err(UnixSocketFailure::check(reason));
    }
    if reason.contains("cleanup.sock") {
        return Err(UnixSocketFailure::check(
            "recheck the documented Unix socket visibility limit",
        ));
    }
    println!("cleanup socket control: bound Unix socket omitted by root selection; holder refused as process leftover; Unix socket absence unmeasured");
    let line = cleanup(home, port).map_err(UnixSocketFailure::check)?;
    if !line.contains("processes:0 paths:[] API sockets:0 temp:0 paths:[]")
        || !line.contains("excludes only test PID")
    {
        return Err(UnixSocketFailure::check(line));
    }
    Ok(())
}

#[test]
fn cleanup_unix_socket_control_reports_its_scope() {
    let home = ThrowawayHome::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    match unix_socket_control(&home, Path::new("/usr/bin/python3"), port) {
        Ok(()) => home.finish().unwrap(),
        Err(UnixSocketFailure::Setup(reason)) => probe::skipped(&reason),
        Err(UnixSocketFailure::Check(reason)) => panic!("{reason}"),
    }
}

fn socket_executable(home: &ThrowawayHome, import_status: u8) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    home.guard(home.home(), home.data()).unwrap();
    let path = home.home().join("socket-executable");
    fs::write(&path, format!(
        "#!/bin/sh\n[ \"$1\" = -I ] && [ \"$2\" = -S ] && [ \"$3\" = -B ] && [ \"$4\" = -c ] || exit 65\nif [ \"$5\" = 'import socket' ]; then exit {import_status}; fi\n: > worker-started\nexit 23\n"
    )).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn assert_socket_worker_absent(home: &ThrowawayHome) {
    for name in ["worker-started", "cleanup.sock", "socket-ready"] {
        assert!(
            !home.home().join(name).try_exists().unwrap(),
            "unexpected {name}"
        );
    }
    assert!(
        agent_conformance::census::root_holders(home, &[home.root().to_owned()])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unix_socket_control_setup_refusals_are_named() {
    use std::os::unix::fs::PermissionsExt;
    let home = ThrowawayHome::new().unwrap();
    let missing = home.home().join("missing-interpreter");
    let start_reason = "Unix socket control setup: interpreter could not start";
    let missing_result = unix_socket_control(&home, &missing, 0);
    assert_socket_worker_absent(&home);
    assert_eq!(
        missing_result,
        Err(UnixSocketFailure::Setup(start_reason.into()))
    );

    let executable = socket_executable(&home, 0);
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o600)).unwrap();
    let unstartable = unix_socket_control(&home, &executable, 0);
    assert_socket_worker_absent(&home);
    assert_eq!(
        unstartable,
        Err(UnixSocketFailure::Setup(start_reason.into()))
    );

    let executable = socket_executable(&home, 37);
    let refused = unix_socket_control(&home, &executable, 0);
    assert_socket_worker_absent(&home);
    assert_eq!(
        refused,
        Err(UnixSocketFailure::Setup(
            "Unix socket control setup: socket import failed: exit status: 37".into()
        )),
        "unsuccessful import must refuse setup with its actual status"
    );
    let executable = socket_executable(&home, 0);
    let repaired = unix_socket_preflight(&home, &executable);
    assert_socket_worker_absent(&home);
    assert_eq!(repaired, Ok(()), "repaired setup uses the same preflight");
    home.finish().unwrap();
}

#[test]
fn unix_socket_control_failure_after_setup_is_fail() {
    let home = ThrowawayHome::new().unwrap();
    let executable = socket_executable(&home, 0);
    let result = unix_socket_control(&home, &executable, 0);
    // The helper has stopped and reaped the worker before returning a refusal.
    let holders =
        agent_conformance::census::root_holders(&home, &[home.root().to_owned()]).unwrap();
    assert!(holders.is_empty(), "failed worker group must be cleaned up");
    assert!(home.home().join("worker-started").is_file());
    for name in ["cleanup.sock", "socket-ready"] {
        assert!(!home.home().join(name).try_exists().unwrap());
    }
    assert_eq!(
        result,
        Err(UnixSocketFailure::Check(
            "Unix socket control exited before binding".into()
        )),
        "post-setup exit must remain a check-stage failure"
    );
    home.finish().unwrap();

    let home = ThrowawayHome::new().unwrap();
    let saved = home.root().join("saved-home");
    fs::rename(home.home(), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, home.home()).unwrap();
    let result = unix_socket_control(&home, Path::new("/usr/bin/python3"), 0);
    fs::remove_file(home.home()).unwrap();
    fs::rename(saved, home.home()).unwrap();
    assert_socket_worker_absent(&home);
    assert_eq!(
        result,
        Err(UnixSocketFailure::Check(
            "home must use directories without symlinks".into()
        )),
        "guard refusal must remain a check-stage failure"
    );
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
