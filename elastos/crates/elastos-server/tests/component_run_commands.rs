//! CLI rows for the Component commands printed in the authoring guide.
//! Each command gets its own Home; the signed row stages before it runs.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const MANIFEST: &str = r#"{"schema":"elastos.capsule/v1","name":"cli-component","version":"0.1.0","role":"app","type":"wasm","runtime_abi":"elastos.component/v1","bus_contract":"elastos:bus@v1","wit_world_sha256":"7a026e0a641c8c04214576dc85a677e0b52c9f02866d231119f9a3ba609d49e2","execution":"component","projections":["cli"],"entrypoint":"my-app.component.wasm"}"#;

fn command(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_elastos"))
        .args(args)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_isolated_home(home: &Path) {
    let show = command(home, &["config", "show"]);
    assert!(show.status.success(), "{}", text(&show));
    assert!(
        text(&show).contains(home.to_str().unwrap()),
        "CLI did not select the isolated test Home: {}",
        text(&show)
    );
}

fn folder(home: &Path, manifest: &str) -> std::path::PathBuf {
    let folder = home.join("my-app");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("capsule.json"), manifest).unwrap();
    fs::write(
        folder.join("my-app.component.wasm"),
        wat::parse_str(
            r#"(component
              (import "elastos:bus/types@1.0.0" (instance $types
                (type $error (variant
                  (case "denied" string) (case "not-found" string) (case "invalid" string)
                  (case "unavailable" string) (case "timeout" string) (case "internal" string)))
                (export "bus-error" (type (eq $error)))))
              (alias export $types "bus-error" (type $bus-error))
              (core module $m
                (memory (export "memory") 1)
                (func (export "run") (result i32) (i32.const 0)))
              (core instance $i (instantiate $m))
              (func $run (result (result (error $bus-error)))
                (canon lift (core func $i "run") (memory $i "memory")))
              (instance $lifecycle (export "run" (func $run)))
              (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#,
        )
        .unwrap(),
    )
    .unwrap();
    folder
}

#[test]
fn documented_stage_then_run_and_explicit_development_commands() {
    // Read at run time: Rust sources outside lab/ must not embed notes (scripts/ci-installed-app-paths-test.py).
    let guide = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/CAPSULE_AUTHORING.md"),
    )
    .unwrap();
    assert!(guide.contains("mkdir my-app-bundle"));
    assert!(guide.contains("cp my-app/capsule.json my-app/my-app.component.wasm my-app-bundle/"));
    assert!(guide.contains("elastos config set dev_mode false"));
    assert!(guide.contains("elastos stage-bundle my-app-bundle\n"));
    assert!(guide.contains("elastos stage-bundle my-app-bundle --signature my-app-bundle.sig.json"));
    assert!(guide.contains("elastos run my-app-bundle"));
    assert!(guide.contains("elastos config set dev_mode true"));
    assert!(guide.contains("elastos run --dev-unsigned-component my-app"));

    let signed_home = tempfile::tempdir().unwrap();
    assert_isolated_home(signed_home.path());
    let signed_folder = folder(signed_home.path(), MANIFEST);
    fs::create_dir(signed_folder.join("target")).unwrap();
    fs::write(signed_folder.join("target/build-output"), b"build output").unwrap();
    let bundle_folder = signed_home.path().join("my-app-bundle");
    let packaged = Command::new("mkdir")
        .arg("my-app-bundle")
        .current_dir(signed_home.path())
        .output()
        .unwrap();
    assert!(packaged.status.success(), "{}", text(&packaged));
    let packaged = Command::new("cp")
        .args([
            "my-app/capsule.json",
            "my-app/my-app.component.wasm",
            "my-app-bundle/",
        ])
        .current_dir(signed_home.path())
        .output()
        .unwrap();
    assert!(packaged.status.success(), "{}", text(&packaged));
    let key = SigningKey::from_bytes(&[91; 32]);
    let configured = command(signed_home.path(), &["config", "set", "dev_mode", "false"]);
    assert!(configured.status.success(), "{}", text(&configured));
    let configured = String::from_utf8(configured.stdout).unwrap();
    let config_path = configured.trim().strip_prefix("Set dev_mode in ").unwrap();
    let key_hex = hex::encode(key.verifying_key().to_bytes());
    fs::OpenOptions::new()
        .append(true)
        .open(config_path)
        .unwrap()
        .write_all(format!("trusted_keys = [\"{key_hex}\"]\n").as_bytes())
        .unwrap();

    let path = bundle_folder.to_str().unwrap();
    let missing = command(signed_home.path(), &["run", path]);
    assert!(!missing.status.success(), "{}", text(&missing));
    assert!(
        text(&missing).contains("bundle_missing"),
        "{}",
        text(&missing)
    );
    assert!(
        text(&missing).contains("elastos stage-bundle <folder> --signature <file>"),
        "{}",
        text(&missing)
    );

    let cid_output = command(signed_home.path(), &["stage-bundle", path]);
    assert!(cid_output.status.success(), "{}", text(&cid_output));
    let cid: serde_json::Value = serde_json::from_slice(&cid_output.stdout).unwrap();
    let cid = cid["cid"].as_str().unwrap();
    let mut digest = Sha256::new();
    digest.update(b"elastos.capsule.bundle.v1\0");
    digest.update(cid.as_bytes());
    let signature = hex::encode(key.sign(&digest.finalize()).to_bytes());
    let did_bytes = [vec![0xed, 0x01], key.verifying_key().to_bytes().to_vec()].concat();
    let signature_file = signed_home.path().join("my-app-bundle.sig.json");
    fs::write(
        &signature_file,
        serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule.bundle-signature/v1",
            "cid": cid,
            "signer_did": format!("did:key:z{}", bs58::encode(did_bytes).into_string()),
            "signature": signature,
        }))
        .unwrap(),
    )
    .unwrap();
    let staged = command(
        signed_home.path(),
        &[
            "stage-bundle",
            path,
            "--signature",
            signature_file.to_str().unwrap(),
        ],
    );
    assert!(staged.status.success(), "{}", text(&staged));
    let run = command(signed_home.path(), &["run", path]);
    assert!(run.status.success(), "{}", text(&run));
    assert!(text(&run).contains("Component capsule 'cli-component' exited"));

    let dev_home = tempfile::tempdir().unwrap();
    assert_isolated_home(dev_home.path());
    let dev_folder = folder(dev_home.path(), MANIFEST);
    let configured = command(dev_home.path(), &["config", "set", "dev_mode", "true"]);
    assert!(configured.status.success(), "{}", text(&configured));
    let dev_run = [
        "run",
        "--dev-unsigned-component",
        dev_folder.to_str().unwrap(),
    ];
    // Without a live operator Runtime the run is refused before anything starts.
    let refused = command(dev_home.path(), &dev_run);
    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(
        text(&refused).contains("This command requires a running runtime."),
        "{}",
        text(&refused)
    );
    assert!(
        !text(&refused).contains("Development Component capsule"),
        "{}",
        text(&refused)
    );

    // With live operator coordinates for this Home, the same run starts.
    let configured = String::from_utf8(configured.stdout).unwrap();
    let config_path = configured.trim().strip_prefix("Set dev_mode in ").unwrap();
    let data_dir = Path::new(config_path).parent().unwrap();
    live_operator_coords(data_dir);
    let run = command(dev_home.path(), &dev_run);
    assert!(run.status.success(), "{}", text(&run));
    assert!(text(&run).contains("Development Component capsule 'cli-component' exited"));
}

/// Operator coordinates the CLI accepts as live: a loopback health answer and
/// this test's own pid, as home_storage_default's Component row writes them.
fn live_operator_coords(data_dir: &Path) {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api_url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
            let _ = stream.write_all(ok);
        }
    });
    let coords = serde_json::json!({"api_url": api_url, "attach_secret": "",
        "pid": std::process::id(), "runtime_kind": "operator"});
    fs::write(data_dir.join("runtime-coords.json"), coords.to_string()).unwrap();
}

#[test]
fn pinned_component_cli_refuses_unstaged_folder() {
    let home = tempfile::tempdir().unwrap();
    assert_isolated_home(home.path());
    let mut manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    manifest["requires"] = serde_json::json!([{
        "name": "viewer", "kind": "capsule",
        "cid": "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy"
    }]);
    let folder = folder(home.path(), &manifest.to_string());
    let result = command(home.path(), &["run", folder.to_str().unwrap()]);
    assert!(!result.status.success(), "{}", text(&result));
    assert!(
        text(&result).contains("bundle_missing"),
        "{}",
        text(&result)
    );
    assert!(text(&result).contains("stage-bundle"), "{}", text(&result));
}

/// A Home that trusts `key`, and the data directory that Home's CLI uses.
#[cfg(unix)]
fn trusted_home(key: &SigningKey) -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    assert_isolated_home(home.path());
    let configured = command(home.path(), &["config", "set", "dev_mode", "false"]);
    assert!(configured.status.success(), "{}", text(&configured));
    let configured = String::from_utf8(configured.stdout).unwrap();
    let config_path = configured
        .trim()
        .strip_prefix("Set dev_mode in ")
        .unwrap()
        .to_owned();
    let key_hex = hex::encode(key.verifying_key().to_bytes());
    fs::OpenOptions::new()
        .append(true)
        .open(&config_path)
        .unwrap()
        .write_all(format!("trusted_keys = [\"{key_hex}\"]\n").as_bytes())
        .unwrap();
    let data_dir = Path::new(&config_path).parent().unwrap().to_path_buf();
    (home, data_dir)
}

#[cfg(unix)]
fn manifest_named(name: &str, requires: Option<serde_json::Value>) -> String {
    let mut json: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    json["name"] = serde_json::json!(name);
    if let Some(requires) = requires {
        json["requires"] = requires;
    }
    json.to_string()
}

/// `folder` always writes `my-app`. A second bundle takes another directory.
#[cfg(unix)]
fn bundle_named(home: &Path, dir: &str, manifest: &str) -> std::path::PathBuf {
    let made = folder(home, manifest);
    let dest = home.join(dir);
    if made != dest {
        fs::rename(&made, &dest).unwrap();
    }
    dest
}

#[cfg(unix)]
fn stage_signed(home: &Path, folder: &Path, key: &SigningKey) -> serde_json::Value {
    let named = command(home, &["stage-bundle", folder.to_str().unwrap()]);
    assert!(named.status.success(), "{}", text(&named));
    let named: serde_json::Value = serde_json::from_slice(&named.stdout).unwrap();
    let cid = named["cid"].as_str().unwrap().to_owned();
    let mut digest = Sha256::new();
    digest.update(b"elastos.capsule.bundle.v1\0");
    digest.update(cid.as_bytes());
    let signature = hex::encode(key.sign(&digest.finalize()).to_bytes());
    let did_bytes = [vec![0xed, 0x01], key.verifying_key().to_bytes().to_vec()].concat();
    let signature_file = home.join(format!("{cid}.sig.json"));
    fs::write(
        &signature_file,
        serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule.bundle-signature/v1",
            "cid": cid,
            "signer_did": format!("did:key:z{}", bs58::encode(&did_bytes).into_string()),
            "signature": signature,
        }))
        .unwrap(),
    )
    .unwrap();
    let staged = command(
        home,
        &[
            "stage-bundle",
            folder.to_str().unwrap(),
            "--signature",
            signature_file.to_str().unwrap(),
        ],
    );
    assert!(staged.status.success(), "{}", text(&staged));
    let receipt: serde_json::Value = serde_json::from_slice(&staged.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", text(&staged)));
    assert_eq!(receipt["cid"].as_str(), Some(cid.as_str()));
    let stderr = String::from_utf8_lossy(&staged.stderr);
    let named = receipt["empty_folders"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if named.is_empty() {
        assert!(
            !stderr.contains("Empty folders are not part"),
            "{}",
            text(&staged)
        );
    } else {
        assert!(
            stderr.contains("Empty folders are not part of a bundle's name or its stored bytes"),
            "{}",
            text(&staged)
        );
        for name in named {
            assert!(stderr.contains(name.as_str().unwrap()), "{}", text(&staged));
        }
    }
    receipt
}

#[cfg(unix)]
fn slot_entrypoint(data_dir: &Path, cid: &str) -> std::path::PathBuf {
    data_dir
        .join("capsules")
        .join("by-cid")
        .join(cid)
        .join("my-app.component.wasm")
}

/// Staging wrote the file read-only. The write bit comes back without the
/// readonly helper clippy refuses.
#[cfg(unix)]
fn flip_last_byte(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(permissions.mode() | 0o200);
    fs::set_permissions(path, permissions).unwrap();
    let mut bytes = fs::read(path).unwrap();
    let last = bytes.last_mut().expect("the entrypoint has a byte");
    *last ^= 0xff;
    fs::write(path, &bytes).unwrap();
}

#[cfg(unix)]
fn assert_ran(home: &Path, cid: &str, name: &str) {
    let ran = command(home, &["run", "--bundle", cid]);
    assert!(ran.status.success(), "{}", text(&ran));
    let body = String::from_utf8_lossy(&ran.stdout);
    assert!(body.contains(name), "{}", text(&ran));
    assert!(
        body.contains("\"ended\":\"ok\"") || body.contains("\"ended\": \"ok\""),
        "{}",
        text(&ran)
    );
}

/// The installed `run --bundle` is a second process. It accepts the slot it
/// staged, then refuses that same slot after one byte of the root changes.
#[cfg(unix)]
#[test]
fn installed_start_refuses_a_root_changed_between_stage_and_launch() {
    let key = SigningKey::from_bytes(&[91; 32]);
    let (home, data_dir) = trusted_home(&key);
    let source = bundle_named(
        home.path(),
        "my-app",
        &manifest_named("cli-component", None),
    );
    fs::create_dir(source.join("spare")).unwrap();
    let staged = stage_signed(home.path(), &source, &key);
    assert_eq!(staged["empty_folders"], serde_json::json!(["spare"]));
    let cid = staged["cid"].as_str().unwrap();
    assert_ran(home.path(), cid, "cli-component");
    flip_last_byte(&slot_entrypoint(&data_dir, cid));
    let refused = command(home.path(), &["run", "--bundle", cid]);
    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(
        text(&refused).contains("bundle_cid_mismatch"),
        "{}",
        text(&refused)
    );
}

/// Same installed start, for a pin. The control run admits the member. The
/// next run, after that member's bytes change, refuses it by name.
#[cfg(unix)]
#[test]
fn installed_start_refuses_a_pinned_member_changed_between_stage_and_launch() {
    let key = SigningKey::from_bytes(&[92; 32]);
    let (home, data_dir) = trusted_home(&key);
    let member = bundle_named(home.path(), "member", &manifest_named("needed", None));
    let member_staged = stage_signed(home.path(), &member, &key);
    let member_cid = member_staged["cid"].as_str().unwrap().to_owned();
    let root = bundle_named(
        home.path(),
        "root",
        &manifest_named(
            "cli-root",
            Some(serde_json::json!([{
                "name": "needed",
                "kind": "capsule",
                "cid": member_cid,
            }])),
        ),
    );
    let root_staged = stage_signed(home.path(), &root, &key);
    let root_cid = root_staged["cid"].as_str().unwrap();
    assert_ran(home.path(), root_cid, "cli-root");
    flip_last_byte(&slot_entrypoint(&data_dir, &member_cid));
    let refused = command(home.path(), &["run", "--bundle", root_cid]);
    assert!(!refused.status.success(), "{}", text(&refused));
    let refusal = text(&refused);
    assert!(refusal.contains("bundle_cid_mismatch"), "{refusal}");
    assert!(refusal.contains("requirement needed"), "{refusal}");
}
