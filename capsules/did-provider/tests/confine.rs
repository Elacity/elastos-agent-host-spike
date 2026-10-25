//! Runs the real did-provider binary under its Seatbelt profile.
//!
//! Each test starts `/usr/bin/sandbox-exec` with `confine.sb` and a temporary
//! storage root, then speaks the provider wire protocol over stdin/stdout.
//! When `sandbox-exec` is unavailable the test prints why it skipped and
//! returns; it never claims a passing confinement check without running one.
//!
//! Network: the provider protocol has no network operation; every request is
//! line-delimited JSON on inherited stdin/stdout. The profile's explicit
//! `(deny network*)` covers sockets, and no TCP probe runs because the
//! provider exposes no socket hook and adding one would add a provider
//! behavior the capsule contract does not have.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const DEVICE_KEY: [u8; 32] = [42u8; 32];

fn provider_binary() -> &'static str {
    env!("CARGO_BIN_EXE_did-provider")
}

fn profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("confine.sb")
}

fn require_sandbox(test: &str) -> bool {
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        true
    } else {
        // Direct stderr writes bypass libtest's successful-test capture.
        writeln!(
            std::io::stderr().lock(),
            "SKIP {test}: /usr/bin/sandbox-exec is unavailable, so did-provider confinement was not exercised"
        )
        .expect("print confinement skip reason");
        false
    }
}

/// The one production profile plus a named fixture rule.
///
/// `confine.sb` stays the single source: the fixture appends one reviewed
/// grant or denial so a test can reach the refusal under examination.
fn profile_with(fixture_rule: &str) -> tempfile::NamedTempFile {
    let mut profile = tempfile::NamedTempFile::new().unwrap();
    write!(
        profile,
        "{}\n; Test-only fixture rule, not part of the production profile.\n{fixture_rule}\n",
        std::fs::read_to_string(profile_path()).unwrap()
    )
    .unwrap();
    profile.flush().unwrap();
    profile
}

/// A provider child driven over the normal line-delimited JSON protocol.
struct ConfinedProvider {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    reaped: bool,
}

impl ConfinedProvider {
    fn spawn(storage_root: &Path) -> Self {
        Self::spawn_with_profile(storage_root, &profile_path(), &[])
    }

    fn spawn_with_profile(storage_root: &Path, profile: &Path, params: &[(&str, &Path)]) -> Self {
        let binary = provider_binary();
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-f")
            .arg(profile)
            .arg("-D")
            .arg(format!("STORAGE_ROOT={}", storage_root.display()))
            .arg("-D")
            .arg(format!("PROVIDER_BINARY={binary}"));
        for (name, value) in params {
            command.arg("-D").arg(format!("{name}={}", value.display()));
        }
        let mut child = command
            .arg(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|error| {
                panic!("failed to start did-provider under the profile: {error}")
            });

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            reaped: false,
        }
    }

    fn request(&mut self, request: Value) -> Value {
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).unwrap();
        assert!(
            read > 0,
            "did-provider closed stdout instead of answering {request}"
        );
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("invalid provider response {line:?}: {error}"))
    }

    fn init(&mut self, storage_root: &Path) -> Value {
        self.request(json!({
            "op": "init",
            "config": {
                "base_path": storage_root.display().to_string(),
                "encryption_key": hex::encode(DEVICE_KEY),
            },
        }))
    }

    fn shutdown(&mut self) -> Value {
        let response = self.request(json!({"op": "shutdown"}));
        let status = self.child.wait().expect("provider exit");
        self.reaped = true;
        assert!(status.success(), "provider exited with {status}");
        response
    }
}

impl Drop for ConfinedProvider {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical storage root");
    (dir, canonical)
}

fn assert_ok(response: &Value) {
    assert_eq!(
        response["status"], "ok",
        "expected an ok response, got {response}"
    );
}

fn error_parts<'a>(response: &'a Value) -> (&'a str, &'a str) {
    assert_eq!(
        response["status"], "error",
        "expected an error response, got {response}"
    );
    (
        response["code"].as_str().expect("error code"),
        response["message"].as_str().expect("error message"),
    )
}

fn assert_refusal(response: &Value, code: &str, reason: &str) {
    let (actual_code, message) = error_parts(response);
    assert_eq!(actual_code, code, "unexpected refusal {response}");
    assert_eq!(message, reason, "wrong refusal reason: {response}");
}

fn permission_error() -> String {
    // Seatbelt returns EPERM on macOS.
    std::io::Error::from_raw_os_error(1).to_string()
}

fn tamper_signature(signature: &str) -> String {
    let mut tampered = signature.to_string();
    let last = tampered.pop().expect("signature hex");
    tampered.push(if last == '0' { '1' } else { '0' });
    tampered
}

fn manifest_operations() -> BTreeSet<String> {
    let manifest = std::fs::read_to_string(format!("{}/capsule.json", env!("CARGO_MANIFEST_DIR")))
        .expect("capsule.json");
    let manifest: Value = serde_json::from_str(&manifest).expect("capsule.json is JSON");
    let mut operations = BTreeSet::new();
    for capability in manifest["authority"]["capabilities"]
        .as_array()
        .expect("authority.capabilities")
    {
        for operation in capability["operations"]
            .as_array()
            .expect("capability operations")
        {
            operations.insert(operation.as_str().expect("operation name").to_string());
        }
    }
    operations
}

/// Sign then verify through the provider only.
///
/// The provider returns the exact payload it signed, so this test forwards
/// provider output unchanged. It builds no signing payload and no signature.
///
/// Falsifier: return a corrupted `payload_hex`; the genuine signature then
/// fails `verify` and this helper fails.
fn chat_signature_roundtrip(provider: &mut ConfinedProvider, did: &str) {
    let signed = provider.request(json!({
        "op": "sign_chat_message",
        "sender_id": did,
        "ts": 1_714_000_000u64,
        "content": "confined hello",
    }));
    assert_ok(&signed);
    let signature = signed["data"]["signature"]
        .as_str()
        .expect("sign_chat_message returns a signature")
        .to_string();
    let payload_hex = signed["data"]["payload_hex"]
        .as_str()
        .expect("sign_chat_message returns the payload it signed")
        .to_string();
    assert!(
        !payload_hex.is_empty(),
        "the signed payload must not be empty"
    );

    let valid = provider.request(json!({
        "op": "verify",
        "did": did,
        "data": payload_hex,
        "signature": signature,
    }));
    assert_ok(&valid);
    assert_eq!(
        valid["data"]["valid"], true,
        "the provider's own signature must verify against the payload it returned"
    );

    let tampered = provider.request(json!({
        "op": "verify",
        "did": did,
        "data": payload_hex,
        "signature": tamper_signature(&signature),
    }));
    assert_ok(&tampered);
    assert_eq!(
        tampered["data"]["valid"], false,
        "a tampered signature must not verify"
    );
}

/// Every operation did-provider serves on its own works under the profile.
///
/// `verify_did_recovery` is task 007 and is not driven here; the manifest
/// comparison keeps it named so nothing is quietly dropped.
#[test]
fn all_operations_under_profile() {
    if !require_sandbox("all_operations_under_profile") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let mut provider = ConfinedProvider::spawn(&storage);
    let mut driven: BTreeSet<String> = BTreeSet::new();

    assert_ok(&provider.init(&storage));

    driven.insert("set_nickname".to_string());
    let set = provider.request(json!({"op": "set_nickname", "nickname": "alice"}));
    assert_ok(&set);
    assert_eq!(set["data"]["nickname"], "alice");

    driven.insert("get_nickname".to_string());
    let get = provider.request(json!({"op": "get_nickname"}));
    assert_ok(&get);
    assert_eq!(
        get["data"]["nickname"], "alice",
        "get_nickname must return what set_nickname stored"
    );

    driven.insert("get_did".to_string());
    let did_response = provider.request(json!({"op": "get_did"}));
    assert_ok(&did_response);
    let did = did_response["data"]["did"]
        .as_str()
        .expect("get_did returns a DID")
        .to_string();
    assert!(did.starts_with("did:key:z"), "unexpected DID {did}");

    driven.insert("get_persona_did".to_string());
    let persona = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
    assert_ok(&persona);
    assert!(
        persona["data"]["did"]
            .as_str()
            .expect("persona DID")
            .starts_with("did:key:z"),
        "unexpected persona {persona}"
    );
    assert_eq!(persona["data"]["owner_did"].as_str(), Some(did.as_str()));

    driven.insert("resolve".to_string());
    let resolved = provider.request(json!({"op": "resolve", "did": did}));
    assert_ok(&resolved);
    assert_eq!(resolved["data"]["document"]["id"], did);
    assert!(resolved["data"]["public_key"].as_str().is_some());

    chat_signature_roundtrip(&mut provider, &did);
    driven.insert("sign_chat_message".to_string());
    driven.insert("verify".to_string());

    let mut expected = driven.clone();
    expected.insert("verify_did_recovery".to_string());
    assert_eq!(
        manifest_operations(),
        expected,
        "every operation this task covers must run under the profile; verify_did_recovery is task 007"
    );

    assert_ok(&provider.shutdown());
}

/// A write that resolves outside the storage root is refused with the exact
/// save error, leaves the outside file untouched and does not stop the provider.
///
/// Falsifier: replace `(deny default)` with `(allow default)`; the write
/// succeeds and this test fails.
#[test]
fn outside_write_denied() {
    if !require_sandbox("outside_write_denied") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let (_outside, outside) = canonical_tempdir();
    let outside_nickname = outside.join("nickname.enc");
    let sentinel = b"outside-nickname-sentinel";
    std::fs::write(&outside_nickname, sentinel).unwrap();

    let mut provider = ConfinedProvider::spawn(&storage);
    assert_ok(&provider.init(&storage));

    // `did/nickname.enc` is a symlink into the outside directory: a provider
    // that could write through it would overwrite the sentinel.
    std::fs::create_dir_all(storage.join("did")).unwrap();
    std::os::unix::fs::symlink(&outside_nickname, storage.join("did/nickname.enc")).unwrap();

    assert_refusal(
        &provider.request(json!({"op": "set_nickname", "nickname": "alice"})),
        "storage_error",
        &format!(
            "did-provider: failed to save nickname: {}",
            permission_error()
        ),
    );
    assert_eq!(
        std::fs::read(&outside_nickname).unwrap(),
        sentinel,
        "a denied write must not change the outside target"
    );

    assert_ok(&provider.request(json!({"op": "get_did"})));
    assert_ok(&provider.shutdown());
}

/// A persona key reached through a symlink outside the storage root cannot be
/// read; the provider reports the exact read refusal and keeps serving.
///
/// The fixture permits metadata only, so the refusal happens at the data read.
/// Falsifier: allow outside data reads; the persona DID comes back and this
/// test fails.
#[test]
fn outside_read_denied() {
    if !require_sandbox("outside_read_denied") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let (_outside, outside) = canonical_tempdir();
    let profile = profile_with(r#"(allow file-read-metadata (subpath (param "OUTSIDE_ROOT")))"#);
    let mut provider = ConfinedProvider::spawn_with_profile(
        &storage,
        profile.path(),
        &[("OUTSIDE_ROOT", &outside)],
    );
    assert_ok(&provider.init(&storage));

    let created = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
    assert_ok(&created);
    let persona_did = created["data"]["did"].as_str().unwrap().to_string();

    // Move the existing persona key outside the root and link it back in.
    let stored_key = storage.join("did/personas/bot.enc");
    let outside_key = outside.join("bot.enc");
    std::fs::rename(&stored_key, &outside_key).unwrap();
    std::os::unix::fs::symlink(&outside_key, &stored_key).unwrap();
    let outside_bytes = std::fs::read(&outside_key).unwrap();

    let response = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
    assert_refusal(
        &response,
        "key_error",
        &format!("Read failed: {}", permission_error()),
    );
    assert!(
        !response.to_string().contains(&persona_did),
        "the outside persona key must not be readable: {response}"
    );
    assert_eq!(
        std::fs::read(&outside_key).unwrap(),
        outside_bytes,
        "a denied read must leave the outside persona key unchanged"
    );

    assert_ok(&provider.request(json!({"op": "get_did"})));
    assert_ok(&provider.shutdown());
}

/// A denied metadata lookup for a persona key is its own refusal, before any
/// key creation or persistence is attempted.
///
/// Falsifier: collapse metadata errors into absence, as a bare `exists()`
/// check does; the provider creates a new key and this test fails.
#[test]
fn outside_persona_metadata_denied() {
    if !require_sandbox("outside_persona_metadata_denied") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let (_outside, outside) = canonical_tempdir();
    let mut provider = ConfinedProvider::spawn(&storage);
    assert_ok(&provider.init(&storage));
    assert_ok(&provider.request(json!({"op": "get_persona_did", "name": "bot"})));

    let stored = storage.join("did/personas/bot.enc");
    let external = outside.join("bot.enc");
    std::fs::rename(&stored, &external).unwrap();
    std::os::unix::fs::symlink(&external, &stored).unwrap();
    let before = std::fs::read(&external).unwrap();

    assert_refusal(
        &provider.request(json!({"op": "get_persona_did", "name": "bot"})),
        "key_error",
        &format!("Metadata lookup failed: {}", permission_error()),
    );
    assert_eq!(std::fs::read(&external).unwrap(), before);
    assert_ok(&provider.request(json!({"op": "get_did"})));
    assert_ok(&provider.shutdown());
}

/// Each persona write refusal keeps its own operation name and OS reason.
///
/// Falsifier: replace either operation-specific reason with a generic error;
/// the exact-reason assertion fails.
#[test]
fn persona_write_refusals_keep_their_reasons() {
    if !require_sandbox("persona_write_refusals_keep_their_reasons") {
        return;
    }
    for (deny_path, operation) in [
        ("did/personas", "Failed to create dir"),
        ("did/personas/bot.enc", "Failed to persist persona key"),
    ] {
        let (_root, storage) = canonical_tempdir();
        std::fs::create_dir_all(storage.join("did")).unwrap();
        if deny_path.ends_with(".enc") {
            std::fs::create_dir_all(storage.join("did/personas")).unwrap();
        }
        let denied = storage.join(deny_path);
        let profile = profile_with(r#"(deny file-write* (subpath (param "DENIED_PATH")))"#);
        let mut provider = ConfinedProvider::spawn_with_profile(
            &storage,
            profile.path(),
            &[("DENIED_PATH", &denied)],
        );
        assert_ok(&provider.init(&storage));
        assert_refusal(
            &provider.request(json!({"op": "get_persona_did", "name": "bot"})),
            "key_error",
            &format!("{operation}: {}", permission_error()),
        );
        assert!(
            !denied.exists(),
            "a refused persona write must leave its target absent"
        );
        assert_ok(&provider.request(json!({"op": "get_did"})));
        assert_ok(&provider.shutdown());
    }
}

/// A nickname symlinked outside the root is a storage refusal on `Init` and on
/// `get_nickname`; a denied lookup never reads as an unset nickname.
fn nickname_refusal(allow_metadata: bool) {
    let (_root, storage) = canonical_tempdir();
    let (_outside, outside) = canonical_tempdir();
    elastos_identity::save_nickname_with_device_key(&storage, &DEVICE_KEY, "alice").unwrap();
    let stored = storage.join("did/nickname.enc");
    let external = outside.join("nickname.enc");
    std::fs::rename(&stored, &external).unwrap();
    std::os::unix::fs::symlink(&external, &stored).unwrap();
    let before = std::fs::read(&external).unwrap();

    let profile = profile_with(r#"(allow file-read-metadata (subpath (param "OUTSIDE_ROOT")))"#);
    let mut provider = if allow_metadata {
        ConfinedProvider::spawn_with_profile(
            &storage,
            profile.path(),
            &[("OUTSIDE_ROOT", &outside)],
        )
    } else {
        ConfinedProvider::spawn(&storage)
    };
    let reason = if allow_metadata {
        // The shared reader returns the OS refusal from the data read.
        format!(
            "did-provider: failed to load nickname: {}",
            permission_error()
        )
    } else {
        format!(
            "did-provider: failed to load nickname: Metadata lookup failed: {}",
            permission_error()
        )
    };

    assert_refusal(&provider.init(&storage), "storage_error", &reason);
    assert_refusal(
        &provider.request(json!({"op": "get_nickname"})),
        "storage_error",
        &reason,
    );
    assert_eq!(std::fs::read(&external).unwrap(), before);
    assert_ok(&provider.request(json!({"op": "get_did"})));

    // Restore the permitted file and prove that a later Init clears the refusal.
    std::fs::remove_file(&stored).unwrap();
    std::fs::rename(&external, &stored).unwrap();
    assert_ok(&provider.init(&storage));
    let nickname = provider.request(json!({"op": "get_nickname"}));
    assert_ok(&nickname);
    assert_eq!(nickname["data"]["nickname"], "alice");
    assert_ok(&provider.shutdown());
}

#[test]
fn outside_nickname_metadata_denied() {
    if require_sandbox("outside_nickname_metadata_denied") {
        nickname_refusal(false);
    }
}

#[test]
fn outside_nickname_read_denied() {
    if require_sandbox("outside_nickname_read_denied") {
        nickname_refusal(true);
    }
}
