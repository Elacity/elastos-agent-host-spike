//! The real DID provider speaks stdin/stdout JSON under its single profile.
//!
//! The provider opens no listener or socket and has no network path; the
//! profile's `(deny network*)` covers that. The test runs no TCP probe because
//! a probe would exercise the host network stack, not the provider, while the
//! profile rule is the one thing that must hold. `profile_denies_network`
//! asserts that rule on every platform.
//!
//! When `/usr/bin/sandbox-exec` is absent the tests print why they did not run
//! and return; they never pass silently.

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_did-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
// Isolated fixture input, unrelated to any installed Home or production key.
const DEVICE_KEY: [u8; 32] = [0x42; 32];

fn sandbox_available() -> bool {
    if Path::new(SANDBOX_EXEC).is_file() {
        return true;
    }
    eprintln!(
        "SKIP did-provider confinement test: {SANDBOX_EXEC} is absent; \
         the profile was not exercised on this machine"
    );
    false
}

fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("fixture path must resolve")
}

struct ConfinedProvider {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ConfinedProvider {
    fn start(base: &Path) -> Self {
        let mut child = Command::new(SANDBOX_EXEC)
            .arg("-f")
            .arg(PROFILE_PATH)
            .arg("-D")
            .arg(format!("STORAGE_ROOT={}", base.join("did").display()))
            .arg("-D")
            .arg(format!("STORAGE_PARENT={}", base.display()))
            .arg("-D")
            .arg(format!(
                "PROVIDER_EXECUTABLE={}",
                resolved(Path::new(PROVIDER_BINARY)).display()
            ))
            .arg(PROVIDER_BINARY)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("sandbox-exec must start the provider");
        let stdin = child.stdin.take().expect("provider stdin");
        let stdout = BufReader::new(child.stdout.take().expect("provider stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, request: Value) -> Value {
        writeln!(self.stdin, "{request}").expect("provider stdin must accept a request");
        self.stdin.flush().expect("provider stdin must flush");
        let mut response = String::new();
        let read = self
            .stdout
            .read_line(&mut response)
            .expect("provider stdout must answer");
        assert!(read > 0, "provider exited without a response");
        serde_json::from_str(&response).expect("provider response must be JSON")
    }

    fn ok(&mut self, request: Value) -> Value {
        let response = self.send(request);
        assert_eq!(
            response["status"], "ok",
            "operation must succeed: {response}"
        );
        response["data"].clone()
    }

    fn init(&mut self, base: &Path) {
        self.ok(json!({
            "op": "init",
            "config": { "base_path": base, "encryption_key": hex::encode(DEVICE_KEY) }
        }));
    }

    fn shutdown(&mut self) {
        self.ok(json!({ "op": "shutdown" }));
        let status = self.child.wait().expect("provider must exit");
        assert!(status.success(), "confined provider exit status: {status}");
    }
}

impl Drop for ConfinedProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The confined provider serves the DID operations over its normal protocol.
///
/// `sign_chat_message` returns the payload it signed together with the
/// signature; both travel unchanged to `verify`. The test renders no signing
/// payload and constructs no signature of its own.
#[test]
fn confined_provider_serves_did_operations_under_its_root() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);

    let did_data = provider.ok(json!({ "op": "get_did" }));
    let did = did_data["did"].as_str().expect("device DID").to_string();
    let document = provider.ok(json!({ "op": "resolve", "did": did }));
    assert_eq!(document["document"]["id"], did);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signed = provider.ok(json!({
        "op": "sign_chat_message", "sender_id": did, "ts": ts, "content": "confined"
    }));
    let payload = signed["payload"]
        .as_str()
        .expect("the provider returns the payload it signed")
        .to_string();
    let signature = signed["signature"]
        .as_str()
        .expect("the provider returns its signature")
        .to_string();
    let verified = provider.ok(json!({
        "op": "verify", "did": did, "data": payload, "signature": signature
    }));
    assert_eq!(verified["valid"], true);

    // Flip one character of the provider's own signature; the same payload
    // must no longer verify.
    let mut tampered = signature.clone();
    let first = tampered.remove(0);
    tampered.insert(0, if first == '0' { '1' } else { '0' });
    let tampered_verified = provider.ok(json!({
        "op": "verify", "did": did, "data": payload, "signature": tampered
    }));
    assert_eq!(tampered_verified["valid"], false);

    provider.ok(json!({ "op": "set_nickname", "nickname": "Confined" }));
    let nickname = provider.ok(json!({ "op": "get_nickname" }));
    assert_eq!(nickname["nickname"], "Confined");
    let persona = provider.ok(json!({ "op": "get_persona_did", "name": "fixture" }));
    assert_eq!(persona["owner_did"], did);
    for relative in ["did/nickname.enc", "did/personas/fixture.enc"] {
        let bytes =
            fs::read(root.join(relative)).expect("identity state under the granted directory");
        assert!(
            !bytes.is_empty(),
            "encrypted identity state must be present"
        );
    }
    provider.shutdown();

    let mut reopened = ConfinedProvider::start(&root);
    reopened.init(&root);
    assert_eq!(reopened.ok(json!({ "op": "get_did" })), did_data);
    assert_eq!(reopened.ok(json!({ "op": "get_nickname" })), nickname);
    assert_eq!(
        reopened.ok(json!({ "op": "get_persona_did", "name": "fixture" })),
        persona
    );
    reopened.shutdown();
}

/// `verify_did_recovery` answers under the profile without a genuine proof.
///
/// No provider operation produces a recovery proof, so building one here would
/// copy the signing path inside the test (P10). This case sends a complete,
/// valid request whose signature is not hex; the handler rejects it on its own
/// merits. Genuine-proof correctness lives in the in-process unit tests in
/// `src/main.rs`: `test_verify_did_recovery_accepts_typed_did_key_proof`,
/// `test_verify_did_recovery_rejects_noncanonical_root_binding`,
/// `test_verify_did_recovery_rejects_tampered_payload_binding`,
/// `test_verify_did_recovery_rejects_expired_proof`,
/// `test_verify_did_recovery_rejects_noncanonical_alias_did_via_shared_codec`,
/// `test_verify_did_recovery_rejects_overlong_did_via_shared_codec` and
/// `test_verify_did_recovery_rejects_did_elastos_until_resolver_exists`.
///
/// Falsifier: panic in the `hex::decode(sig_hex)` error branch of
/// `verify_did_recovery` in `src/main.rs`; the confined process dies and this
/// case fails because no response line comes back.
#[test]
fn verify_did_recovery_under_profile() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);

    let did = provider.ok(json!({ "op": "get_did" }))["did"]
        .as_str()
        .expect("device DID")
        .to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();

    let response = provider.send(json!({
        "op": "verify_did_recovery",
        "did": did,
        "principal_id": "person:local:confined",
        "localhost_root": "localhost://Users/person:local:confined",
        "protector_id": "protector:did:confined",
        "data_key_id": "pdek:confined",
        "nonce": "nonce:confined",
        "issued_at": now,
        "expires_at": now + 300,
        "signature": "not-hex"
    }));
    assert_eq!(
        response["status"], "error",
        "the refusal must be handled, not a crash: {response}"
    );
    assert_eq!(response["code"], "invalid_signature");
    assert!(
        response["message"]
            .as_str()
            .expect("refusal must state a reason")
            .starts_with("Invalid hex sig:"),
        "the refusal must come from the signature decode: {response}"
    );

    // The handled refusal left the provider in service.
    provider.ok(json!({ "op": "get_did" }));
    provider.shutdown();
}

/// A write through a symlink that leaves the storage root is denied, and the
/// provider reports it and stays in service.
///
/// Falsifier: replace `(deny default)` with `(allow default)` (keeping
/// `(version 1)` first); the outside write then succeeds and this test fails.
#[test]
fn outside_write_denied() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let outside = tempfile::tempdir().expect("unrelated base");
    let outside = resolved(outside.path());
    let outside_target = outside.join("nickname.enc");
    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);
    provider.ok(json!({ "op": "set_nickname", "nickname": "Allowed" }));

    // Point the granted nickname file at an unrelated directory. The profile
    // resolves the link, so the write target stays outside the grant.
    let granted = root.join("did").join("nickname.enc");
    fs::remove_file(&granted).expect("granted nickname file");
    std::os::unix::fs::symlink(&outside_target, &granted).expect("outside symlink");

    let denied = provider.send(json!({ "op": "set_nickname", "nickname": "Outside" }));
    assert_eq!(
        denied["status"], "error",
        "the outside write must be denied: {denied}"
    );
    assert_eq!(denied["code"], "storage_error");
    assert!(
        denied["message"]
            .as_str()
            .expect("denial must state a reason")
            .starts_with("did-provider: failed to save nickname:"),
        "the refusal must name the failed write: {denied}"
    );
    assert!(
        !outside_target.exists(),
        "nothing may land outside the storage root"
    );
    assert_eq!(
        fs::read_dir(&outside).expect("outside directory").count(),
        0,
        "the outside directory must stay unchanged"
    );

    // Remove the escape and confirm the provider still serves its root.
    fs::remove_file(&granted).expect("remove outside symlink");
    provider.ok(json!({ "op": "set_nickname", "nickname": "Recovered" }));
    let nickname = provider.ok(json!({ "op": "get_nickname" }));
    assert_eq!(nickname["nickname"], "Recovered");
    provider.ok(json!({ "op": "get_did" }));
    provider.shutdown();
}

/// A read through a symlink that leaves the storage root is denied by the
/// single shared loader, and the provider reports it and stays in service.
///
/// Falsifier: restore the `if let Ok(Some(nick))` swallow in
/// `try_load_nickname`; the denied read becomes "no nickname", `Init` returns
/// ok and this test fails. Replacing `(deny default)` with `(allow default)`
/// also makes the read succeed and fails this test.
#[test]
fn outside_read_denied() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let outside = tempfile::tempdir().expect("unrelated base");
    let outside = resolved(outside.path());
    // Plant real encrypted nickname state outside the grant. With the profile
    // intact the loader cannot read it; with `(allow default)` it would load
    // "Outside" and `Init` would succeed, which fails this test.
    elastos_identity::save_nickname_with_device_key(&outside, &DEVICE_KEY, "Outside")
        .expect("outside nickname fixture");
    let outside_secret = outside.join("did").join("nickname.enc");
    let planted = fs::read(&outside_secret).expect("outside fixture file");

    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);

    // The loader stats and reads `did/nickname.enc`. Point that path outside
    // the grant; the shared loader must return the denial, not "absent".
    let granted = root.join("did").join("nickname.enc");
    fs::create_dir_all(granted.parent().expect("nickname parent"))
        .expect("granted identity directory");
    std::os::unix::fs::symlink(&outside_secret, &granted).expect("outside symlink");

    let denied = provider.send(json!({
        "op": "init",
        "config": { "base_path": root, "encryption_key": hex::encode(DEVICE_KEY) }
    }));
    assert_eq!(
        denied["status"], "error",
        "the outside read must be denied: {denied}"
    );
    assert_eq!(denied["code"], "storage_error");
    assert!(
        denied["message"]
            .as_str()
            .expect("denial must state a reason")
            .starts_with("did-provider: failed to read nickname:"),
        "the refusal must reach the nickname loader: {denied}"
    );
    assert_eq!(
        fs::read(&outside_secret).expect("outside file stays readable to the test"),
        planted,
        "the outside target must stay unchanged"
    );

    fs::remove_file(&granted).expect("remove outside symlink");
    provider.init(&root);
    let nickname = provider.send(json!({ "op": "get_nickname" }));
    assert_eq!(
        nickname["code"], "not_set",
        "the provider must not adopt outside state: {nickname}"
    );
    provider.ok(json!({ "op": "get_did" }));
    provider.shutdown();
}

/// The one profile source denies the network and every default grant.
///
/// Falsifier: remove `(deny network*)` from `confine.sb`; this test fails.
#[test]
fn profile_denies_network() {
    let profile = fs::read_to_string(PROFILE_PATH).expect("single profile source");
    let forms = profile_forms(&profile);
    assert_eq!(forms.first().map(String::as_str), Some("(version 1)"));
    assert!(forms.iter().any(|form| form == "(deny default)"));
    assert!(
        forms.iter().any(|form| form == "(deny network*)"),
        "the profile must deny the network explicitly"
    );
    for form in forms {
        assert!(
            !(form.starts_with("(allow ") && form.contains("network")),
            "network grant: {form}"
        );
        assert!(
            !(form.starts_with("(allow ")
                && form.split([' ', '(', ')']).any(|token| token == "default")),
            "default grant: {form}"
        );
    }
}

fn profile_forms(profile: &str) -> Vec<String> {
    let mut text = String::new();
    for line in profile.lines() {
        text.push_str(line.split(';').next().unwrap_or(""));
        text.push(' ');
    }
    let mut forms = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for token in text.split_whitespace() {
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(token);
        depth += token.matches('(').count();
        depth = depth.saturating_sub(token.matches(')').count());
        if depth == 0 && !current.is_empty() {
            forms.push(std::mem::take(&mut current));
        }
    }
    assert!(current.is_empty(), "incomplete profile form: {current}");
    forms
}
