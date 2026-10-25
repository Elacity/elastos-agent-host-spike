//! Runs the real did-provider binary under its Seatbelt profile.
//!
//! Each test starts `/usr/bin/sandbox-exec` with `confine.sb` and a temporary
//! storage root, then speaks the provider wire protocol over stdin/stdout.
//! When `sandbox-exec` is unavailable the test prints why it skipped and
//! returns; it never claims a passing confinement check without running one.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DEVICE_KEY: [u8; 32] = [42u8; 32];
const RECOVERY_SCHEMA: &str = "elastos.did.recovery-proof/v1";

fn provider_binary() -> &'static str {
    env!("CARGO_BIN_EXE_did-provider")
}

fn profile_path() -> String {
    format!("{}/confine.sb", env!("CARGO_MANIFEST_DIR"))
}

fn require_sandbox(test: &str) -> bool {
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        true
    } else {
        eprintln!(
            "SKIP {test}: /usr/bin/sandbox-exec is unavailable, so did-provider confinement was not exercised"
        );
        false
    }
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
        let binary = provider_binary();
        let mut child = Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(profile_path())
            .arg("-D")
            .arg(format!("STORAGE_ROOT={}", storage_root.display()))
            .arg("-D")
            .arg(format!("PROVIDER_BINARY={binary}"))
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

fn assert_permission_denied(message: &str) {
    assert!(
        message.contains("Operation not permitted") || message.contains("Permission denied"),
        "expected a permission-denial reason, got {message:?}"
    );
}

fn tamper_signature(signature: &str) -> String {
    let mut tampered = signature.to_string();
    let last = tampered.pop().expect("signature hex");
    tampered.push(if last == '0' { '1' } else { '0' });
    tampered
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn recovery_signature(
    did: &str,
    principal_id: &str,
    localhost_root: &str,
    protector_id: &str,
    data_key_id: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> String {
    use ed25519_dalek::Signer;

    // Mirrors DidRecoveryPayload::to_payload in src/main.rs (wire contract).
    let payload = format!(
        "ElastOS DID recovery request\n\
         schema: {RECOVERY_SCHEMA}\n\
         did: {did}\n\
         principal_id: {principal_id}\n\
         localhost_root: {localhost_root}\n\
         protector_id: {protector_id}\n\
         data_key_id: {data_key_id}\n\
         nonce: {nonce}\n\
         issued_at: {issued_at}\n\
         expires_at: {expires_at}\n"
    );
    let (signing_key, _) = elastos_identity::derive_did(&DEVICE_KEY);
    hex::encode(signing_key.sign(payload.as_bytes()).to_bytes())
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

/// Every advertised operation works under the profile, and verification
/// rejects tampered signatures instead of reporting success.
#[test]
fn all_operations_under_profile() {
    if !require_sandbox("all_operations_under_profile") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let mut provider = ConfinedProvider::spawn(&storage);
    let mut driven: BTreeSet<String> = BTreeSet::new();

    assert_ok(&provider.init(&storage));

    let did = {
        driven.insert("get_did".to_string());
        let response = provider.request(json!({"op": "get_did"}));
        assert_ok(&response);
        let did = response["data"]["did"]
            .as_str()
            .expect("get_did returns a DID")
            .to_string();
        assert!(did.starts_with("did:key:z"), "unexpected DID {did}");
        did
    };

    {
        driven.insert("resolve".to_string());
        let response = provider.request(json!({"op": "resolve", "did": did}));
        assert_ok(&response);
        assert_eq!(response["data"]["document"]["id"], did);
        assert!(response["data"]["public_key"].as_str().is_some());
    }

    let ts = 1_714_000_000u64;
    let content = "confined hello";
    let signature = {
        driven.insert("sign_chat_message".to_string());
        let response = provider.request(json!({
            "op": "sign_chat_message",
            "sender_id": did,
            "ts": ts,
            "content": content,
        }));
        assert_ok(&response);
        response["data"]["signature"]
            .as_str()
            .expect("signature")
            .to_string()
    };
    let payload_hex = elastos_common::chat_protocol::signing_payload_hex(&did, ts, content);

    {
        driven.insert("verify".to_string());
        let valid = provider.request(json!({
            "op": "verify",
            "did": did,
            "data": payload_hex,
            "signature": signature,
        }));
        assert_ok(&valid);
        assert_eq!(
            valid["data"]["valid"], true,
            "genuine signature must verify"
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

    let principal_id = "person:local:confine";
    let localhost_root = format!("localhost://Users/{principal_id}");
    let issued_at = now_ts();
    let expires_at = issued_at + 300;
    let recovery_args = (
        did.clone(),
        principal_id.to_string(),
        localhost_root.clone(),
        "protector:did:confine".to_string(),
        "pdek:confine".to_string(),
        "nonce:confine".to_string(),
        issued_at,
        expires_at,
    );
    let recovery_sig = recovery_signature(
        &recovery_args.0,
        &recovery_args.1,
        &recovery_args.2,
        &recovery_args.3,
        &recovery_args.4,
        &recovery_args.5,
        recovery_args.6,
        recovery_args.7,
    );
    let recovery_request = |signature: &str| {
        json!({
            "op": "verify_did_recovery",
            "did": recovery_args.0,
            "principal_id": recovery_args.1,
            "localhost_root": recovery_args.2,
            "protector_id": recovery_args.3,
            "data_key_id": recovery_args.4,
            "nonce": recovery_args.5,
            "issued_at": recovery_args.6,
            "expires_at": recovery_args.7,
            "signature": signature,
        })
    };

    {
        driven.insert("verify_did_recovery".to_string());
        let valid = provider.request(recovery_request(&recovery_sig));
        assert_ok(&valid);
        assert_eq!(
            valid["data"]["valid"], true,
            "genuine recovery proof must verify"
        );

        let tampered = provider.request(recovery_request(&tamper_signature(&recovery_sig)));
        assert_ok(&tampered);
        assert_eq!(
            tampered["data"]["valid"], false,
            "a tampered recovery proof must not verify"
        );
    }

    {
        driven.insert("set_nickname".to_string());
        let response = provider.request(json!({"op": "set_nickname", "nickname": "alice"}));
        assert_ok(&response);
        assert_eq!(response["data"]["nickname"], "alice");
    }

    {
        driven.insert("get_nickname".to_string());
        let response = provider.request(json!({"op": "get_nickname"}));
        assert_ok(&response);
        assert_eq!(response["data"]["nickname"], "alice");
    }

    {
        driven.insert("get_persona_did".to_string());
        let response = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
        assert_ok(&response);
        let persona = response["data"]["did"].as_str().expect("persona DID");
        assert!(
            persona.starts_with("did:key:z"),
            "unexpected persona {persona}"
        );
    }

    assert_eq!(
        driven,
        manifest_operations(),
        "every capsule.json operation must run under the profile"
    );

    assert_ok(&provider.shutdown());
}

/// A write that resolves outside the storage root is refused with a storage
/// error, leaves the outside file untouched and does not stop the provider.
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

    // `did/nickname.enc` is a symlink into the outside directory: a provider
    // that could write through it would overwrite the sentinel.
    std::fs::create_dir_all(storage.join("did")).unwrap();
    std::os::unix::fs::symlink(&outside_nickname, storage.join("did").join("nickname.enc"))
        .unwrap();

    let mut provider = ConfinedProvider::spawn(&storage);
    assert_ok(&provider.init(&storage));

    let response = provider.request(json!({"op": "set_nickname", "nickname": "alice"}));
    let (code, message) = error_parts(&response);
    assert_eq!(code, "storage_error", "unexpected refusal {response}");
    assert_permission_denied(message);
    assert_eq!(
        std::fs::read(&outside_nickname).unwrap(),
        sentinel,
        "a denied write must not change the outside target"
    );

    let after = provider.request(json!({"op": "get_did"}));
    assert_ok(&after);

    assert_ok(&provider.shutdown());
}

/// A persona key reached through a symlink outside the storage root cannot be
/// read; the provider refuses and keeps serving.
#[test]
fn outside_read_denied() {
    if !require_sandbox("outside_read_denied") {
        return;
    }
    let (_root, storage) = canonical_tempdir();
    let (_outside, outside) = canonical_tempdir();

    let mut provider = ConfinedProvider::spawn(&storage);
    assert_ok(&provider.init(&storage));

    let created = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
    assert_ok(&created);
    let persona_did = created["data"]["did"].as_str().unwrap().to_string();

    // Move the existing persona key outside the root and link it back in.
    let stored_key = storage.join("did").join("personas").join("bot.enc");
    let outside_key = outside.join("bot.enc");
    std::fs::rename(&stored_key, &outside_key).unwrap();
    std::os::unix::fs::symlink(&outside_key, &stored_key).unwrap();
    let outside_bytes = std::fs::read(&outside_key).unwrap();

    let response = provider.request(json!({"op": "get_persona_did", "name": "bot"}));
    let (_, message) = error_parts(&response);
    assert_permission_denied(message);
    assert!(
        !response.to_string().contains(&persona_did),
        "the outside persona key must not be readable: {response}"
    );
    assert_eq!(
        std::fs::read(&outside_key).unwrap(),
        outside_bytes,
        "a denied read must leave the outside persona key unchanged"
    );

    let after = provider.request(json!({"op": "get_did"}));
    assert_ok(&after);

    assert_ok(&provider.shutdown());
}
