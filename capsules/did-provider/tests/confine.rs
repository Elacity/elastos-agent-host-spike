//! The real DID provider speaks stdin/stdout JSON under its single profile.
//! It opens no listener or socket; the profile denies network operations.

use ed25519_dalek::Signer;
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
            .arg(format!("DID_STORAGE_ROOT={}", base.join("did").display()))
            .arg("-D")
            .arg(format!("DID_STORAGE_PARENT={}", base.display()))
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
    let did = did_data["did"].as_str().expect("device DID");
    let document = provider.ok(json!({ "op": "resolve", "did": did }));
    assert_eq!(document["document"]["id"], did);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signed = provider.ok(json!({
        "op": "sign_chat_message", "sender_id": did, "ts": ts, "content": "confined"
    }));
    let verified = provider.ok(json!({
        "op": "verify", "did": did,
        "data": elastos_common::chat_protocol::signing_payload_hex(did, ts, "confined"),
        "signature": signed["signature"]
    }));
    assert_eq!(verified["valid"], true);

    let expires = ts + 120;
    let payload = format!(
        "ElastOS DID recovery request\n\
         schema: elastos.did.recovery-proof/v1\n\
         did: {did}\n\
         principal_id: person:confine\n\
         localhost_root: localhost://Users/person:confine\n\
         protector_id: protector:confine\n\
         data_key_id: pdek:confine\n\
         nonce: confine\n\
         issued_at: {ts}\n\
         expires_at: {expires}\n"
    );
    let (signing_key, _) = elastos_identity::derive_did(&DEVICE_KEY);
    let recovered = provider.ok(json!({
        "op": "verify_did_recovery", "did": did,
        "principal_id": "person:confine", "localhost_root": "localhost://Users/person:confine",
        "protector_id": "protector:confine", "data_key_id": "pdek:confine", "nonce": "confine",
        "issued_at": ts, "expires_at": expires,
        "signature": hex::encode(signing_key.sign(payload.as_bytes()).to_bytes())
    }));
    assert_eq!(recovered["valid"], true);

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

/// Replacing deny default with allow default makes the outside write succeed.
#[test]
fn confined_outside_write_is_denied() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let outside = tempfile::tempdir().expect("unrelated base");
    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);
    provider.ok(json!({ "op": "set_nickname", "nickname": "Allowed" }));

    for base in [resolved(outside.path()), root.join("sibling")] {
        fs::create_dir_all(&base).expect("outside base fixture");
        provider.init(&base);
        let denied = provider.send(json!({ "op": "set_nickname", "nickname": "Outside" }));
        assert_eq!(
            denied["status"], "error",
            "outside write must fail: {denied}"
        );
        assert_eq!(denied["code"], "storage_error");
        assert!(denied["message"]
            .as_str()
            .unwrap()
            .starts_with("did-provider: failed to save nickname:"));
        assert!(
            !base.join("did/nickname.enc").exists(),
            "outside state must stay absent"
        );
        let persona = provider.send(json!({ "op": "get_persona_did", "name": "outside" }));
        assert_eq!(
            persona["status"], "error",
            "persona writes share the same boundary: {persona}"
        );
        assert!(!base.join("did/personas/outside.enc").exists());
        provider.ok(json!({ "op": "get_did" }));
    }
    provider.init(&root);
    provider.ok(json!({ "op": "set_nickname", "nickname": "Recovered" }));
    provider.shutdown();
}

#[test]
fn profile_denies_network() {
    let profile = fs::read_to_string(PROFILE_PATH).expect("single profile source");
    let forms = profile_forms(&profile);
    assert_eq!(forms.first().map(String::as_str), Some("(version 1)"));
    assert!(forms.iter().any(|form| form == "(deny default)"));
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
