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
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_did-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
/// The longest the harness waits for a response, a stderr line or a child
/// exit; a failure stops at a bounded message instead of hanging.
const DIAGNOSTIC_DEADLINE: Duration = Duration::from_secs(10);
// Isolated fixture input, unrelated to any installed Home or production key.
const DEVICE_KEY: [u8; 32] = [0x42; 32];

#[test]
#[ignore = "fixture for the falsifier list's ignored-test check"]
fn ignored_falsifier_fixture() {
    panic!("the ignored fixture must be refused by the falsifier list");
}

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
    responses: Receiver<Value>,
    stderr: Receiver<String>,
}

impl ConfinedProvider {
    fn start(base: &Path) -> Self {
        Self::start_with_profile(base, Path::new(PROFILE_PATH))
    }

    /// Starts the provider under `profile` and drains both pipes from spawn.
    ///
    /// The provider's only reason for a startup denial is on stderr; a thread
    /// reads it from the start, so a full pipe cannot block the child's exit.
    fn start_with_profile(base: &Path, profile: &Path) -> Self {
        let mut child = Command::new(SANDBOX_EXEC)
            .arg("-f")
            .arg(profile)
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
        let stdout = child.stdout.take().expect("provider stdout");
        let (response_tx, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(response) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                if response_tx.send(response).is_err() {
                    break;
                }
            }
        });
        let stderr = child.stderr.take().expect("provider stderr");
        let (stderr_tx, stderr_rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if stderr_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
            stderr: stderr_rx,
        }
    }

    /// Sends one request and returns its response.
    ///
    /// A request the child cannot take, and a response that never comes, both
    /// end at `failure`, which names the request, the child's exit status and
    /// the child's stderr. Normal answers keep their old shape.
    fn try_send(&mut self, request: Value) -> Result<Value, String> {
        let line = serde_json::to_string(&request).expect("request must serialize");
        let write = writeln!(self.stdin, "{line}").and_then(|()| self.stdin.flush());
        let Ok(response) = self.responses.recv_timeout(DIAGNOSTIC_DEADLINE) else {
            return Err(self.failure(&line, write.err()));
        };
        Ok(response)
    }

    fn send(&mut self, request: Value) -> Value {
        self.try_send(request)
            .unwrap_or_else(|reason| panic!("{reason}"))
    }

    /// The one message for a request the child did not answer.
    fn failure(&mut self, request: &str, write: Option<std::io::Error>) -> String {
        let status = self.await_exit();
        let stderr = self.drained_stderr();
        let write = write.map_or_else(String::new, |err| format!("; request write failed: {err}"));
        format!(
            "provider did not answer request {request}{write}; child exit status: {status}; child stderr: {stderr}"
        )
    }

    /// The child's exit status, or a bounded refusal after the deadline.
    fn await_exit(&mut self) -> String {
        let deadline = Instant::now() + DIAGNOSTIC_DEADLINE;
        loop {
            match self
                .child
                .try_wait()
                .expect("provider status must be readable")
            {
                Some(status) => return describe_status(status),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => {
                    let _ = self.child.kill();
                    let status = self.child.wait().expect("killed provider must be reaped");
                    return format!(
                        "{} (still running after {DIAGNOSTIC_DEADLINE:?}; killed)",
                        describe_status(status)
                    );
                }
            }
        }
    }

    /// Every stderr line the drain thread received. The deadline keeps a
    /// process that holds the pipe open from hanging the failure report.
    fn drained_stderr(&mut self) -> String {
        let mut text = String::new();
        let deadline = Instant::now() + DIAGNOSTIC_DEADLINE;
        loop {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                text.push_str(&format!(
                    "[stderr drain did not finish within {DIAGNOSTIC_DEADLINE:?}]"
                ));
                break;
            };
            match self.stderr.recv_timeout(left) {
                Ok(line) => {
                    text.push_str(&line);
                    text.push('\n');
                }
                Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => break,
            }
        }
        if text.is_empty() {
            "(empty)".to_string()
        } else {
            text
        }
    }

    /// The next drained stderr line, bounded; proves the drain runs before
    /// any wait for the child.
    fn next_stderr_line(&mut self) -> String {
        match self.stderr.recv_timeout(DIAGNOSTIC_DEADLINE) {
            Ok(line) => line,
            Err(err) => panic!("provider stderr is not drained before a wait: {err:?}"),
        }
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

/// Names an exit status without repeating the `exit status:` prefix, so the
/// one failure message reads clearly for an exit code or a signal.
fn describe_status(status: ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| status.to_string(), |code| format!("exit code {code}"))
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

/// The harness drains stderr from spawn, before it waits for the child.
///
/// The startup line reaches the test while the provider still runs, so the
/// drain cannot depend on a wait and a full stderr pipe cannot block the
/// child's exit.
///
/// Falsifier: replace the stderr drain loop with dropping its pipe and sender
/// (DID16); no line arrives and this test fails on its bounded deadline.
#[test]
fn stderr_is_drained_before_wait() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let mut provider = ConfinedProvider::start(&root);
    let line = provider.next_stderr_line();
    assert!(
        line.contains("did-provider: starting"),
        "the first drained line must be the provider's startup log: {line}"
    );
    assert!(
        provider
            .child
            .try_wait()
            .expect("provider status must be readable")
            .is_none(),
        "the drained line must arrive while the provider still runs"
    );
    provider.init(&root);
    provider.shutdown();
}

/// A startup the profile refuses reports the child's own reason.
///
/// The fixture profile denies everything, so `sandbox-exec` cannot execute
/// the provider. The one failure message names the request, the child's exit
/// status and the child's stderr, whether the request write lands first or
/// the child has already exited.
///
/// Falsifier: drop the child's stderr from `failure` (DID12); this test fails
/// because `Operation not permitted` is missing. Dropping the request
/// (DID13), the exit status (DID14) or the shared diagnostic (DID15) fails it
/// too.
#[test]
fn startup_denial_reports_its_reason() {
    if !sandbox_available() {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let profile = fixture.path().join("deny-all.sb");
    fs::write(&profile, "(version 1)\n(deny default)\n").expect("fixture profile");
    let request = json!({
        "op": "init",
        "config": { "base_path": root, "encryption_key": hex::encode(DEVICE_KEY) }
    });

    // The child may exit before or after the write lands; both situations
    // must end at the one diagnostic that carries the reason.
    let mut provider = ConfinedProvider::start_with_profile(&root, &profile);
    let message = provider
        .try_send(request.clone())
        .expect_err("a denied startup must not answer");
    eprintln!("startup denial: {message}");
    assert!(
        message.contains("\"op\":\"init\""),
        "the failure must name the request: {message}"
    );
    assert!(
        message.contains("child exit status:"),
        "the failure must name the exit status: {message}"
    );
    assert!(
        message.contains("Operation not permitted"),
        "the failure must carry the child's stderr: {message}"
    );

    // Once the child has exited, the request cannot be written; the same
    // diagnostic still names the actual exit status and the child's stderr.
    let mut exited = ConfinedProvider::start_with_profile(&root, &profile);
    let status = exited.await_exit();
    let message = exited
        .try_send(request)
        .expect_err("a closed request pipe must fail the same way");
    eprintln!("closed request pipe: {message}");
    assert!(
        message.contains("request write failed:"),
        "the failure must name the refused write: {message}"
    );
    assert!(
        message.contains(&status),
        "the failure must name the actual exit status {status}: {message}"
    );
    assert!(
        message.contains("\"op\":\"init\""),
        "the failure must name the request: {message}"
    );
    assert!(
        message.contains("Operation not permitted"),
        "the failure must carry the child's stderr: {message}"
    );
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
