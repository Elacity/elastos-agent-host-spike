//! The real DID provider speaks stdin/stdout JSON under its single profile.
//!
//! The provider opens no listener or socket and has no network path; the
//! profile's `(deny network*)` covers that. The test runs no TCP probe because
//! a probe would exercise the host network stack, not the provider, while the
//! profile rule is the one thing that must hold. `profile_denies_network`
//! asserts that rule on every platform.
//!
//! `CONFINEMENT.md` says the confinement tests exercise these profiles on
//! macOS through `/usr/bin/sandbox-exec`. On a declared host OS a missing
//! `/usr/bin/sandbox-exec` fails the test, and `sandbox_available` is the call
//! that fails it. On any other OS, when that tool is missing, the test prints
//! why it did not run and returns.

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The host OSes where `CONFINEMENT.md` says the confinement tests exercise
/// these profiles through `/usr/bin/sandbox-exec`, so a test there must run,
/// not skip.
const DECLARED_CONFINED_OS: [&str; 1] = ["macos"];
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_did-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
// Isolated fixture input, unrelated to any installed Home or production key.
const DEVICE_KEY: [u8; 32] = [0x42; 32];
/// How long a failure path waits for the child to exit before it reports.
const CHILD_EXIT_DEADLINE: Duration = Duration::from_secs(10);
/// How often the bounded wait checks whether the child has exited.
const CHILD_EXIT_POLL: Duration = Duration::from_millis(20);

#[test]
#[ignore = "fixture for the falsifier list's ignored-test check"]
fn ignored_falsifier_fixture() {
    panic!("the ignored fixture must be refused by the falsifier list");
}

/// Whether a sandbox test runs on this host.
///
/// A present `sandbox_exec` runs the test on any OS. A missing one is an error
/// on an OS where `CONFINEMENT.md` says the confinement tests exercise these
/// profiles, because a test there must run, not skip, and a skip would pass a
/// profile that was never exercised (P11). On any other OS it is a skip.
fn sandbox_gate(os: &str, sandbox_exec: &Path) -> Result<bool, String> {
    if sandbox_exec.is_file() {
        return Ok(true);
    }
    if DECLARED_CONFINED_OS.contains(&os) {
        return Err(format!(
            "CONFINEMENT.md says the confinement tests exercise these profiles on {os}, \
             so a test there must run, not skip: {} is absent",
            sandbox_exec.display()
        ));
    }
    Ok(false)
}

/// Returns `true` when the confinement test can run.
///
/// On `Err` from `sandbox_gate` this fails the test with that reason. It does
/// not return `false` for an error. It prints the skip line only when the gate
/// answers `Ok(false)`.
fn sandbox_available(os: &str, sandbox_exec: &Path) -> bool {
    match sandbox_gate(os, sandbox_exec) {
        Ok(true) => true,
        Ok(false) => {
            eprintln!(
                "SKIP did-provider confinement test: {} is absent; \
                 the profile was not exercised on this machine",
                sandbox_exec.display()
            );
            false
        }
        Err(reason) => panic!("{reason}"),
    }
}

/// A declared host OS runs its confinement tests; it never passes by skipping.
///
/// A missing `sandbox-exec` on `macos` is an error that names the OS and the
/// path, a missing one on `linux` is a skip, and a present one on `macos` runs
/// the test. The test starts no process, so it runs on every supported build
/// target.
///
/// Falsifier: return `Ok(false)` from the declared-OS branch (DID20); the
/// `macos` case fails because a missing `sandbox-exec` skips and passes.
#[test]
fn sandbox_gate_fails_instead_of_skipping_on_a_declared_os() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = std::env::current_exe().expect("the test executable path must be available");
    assert!(
        present.is_file(),
        "the present fixture must be a file: {}",
        present.display()
    );

    let refusal = sandbox_gate("macos", &missing)
        .expect_err("a declared OS must run its confinement test, not skip it");
    assert!(
        refusal.contains("macos") && refusal.contains(&missing.display().to_string()),
        "the refusal must name the OS and the missing path: {refusal}"
    );
    assert_eq!(
        sandbox_gate("linux", &missing),
        Ok(false),
        "an undeclared OS may skip the test it cannot run"
    );
    assert_eq!(
        sandbox_gate("macos", &present),
        Ok(true),
        "a declared OS runs the test when sandbox-exec is present"
    );
}

/// `sandbox_available` fails the test when `sandbox_gate` refuses a declared
/// OS. The test calls it with `macos` and a missing path, inside
/// `std::panic::catch_unwind`. The call panics, and the payload is the gate's
/// reason, which names `macos` and the path. A return of `false` fails this
/// test. A present path on `macos` returns `true`. The test calls no OS that
/// skips, so it prints no skip line, and it starts no process.
///
/// Falsifier: return `false` from the error arm of `sandbox_available`
/// (DID22), so a missing `sandbox-exec` on macOS returns and this test fails.
#[test]
fn sandbox_available_fails_for_macos_when_sandbox_exec_is_missing() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = std::env::current_exe().expect("the test executable path must be available");
    assert!(
        present.is_file(),
        "the present fixture must be a file: {}",
        present.display()
    );

    let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandbox_available("macos", &missing)
    }));
    let failure = match settled {
        Err(payload) => payload
            .downcast_ref::<String>()
            .expect("the panic payload must be the gate's reason")
            .clone(),
        Ok(returned) => panic!(
            "a missing sandbox-exec on macos must fail the test, \
             but sandbox_available returned {returned}"
        ),
    };
    let expected = sandbox_gate("macos", &missing)
        .expect_err("a declared OS must refuse a missing sandbox-exec");
    assert_eq!(
        failure, expected,
        "the panic payload must be the gate's reason"
    );
    assert!(
        failure.contains("macos") && failure.contains(&missing.display().to_string()),
        "the refusal must name the OS and the missing path: {failure}"
    );
    assert!(
        sandbox_available("macos", &present),
        "a present sandbox-exec on macos must let the confined test run"
    );
}

fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("fixture path must resolve")
}

/// The three parameter bindings the tests make for one storage root.
fn canonical_bindings(base: &Path) -> [(&'static str, String); 3] {
    [
        ("STORAGE_ROOT", base.join("did").display().to_string()),
        ("STORAGE_PARENT", base.display().to_string()),
        (
            "PROVIDER_EXECUTABLE",
            resolved(Path::new(PROVIDER_BINARY)).display().to_string(),
        ),
    ]
}

/// The one launch builder: `sandbox-exec -f <profile>` with each binding, then
/// `program`, the one program this launch starts.
///
/// `start_under` starts the provider binary. A test that needs a launch the
/// Runtime cannot make passes fewer bindings, or another program, through the
/// same command shape, so one builder covers every start (P10).
fn confinement_command(profile: &Path, bindings: &[(&str, String)], program: &Path) -> Command {
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-f").arg(profile);
    for (name, value) in bindings {
        command.arg("-D").arg(format!("{name}={value}"));
    }
    command.arg(program);
    command
}

/// The child's exit, or the deadline that ended the wait.
enum ChildExit {
    Exited(ExitStatus),
    TimedOut,
}

impl ChildExit {
    fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(status) => status.code(),
            Self::TimedOut => None,
        }
    }
}

impl std::fmt::Display for ChildExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited(status) => write!(f, "{status}"),
            Self::TimedOut => write!(
                f,
                "no exit within {}s, so it was killed",
                CHILD_EXIT_DEADLINE.as_secs()
            ),
        }
    }
}

/// One confined provider process, or a fixture child, spoken to over its
/// standard streams.
///
/// `spawn` is the only spawn path. It pipes all three streams and drains
/// standard error on its own thread from the moment the child starts, so a
/// child that fills the pipe still reaches its own exit. A request the child
/// never answered fails with the one message from `unanswered`, which names the
/// request, the child's exit status or the deadline that ended the wait, and
/// all the child wrote to standard error. An answer that is not JSON fails with
/// its own message, which names the request, the parse error and the answer.
struct ConfinedProvider {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_reader: Option<JoinHandle<String>>,
    stderr_text: String,
}

impl ConfinedProvider {
    /// The one spawn path; `command` already carries its arguments.
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the test child must start");
        let stdin = child.stdin.take().expect("provider stdin");
        let stdout = BufReader::new(child.stdout.take().expect("provider stdout"));
        let mut stderr_pipe = child.stderr.take().expect("provider stderr");
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        });
        Self {
            child,
            stdin,
            stdout,
            stderr_reader: Some(stderr_reader),
            stderr_text: String::new(),
        }
    }

    fn start(base: &Path) -> Self {
        Self::start_under(Path::new(PROFILE_PATH), base)
    }

    /// Starts the provider under `profile`, its one profile source.
    fn start_under(profile: &Path, base: &Path) -> Self {
        Self::spawn(confinement_command(
            profile,
            &canonical_bindings(base),
            Path::new(PROVIDER_BINARY),
        ))
    }

    /// Sends one request and returns its answer; a failure panics with the
    /// message from `try_send`. A request the child never answered fails with
    /// the one message from `unanswered`, which names the request, the child's
    /// exit status or the deadline that ended the wait, and all the child
    /// wrote to standard error. An answer that is not JSON fails with its own
    /// message, which names the request, the parse error and the answer.
    fn send(&mut self, request: Value) -> Value {
        self.try_send(&request)
            .unwrap_or_else(|failure| panic!("{failure}"))
    }

    /// Sends one request and returns its answer. A request the child never
    /// answered fails with the one message from `unanswered`, which names the
    /// request, the child's exit status or the deadline that ended the wait,
    /// and all the child wrote to standard error. An answer that is not JSON
    /// fails with its own message, which names the request, the parse error
    /// and the answer.
    fn try_send(&mut self, request: &Value) -> Result<Value, String> {
        let written = writeln!(self.stdin, "{request}").and_then(|()| self.stdin.flush());
        if let Err(err) = written {
            return Err(self.unanswered(request, &format!("writing the request failed: {err}")));
        }
        let mut response = String::new();
        let read = self.stdout.read_line(&mut response);
        match read {
            Ok(0) => Err(self.unanswered(request, "the response stream ended")),
            Ok(_) => serde_json::from_str(&response).map_err(|err| {
                format!("provider answered request {request} with invalid JSON: {err}: {response}")
            }),
            Err(err) => {
                Err(self.unanswered(request, &format!("reading the response failed: {err}")))
            }
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
        let exit = self.wait_for_exit();
        assert!(exit.code() == Some(0), "confined provider {exit}");
    }

    /// Waits up to `CHILD_EXIT_DEADLINE` for the child to exit.
    fn wait_for_exit(&mut self) -> ChildExit {
        let started = Instant::now();
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("child status must be readable")
            {
                return ChildExit::Exited(status);
            }
            if started.elapsed() >= CHILD_EXIT_DEADLINE {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return ChildExit::TimedOut;
            }
            std::thread::sleep(CHILD_EXIT_POLL);
        }
    }

    /// Every byte the child wrote to standard error, once the drainer reached
    /// end of file. Call it after the child exits.
    fn stderr(&mut self) -> &str {
        if let Some(reader) = self.stderr_reader.take() {
            self.stderr_text = reader.join().expect("the stderr drainer must not panic");
        }
        &self.stderr_text
    }

    /// The one failure message for a request the provider never answered.
    fn unanswered(&mut self, request: &Value, cause: &str) -> String {
        let exit = self.wait_for_exit();
        let stderr = self.stderr().to_string();
        format!(
            "provider did not answer request {request} ({cause}); child {exit}; standard error: {stderr}"
        )
    }
}

impl Drop for ConfinedProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

/// The confined provider serves the DID operations over its normal protocol.
///
/// `sign_chat_message` returns the payload it signed together with the
/// signature; both travel unchanged to `verify`. The test renders no signing
/// payload and constructs no signature of its own.
#[test]
fn confined_provider_serves_did_operations_under_its_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
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
/// Falsifiers: panic in the `hex::decode(sig_hex)` error branch of
/// `verify_did_recovery` in `src/main.rs` (DID06); the confined process dies
/// and this case fails because no response line comes back. Return
/// `parse_error` instead of the signature refusal in that branch (DID11); the
/// response no longer names `invalid_signature` and this case fails.
#[test]
fn verify_did_recovery_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
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
/// The link case runs for two targets: an unrelated directory, and a sibling
/// of `did/` under the same base directory, so the write grant must stop at
/// `Init.base_path/did`.
///
/// Falsifiers: replace `(deny default)` with `(allow default)`, keeping
/// `(version 1)` first (DID04); widen the write grant from `STORAGE_ROOT` to
/// `STORAGE_PARENT` (DID18), so the sibling write succeeds and this test fails
/// on that target.
#[test]
fn outside_write_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let outside = tempfile::tempdir().expect("unrelated base");
    let outside = resolved(outside.path());
    // A sibling of `did/` under the same base; the test creates it before it
    // links so the refusal must come from the profile, not a missing path.
    let sibling = root.join("sibling");
    fs::create_dir_all(&sibling).expect("sibling directory under the same base");
    let mut provider = ConfinedProvider::start(&root);
    provider.init(&root);

    // The profile resolves each link, so the write target stays outside the
    // grant. Only the second target separates a grant on `did/` from one on
    // its parent.
    let granted = root.join("did").join("nickname.enc");
    for target in [outside.join("nickname.enc"), sibling.join("nickname.enc")] {
        let target_dir = target.parent().expect("target directory");
        provider.ok(json!({ "op": "set_nickname", "nickname": "Allowed" }));
        fs::remove_file(&granted).expect("granted nickname file");
        std::os::unix::fs::symlink(&target, &granted).expect("outside symlink");

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
            !target.exists(),
            "nothing may land outside the storage root: {}",
            target.display()
        );
        assert_eq!(
            fs::read_dir(target_dir).expect("target directory").count(),
            0,
            "the target directory must stay unchanged: {}",
            target_dir.display()
        );

        // Remove the escape and confirm the provider still serves its root.
        fs::remove_file(&granted).expect("remove outside symlink");
        provider.ok(json!({ "op": "set_nickname", "nickname": "Recovered" }));
        let nickname = provider.ok(json!({ "op": "get_nickname" }));
        assert_eq!(nickname["nickname"], "Recovered");
    }

    provider.ok(json!({ "op": "get_did" }));
    provider.shutdown();
}

/// A read through a symlink that leaves the storage root is denied by the
/// single shared loader, and the provider reports it and stays in service.
///
/// Falsifiers: replace the nickname read error with `.ok().flatten()` in
/// `try_load_nickname` (DID03); the denied read becomes "no nickname", `Init`
/// returns ok and this test fails. Replace `(deny default)` with
/// `(allow default)` (DID04); the read succeeds and this test fails.
#[test]
fn outside_read_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
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

/// A confined start that fails before it answers shows its reason.
///
/// The fixture profile keeps `(version 1)` first and `(deny default)` second,
/// so `sandbox-exec` cannot exec the provider. The test waits for that child to
/// exit, sends `init`, and requires the one harness failure to name the
/// request, the exit status and `sandbox-exec`'s own denial on standard error.
/// A fixture child that reads one request and exits without answering reaches
/// the response-stream branch of the same harness with the same three facts.
///
/// Falsifier: drop the child's standard error from `unanswered` (DID12); the
/// denied start loses `Operation not permitted`, so this test fails on that
/// assertion at the first case.
///
/// Falsifier: omit the request from `unanswered` (DID14); the denied start's
/// failure no longer names the request, so this test fails on its request
/// assertion at the first case.
///
/// Falsifier: omit the exit status from `unanswered` (DID15); the denied
/// start's failure no longer names the child's exit status, so this test fails
/// on its exit-status assertion at the first case.
///
/// Falsifier: return a fixed message from the failed-write branch instead of
/// the shared diagnostic (DID16); the denied start's failure reads `provider
/// stdin must accept a request`, so this test fails on its request assertion at
/// the first case.
///
/// Falsifier: return a fixed message from the response-stream branch instead of
/// the shared diagnostic (DID17); the silent child's failure reads `provider
/// exited without a response`, so this test fails on its request assertion in
/// the second case.
///
/// Falsifier: use a fixed `Operation not permitted` instead of the child's
/// standard error in `unanswered` (DID24); the denied start's failure names no
/// `execvp()` denial, so this test fails on that assertion at the first case.
#[test]
fn startup_denial_reports_its_reason() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile = resolved(profile_root.path()).join("deny-all.sb");
    fs::write(&profile, "(version 1)\n(deny default)\n").expect("fixture profile must be writable");
    let request = json!({
        "op": "init",
        "config": { "base_path": root, "encryption_key": hex::encode(DEVICE_KEY) }
    });

    // The denied provider exits before it reads the request, so the harness
    // cannot write it. It reports the exit status and the sandbox denial.
    let mut denied = ConfinedProvider::start_under(&profile, &root);
    let exit = denied.wait_for_exit();
    assert_ne!(
        exit.code(),
        Some(0),
        "sandbox-exec must not exec the provider: {exit}"
    );
    let denial = denied
        .try_send(&request)
        .expect_err("a denied provider must not answer");
    assert!(
        denial.contains(&request.to_string()),
        "the failure must name the request: {denial}"
    );
    assert!(
        denial.contains(&exit.to_string()),
        "the failure must name the exit status: {denial}"
    );
    assert!(
        denial.contains("Operation not permitted"),
        "the failure must carry sandbox-exec's denial: {denial}"
    );
    assert!(
        denial.contains("execvp()") && denial.contains(PROVIDER_BINARY),
        "the denial must be sandbox-exec's exec denial of the provider binary: {denial}"
    );
    eprintln!("startup denial failure: {denial}");

    // A child that answers nothing reaches the response-stream branch with the
    // same three facts.
    let mut silent = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read request; printf 'fixture: read one request\\n' >&2; exit 3");
        command
    });
    let silence = silent
        .try_send(&request)
        .expect_err("a child that exits without answering must fail");
    let exit = silent.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(3),
        "the fixture must reach its own exit: {exit}"
    );
    assert!(
        silence.contains(&request.to_string()),
        "the failure must name the request: {silence}"
    );
    assert!(
        silence.contains(&exit.to_string()),
        "the failure must name the exit status: {silence}"
    );
    assert!(
        silence.contains("fixture: read one request"),
        "the failure must carry the child's standard error: {silence}"
    );
    eprintln!("response-stream failure: {silence}");
}

/// One launch whose profile cannot be applied is refused with its reason.
///
/// The launch goes through `confinement_command`, waits for the child, sends
/// `init`, and requires the one harness failure to name the request, the exit
/// status and `sandbox-exec`'s own reason on standard error. The failure must
/// not name `execvp`, so the exec was never attempted. The base stays empty,
/// because the provider took no `Init.base_path`.
fn assert_startup_is_refused(
    case: &str,
    profile: &Path,
    bindings: &[(&str, String)],
    marker: &str,
    root: &Path,
    request: &Value,
) {
    let mut child = ConfinedProvider::spawn(confinement_command(
        profile,
        bindings,
        Path::new(PROVIDER_BINARY),
    ));
    let exit = child.wait_for_exit();
    // A live child means the launch fell back to an unconfined start; the
    // deadline killed it before it could answer, so check that first.
    assert!(
        !matches!(exit, ChildExit::TimedOut),
        "{case}: the provider must not start, so sandbox-exec must exit: {exit}"
    );
    assert_ne!(
        exit.code(),
        Some(0),
        "{case}: the launch must fail instead of starting the provider: {exit}"
    );
    let failure = child
        .try_send(request)
        .expect_err("a refused launch must not answer the init request");
    assert!(
        !failure.contains("execvp"),
        "{case}: sandbox-exec must stop before the exec: {failure}"
    );
    assert!(
        failure.contains(&request.to_string()),
        "{case}: the failure must name the request: {failure}"
    );
    assert!(
        failure.contains(&exit.to_string()),
        "{case}: the failure must name the exit status: {failure}"
    );
    assert!(
        failure.contains(marker),
        "{case}: the failure must carry sandbox-exec's reason, {marker:?}: {failure}"
    );
    assert!(
        fs::read_dir(root)
            .expect("the storage root must stay readable")
            .next()
            .is_none(),
        "{case}: a refused launch must leave Init.base_path empty, with nothing under {}",
        root.display()
    );
    eprintln!("{case} refusal: {failure}");
}

/// A launch whose profile cannot be applied never starts the provider.
///
/// Three profiles cannot load on this Mac: one whose path does not exist, one
/// that does not parse because its last `)` is removed, and the real profile
/// with every parameter bound except `STORAGE_ROOT`. `sandbox-exec` exits with
/// a status other than 0 for each before it reaches the exec, and the one
/// harness reports its reason from standard error.
///
/// Falsifier: start the provider binary directly when the profile file does
/// not exist (DID21); the provider stays alive to the deadline instead of
/// being refused, and this test fails on its first case.
#[test]
fn startup_is_refused_when_the_profile_cannot_be_applied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary identity root");
    let root = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_root = resolved(profile_root.path());
    let missing = profile_root.join("missing.sb");
    let broken = profile_root.join("broken.sb");
    let source = fs::read_to_string(PROFILE_PATH).expect("single profile source");
    let trimmed = source.trim_end();
    assert!(
        trimmed.ends_with(')'),
        "the fixture needs the profile's last closing form: {trimmed}"
    );
    fs::write(&broken, &trimmed[..trimmed.len() - 1]).expect("fixture profile must be writable");

    let request = json!({
        "op": "init",
        "config": { "base_path": root, "encryption_key": hex::encode(DEVICE_KEY) }
    });
    let canonical = canonical_bindings(&root);
    let unbound_root: Vec<(&str, String)> = canonical
        .iter()
        .filter(|(name, _)| *name != "STORAGE_ROOT")
        .cloned()
        .collect();

    assert_startup_is_refused(
        "missing profile",
        &missing,
        &canonical,
        &missing.display().to_string(),
        &root,
        &request,
    );
    assert_startup_is_refused(
        "unparsable profile",
        &broken,
        &canonical,
        "syntax error: expecting ')'",
        &root,
        &request,
    );
    assert_startup_is_refused(
        "unbound STORAGE_ROOT",
        Path::new(PROFILE_PATH),
        &unbound_root,
        "invalid data type of path filter",
        &root,
        &request,
    );
}

/// The stored-copy fixture shared by `unbound_copy_is_refused_under_profile`
/// and its control. It keeps the temporary base alive, resolves it, creates
/// `STORAGE_ROOT` first, and copies the provider binary there byte for byte,
/// so the copy and the binary differ only by path.
struct StoredCopy {
    _fixture: tempfile::TempDir,
    base: PathBuf,
    storage: PathBuf,
    copy: PathBuf,
}

impl StoredCopy {
    fn prepare() -> Self {
        let fixture = tempfile::tempdir().expect("temporary identity root");
        let base = resolved(fixture.path());
        let binary = resolved(Path::new(PROVIDER_BINARY));
        let storage = base.join("did");
        fs::create_dir(&storage).expect("STORAGE_ROOT must be created first");
        let copy = storage.join(binary.file_name().expect("the provider binary's file name"));
        fs::copy(&binary, &copy).expect("copy the provider binary under STORAGE_ROOT");
        let copy = resolved(&copy);
        assert_eq!(
            fs::read(&copy).expect("the copy must be readable"),
            fs::read(&binary).expect("the binary must be readable"),
            "the copy must be byte-identical to the bound binary"
        );
        Self {
            _fixture: fixture,
            base,
            storage,
            copy,
        }
    }
}

/// Under the real profile, only the path bound as `PROVIDER_EXECUTABLE` can be
/// started. The test runs `confine.sb` itself, with no fixture rule. It binds
/// the real provider binary as `PROVIDER_EXECUTABLE` and the storage
/// parameters as usual, and starts the byte-identical copy under
/// `STORAGE_ROOT`. `sandbox-exec` applies the profile before it executes its
/// program, so the refused step is that exec of the copy, checked by the same
/// `process-exec` rule as any exec by the confined provider. `sandbox-exec`
/// exits 71 and logs `execvp() of '<copy>' failed: Operation not permitted`,
/// and `STORAGE_ROOT` keeps only the copy. A missing program also exits 71,
/// but with `No such file or directory`, so the test checks the EPERM line.
/// `bound_copy_serves_under_profile` is the control: the same copy from the
/// same fixture, bound and started, serves.
///
/// Falsifier: append one `(allow process-exec)` after the exec rule (DID26);
/// the copy starts and stays alive to the deadline, so this test fails on its
/// deadline assertion.
#[test]
fn unbound_copy_is_refused_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare();
    let before = fs::read(&stored.copy).expect("the copy must be readable");
    let request = json!({
        "op": "init",
        "config": { "base_path": stored.base, "encryption_key": hex::encode(DEVICE_KEY) }
    });
    let mut refused = ConfinedProvider::spawn(confinement_command(
        Path::new(PROFILE_PATH),
        &canonical_bindings(&stored.base),
        &stored.copy,
    ));

    let exit = refused.wait_for_exit();
    assert!(
        !matches!(exit, ChildExit::TimedOut),
        "the profile must refuse the exec, so sandbox-exec must exit: {exit}"
    );
    assert_eq!(
        exit.code(),
        Some(71),
        "sandbox-exec must exit 71 when the profile refuses the exec: {exit}"
    );
    refused
        .try_send(&request)
        .expect_err("the refused copy must not answer init");

    // Quote only `sandbox-exec`'s exec lines, never the whole stream.
    let copy = stored.copy.display().to_string();
    let stderr = refused.stderr();
    let execs: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("execvp()"))
        .collect();
    assert!(
        execs
            .iter()
            .any(|line| line.contains(&copy) && line.contains("Operation not permitted")),
        "sandbox-exec must log the refused exec of {copy} with EPERM: {execs:?}"
    );

    let entries: Vec<PathBuf> = fs::read_dir(&stored.storage)
        .expect("STORAGE_ROOT must stay readable")
        .map(|entry| entry.expect("STORAGE_ROOT entry").path())
        .collect();
    assert_eq!(
        entries,
        [stored.copy.clone()],
        "STORAGE_ROOT must hold only the copy"
    );
    assert_eq!(
        fs::read(&stored.copy).expect("the copy must stay readable"),
        before,
        "the refused run must leave the copy's bytes unchanged"
    );
}

/// The control for `unbound_copy_is_refused_under_profile`: the same fixture,
/// with the copy at the same place under `STORAGE_ROOT` bound as
/// `PROVIDER_EXECUTABLE` and started under the same `confine.sb`. `init` with
/// `base_path` as the fixture base answers `ok`, a following `get_did` answers
/// `ok`, and `shutdown` exits 0. The binding is the only difference between
/// the two runs.
#[test]
fn bound_copy_serves_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare();
    let bindings: Vec<(&str, String)> = canonical_bindings(&stored.base)
        .into_iter()
        .map(|(name, value)| match name {
            "PROVIDER_EXECUTABLE" => (name, stored.copy.display().to_string()),
            _ => (name, value),
        })
        .collect();
    let mut provider = ConfinedProvider::spawn(confinement_command(
        Path::new(PROFILE_PATH),
        &bindings,
        &stored.copy,
    ));
    provider.ok(json!({
        "op": "init",
        "config": { "base_path": stored.base, "encryption_key": hex::encode(DEVICE_KEY) }
    }));
    provider.ok(json!({ "op": "get_did" }));
    provider.shutdown();
}

/// The harness drains standard error while the child runs.
///
/// The fixture writes 128 KiB, more than the pipe buffer, to standard error and
/// exits with status 7. The harness must reach that status within its bounded
/// deadline and collect every byte.
///
/// Falsifier: drop the stderr pipe instead of draining it (DID13); only `dd`
/// dies on the closed pipe, so the shell still exits 7, and the collected text
/// is empty, so this test fails on its byte count, `left: 0`, `right: 131072`.
///
/// Falsifier: start reading only after `wait_for_exit` has returned (DID23);
/// the fixture fills the pipe and blocks, so the wait kills it, and this test
/// fails on its exit assertion, `no exit within 10s, so it was killed`.
#[test]
fn stderr_is_drained_before_wait() {
    let mut child = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("dd if=/dev/zero bs=1024 count=128 >&2 2>/dev/null; exit 7");
        command
    });
    let exit = child.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(7),
        "the child must reach its own exit: {exit}"
    );
    let stderr = child.stderr();
    assert_eq!(stderr.len(), 128 * 1024, "every drained byte must survive");
    assert!(
        stderr.as_bytes().iter().all(|byte| *byte == 0),
        "the drained bytes must be the fixture's zero bytes"
    );
}

/// An answer that is not JSON fails with its own message.
///
/// Through `spawn`, a fixture child reads one request, prints `not json` and a
/// newline to standard output, and exits 0. The failure names the request,
/// `invalid JSON`, the parse error `serde_json` gives for the answer and the
/// answer itself, and it does not say the provider did not answer. The test
/// starts no sandbox and does not call `sandbox_available`.
///
/// Falsifier: return the shared unanswered message from the invalid-JSON branch
/// (DID25); the answer loses its parse error and says the provider did not
/// answer, so this test fails on its `invalid JSON` assertion.
#[test]
fn invalid_json_answer_names_the_request_and_the_parse_error() {
    let mut child = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read request; echo 'not json'; exit 0");
        command
    });
    let request = json!({ "op": "get_did" });
    let failure = child
        .try_send(&request)
        .expect_err("an answer that is not JSON must fail");
    let parse_error = serde_json::from_str::<Value>("not json\n")
        .expect_err("the fixture answer must not parse as JSON")
        .to_string();
    assert!(
        failure.contains(&request.to_string()),
        "the failure must name the request: {failure}"
    );
    assert!(
        failure.contains("invalid JSON"),
        "the failure must name the invalid JSON answer: {failure}"
    );
    assert!(
        failure.contains(&parse_error),
        "the failure must carry the parse error: {failure}"
    );
    assert!(
        failure.contains("not json"),
        "the failure must carry the answer: {failure}"
    );
    assert!(
        !failure.contains("did not answer"),
        "an invalid answer is not an unanswered request: {failure}"
    );
    eprintln!("invalid-JSON failure: {failure}");
}

/// The one profile source denies the network and every default grant.
///
/// Falsifier: replace `(deny network*)` with `(allow network*)` (DID05); this
/// test fails on the missing explicit denial and the network grant.
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
