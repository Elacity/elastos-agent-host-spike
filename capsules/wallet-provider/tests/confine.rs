//! Confinement proof for wallet-provider.
//!
//! Each test starts the real provider binary under `capsules/wallet-provider/confine.sb`
//! with `/usr/bin/sandbox-exec` and drives it over its normal stdin/stdout
//! protocol. The provider opens no network listener or socket: it reads
//! line-delimited JSON from stdin and writes one JSON response per line to
//! stdout, and the profile denies every network operation.
//!
//! `CONFINEMENT.md` says the confinement tests exercise these profiles on
//! macOS through `/usr/bin/sandbox-exec`. On a declared host OS a missing
//! `/usr/bin/sandbox-exec` fails the test, and `sandbox_available` is the call
//! that fails it. On any other OS, when that tool is missing, the test prints
//! why it did not run and returns.

use elastos_wallet_contract::{
    VerifiedWalletInvocationContext, WalletProviderOperationV2, WalletProviderRequestV2,
    WalletProviderResponseV2, WalletResultV2,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The host OSes where `CONFINEMENT.md` says the confinement tests exercise
/// these profiles through `/usr/bin/sandbox-exec`, so a test there must run,
/// not skip.
const DECLARED_CONFINED_OS: [&str; 1] = ["macos"];
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_wallet-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
const WALLET_KEY_FILE: &str = "wallet-key.hex";
const WALLET_DIR: [&str; 3] = ["ElastOS", "SystemServices", "Wallet"];
/// How long a failure path waits for the child to exit before it reports.
const CHILD_EXIT_DEADLINE: Duration = Duration::from_secs(10);
/// How often the bounded wait checks whether the child has exited.
const CHILD_EXIT_POLL: Duration = Duration::from_millis(20);

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

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

/// Returns `true` when the test can run, and fails it on a declared OS.
///
/// On `Err` from `sandbox_gate` this fails the test with that reason. It does
/// not return `false` for an error. It prints the skip line only when the gate
/// answers `Ok(false)`.
fn sandbox_available(os: &str, sandbox_exec: &Path) -> bool {
    match sandbox_gate(os, sandbox_exec) {
        Ok(true) => true,
        Ok(false) => {
            eprintln!(
                "SKIP wallet-provider confinement test: {} is absent; \
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
/// Falsifier: return `Ok(false)` from the declared-OS branch (WP27); the
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

/// The one caller fails the test when the gate refuses a declared host OS.
///
/// With `macos` and a missing `sandbox-exec` the call panics and its payload,
/// read as a `String`, is the gate's reason, which names the OS and the path.
/// A return fails this test with the returned value. A present path on
/// `macos` returns `true`. The test calls no OS that skips, so it prints no
/// skip line, and it starts no process.
///
/// Falsifier: WP30 returns `false` from the error arm of `sandbox_available`,
/// so a missing `sandbox-exec` on `macos` returns and this test fails.
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
            .cloned()
            .expect("the gate's reason must arrive as a String payload"),
        Ok(returned) => panic!(
            "a missing sandbox-exec on macos must fail the test, but sandbox_available returned {returned}"
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

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_secs()
}

fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("wallet directory must resolve")
}

fn wallet_dir(root: &Path) -> PathBuf {
    WALLET_DIR
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// The three parameter bindings the tests make for one storage root.
fn canonical_bindings(base: &Path) -> [(&'static str, PathBuf); 3] {
    let wallet_root = wallet_dir(base);
    let parent = wallet_root.parent().expect("wallet parent").to_path_buf();
    [
        ("STORAGE_ROOT", wallet_root),
        ("STORAGE_PARENT", parent),
        ("PROVIDER_EXECUTABLE", resolved(Path::new(PROVIDER_BINARY))),
    ]
}

/// The test creates the directory `STORAGE_PARENT` names before the launch,
/// and the provider creates `Wallet`. The binding the launch receives names
/// that directory, so the folder created and the folder bound cannot drift
/// apart (P10).
fn create_shared_ancestors(bindings: &[(&'static str, PathBuf)]) {
    let (_, parent) = bindings
        .iter()
        .find(|(name, _)| *name == "STORAGE_PARENT")
        .expect("the tests bind STORAGE_PARENT");
    fs::create_dir_all(parent).expect("prepare shared service directories");
}

fn runtime_invocation_envelope() -> Value {
    json!({
        "schema": "elastos.provider.invocation/v1",
        "source": "runtime",
        "target": "wallet",
        "op": "wallet_contract",
        "capability": "provider:runtime->wallet:wallet_contract",
        "transport": "runtime-local-provider-plane",
        "carrier": null,
        "transfer": "json",
        "range": null,
        "progress": null,
        "abi": {
            "schema": "elastos.provider.transfer-abi/v1",
            "transfer": "json",
            "transport": "runtime-local-provider-plane",
            "range_supported": false,
            "progress_supported": false,
            "progress_mode": "none",
            "transport_native_stream": false,
            "backpressure": "not_applicable",
            "cancel_supported": false
        }
    })
}

fn wallet_request(operation: WalletProviderOperationV2) -> WalletProviderRequestV2 {
    let context = VerifiedWalletInvocationContext::new(
        "person:local:alice",
        "session:confine",
        Some("proof:confine".to_string()),
        "grant:confine",
        "wallet",
        "launch:confine",
    )
    .expect("confine test authority must be valid");
    let sequence = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let issued_at = now_ts();
    WalletProviderRequestV2::new(
        &context,
        format!("wallet-request:{sequence:032x}"),
        issued_at,
        issued_at.saturating_add(120),
        operation,
    )
    .expect("confine test request must be valid")
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

/// The real provider binary, confined by `confine.sb`, speaking its normal
/// line-delimited JSON protocol.
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
        Self::start_with_profile(base, Path::new(PROFILE_PATH), &[])
    }

    fn start_with_profile(base: &Path, profile: &Path, parameters: &[(&str, &Path)]) -> Self {
        let canonical = canonical_bindings(base);
        create_shared_ancestors(&canonical);
        let mut bindings: Vec<(&str, &Path)> = canonical
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        bindings.extend_from_slice(parameters);
        Self::start_under(profile, &bindings)
    }

    /// The one launch builder: the provider binary under `profile`, with
    /// exactly the `bindings` it is given. A caller can leave a parameter
    /// unbound, as a Runtime bug would.
    fn start_under(profile: &Path, bindings: &[(&str, &Path)]) -> Self {
        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-f").arg(profile);
        for (name, path) in bindings {
            command.arg("-D").arg(format!("{name}={}", path.display()));
        }
        command.arg(PROVIDER_BINARY);
        Self::spawn(command)
    }

    /// Sends one request and returns its answer; a failure panics with the
    /// message from `try_send`. A request the child never answered fails with
    /// the one message from `unanswered`, which names the request, the child's
    /// exit status or the deadline that ended the wait, and all the child
    /// wrote to standard error. An answer that is not JSON fails with its own
    /// message, which names the request, the parse error and the answer.
    fn send(&mut self, request: &Value) -> Value {
        self.try_send(request)
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
        match self.stdout.read_line(&mut response) {
            Ok(0) => Err(self.unanswered(request, "the response stream ended")),
            Ok(_) => serde_json::from_str(&response).map_err(|err| {
                format!("provider answered request {request} with invalid JSON: {err}: {response}")
            }),
            Err(err) => {
                Err(self.unanswered(request, &format!("reading the response failed: {err}")))
            }
        }
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

    fn init(&mut self, root: &Path) -> Value {
        self.send(&json!({
            "op": "init",
            "config": { "base_path": root.display().to_string() }
        }))
    }

    fn wallet(&mut self, operation: WalletProviderOperationV2) -> WalletResultV2 {
        let request = wallet_request(operation);
        let response = self.send(&json!({
            "op": "wallet_contract",
            "request": request,
            "_runtime_invocation": runtime_invocation_envelope(),
        }));
        assert_eq!(
            response["status"], "ok",
            "wallet_contract must answer through the protocol: {response}"
        );
        let data = response
            .get("data")
            .expect("wallet_contract answer must carry a bound response");
        let bytes = serde_json::to_vec(data).expect("bound response must serialize");
        WalletProviderResponseV2::decode_for_request(&bytes, &request)
            .expect("provider response must bind to its request")
            .result
    }

    fn shutdown(&mut self) {
        let response = self.send(&json!({ "op": "shutdown" }));
        assert_eq!(response["status"], "ok", "shutdown must answer: {response}");
        let exit = self.wait_for_exit();
        assert!(exit.code() == Some(0), "confined provider {exit}");
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

fn assert_storage_error(response: &Value) {
    assert_eq!(
        response["status"], "error",
        "expected a storage refusal, got {response}"
    );
    assert_eq!(response["code"], "storage_error");
    let message = response["message"]
        .as_str()
        .expect("storage refusal must carry a reason");
    assert!(
        message.contains("wallet storage"),
        "storage refusal must state what it could not reach: {message}"
    );
}

fn ok_data(result: WalletResultV2) -> Value {
    match result {
        WalletResultV2::Ok { data } => data,
        WalletResultV2::Error { code, message } => {
            panic!("expected wallet operation success, got {code}: {message}")
        }
    }
}

fn read_store(root: &Path) -> Value {
    let path = wallet_dir(root).join("wallet-state.json");
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    serde_json::from_slice(&bytes).expect("wallet store must be JSON")
}

/// The confined provider serves real wallet operations over its protocol and
/// keeps account and key state under the wallet directory it was given.
///
/// Falsifier: deny the storage-root write in `confine.sb`; `Init` then fails
/// and this test fails.
#[test]
fn confined_provider_serves_wallet_operations_under_its_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");
    assert_eq!(init["data"]["storage_configured"], true);
    assert_eq!(init["data"]["managed_wallets_configured"], true);

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "capsule status must answer: {status}"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Confined".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    assert!(
        !account_id.is_empty(),
        "managed account id must not be empty"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("account listing must be an array");
    assert!(
        accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str()),
        "the created managed account must be listed: {data}"
    );

    let store = read_store(&root);
    assert!(
        store["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "account state must land under the wallet root: {store}"
    );
    let key_path = wallet_dir(&root).join(WALLET_KEY_FILE);
    assert!(
        fs::metadata(&key_path).is_ok_and(|metadata| metadata.len() > 0),
        "the storage key must land under the wallet root: {}",
        key_path.display()
    );

    provider.shutdown();
}

/// A write outside the wallet directory is denied by the profile, and the
/// provider reports it and stays in service.
///
/// Falsifier: replace `(deny default)` with `(allow default)`; the outside
/// `Init` then succeeds and this test fails.
#[test]
fn confined_outside_write_is_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let outside = tempfile::tempdir().expect("temporary outside directory");
    let outside = resolved(outside.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    // Both an unrelated base and a sibling inside the shared base are outside
    // the wallet grant. Precreate their parents so denial must reach Wallet.
    for denied_base in [
        outside,
        root.join("sibling"),
        root.join("ElastOS/SystemServices/Sibling"),
    ] {
        let outside_wallet = wallet_dir(&denied_base);
        fs::create_dir_all(outside_wallet.parent().unwrap()).expect("outside parent fixture");
        let denied = provider.init(&denied_base);
        assert_storage_error(&denied);
        assert!(
            !outside_wallet.exists(),
            "a denied write must create nothing outside the wallet root: {}",
            outside_wallet.display()
        );

        let status = provider.send(&json!({ "op": "status" }));
        assert_eq!(
            status["status"], "ok",
            "the provider must answer after a denied write instead of exiting: {status}"
        );
    }

    let recovered = provider.init(&root);
    assert_eq!(
        recovered["status"], "ok",
        "the allowed root remains usable: {recovered}"
    );

    provider.shutdown();
}

/// A read outside the wallet directory is denied by the profile, so the
/// provider refuses that root instead of adopting state it was not granted.
///
/// Falsifier: add a sibling-file read allowance to `confine.sb`; the outside
/// `Init` then adopts the planted key and this test fails.
#[test]
fn confined_outside_read_is_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let outside = root.join("sibling");
    let outside_wallet = wallet_dir(&outside);
    plant_storage_key(&outside_wallet);
    // Let Init inspect/sync the fixture directories and stat the key and
    // absent store. Only reading the key's contents remains denied. The
    // profile under test is still read from the single confine.sb source.
    let profile = fs::read_to_string(PROFILE_PATH).expect("profile source");
    let mut read_profile = tempfile::NamedTempFile::new().expect("read fixture profile");
    write!(read_profile, "{profile}\n\
        (allow file-read* (literal (param \"READ_FIXTURE_WALLET\")) (literal (param \"READ_FIXTURE_PARENT\")))\n\
        (allow file-read-metadata (literal (param \"READ_FIXTURE_KEY\")) (literal (param \"READ_FIXTURE_STORE\")))\n")
        .expect("write read fixture profile");
    let key_path = outside_wallet.join(WALLET_KEY_FILE);
    let store_path = outside_wallet.join("wallet-state.json");
    let mut provider = ConfinedProvider::start_with_profile(
        &root,
        read_profile.path(),
        &[
            ("READ_FIXTURE_WALLET", &outside_wallet),
            ("READ_FIXTURE_PARENT", outside_wallet.parent().unwrap()),
            ("READ_FIXTURE_KEY", &key_path),
            ("READ_FIXTURE_STORE", &store_path),
        ],
    );

    let denied = provider.init(&outside);
    assert_storage_error(&denied);
    assert!(
        denied["message"]
            .as_str()
            .unwrap()
            .starts_with("failed to open wallet storage key:"),
        "the refusal must reach the planted key read: {denied}"
    );

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the provider must answer after a denied read: {status}"
    );

    provider.shutdown();
}

/// A complete key file makes the outside root readable if the profile ever
/// grants that path, so the denial above proves the profile, not the file.
fn plant_storage_key(wallet_dir: &Path) {
    fs::create_dir_all(wallet_dir).expect("plant wallet directory");
    let key_path = wallet_dir.join(WALLET_KEY_FILE);
    fs::write(&key_path, format!("{}\n", "11".repeat(32))).expect("plant storage key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("planted key must be private so only the read rule decides");
    }
}

/// A confined start that cannot apply its profile is refused, and the refusal
/// says why.
///
/// Three profiles cannot be applied: a path that does not exist, a copy of
/// `confine.sb` with its last `)` removed, and the real profile with every
/// parameter bound except `STORAGE_ROOT`. `sandbox-exec` exits before the
/// provider starts in each case. The test waits for that exit first, then
/// sends `init`, and requires the one harness failure to name the request, the
/// exit status and `sandbox-exec`'s own line on standard error.
///
/// Falsifier: start the provider directly when the profile file is missing
/// (WP28); case (a) then times out at the bounded wait with the provider
/// running, so this test fails before `try_send`. Drop the child's standard
/// error from `unanswered` (WP29); every failure loses `sandbox-exec`'s line
/// and this test fails.
#[test]
fn startup_is_refused_when_the_profile_cannot_be_applied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_root = resolved(profile_root.path());
    let missing_profile = profile_root.join("absent-profile.sb");
    let source = fs::read_to_string(PROFILE_PATH).expect("profile source");
    let last = source.rfind(')').expect("the profile must close");
    let mut unclosed = source;
    unclosed.remove(last);
    let unclosed_profile = profile_root.join("unclosed-profile.sb");
    fs::write(&unclosed_profile, unclosed).expect("unclosed profile must be writable");

    let wallet_root = wallet_dir(&base);
    let canonical = canonical_bindings(&base);
    create_shared_ancestors(&canonical);
    let unbound_root: Vec<(&str, PathBuf)> = canonical
        .iter()
        .filter(|(name, _)| *name != "STORAGE_ROOT")
        .cloned()
        .collect();
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });
    // Each case keeps the stable part of `sandbox-exec`'s line that discovery
    // quoted on this host.
    let cases: [(&str, PathBuf, Vec<(&str, PathBuf)>, String); 3] = [
        (
            "(a) the profile file does not exist",
            missing_profile.clone(),
            canonical.to_vec(),
            missing_profile.display().to_string(),
        ),
        (
            "(b) the profile does not parse",
            unclosed_profile,
            canonical.to_vec(),
            "syntax error: expecting ')'".to_string(),
        ),
        (
            "(c) the profile names an unbound parameter",
            PathBuf::from(PROFILE_PATH),
            unbound_root,
            "invalid data type of path filter".to_string(),
        ),
    ];

    for (case, profile, bindings, marker) in cases {
        let bindings: Vec<(&str, &Path)> = bindings
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        let mut provider = ConfinedProvider::start_under(&profile, &bindings);
        let exit = provider.wait_for_exit();
        assert!(
            exit.code().is_some(),
            "{case}: sandbox-exec must exit instead of starting the provider: {exit}"
        );
        assert_ne!(
            exit.code(),
            Some(0),
            "{case}: sandbox-exec must refuse the profile: {exit}"
        );
        let failure = provider
            .try_send(&request)
            .expect_err("a refused start must not answer a request");
        assert!(
            failure.contains(&request.to_string()),
            "{case}: the failure must name the request: {failure}"
        );
        assert!(
            failure.contains(&exit.to_string()),
            "{case}: the failure must name the exit status: {failure}"
        );
        assert!(
            failure.contains(&marker),
            "{case}: the failure must carry sandbox-exec's line: {failure}"
        );
        assert!(
            !failure.contains("execvp"),
            "{case}: sandbox-exec must refuse the profile before any exec: {failure}"
        );
        assert!(
            !wallet_root.exists(),
            "{case}: a refused start must create no wallet directory: {}",
            wallet_root.display()
        );
        eprintln!("{case} startup refusal: {failure}");
    }
}

/// Whether `form` is a top-level allow rule that grants the network. This is
/// the one copy of the rule, used both by the provider's own profile test and
/// by the shared file-profile contract check (P10).
fn is_network_allow(form: &str) -> bool {
    form.starts_with("(allow ") && form.contains("network")
}

/// Whether `form` is a top-level allow rule that grants every operation by
/// default. This is the one copy of the rule, used both by the provider's own
/// profile test and by the shared file-profile contract check (P10).
fn is_default_allow(form: &str) -> bool {
    form.starts_with("(allow ") && form.split([' ', '(', ')']).any(|token| token == "default")
}

/// The profile denies every network operation: it starts from `(deny default)`
/// and grants no network rule. The provider has no network path of its own,
/// so this rule is what keeps that true if a later change adds one.
///
/// Falsifier: add `(allow network*)` to `confine.sb`; this test fails.
#[test]
fn profile_denies_network() {
    let profile = fs::read_to_string(PROFILE_PATH).expect("profile must be readable");
    let forms = profile_forms(&profile);
    assert_eq!(
        forms.first().map(String::as_str),
        Some("(version 1)"),
        "the profile must start with its version"
    );
    assert!(
        forms.iter().any(|form| form == "(deny default)"),
        "the profile must deny by default"
    );
    for form in &forms {
        assert!(
            !is_default_allow(form),
            "the profile must reject allow default, including after deny default: {form}"
        );
        assert!(
            !is_network_allow(form),
            "the profile must not grant network access: {form}"
        );
    }
}

/// The parameter tokens every file-profile provider's profile declares. The
/// tests bind these three for each launch; one generator for every provider is
/// the Runtime bridge change, and that Runtime half is not built. A
/// provider-prefixed token would add a second path for one operation (P10).
const CANONICAL_PARAMS: [&str; 3] = ["PROVIDER_EXECUTABLE", "STORAGE_ROOT", "STORAGE_PARENT"];
const PARAM_PREFIX: &str = "(param \"";
/// The three rules every file profile binds verbatim.
const SHARED_RULES: [&str; 3] = [
    r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"#,
    r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#,
    r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"#,
];
/// The file profiles the one contract check requires. Every one of them must
/// present the contract, in this order.
const FILE_PROFILES: [&str; 3] = ["did-provider", "wallet-provider", "model-provider"];

/// The one file-profile contract every file profile declares: `(version 1)`
/// first, `(deny default)` second, an explicit `(deny network*)`, no
/// `(allow default)`, no network allow, only the canonical parameter tokens,
/// and the three shared rules verbatim. The profile the Runtime generates must
/// match it; that Runtime bridge change is not built. Every refusal names the
/// profile and the rule.
fn check_profile_contract(name: &str, profile: &str) -> Result<(), String> {
    let forms = profile_forms(profile);
    if forms.first().map(String::as_str) != Some("(version 1)") {
        return Err(format!("{name} must start with (version 1)"));
    }
    if forms.get(1).map(String::as_str) != Some("(deny default)") {
        return Err(format!(
            "{name} must deny by default immediately after the version"
        ));
    }
    if !forms.iter().any(|form| form == "(deny network*)") {
        return Err(format!(
            "{name} must deny the network explicitly with (deny network*)"
        ));
    }
    for form in &forms {
        if is_default_allow(form) {
            return Err(format!("{name} must reject (allow default): {form}"));
        }
        if is_network_allow(form) {
            return Err(format!(
                "{name} must not grant network access; a network allow is refused: {form}"
            ));
        }
        let mut rest = form.as_str();
        while let Some(at) = rest.find(PARAM_PREFIX) {
            let tail = &rest[at + PARAM_PREFIX.len()..];
            let Some(end) = tail.find('"') else {
                return Err(format!("{name} parameter token must close: {form}"));
            };
            let token = &tail[..end];
            if !CANONICAL_PARAMS.contains(&token) {
                return Err(format!(
                    "{name} declares the non-canonical parameter token {token}; \
                     every file profile binds STORAGE_ROOT, STORAGE_PARENT and PROVIDER_EXECUTABLE"
                ));
            }
            rest = &tail[end..];
        }
    }
    for rule in SHARED_RULES {
        if !forms.iter().any(|form| form == rule) {
            return Err(format!("{name} must bind the shared rule {rule}"));
        }
    }
    Ok(())
}

/// Runs the one contract check over every required file profile under
/// `capsules` and returns the names it checked, in list order.
///
/// `did-provider`, `wallet-provider` and `model-provider` are required; a
/// missing or unreadable one is a refusal that names its path. There is no
/// skip path.
fn check_file_profiles(capsules: &Path) -> Result<Vec<&'static str>, String> {
    let mut checked = Vec::new();
    for name in FILE_PROFILES {
        let path = capsules.join(name).join("confine.sb");
        let profile = match fs::read_to_string(&path) {
            Ok(profile) => profile,
            Err(err) => {
                return Err(format!(
                    "{name} profile {} must be readable: {err}",
                    path.display()
                ))
            }
        };
        check_profile_contract(name, &profile)?;
        checked.push(name);
    }
    Ok(checked)
}

/// A minimal profile built from the contract's own pieces: the head forms and
/// the shared rules. It copies no provider's profile.
fn contract_fixture_profile(deny_network: bool) -> String {
    let mut fixture = String::from("(version 1)\n(deny default)\n");
    if deny_network {
        fixture.push_str("(deny network*)\n");
    }
    for rule in SHARED_RULES {
        fixture.push_str(rule);
        fixture.push('\n');
    }
    fixture
}

/// Writes `profile` as `capsules/<provider>/confine.sb` under a temporary
/// directory.
fn write_fixture_profile(capsules: &Path, provider: &str, profile: &str) {
    let dir = capsules.join(provider);
    fs::create_dir_all(&dir).expect("fixture provider directory");
    fs::write(dir.join("confine.sb"), profile).expect("fixture profile");
}

/// A temporary `capsules/` directory holding the passing fixture for all
/// three required file profiles.
fn contract_fixture_capsules() -> tempfile::TempDir {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let fixture = contract_fixture_profile(true);
    for name in FILE_PROFILES {
        write_fixture_profile(capsules.path(), name, &fixture);
    }
    capsules
}

/// The did, wallet and model file profiles present one contract: the same
/// canonical parameter tokens and the same deny-by-default head. The tests
/// bind `STORAGE_ROOT`, `STORAGE_PARENT` and `PROVIDER_EXECUTABLE` with one
/// launch for every provider, and the Runtime bridge change does the same; it
/// is not built. A provider-prefixed token would add a second path for one
/// operation (P10). All three profiles are required, in list order.
///
/// Falsifier: rename `STORAGE_ROOT` to `WALLET_STORAGE_ROOT` in either
/// `confine.sb`; this test fails on the non-canonical token.
#[test]
fn both_file_profiles_bind_one_storage_parameter_contract() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let checked = check_file_profiles(capsules).unwrap_or_else(|err| panic!("{err}"));
    assert!(
        checked.starts_with(&FILE_PROFILES),
        "the required file profiles must be checked first: {checked:?}"
    );
}

/// The one contract check refuses a profile that omits the explicit network
/// denial, and names that rule. The fixtures are built in the test; no file
/// is read.
///
/// Falsifier: delete the `(deny network*)` requirement from
/// `check_profile_contract`; this test fails because the incomplete fixture
/// passes.
#[test]
fn file_profile_contract_rejects_a_profile_without_deny_network() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let incomplete = contract_fixture_profile(false);
    let refusal = check_profile_contract("fixture-provider", &incomplete)
        .expect_err("a profile without its (deny network*) form must fail");
    assert!(
        refusal.contains("(deny network*)"),
        "the refusal must name the missing rule: {refusal}"
    );
}

/// The one contract check refuses a profile that grants the network, in any
/// allow form, and names that rule and the form. The fixtures are built in the
/// test; no file is read.
///
/// Falsifier: remove the network-allow rule from `check_profile_contract`;
/// this test fails because the granting fixture passes.
#[test]
fn file_profile_contract_rejects_a_network_allow() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    for grant in [
        "(allow network*)",
        r#"(allow network-outbound (remote ip "localhost:*"))"#,
    ] {
        let profile = format!("{complete}{grant}\n");
        let refusal = check_profile_contract("fixture-provider", &profile)
            .expect_err("a profile with a network allow must fail");
        assert!(
            refusal.contains("fixture-provider") && refusal.contains(grant),
            "the refusal must name the profile and the form: {refusal}"
        );
        assert!(
            refusal.contains("network allow is refused"),
            "the refusal must say a network allow is refused: {refusal}"
        );
    }
}

/// The one contract check refuses a profile that adds `(allow default)` after
/// its default denial and names that rule and the profile. The fixture is
/// built in the test; no file is read.
///
/// Falsifier: remove the allow-default rule from `check_profile_contract`;
/// this test fails because the granting fixture passes.
#[test]
fn file_profile_contract_rejects_an_allow_default() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let profile = format!("{complete}(allow default)\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile with an (allow default) form must fail");
    assert!(
        refusal.contains("fixture-provider") && refusal.contains("must reject (allow default)"),
        "the refusal must name the profile and the rule: {refusal}"
    );
}

/// The one contract check refuses a profile that binds a parameter token
/// outside the canonical three, and names the profile and that token. The
/// fixtures are built in the test; no file is read.
///
/// Falsifier: remove the canonical-token refusal from
/// `check_profile_contract`; this test fails because the extra-token fixture
/// passes.
#[test]
fn file_profile_contract_rejects_a_non_canonical_token() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let profile = format!("{complete}(allow file-read* (literal (param \"READ_FIXTURE_KEY\")))\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile with a non-canonical parameter token must fail");
    assert!(
        refusal.contains("fixture-provider")
            && refusal.contains("non-canonical parameter token READ_FIXTURE_KEY"),
        "the refusal must name the profile and the token: {refusal}"
    );
}

/// The profile lines whose `;`, `(` and `)` sit inside strings, with an
/// `(allow default)` after the first one. `sandbox-exec` reads those three
/// characters as text, so the lines hold two forms and then one more.
const STRING_LINES: &str = r#"(deny file-read* (literal "/x;")) (allow default)
(deny file-read* (literal "/))"))
"#;

/// The parser reads a `;` and every parenthesis inside a string as
/// `sandbox-exec` does, so the one contract check sees the `(allow default)`
/// that these lines hold. It keeps an escaped quote and an escaped backslash
/// inside their string, keeps whitespace inside a string, collapses whitespace
/// outside strings, and loads a form after a comment's newline. The fixtures
/// are built in the test; no file is read and no process starts.
///
/// Falsifier: WP31 restores the plain cut at every `;` and the parenthesis
/// count inside strings; this test fails because the hidden `(allow default)`
/// then passes the check. WP32 to WP35 disable escaping, the in-string
/// whitespace, the outside collapse and the comment's end at its newline;
/// this test fails on each.
#[test]
fn file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete)
        .expect("the passing fixture must pass the one check");
    let profile = format!("{complete}{STRING_LINES}");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a fixture whose strings hold (allow default) must fail");
    assert!(
        refusal.contains("fixture-provider") && refusal.contains("must reject (allow default)"),
        "the refusal must name the profile and the rule: {refusal}"
    );

    let forms = profile_forms(STRING_LINES);
    assert_eq!(forms.len(), 3, "the two lines hold three forms: {forms:?}");
    assert_eq!(
        forms[1], "(allow default)",
        "the second form must be the allow default: {forms:?}"
    );

    assert_eq!(
        profile_forms("(version 1) ; (allow default)"),
        vec!["(version 1)"],
        "a `;` outside a string must comment out the rest of its line"
    );

    let escaped_quote = r#"(deny file-read* (literal "/a\"b)"))"#;
    assert_eq!(
        profile_forms(escaped_quote),
        vec![escaped_quote],
        "a backslash must escape the next character inside a string"
    );

    let escaped_backslash = r#"(deny file-read* (literal "/a\\"))"#;
    assert_eq!(
        profile_forms(escaped_backslash),
        vec![escaped_backslash],
        "an escaped backslash must stay inside its string"
    );

    let spaced = r#"(deny file-read* (literal "/a  b"))"#;
    assert_eq!(
        profile_forms(spaced),
        vec![spaced],
        "whitespace inside a string must be kept"
    );

    assert_eq!(
        profile_forms("(version   1)"),
        vec!["(version 1)"],
        "whitespace outside strings must collapse to one space"
    );

    assert_eq!(
        profile_forms("(version 1) ; (allow default)\n(deny default)"),
        vec!["(version 1)", "(deny default)"],
        "a form after a comment's newline must still load"
    );
}

/// A comment inside a form ends at its newline, and that newline still
/// separates the form's tokens, as `sandbox-exec` reads it. Without the
/// separator `(allow;x\ndefault)` reads as `(allowdefault)`, which matches
/// neither `is_default_allow` nor `is_network_allow`; both forms would then
/// pass the one check while `sandbox-exec` applies them. The fixtures are
/// built in the test; no file is read and no process starts.
///
/// Falsifier: WP38 drops the newline that ends a comment; this test fails
/// because the glued form passes the check and the parser returns
/// `(allowdefault)`.
#[test]
fn a_comment_inside_a_form_keeps_its_tokens_apart() {
    assert_eq!(
        profile_forms("(allow;x\ndefault)"),
        vec!["(allow default)"],
        "the newline that ends a comment must separate the tokens"
    );
    assert_eq!(
        profile_forms("(allow;x\nnetwork*)"),
        vec!["(allow network*)"],
        "the newline that ends a comment must separate the tokens"
    );

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "(allow;x\ndefault)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "(allow;x\nnetwork*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a form split by a comment must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the hidden form"
        );
    }
}

/// Whitespace directly after an opening parenthesis does not change the rule
/// name, as `sandbox-exec` reads it. Without the normalization
/// `( allow default)` and `(;x\nallow default)` read as `( allow default)`,
/// which matches neither `is_default_allow` nor `is_network_allow`; the hidden
/// rule would then pass the one check while `sandbox-exec` applies it. The
/// same holds for the network form. The fixtures are built in the test; no
/// file is read and no process starts.
///
/// Falsifier: WP40 adds the separator space after an opening parenthesis; this
/// test fails because the parser returns `( allow default)` and both spaced
/// forms pass the check.
#[test]
fn a_space_after_the_opening_parenthesis_still_names_its_rule() {
    for line in ["(allow default)", "( allow default)", "(;x\nallow default)"] {
        assert_eq!(
            profile_forms(line),
            vec!["(allow default)"],
            "whitespace after the opening parenthesis must not name a new rule"
        );
    }
    for line in [
        "(allow network*)",
        "( allow network*)",
        "(;x\nallow network*)",
    ] {
        assert_eq!(
            profile_forms(line),
            vec!["(allow network*)"],
            "whitespace after the opening parenthesis must not name a new rule"
        );
    }

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "( allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "(;x\nallow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "( allow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
        (
            "(;x\nallow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a spaced allow form must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the spaced form"
        );
    }
}

/// A bare value outside every form, such as `1` or `"x"`, is its own form,
/// as `sandbox-exec` reads it: whitespace or a `(` ends it. Without that split
/// `1 (allow default)` reads as one form, which matches neither
/// `is_default_allow` nor `is_network_allow`; the hidden rule would then pass
/// the one check while `sandbox-exec` applies it. A bare value at the end of the
/// profile is a form too, not an unclosed one. The fixtures are built in the
/// test; no file is read and no process starts.
///
/// Falsifier: WP39 drops the split outside every form; this test fails
/// because the parser returns `1 (allow default)` and the glued form passes
/// the check.
#[test]
fn a_bare_top_level_value_is_its_own_form() {
    assert_eq!(
        profile_forms("1\n(allow default)"),
        vec!["1", "(allow default)"],
        "whitespace outside every form must end a bare value"
    );
    assert_eq!(
        profile_forms("1(allow default)"),
        vec!["1", "(allow default)"],
        "a `(` outside every form must end a bare value"
    );
    assert_eq!(
        profile_forms(r#""x" (allow default)"#),
        vec![r#""x""#, "(allow default)"],
        "a bare string must be its own form"
    );
    assert_eq!(
        profile_forms("(version 1) 1"),
        vec!["(version 1)", "1"],
        "a bare value at the end of the profile must be its own form"
    );

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "1\n(allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "\"x\" (allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "1(allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "1 (allow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a form after a bare value must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the form after the bare value"
        );
    }
}

/// `sandbox-exec` itself reads a bare value before a form as two forms: it
/// evaluates the `1`, ignores it and applies the `(allow default)` after it.
/// The fixture writes `(version 1)(deny default) 1 (allow default)` to a
/// temporary file and runs `/usr/bin/true` under it, which must exit 0. Under
/// `(deny default)` alone `/usr/bin/true` cannot start, so the exit shows the
/// premise of `a_bare_top_level_value_is_its_own_form`. It checks that premise,
/// not a rule, so it carries no falsifier entry.
#[test]
fn the_bare_value_fixture_loads_under_sandbox_exec() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let mut file = tempfile::NamedTempFile::new().expect("temporary bare value fixture profile");
    file.write_all(b"(version 1)(deny default) 1 (allow default)\n")
        .expect("write the bare value fixture profile");
    let output = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(file.path())
        .arg("/usr/bin/true")
        .output()
        .expect("sandbox-exec must start");
    assert!(
        output.status.success(),
        "sandbox-exec must load the bare value fixture and start true: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `sandbox-exec` itself reads the two string lines as `profile_forms` does:
/// it parses their `;`, `(` and `)` as text and applies the `(allow default)`
/// they hold. The fixture writes `(version 1)`, `(deny default)` and those two
/// lines to a temporary file and runs `/usr/bin/true` under it, which must
/// exit 0. Under `(deny default)` alone `/usr/bin/true` cannot start, so the
/// exit shows the fixture's premise. It checks that premise, not a rule, so it
/// carries no falsifier entry.
#[test]
fn the_string_fixture_loads_under_sandbox_exec() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let profile = format!("(version 1)\n(deny default)\n{STRING_LINES}");
    let mut file = tempfile::NamedTempFile::new().expect("temporary string fixture profile");
    file.write_all(profile.as_bytes())
        .expect("write the string fixture profile");
    let status = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(file.path())
        .arg("/usr/bin/true")
        .status()
        .expect("sandbox-exec must start");
    assert!(
        status.success(),
        "sandbox-exec must load the string fixture and start true: {status}"
    );
}

/// The parser refuses an unclosed string with the existing "must not end
/// early" reason and a detail that names the string. It reads no form past it.
///
/// Falsifier: WP36 drops the unclosed-string refusal; this test fails because
/// the profile then ends as an unclosed form, whose reason names no string.
#[test]
fn profile_forms_rejects_unclosed_string() {
    let refusal = std::panic::catch_unwind(|| profile_forms("(literal \"/unclosed)"))
        .expect_err("an unclosed string must fail");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    assert_eq!(
        message.as_str(),
        "the profile must not end early: unclosed string in (literal \"/unclosed)",
        "the refusal must be the exact reason for the unclosed string"
    );
}

/// The parser refuses an unclosed form with the existing "must not end early"
/// reason and a detail that names the form, while a closed form loads.
///
/// Falsifier: WP37 drops the unclosed-form refusal; this test fails because
/// the incomplete profile returns no refusal.
#[test]
fn profile_forms_rejects_unclosed_form() {
    let refusal = std::panic::catch_unwind(|| profile_forms("(deny default"))
        .expect_err("an unclosed form must fail");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    assert_eq!(
        message.as_str(),
        "the profile must not end early: unclosed form (deny default",
        "the refusal must be the exact reason for the unclosed form"
    );
    assert_eq!(
        profile_forms("(deny default)"),
        vec!["(deny default)"],
        "a closed form must load"
    );
}

/// The one list requires the model profile with the did and wallet profiles
/// and refuses a missing or unreadable one instead of skipping it.
#[test]
fn file_profile_contract_checks_the_model_profile_when_present() {
    let capsules = contract_fixture_capsules();
    let checked =
        check_file_profiles(capsules.path()).expect("the three passing fixtures must pass");
    assert_eq!(
        checked,
        vec!["did-provider", "wallet-provider", "model-provider"],
        "the one list must check all three required profiles in order"
    );

    let capsules = contract_fixture_capsules();
    write_fixture_profile(
        capsules.path(),
        "model-provider",
        &contract_fixture_profile(false),
    );
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a model profile without (deny network*) must fail");
    assert!(
        refusal.contains("model-provider") && refusal.contains("(deny network*)"),
        "the refusal must name the model profile and the missing rule: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    let model_profile = capsules.path().join("model-provider").join("confine.sb");
    fs::remove_file(&model_profile).expect("remove the model profile");
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a missing model profile is a required refusal, not a skip");
    assert!(
        refusal.contains("model-provider")
            && refusal.contains(&model_profile.display().to_string()),
        "the refusal must name the model profile and its path: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    let model_profile = capsules.path().join("model-provider").join("confine.sb");
    fs::remove_file(&model_profile).expect("remove the model profile");
    fs::create_dir_all(&model_profile).expect("model profile directory");
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a model profile directory is a read error, not an absence");
    assert!(
        refusal.contains(&model_profile.display().to_string()),
        "the refusal must name the model profile path: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    fs::remove_file(capsules.path().join("did-provider").join("confine.sb"))
        .expect("remove the did profile");
    let refusal = check_file_profiles(capsules.path()).expect_err("the did profile is required");
    assert!(
        refusal.contains("did-provider"),
        "the refusal must name the did profile: {refusal}"
    );
}

/// Splits the profile into top-level s-expressions the way `sandbox-exec`
/// reads it. `profile_characters` removes comments and marks strings; this
/// function collapses whitespace outside strings, keeps every character inside
/// one, counts parentheses only outside strings and collects the forms. Outside
/// every form, whitespace or a `(` ends a bare value such as `1` or `"x"`, so
/// that value is its own form and every top-level form starts its own entry.
/// Whitespace directly after an opening parenthesis is dropped, so
/// `( allow default)` reads as the form `(allow default)`.
/// An unclosed form is a refusal with its own reason.
fn profile_forms(profile: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut space_due = false;
    for (ch, in_string) in profile_characters(profile) {
        if in_string {
            if space_due {
                push_separator(&mut current);
            }
            space_due = false;
            current.push(ch);
            continue;
        }
        if depth == 0 && (ch.is_whitespace() || ch == '(') && !current.is_empty() {
            forms.push(std::mem::take(&mut current));
        }
        match ch {
            _ if ch.is_whitespace() => space_due = true,
            '(' | ')' => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
                if ch == '(' {
                    depth += 1;
                } else {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && !current.is_empty() {
                        forms.push(std::mem::take(&mut current));
                    }
                }
            }
            _ => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
            }
        }
    }
    if depth == 0 && !current.is_empty() {
        forms.push(std::mem::take(&mut current));
    }
    assert!(
        current.is_empty(),
        "the profile must not end early: unclosed form {current}"
    );
    forms
}

/// Adds the one separator space between tokens. No separator is added directly
/// after an opening parenthesis, where no token has started, so `( allow
/// default)` reads as the form `(allow default)` and the allow rules still
/// match it.
fn push_separator(current: &mut String) {
    if !current.is_empty() && !current.ends_with('(') {
        current.push(' ');
    }
}

/// The characters the profile reader consumes, each marked with whether it
/// sits inside a double-quoted string. A `;` outside a string starts a comment
/// that runs to the end of its line; the newline that ends the comment stays
/// as a separator, so a comment inside a form keeps its two tokens apart.
/// Inside a string a backslash escapes the next character, so a `;`, `(` and
/// `)` there stay text and a quote does not end the string. The reader reads
/// no block comment and no `#` literal, because no profile holds either. An
/// unclosed string is a refusal with its own reason.
fn profile_characters(profile: &str) -> Vec<(char, bool)> {
    let mut characters = Vec::new();
    let mut in_string = false;
    let mut in_comment = false;
    let mut escaped = false;
    for ch in profile.chars() {
        if in_comment {
            in_comment = ch != '\n';
            if !in_comment {
                characters.push((ch, false));
            }
            continue;
        }
        if escaped {
            characters.push((ch, true));
            escaped = false;
            continue;
        }
        if in_string && ch == '\\' {
            characters.push((ch, true));
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            characters.push((ch, true));
            continue;
        }
        if !in_string && ch == ';' {
            in_comment = true;
            continue;
        }
        characters.push((ch, in_string));
    }
    assert!(
        !in_string,
        "the profile must not end early: unclosed string in {profile}"
    );
    characters
}
