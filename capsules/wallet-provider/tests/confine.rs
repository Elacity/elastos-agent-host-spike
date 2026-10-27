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

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bitcoin::hashes::Hash as _;
use elastos_auth::ethereum_signed_message_hash;
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1,
    CustodyEpochIdentityV1, CustodyPoolIdentityV1, Digest32, EncryptedContentIdentityV1,
    EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyEnvelopeIdentityV1,
    ProfileIdentityV1, ProtectedContentBindingV1, RecipientKeyIdentityV1, ReplayNonce16,
    RightsActionV1, RightsObservationFinalityV1, RightsPolicyBodyV1, RightsRequestV1,
    RightsSubjectSourceV1, RuntimeSessionBindingV1, ThresholdV1, WalletAddress,
};
use elastos_wallet_contract::{
    Erc1271ProofEvidenceV1, ManagedRecoveryKeyEntryV1, ManagedRecoverySetV1, PublicNetwork,
    ValidatedChainOutcomeBindingV1, ValidatedChainOutcomeV1, VerifiedWalletInvocationContext,
    WalletProviderOperationV2, WalletProviderRequestV2, WalletProviderResponseV2, WalletResultV2,
    PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT, VALIDATED_CHAIN_OUTCOME_SCHEMA,
};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
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

/// The test launch refuses a second binding of a canonical parameter.
///
/// `start_with_profile` takes the three canonical bindings from
/// `canonical_bindings`, which derives them from one base, and then appends
/// the caller's parameters. A caller that binds `STORAGE_ROOT`,
/// `STORAGE_PARENT` or `PROVIDER_EXECUTABLE` again could point the launch at a
/// folder the test did not create, so the call panics with a message that
/// names the parameter and says the canonical bindings come only from
/// `canonical_bindings`. The refusal comes before the shared ancestors are
/// created and before any spawn, so the test needs no `sandbox_available` gate
/// and no directory appears under the base.
///
/// Falsifier: drop the refusal from `start_with_profile` (WP54); on a Mac this
/// returns a running provider instead of the panic, and without
/// `sandbox-exec` the spawn panics with a different message, so the test fails
/// on every host.
#[test]
fn start_with_profile_refuses_a_canonical_parameter() {
    for name in CANONICAL_PARAMS {
        let base = tempfile::tempdir().expect("temporary wallet base");
        let base = resolved(base.path());
        let rebinding = wallet_dir(&base).join("rebound");
        let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ConfinedProvider::start_with_profile(
                &base,
                Path::new(PROFILE_PATH),
                &[(name, rebinding.as_path())],
            )
        }));
        let failure = match settled {
            Err(payload) => payload,
            Ok(_provider) => panic!(
                "binding the canonical parameter {name} again must be refused, \
                 but start_with_profile returned a provider"
            ),
        };
        let message = failure
            .downcast_ref::<String>()
            .expect("the refusal must arrive as a String payload");
        assert!(
            message.contains(name),
            "the refusal must name {name}: {message}"
        );
        assert!(
            message.contains("canonical_bindings"),
            "the refusal must say the canonical bindings come only from canonical_bindings: {message}"
        );
        assert!(
            fs::read_dir(&base)
                .expect("the temporary base must be readable")
                .next()
                .is_none(),
            "the refusal must come before the shared ancestors are created: {}",
            base.display()
        );
    }
}

/// The same launch check owns canonical names encoded before `=`.
///
/// `sandbox-exec -D` reads the name before the first `=`, so a caller's
/// `STORAGE_ROOT=/outside` would replace the canonical storage binding.
/// Check every canonical name with an empty value, a path, and another `=`.
/// Each refusal names the caller's parameter and precedes directory creation.
///
/// Falsifier: WP55 checks the caller's whole name again, so an encoded
/// canonical name reaches the launch instead of this refusal.
#[test]
fn start_with_profile_refuses_an_encoded_canonical_parameter() {
    for canonical_name in CANONICAL_PARAMS {
        for suffix in ["", "/outside", "/outside=/fixture"] {
            let name = format!("{canonical_name}={suffix}");
            let base = tempfile::tempdir().expect("temporary wallet base");
            let base = resolved(base.path());
            let rebinding = wallet_dir(&base).join("rebound");
            let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ConfinedProvider::start_with_profile(
                    &base,
                    Path::new(PROFILE_PATH),
                    &[(name.as_str(), rebinding.as_path())],
                )
            }));
            let failure = match settled {
                Err(payload) => payload,
                Ok(_provider) => panic!(
                    "binding the encoded canonical parameter {name} must be refused, \
                     but start_with_profile returned a provider"
                ),
            };
            let message = failure
                .downcast_ref::<String>()
                .expect("the refusal must arrive as a String payload");
            assert_eq!(
                message,
                &format!(
                    "the launch must not bind the canonical parameter {name} again: \
                     canonical bindings come only from canonical_bindings"
                ),
                "the encoded canonical parameter must receive the canonical-binding refusal"
            );
            assert!(
                fs::read_dir(&base)
                    .expect("the temporary base must be readable")
                    .next()
                    .is_none(),
                "the refusal must come before the shared ancestors are created: {}",
                base.display()
            );
        }
    }
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
/// apart (P10). `start_with_profile` refuses a second binding of a canonical
/// parameter, so this derivation stays the only source of those three paths;
/// `start_with_profile_refuses_a_canonical_parameter` and WP54 hold that rule.
/// `start_with_profile_refuses_an_encoded_canonical_parameter` and WP55 cover
/// names encoded before `=` through the same check.
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
        for (name, _) in parameters {
            // Match the name sandbox-exec reads from the serialized -D binding.
            let binding_name = name.split_once('=').map_or(*name, |(binding, _)| binding);
            assert!(
                !CANONICAL_PARAMS.contains(&binding_name),
                "the launch must not bind the canonical parameter {name} again: \
                 canonical bindings come only from canonical_bindings"
            );
        }
        let canonical = canonical_bindings(base);
        create_shared_ancestors(&canonical);
        let mut bindings: Vec<(&str, &Path)> = canonical
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        bindings.extend_from_slice(parameters);
        Self::start_under(profile, &bindings, Path::new(PROVIDER_BINARY))
    }

    /// The one launch builder: `program` under `profile`, with exactly the
    /// `bindings` it is given. The tests start the provider binary; a test
    /// that needs another program passes it through the same builder. A
    /// caller can leave a parameter unbound, as a Runtime bug would.
    fn start_under(profile: &Path, bindings: &[(&str, &Path)], program: &Path) -> Self {
        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-f").arg(profile);
        for (name, path) in bindings {
            command.arg("-D").arg(format!("{name}={}", path.display()));
        }
        command.arg(program);
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
        self.wallet_with_lifecycle(operation).0
    }

    /// The same request path as `wallet`, and the request's lifecycle id, so a
    /// test can find the record an effectful call saves in the store.
    fn wallet_with_lifecycle(
        &mut self,
        operation: WalletProviderOperationV2,
    ) -> (WalletResultV2, String) {
        let request = wallet_request(operation);
        let lifecycle_id = request.lifecycle_id.clone();
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
        let result = WalletProviderResponseV2::decode_for_request(&bytes, &request)
            .expect("provider response must bind to its request")
            .result;
        (result, lifecycle_id)
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

/// The wallet account edits answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s the root, creates a managed account, then renames it,
/// sets it as the default for `publish_envelope`, reads that default back and
/// revokes the account; each answer passes through `ok_data`. A second
/// provider on the same root `init`s it and reloads the new label and the
/// revoked marker from `list_accounts` with `include_revoked` and from
/// `wallet-state.json` under the wallet directory.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; WP18 is the only removal this side can use, and this
/// test fails on its first call.
#[test]
fn account_edits_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Editable".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let renamed = "Renamed";
    let data = ok_data(provider.wallet(WalletProviderOperationV2::RenameAccount {
        account_id: account_id.clone(),
        label: renamed.to_string(),
    }));
    assert_eq!(
        data["account"]["label"], renamed,
        "rename_account must answer the new label"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
            account_id: account_id.clone(),
        }),
    );
    assert_eq!(
        data["default_account"]["account_id"], account_id,
        "set_default_account must answer the account just set"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::DefaultAccount {
        chain_namespace: "eip155:20".to_string(),
        intent: "publish_envelope".to_string(),
    }));
    assert_eq!(
        data["default_account"]["account_id"], account_id,
        "default_account must answer the account just set"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RevokeAccount {
        account_id: account_id.clone(),
    }));
    assert!(
        data["account"]["revoked_at"].is_number(),
        "revoke_account must answer the revoked account"
    );

    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: true,
    }));
    let listed = data["accounts"]
        .as_array()
        .and_then(|accounts| {
            accounts
                .iter()
                .find(|account| account["account_id"] == account_id.as_str())
        })
        .expect("the reloaded listing must hold the created account");
    assert_eq!(
        listed["label"], renamed,
        "the renamed label must reload from the store"
    );
    assert!(
        listed["revoked_at"].is_number(),
        "the revoked marker must reload from the store"
    );

    let store = read_store(&root);
    let stored = store["accounts"]
        .as_array()
        .and_then(|accounts| {
            accounts
                .iter()
                .find(|account| account["account_id"] == account_id.as_str())
        })
        .expect("the store under the wallet directory must hold the account");
    assert_eq!(
        stored["label"], renamed,
        "the store under the wallet directory must hold the new label"
    );
    assert!(
        stored["revoked_at"].is_number(),
        "the store under the wallet directory must hold the revoked marker"
    );

    provider.shutdown();
}

/// The managed recovery calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a source root, creates one managed account on
/// `eip155:20` and one on Bitcoin, then exports the first account's recovery
/// key and the set of both active managed accounts; each answer passes through
/// `ok_data`. A second provider on a second root imports the exported key
/// under a new label and then the exported set, and a fresh start on that root
/// `init`s it and reloads both accounts with `managed_key_available` and the
/// set's labels from `list_accounts` and from `wallet-state.json` under its
/// wallet directory. A fresh start on the source root shows the export
/// requests' consumed lifecycle records in that root's store. The exported key
/// and set stay test data in the temporary roots, and no assertion formats
/// them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; this test fails on its first `init`.
#[test]
fn managed_recovery_writes_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let source_root = tempfile::tempdir().expect("temporary source root");
    let source_root = resolved(source_root.path());
    let target_root = tempfile::tempdir().expect("temporary target root");
    let target_root = resolved(target_root.path());
    let bitcoin_chain = "bip122:000000000019d6689c085ae165831e93";

    let mut source = ConfinedProvider::start(&source_root);
    let init = source.init(&source_root);
    assert_eq!(
        init["status"], "ok",
        "confined source Init must succeed: {init}"
    );

    let data = ok_data(
        source.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Spending".to_string()),
            create_new: true,
        }),
    );
    let spending_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let data = ok_data(
        source.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: bitcoin_chain.to_string(),
            label: Some("Savings".to_string()),
            create_new: true,
        }),
    );
    let savings_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let (result, export_key_lifecycle) =
        source.wallet_with_lifecycle(WalletProviderOperationV2::ExportManagedRecoveryKey {
            account_id: spending_id.clone(),
        });
    let recovery_key = ok_data(result);
    assert_eq!(
        recovery_key["schema"], "elastos.wallet.recovery-key/v1",
        "export_managed_recovery_key must answer its schema"
    );
    assert_eq!(
        recovery_key["account_id"].as_str(),
        Some(spending_id.as_str()),
        "export_managed_recovery_key must answer the requested account"
    );

    let (result, export_set_lifecycle) =
        source.wallet_with_lifecycle(WalletProviderOperationV2::ExportManagedRecoverySet {});
    let data = ok_data(result);
    let exported_labels = data["keys"]
        .as_array()
        .expect("export_managed_recovery_set must answer its keys")
        .iter()
        .filter_map(|entry| entry["label"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        exported_labels.len(),
        2,
        "export_managed_recovery_set must answer both active managed accounts"
    );
    assert!(
        exported_labels.contains(&"Spending") && exported_labels.contains(&"Savings"),
        "export_managed_recovery_set must answer both labels"
    );
    let recovery_set: ManagedRecoverySetV1 =
        serde_json::from_value(data).expect("the exported set must decode as a recovery set");
    source.shutdown();

    let mut target = ConfinedProvider::start(&target_root);
    let init = target.init(&target_root);
    assert_eq!(
        init["status"], "ok",
        "confined target Init must succeed: {init}"
    );
    let (result, import_key_lifecycle) =
        target.wallet_with_lifecycle(WalletProviderOperationV2::ImportManagedRecoveryKey {
            recovery_key,
            label: Some("Recovered".to_string()),
        });
    let data = ok_data(result);
    assert_eq!(
        data["imported"], true,
        "import_managed_recovery_key must answer that it imported"
    );
    assert_eq!(
        data["account"]["account_id"].as_str(),
        Some(spending_id.as_str()),
        "import_managed_recovery_key must answer the recovered account"
    );
    assert_eq!(
        data["account"]["label"], "Recovered",
        "import_managed_recovery_key must answer the new label"
    );

    let (result, import_set_lifecycle) =
        target.wallet_with_lifecycle(WalletProviderOperationV2::ImportManagedRecoverySet {
            recovery_set,
        });
    let data = ok_data(result);
    assert_eq!(
        data["imported"], true,
        "import_managed_recovery_set must answer that it imported"
    );
    assert_eq!(
        data["account_count"], 2,
        "import_managed_recovery_set must answer both recovered accounts"
    );
    target.shutdown();

    let mut target = ConfinedProvider::start(&target_root);
    let init = target.init(&target_root);
    assert_eq!(
        init["status"], "ok",
        "confined target re-Init must succeed: {init}"
    );

    let data = ok_data(target.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("list_accounts must answer its accounts");
    assert_eq!(
        accounts.len(),
        2,
        "the reloaded listing must hold both imported accounts"
    );
    for (account_id, label) in [(&spending_id, "Spending"), (&savings_id, "Savings")] {
        let account = accounts
            .iter()
            .find(|account| account["account_id"].as_str() == Some(account_id.as_str()))
            .expect("the reloaded listing must hold the imported account");
        assert_eq!(
            account["label"], label,
            "the set import must restore the label after the re-Init"
        );
        assert_eq!(
            account["signing_status"], "managed_key_available",
            "the imported account must keep its key available after the re-Init"
        );
    }

    let store = read_store(&target_root);
    let stored = store["accounts"]
        .as_array()
        .expect("the store under the target root must hold its accounts");
    assert_eq!(
        stored.len(),
        2,
        "the store under the target root must hold both imported accounts"
    );
    for (account_id, label) in [(&spending_id, "Spending"), (&savings_id, "Savings")] {
        let account = stored
            .iter()
            .find(|account| account["account_id"].as_str() == Some(account_id.as_str()))
            .expect("the store under the target root must hold the imported account");
        assert_eq!(
            account["label"], label,
            "the store under the target root must hold the restored label"
        );
    }
    for lifecycle_id in [&import_key_lifecycle, &import_set_lifecycle] {
        assert!(
            store["consumed_lifecycles"]
                .as_array()
                .is_some_and(|records| records.iter().any(|record| {
                    record["lifecycle_id"].as_str() == Some(lifecycle_id.as_str())
                })),
            "the reloaded store must hold the import request's consumed lifecycle"
        );
    }
    target.shutdown();

    let mut source = ConfinedProvider::start(&source_root);
    let init = source.init(&source_root);
    assert_eq!(
        init["status"], "ok",
        "confined source re-Init must succeed: {init}"
    );
    let store = read_store(&source_root);
    for lifecycle_id in [&export_key_lifecycle, &export_set_lifecycle] {
        assert!(
            store["consumed_lifecycles"]
                .as_array()
                .is_some_and(|records| records.iter().any(|record| {
                    record["lifecycle_id"].as_str() == Some(lifecycle_id.as_str())
                })),
            "the reloaded store must hold the export request's consumed lifecycle"
        );
    }
    source.shutdown();
}

/// The fixed test key the EVM proof calls sign with.
fn evm_test_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[3u8; 32]).into()).expect("deterministic test key")
}

/// The address of `signing_key`, derived as `src/tests/support.rs::test_address`
/// derives it.
fn evm_test_address(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..]))
}

/// Signs `message` as `src/tests/support.rs::sign_message_bytes` signs it.
fn sign_test_message(signing_key: &SigningKey, message: &str) -> String {
    let hash = ethereum_signed_message_hash(message.as_bytes());
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash)
        .expect("test signature should be recoverable");
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    format!("0x{}", hex::encode(bytes))
}

/// The ERC-1271 evidence in `src/tests/support.rs::erc1271_proof`'s shape: the
/// SIWE message hash, a SHA-256 of the signature bytes, and no chain access.
fn erc1271_evidence(message: &str, signature: &str, contract: &str) -> Erc1271ProofEvidenceV1 {
    let message_hash = ethereum_signed_message_hash(message.as_bytes());
    let signature_hex = signature.strip_prefix("0x").unwrap_or(signature);
    let signature_bytes = hex::decode(signature_hex).expect("test signature must be hex");
    serde_json::from_value(json!({
        "schema": "elastos.chain.erc1271_proof/v1",
        "network": "esc-local",
        "chain_id": 20,
        "contract": contract.to_ascii_lowercase(),
        "message_hash": format!("0x{}", hex::encode(message_hash)),
        "signature_hash": format!("0x{}", hex::encode(Sha256::digest(&signature_bytes))),
        "valid": true,
        "magic_value": "0x1626ba7e",
        "checked_at": now_ts(),
    }))
    .expect("the ERC-1271 evidence must decode as its typed value")
}

/// The fixed test key the Bitcoin proof calls sign with.
fn bitcoin_test_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("deterministic test key")
}

/// The P2PKH address of `signing_key`, derived as
/// `src/tests/support.rs::bitcoin_p2pkh_test_address` derives it.
fn bitcoin_test_address(signing_key: &SigningKey) -> String {
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let compressed =
        bitcoin::CompressedPublicKey::from_slice(&pubkey).expect("deterministic test public key");
    bitcoin::Address::p2pkh(compressed, bitcoin::Network::Bitcoin).to_string()
}

/// The compressed public key of `signing_key`, encoded as
/// `src/tests/support.rs::bitcoin_test_public_key` encodes it.
fn bitcoin_test_public_key(signing_key: &SigningKey) -> String {
    hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

/// Signs `message` as `src/tests/support.rs::sign_bitcoin_message` signs it,
/// with the pinned `bitcoin` crate's public message hash.
fn sign_bitcoin_test_message(signing_key: &SigningKey, message: &str) -> String {
    let hash = bitcoin::sign_message::signed_msg_hash(message);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash.to_byte_array())
        .expect("test Bitcoin message signature");
    let mut bytes = vec![27 + recovery_id.to_byte()];
    bytes.extend_from_slice(signature.to_bytes().as_ref());
    BASE64_STANDARD.encode(bytes)
}

/// The result error of one wallet call, refusing an ok answer.
fn result_error(result: WalletResultV2) -> (String, String) {
    match result {
        WalletResultV2::Ok { data } => {
            panic!("expected a wallet operation result error, got {data}")
        }
        WalletResultV2::Error { code, message } => (code, message),
    }
}

/// The EVM proof and account-link calls answer under the profile and persist
/// under `STORAGE_ROOT`.
///
/// One provider `init`s a root and asks for two challenges: one for a fixed
/// EOA address and one for a fixed contract address. A fresh confined start on
/// the same root `init`s it and `status` shows `pending_challenge_count` 2, so
/// both challenges reloaded from the store. `verify_proof` on the first and
/// `verify_contract_proof` on the second answer ok with `proof_type` `siwe` and
/// `siwe_erc1271`, and `link_verified_account` with the first answer's
/// `proof_binding_id` answers ok. A second restart `init`s the same root and
/// `status` shows `pending_challenge_count` 0; each replayed verify answers
/// `invalid_proof` with "already consumed"; `list_accounts` holds the linked
/// account with that binding; and `read_store` shows both challenges with
/// `consumed_at` set under the root's wallet directory. The fixed signing key,
/// the messages and the signature stay test data in the temporary root, and no
/// assertion formats them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no narrower profile falsifier exists: no profile
/// edit can fail one of these calls and leave `init` working, and this test
/// fails on its first `init`.
#[test]
fn evm_proofs_and_link_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let signing_key = evm_test_signing_key();
    let eoa_address = evm_test_address(&signing_key);
    let contract = "0x00000000000000000000000000000000000000cc";

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(provider.wallet(WalletProviderOperationV2::Challenge {
        domain: "http://elastos.local".to_string(),
        uri: "http://elastos.local/apps/home/".to_string(),
        address: eoa_address.clone(),
        chain_id: 20,
        resources: vec!["elastos://wallet/account/link".to_string()],
    }));
    let eoa_message = data["message"]
        .as_str()
        .expect("a challenge must answer its message")
        .to_string();
    let eoa_challenge_id = data["challenge_id"]
        .as_str()
        .expect("a challenge must answer its id")
        .to_string();

    let data = ok_data(provider.wallet(WalletProviderOperationV2::Challenge {
        domain: "http://elastos.local".to_string(),
        uri: "http://elastos.local/apps/home/".to_string(),
        address: contract.to_string(),
        chain_id: 20,
        resources: vec!["elastos://wallet/account/link".to_string()],
    }));
    let contract_message = data["message"]
        .as_str()
        .expect("a challenge must answer its message")
        .to_string();
    let contract_challenge_id = data["challenge_id"]
        .as_str()
        .expect("a challenge must answer its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_challenge_count"], 2,
        "both challenges must reload from the store: {status}"
    );

    let eoa_signature = sign_test_message(&signing_key, &eoa_message);
    let data = ok_data(provider.wallet(WalletProviderOperationV2::VerifyProof {
        message: eoa_message.clone(),
        signature: eoa_signature.clone(),
    }));
    assert_eq!(
        data["proof_type"], "siwe",
        "verify_proof must answer its proof type"
    );
    assert_eq!(data["chain_namespace"], "eip155:20");
    assert_eq!(data["address"], eoa_address.to_ascii_lowercase());
    let proof_binding_id = data["proof_binding_id"]
        .as_str()
        .expect("a verified proof must answer its binding")
        .to_string();
    assert_eq!(
        proof_binding_id,
        format!(
            "proof:wallet:eip155:20:{}",
            eoa_address.to_ascii_lowercase()
        ),
        "the verified proof must answer its binding"
    );

    let contract_signature = "0x01020304";
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::VerifyContractProof {
            message: contract_message.clone(),
            signature: contract_signature.to_string(),
            evidence: erc1271_evidence(&contract_message, contract_signature, contract),
        }),
    );
    assert_eq!(
        data["proof_type"], "siwe_erc1271",
        "verify_contract_proof must answer its proof type"
    );
    assert_eq!(data["chain_namespace"], "eip155:20");
    assert_eq!(data["address"], contract);
    assert_eq!(
        data["proof_binding_id"],
        format!("proof:wallet:eip155:20:{contract}"),
        "the contract proof must answer its binding"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: proof_binding_id.clone(),
            chain_namespace: "eip155:20".to_string(),
            address: eoa_address.clone(),
            proof_type: "siwe".to_string(),
            label: Some("Proof".to_string()),
        }),
    );
    assert_eq!(
        data["account"]["proof_binding_id"].as_str(),
        Some(proof_binding_id.as_str()),
        "link_verified_account must answer the binding it was given"
    );
    let linked_account_id = data["account"]["account_id"]
        .as_str()
        .expect("a linked account must name its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_challenge_count"], 0,
        "both consumed challenges must reload from the store: {status}"
    );

    for operation in [
        WalletProviderOperationV2::VerifyProof {
            message: eoa_message.clone(),
            signature: eoa_signature.clone(),
        },
        WalletProviderOperationV2::VerifyContractProof {
            message: contract_message.clone(),
            signature: contract_signature.to_string(),
            evidence: erc1271_evidence(&contract_message, contract_signature, contract),
        },
    ] {
        let (code, message) = result_error(provider.wallet(operation));
        assert_eq!(
            code, "invalid_proof",
            "a replayed verify must be refused: {message}"
        );
        assert!(
            message.contains("already consumed"),
            "a replay must name the consumed challenge: {message}"
        );
    }

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("list_accounts must answer its accounts");
    assert_eq!(
        accounts.len(),
        1,
        "the reloaded listing must hold the linked account"
    );
    assert_eq!(accounts[0]["account_id"], linked_account_id);
    assert_eq!(
        accounts[0]["proof_binding_id"].as_str(),
        Some(proof_binding_id.as_str()),
        "the reloaded listing must hold the proof binding"
    );
    assert_eq!(accounts[0]["proof_type"], "siwe");
    assert_eq!(accounts[0]["address"], eoa_address.to_ascii_lowercase());

    let store = read_store(&root);
    let stored = store["challenges"]
        .as_array()
        .expect("the store under the wallet directory must hold its challenges");
    assert_eq!(
        stored.len(),
        2,
        "the store under the wallet directory must hold both challenges"
    );
    for challenge_id in [&eoa_challenge_id, &contract_challenge_id] {
        let challenge = stored
            .iter()
            .find(|stored| {
                stored["challenge"]["challenge_id"].as_str() == Some(challenge_id.as_str())
            })
            .expect("the store under the wallet directory must hold the challenge");
        assert!(
            challenge["consumed_at"].as_u64().is_some(),
            "the store under the wallet directory must hold the consumed challenge"
        );
    }
    provider.shutdown();
}

/// The Bitcoin proof calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a root and asks for a challenge for a fixed P2PKH
/// address. The answer is ok with `proof_type` `bitcoin_signed_message`, and
/// the test signs the challenge message. A fresh confined start on the same
/// root `init`s it and `status` shows `pending_bitcoin_challenge_count` 1, so
/// the challenge reloaded from the store. `verify_bip322_proof` with the
/// `bitcoin_signed_message` signature, type and public key answers ok with
/// `proof_type` `bitcoin_signed_message` and the same address. A second
/// restart `init`s the same root and `status` shows
/// `pending_bitcoin_challenge_count` 0; the replayed verify answers
/// `invalid_proof` with "already consumed"; and `read_store` shows the
/// challenge with `consumed_at` set under the root's wallet directory. The
/// fixed signing key, the message and the signature stay test data in the
/// temporary root, and no assertion formats them.
///
/// The test signs the `bitcoin_signed_message` type on a P2PKH address, not
/// the `bip322_simple` type: the simple type is signed through
/// `src/crypto/bitcoin.rs`'s `bip322_message_hash`, `bip322_to_spend_tx` and
/// `bip322_to_sign_tx`, which are `pub(crate)` in a binary crate, so an
/// integration test cannot call them, and building them again here would be a
/// second copy of that rule (P10). Both types reach the same handler, the same
/// stored challenge and the same consumption.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no narrower profile falsifier exists: no profile
/// edit can fail one of these calls and leave `init` working, and this test
/// fails on its first `init`.
#[test]
fn bitcoin_proofs_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let signing_key = bitcoin_test_signing_key();
    let address = bitcoin_test_address(&signing_key);
    let public_key = bitcoin_test_public_key(&signing_key);

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::BitcoinChallenge {
            domain: "elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: address.clone(),
            network: PublicNetwork::bitcoin(),
            resources: vec!["elastos://wallet/account/link".to_string()],
        }),
    );
    assert_eq!(
        data["proof_type"], "bitcoin_signed_message",
        "a P2PKH challenge must answer the signed-message proof type"
    );
    let message = data["message"]
        .as_str()
        .expect("a Bitcoin challenge must answer its message")
        .to_string();
    let challenge_id = data["challenge_id"]
        .as_str()
        .expect("a Bitcoin challenge must answer its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_bitcoin_challenge_count"], 1,
        "the Bitcoin challenge must reload from the store: {status}"
    );

    let signature = sign_bitcoin_test_message(&signing_key, &message);
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::VerifyBip322Proof {
            message: message.clone(),
            signature: signature.clone(),
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(public_key.clone()),
        }),
    );
    assert_eq!(
        data["proof_type"], "bitcoin_signed_message",
        "verify_bip322_proof must answer its proof type"
    );
    assert_eq!(
        data["address"], address,
        "verify_bip322_proof must answer the challenge address"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_bitcoin_challenge_count"], 0,
        "the consumed Bitcoin challenge must reload from the store: {status}"
    );

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::VerifyBip322Proof {
            message: message.clone(),
            signature,
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(public_key),
        },
    ));
    assert_eq!(
        code, "invalid_proof",
        "a replayed verify must be refused: {refusal}"
    );
    assert!(
        refusal.contains("already consumed"),
        "a replay must name the consumed challenge: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["bitcoin_challenges"]
        .as_array()
        .expect("the store under the wallet directory must hold its Bitcoin challenges");
    assert_eq!(
        stored.len(),
        1,
        "the store under the wallet directory must hold the challenge"
    );
    assert_eq!(
        stored[0]["challenge"]["challenge_id"].as_str(),
        Some(challenge_id.as_str())
    );
    assert!(
        stored[0]["consumed_at"].as_u64().is_some(),
        "the store under the wallet directory must hold the consumed challenge"
    );
    provider.shutdown();
}

/// The `request_approval` operation of
/// `src/tests/approvals/managed.rs::managed_account_signs_only_after_runtime_approval`
/// for a Browser `personal_sign` request on a managed `eip155:20` account.
///
/// The integration test writes the payload value itself because
/// `src/tests/support.rs::browser_personal_sign_payload` is crate-private; it is
/// request data, not provider logic. `expires_at` is ten minutes ahead, inside
/// `src/main.rs`'s `MAX_APPROVAL_REQUEST_TTL_SECS` of thirty minutes, as the
/// unit test's `APPROVAL_REQUEST_TTL_SECS` does.
fn personal_sign_approval(
    account_id: &str,
    address: &str,
    message: &str,
) -> WalletProviderOperationV2 {
    WalletProviderOperationV2::RequestApproval {
        account_id: account_id.to_string(),
        chain_namespace: "eip155:20".to_string(),
        intent: "browser_personal_sign".to_string(),
        resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".to_string(),
        reason: "Browser page requests personal_sign".to_string(),
        payload: json!({
            "schema": "elastos.browser.wallet-signature-request/v1",
            "method": "personal_sign",
            "params": [message, address],
            "message": message,
            "address": address,
            "account_id": account_id,
            "chain_namespace": "eip155:20",
            "page_url": "https://dapp.example/sign",
            "origin": "https://dapp.example",
            "requires_wallet_approval": true
        }),
        expires_at: now_ts().saturating_add(10 * 60),
    }
}

/// The managed approval calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a root, creates one managed account on `eip155:20` and
/// sends two `request_approval` calls whose answers pass through `ok_data`.
/// Every request carries principal `person:local:alice`, session
/// `session:confine` and actor `wallet`, the same across restarts. A fresh
/// confined start on the same root `init`s it and `status` shows
/// `pending_approval_count` 2, so both requests reloaded from the store, and
/// `list_approvals` without `include_resolved` lists both request ids. Then
/// `approve_and_sign_managed` on the first answers `completed` with a
/// signature, and `reject_approval` on the second answers `rejected`. A second
/// restart `init`s the same root and `status` shows `pending_approval_count` 0;
/// `list_approvals` without `include_resolved` is empty and with it shows the
/// first `completed` and the second `rejected`; a replayed
/// `approve_and_sign_managed` on the first answers `invalid_request` with
/// "not pending"; and `read_store` shows both requests with those statuses
/// under the root's wallet directory. The payloads and the signature stay test
/// data in the temporary root, and no assertion formats them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; no narrower profile falsifier exists, and this test
/// fails on its first `init`.
#[test]
fn managed_approvals_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Approvals".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let address = data["account"]["address"]
        .as_str()
        .expect("managed account must name its address")
        .to_string();

    let mut request_ids = Vec::new();
    for message in ["First managed approval", "Second managed approval"] {
        let data = ok_data(provider.wallet(personal_sign_approval(&account_id, &address, message)));
        let approval = &data["approval_request"];
        assert_eq!(
            approval["status"], "pending",
            "request_approval must answer a pending request"
        );
        request_ids.push(
            approval["request_id"]
                .as_str()
                .expect("an approval request must name its id")
                .to_string(),
        );
    }
    let first_id = request_ids[0].clone();
    let second_id = request_ids[1].clone();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_approval_count"], 2,
        "both approval requests must reload from the store: {status}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: false,
    }));
    let pending = data["approval_requests"]
        .as_array()
        .expect("list_approvals must answer its requests");
    assert_eq!(
        pending.len(),
        2,
        "the reloaded listing must hold both pending approvals"
    );
    for request_id in [&first_id, &second_id] {
        assert!(
            pending
                .iter()
                .any(|request| request["request_id"].as_str() == Some(request_id.as_str())),
            "the reloaded listing must hold the pending approval"
        );
    }

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: first_id.clone(),
            reason: "approved".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "approve_and_sign_managed must answer the completed request"
    );
    assert!(
        data["signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty()),
        "approve_and_sign_managed must answer a signature"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RejectApproval {
        request_id: second_id.clone(),
        reason: "rejected".to_string(),
    }));
    assert_eq!(
        data["approval_request"]["status"], "rejected",
        "reject_approval must answer the rejected request"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_approval_count"], 0,
        "both resolved approvals must reload from the store: {status}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: false,
    }));
    assert!(
        data["approval_requests"]
            .as_array()
            .is_some_and(|requests| requests.is_empty()),
        "resolved approvals must stay out of the pending listing"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: true,
    }));
    let resolved = data["approval_requests"]
        .as_array()
        .expect("list_approvals must answer its requests");
    for (request_id, expected) in [(&first_id, "completed"), (&second_id, "rejected")] {
        let request = resolved
            .iter()
            .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
            .expect("the resolved listing must hold the request");
        assert_eq!(
            request["status"], expected,
            "the resolved listing must hold the stored status"
        );
    }

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: first_id.clone(),
            reason: "approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals");
    for (request_id, expected) in [(&first_id, "completed"), (&second_id, "rejected")] {
        let request = stored
            .iter()
            .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
            .expect("the store under the wallet directory must hold the request");
        assert_eq!(
            request["status"], expected,
            "the store under the wallet directory must hold the status"
        );
    }
    provider.shutdown();
}

/// The fixed digest a rights fixture field uses.
fn rights_digest(seed: u8) -> Digest32 {
    Digest32::new([seed; 32])
}

/// The 20-byte Wallet address a rights request binds.
fn rights_wallet_address(address: &str) -> WalletAddress {
    let hex = address.strip_prefix("0x").unwrap_or(address);
    let bytes = hex::decode(hex).expect("the rights wallet address must be hex");
    WalletAddress::new(
        bytes
            .try_into()
            .expect("the rights wallet must be a 20-byte address"),
    )
}

/// The protected-content rights request the wallet test signs.
///
/// This is request data, not provider logic. It repeats the constant inputs
/// `src/tests/approvals/protected_content.rs::RightsRequestFixture::build`
/// builds, because that fixture is crate-private and this integration test is
/// a separate crate. Only the wallet address, the validity window and the
/// nonce vary.
fn protected_content_rights_request(
    address: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: u8,
) -> RightsRequestV1 {
    let encrypted_content = EncryptedContentIdentityV1::new(rights_digest(0x11), 4096)
        .expect("the rights content identity must be valid");
    let key_envelope = KeyEnvelopeIdentityV1::new(
        encrypted_content.clone(),
        rights_digest(0x22),
        2048,
        rights_digest(0x23),
        ThresholdV1::new(2, 3).expect("the rights threshold must be valid"),
        CustodyPoolIdentityV1::new(rights_digest(0x24), 512)
            .expect("the rights custody pool must be valid"),
        CustodyEpochIdentityV1::new(rights_digest(0x25), 512)
            .expect("the rights custody epoch must be valid"),
        CustodyCommitteeAuthorizationIdentityV1::new(rights_digest(0x26), 512)
            .expect("the rights committee authorization must be valid"),
    )
    .expect("the rights key envelope must be valid");
    let action = RightsActionV1::View;
    let policy = RightsPolicyBodyV1::new(
        encrypted_content.clone(),
        ContentAccessIdV1::new([0x27; 16]).expect("the rights content access id must be valid"),
        action,
        RightsSubjectSourceV1::WalletAddress,
        20,
        EvmContractAddressV1::new([0x44; 20]).expect("the rights contract must be valid"),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78])
            .expect("the rights selector must be valid"),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .expect("the rights policy must be valid");
    let binding = ProtectedContentBindingV1::new(
        encrypted_content,
        key_envelope,
        policy
            .policy_identity()
            .expect("the rights policy identity must be valid"),
        ProfileIdentityV1::from_did_key("did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z")
            .expect("the rights profile identity must be valid"),
        rights_wallet_address(address),
        RuntimeSessionBindingV1::new(rights_digest(0x66))
            .expect("the rights runtime session binding must be valid"),
    )
    .expect("the rights binding must be valid");
    RightsRequestV1::new(
        binding,
        action,
        RecipientKeyIdentityV1::new("x25519-hkdf-sha256-hpke-v1", rights_digest(0xa0))
            .expect("the rights recipient key must be valid"),
        issued_at,
        expires_at,
        ReplayNonce16::new([nonce; 16]),
    )
    .expect("the rights request must be valid")
}

/// The protected-content rights call answers under the profile and persists
/// under `STORAGE_ROOT`.
///
/// One provider `init`s a root and creates one managed account on `eip155:20`,
/// then sends `request_protected_content_rights_signature` with a rights
/// request bound to that account's address over the window `now_ts()` to
/// `now_ts()` plus 120 s. Every request carries principal `person:local:alice`,
/// session `session:confine` and actor `wallet`, the same across restarts. The
/// answer requires approval, holds intent
/// `protected_content_rights_signature`, and carries the hex sent in
/// `approval_request.payload.canonical_rights_request_hex`. A fresh confined
/// start on the same root `init`s it, and `approve_and_sign_managed` on the
/// request answers ok with `approval_request.status` `completed` and a
/// `signed_result` present. After a second restart, a replayed
/// `approve_and_sign_managed` answers `invalid_request` with "not pending", and
/// `read_store` shows the request `completed` with a `signed_result` under the
/// root's wallet directory. The rights request and the signed result stay test
/// data in the temporary root, and no assertion message prints them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail this call and leave `init`
/// working; no narrower profile falsifier exists, and this test fails on its
/// first `init`.
#[test]
fn protected_content_rights_request_persists_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Protected content".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let address = data["account"]["address"]
        .as_str()
        .expect("managed account must name its address")
        .to_string();

    let issued_at = now_ts();
    let rights_request =
        protected_content_rights_request(&address, issued_at, issued_at.saturating_add(120), 0x51);
    let canonical_rights_request_hex = hex::encode(
        rights_request
            .canonical_bytes()
            .expect("the rights request must encode canonically"),
    );
    let data = ok_data(provider.wallet(
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id,
            canonical_rights_request_hex: canonical_rights_request_hex.clone(),
            reason: "Review and sign the exact protected-content rights request".to_string(),
        },
    ));
    assert_eq!(
        data["requires_approval"], true,
        "the rights call must answer a request that needs approval"
    );
    assert_eq!(
        data["approval_request"]["intent"], PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT,
        "the approval request must carry the rights intent"
    );
    assert!(
        data["approval_request"]["payload"]["canonical_rights_request_hex"]
            .as_str()
            .is_some_and(|hex| hex == canonical_rights_request_hex.as_str()),
        "the approval request must carry the hex sent"
    );
    let request_id = data["approval_request"]["request_id"]
        .as_str()
        .expect("an approval request must name its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "approved".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "approve_and_sign_managed must answer the completed request"
    );
    assert!(
        data["approval_request"]["signed_result"].is_object(),
        "approve_and_sign_managed must answer a signed result"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals")
        .iter()
        .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
        .expect("the store under the wallet directory must hold the request");
    assert_eq!(
        stored["status"], "completed",
        "the store must hold the completed status"
    );
    assert!(
        stored["signed_result"].is_object(),
        "the store must hold the signed result"
    );
    provider.shutdown();
}

/// The external connector address the connector-path test links.
const CONNECTOR_ADDRESS: &str = "0x3333333333333333333333333333333333333333";
/// The transaction hash the connector-path test completes with.
const CONNECTOR_TRANSACTION_HASH: &str =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The external transaction intent the connector approval carries.
///
/// This is request data, not provider logic. It repeats the value
/// `src/tests/support.rs::transaction_intent_payload` builds, because that
/// function is crate-private and this integration test is a separate crate,
/// and adds the `page_url`, `origin` and `network` fields the external
/// handoff uses.
fn external_transaction_payload(from: &str) -> Value {
    json!({
        "schema": "elastos.chain.unsigned_transaction_intent/v1",
        "transaction_type": "eip155_legacy",
        "from": from,
        "to": "0x0000000000000000000000000000000000000002",
        "value": "0x0",
        "data": "0x",
        "chain_id": 20,
        "nonce": "0x7",
        "gas_price": "0x3b9aca00",
        "gas_limit": "0x5208",
        "requires_wallet_approval": true,
        "wallet_intent": "transaction_intent",
        "page_url": "https://ela.city/cinema/view/test",
        "origin": "https://ela.city",
        "network": { "id": "esc-mainnet" }
    })
}

/// The external connector's validated Chain outcome for one approval request.
///
/// `chain_observation` carries the fields the provider's chain-observation
/// binding checks: the network, the transaction hash and the originating
/// account.
fn external_chain_outcome(
    request_id: &str,
    account_id: &str,
    transaction_hash: &str,
) -> ValidatedChainOutcomeV1 {
    ValidatedChainOutcomeV1 {
        schema: VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id.to_string(),
        account_id: account_id.to_string(),
        chain_namespace: "eip155:20".to_string(),
        network: PublicNetwork::new("esc-mainnet").expect("the fixture network must be valid"),
        binding: ValidatedChainOutcomeBindingV1::ExternalConnector {
            connector_id: "wallet".to_string(),
            originating_address: CONNECTOR_ADDRESS.to_string(),
        },
        transaction_hash: transaction_hash.to_string(),
        chain_observation: json!({
            "network": "esc-mainnet",
            "hash": transaction_hash,
            "transaction": {
                "hash": transaction_hash,
                "from": CONNECTOR_ADDRESS,
                "blockNumber": "0x2a"
            }
        }),
        confirmed_at: now_ts(),
    }
}

/// The connector handoff and Chain outcome calls answer under the profile and
/// persist under `STORAGE_ROOT`.
///
/// One provider `init`s a root, links a fixed external address with proof type
/// `siwe`, so the linked account's `connector_id` is the actor `wallet`, and
/// sends one `request_approval` with intent `transaction_intent`; its answer
/// holds a `pending` request. `approve_connector_handoff` answers `approved`
/// with a handoff of intent `transaction_intent`. Every request carries
/// principal `person:local:alice`, session `session:confine`, grant
/// `grant:confine`, launch `launch:confine` and actor `wallet`, the same across
/// restarts. A fresh confined start on the same root `init`s it, a replayed
/// `approve_connector_handoff` answers `invalid_request` with "not pending",
/// `complete_connector_handoff` answers `completed` with the transaction hash
/// sent in `signed_result`, and `attach_validated_chain_outcome` answers ok
/// with the outcome in `approval_request.validated_chain_outcome`. After a
/// second restart, a replayed `complete_connector_handoff` answers
/// `invalid_request` with "must be approved before completion", the same
/// outcome attached again answers ok, a substituted outcome answers
/// `chain_outcome_conflict` with "substitution was rejected", and `read_store`
/// shows the request `completed` with that outcome under the root's wallet
/// directory. The payload, the handoff, the transaction hash and the outcome
/// stay test data in the temporary root, and no assertion message prints a
/// whole payload, outcome or store.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; no narrower profile falsifier exists, and this test
/// fails on its first `init`.
#[test]
fn connector_handoff_and_chain_outcome_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: format!("proof:eip155:20:{CONNECTOR_ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            address: CONNECTOR_ADDRESS.to_string(),
            proof_type: "siwe".to_string(),
            label: None,
        }),
    );
    assert_eq!(
        data["account"]["connector_id"], "wallet",
        "the linked account must carry the request's actor as its connector"
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("the linked account must name its id")
        .to_string();

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RequestApproval {
        account_id: account_id.clone(),
        chain_namespace: "eip155:20".to_string(),
        intent: "transaction_intent".to_string(),
        resource: "elastos://chain/esc-mainnet/broadcast_transaction".to_string(),
        reason: "Send EVM transaction".to_string(),
        payload: external_transaction_payload(CONNECTOR_ADDRESS),
        expires_at: now_ts().saturating_add(10 * 60),
    }));
    let approval = &data["approval_request"];
    assert_eq!(
        approval["status"], "pending",
        "request_approval must answer a pending request"
    );
    let request_id = approval["request_id"]
        .as_str()
        .expect("an approval request must name its id")
        .to_string();
    let payload_hash = approval["payload_hash"]
        .as_str()
        .expect("an approval request must name its payload hash")
        .to_string();

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved transaction".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "approved",
        "approve_connector_handoff must answer the approved request"
    );
    assert_eq!(
        data["handoff"]["intent"], "transaction_intent",
        "the handoff must carry the approval's intent"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let completion = WalletProviderOperationV2::CompleteConnectorHandoff {
        request_id: request_id.clone(),
        payload_hash: payload_hash.clone(),
        signature: None,
        signature_type: None,
        public_key: None,
        signer: CONNECTOR_ADDRESS.to_string(),
        transaction_hash: Some(CONNECTOR_TRANSACTION_HASH.to_string()),
    };
    let data = ok_data(provider.wallet(completion.clone()));
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "complete_connector_handoff must answer the completed request"
    );
    assert_eq!(
        data["approval_request"]["signed_result"]["transaction_hash"], CONNECTOR_TRANSACTION_HASH,
        "the completion must answer the transaction hash sent"
    );

    let outcome = external_chain_outcome(&request_id, &account_id, CONNECTOR_TRANSACTION_HASH);
    let expected_outcome =
        serde_json::to_value(&outcome).expect("the fixture outcome must serialize");
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: outcome.clone(),
        }),
    );
    assert!(
        data["approval_request"]["validated_chain_outcome"] == expected_outcome,
        "the attach answer must carry the stored outcome"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );

    let (code, refusal) = result_error(provider.wallet(completion));
    assert_eq!(
        code, "invalid_request",
        "a replayed completion must be refused: {refusal}"
    );
    assert!(
        refusal.contains("must be approved before completion"),
        "a replay must name the completed request: {refusal}"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: outcome.clone(),
        }),
    );
    assert!(
        data["approval_request"]["validated_chain_outcome"] == expected_outcome,
        "the same outcome attached again must answer the stored outcome"
    );

    let mut substituted = outcome.clone();
    substituted.chain_observation["status"] = json!("substituted");
    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: substituted,
        },
    ));
    assert_eq!(
        code, "chain_outcome_conflict",
        "a substituted outcome must be refused: {refusal}"
    );
    assert!(
        refusal.contains("substitution was rejected"),
        "the refusal must name the substitution: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals")
        .iter()
        .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
        .expect("the store under the wallet directory must hold the request");
    assert_eq!(
        stored["status"], "completed",
        "the store must hold the completed status"
    );
    assert!(
        stored["validated_chain_outcome"] == expected_outcome,
        "the store must hold the attached outcome"
    );
    provider.shutdown();
}

/// A write outside the wallet directory is denied by the profile, and the
/// provider reports it and stays in service.
///
/// The last case is the write beneath `STORAGE_PARENT`: `Init` for
/// `<STORAGE_PARENT>/Fresh`, where nothing is precreated at `Fresh` or beneath
/// it, walks up to the granted parent, so its first ungranted step is the
/// `mkdir` of `Fresh`. A write grant on the parent (WP65) creates it, so this
/// test fails on the absence check.
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

    // Nothing is precreated at `<STORAGE_PARENT>/Fresh` or beneath it, so the
    // walk reaches the granted parent and the first ungranted step is the
    // `mkdir`.
    let fresh_base = wallet_dir(&root)
        .parent()
        .expect("wallet parent")
        .join("Fresh");
    let denied = provider.init(&fresh_base);
    assert_storage_error(&denied);
    assert!(
        !fresh_base.exists(),
        "a denied write beneath STORAGE_PARENT must create nothing: {}",
        fresh_base.display()
    );
    let message = denied["message"]
        .as_str()
        .expect("storage refusal must carry a reason");
    assert!(
        message.starts_with("failed to create wallet storage directory"),
        "the refused step must be the write beneath STORAGE_PARENT, not an inspect: {message}"
    );

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the provider must answer after a denied write instead of exiting: {status}"
    );

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

/// A key planted beneath `STORAGE_PARENT` stays unread.
///
/// The parent read grants the directory itself only, not a directory beneath
/// it, and the storage-root write grant stops at `STORAGE_ROOT`. The test
/// plants a complete key at
/// `<STORAGE_PARENT>/Sibling/ElastOS/SystemServices/Wallet`, beneath
/// `STORAGE_PARENT` and outside `STORAGE_ROOT`, and records its bytes. With
/// the real profile `init` for that sibling base refuses with `storage_error`,
/// the planted bytes stay unchanged and no `wallet-state.json` appears beside
/// them. The provider then serves its own root, and the key it writes there
/// differs from the planted one, so it never adopted the planted key. The
/// write half beneath the parent is the `<STORAGE_PARENT>/Fresh` case of
/// `confined_outside_write_is_denied`, which is refused at its first write
/// (the `mkdir`).
///
/// Falsifier: widen the parent read from `literal` to `subpath` (WP57); the
/// planted key then loads, `init` answers ok and this test fails on its
/// refusal.
#[test]
fn planted_key_beneath_storage_parent_is_not_read() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    // `<STORAGE_PARENT>/Sibling`: beneath the granted parent and outside
    // `STORAGE_ROOT`, which is `<STORAGE_PARENT>/Wallet`.
    let planted = wallet_dir(&root)
        .parent()
        .expect("wallet parent")
        .join("Sibling");
    let planted_wallet = wallet_dir(&planted);
    plant_storage_key(&planted_wallet);
    let planted_key = planted_wallet.join(WALLET_KEY_FILE);
    let planted_bytes = fs::read(&planted_key).expect("planted key file");

    let mut provider = ConfinedProvider::start(&root);

    let denied = provider.init(&planted);
    assert_storage_error(&denied);
    assert_eq!(
        fs::read(&planted_key).expect("planted key stays readable to the test"),
        planted_bytes,
        "the planted key must stay unchanged after the refused read"
    );
    assert!(
        !planted_wallet.join("wallet-state.json").exists(),
        "a refused read must write no store beside the planted key: {}",
        planted_wallet.display()
    );

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the provider must answer after a denied read: {status}"
    );

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "the granted root must serve: {init}");
    let own_key = wallet_dir(&root).join(WALLET_KEY_FILE);
    let own_bytes = fs::read(&own_key).expect("the provider writes its own key");
    assert_ne!(
        own_bytes,
        planted_bytes,
        "the provider must not adopt the planted key: {}",
        own_key.display()
    );

    provider.shutdown();
}

/// Account operations beneath `STORAGE_PARENT` are refused.
///
/// `<STORAGE_PARENT>/Sibling` is outside `STORAGE_ROOT`, and its wallet
/// directory is precreated empty, so the refusal is neither the `mkdir` of
/// `<STORAGE_PARENT>/Fresh` nor a read of a planted key. `init` for that
/// sibling base refuses with `storage_error`, and `init` resets the root
/// first, so the provider keeps no usable root. The wallet calls that follow
/// therefore answer through `data.result` with `status` `error`, `code`
/// `not_initialized` and a reason, and the sibling's wallet directory stays
/// empty. The array sends `rename_account`, `revoke_account`,
/// `set_default_account` and `default_account` before the
/// `export_managed_recovery_key`, `import_managed_recovery_key`,
/// `export_managed_recovery_set` and `import_managed_recovery_set` calls, then
/// the `challenge`, `verify_proof`, `verify_contract_proof` and
/// `link_verified_account` calls of task 082, the `bitcoin_challenge` and
/// `verify_bip322_proof` calls of task 083, the `request_approval`,
/// `approve_and_sign_managed`, `reject_approval` and `list_approvals` calls of
/// task 084, the `approve_connector_handoff`, `complete_connector_handoff` and
/// `attach_validated_chain_outcome` calls of task 085, the
/// `request_protected_content_rights_signature` call of task 086, and the
/// `create_managed_account` and `list_accounts` calls that 072 named come last.
/// The loop sends every call in the array and records each call that is not
/// refused; after the loop one assertion fails, naming every recorded kind
/// with its result status and code, so a WP88 run names every call in the
/// array. The array runs before the `storage_error` check, so a grant on the
/// parent fails on the calls that are not refused rather than only on `init`.
/// `list_accounts` is sent only to
/// show that the refused `create_managed_account` created nothing. After
/// `init` for the granted root answers ok, the same call answers ok, the
/// listing holds that account, and the account is in the store under the root.
///
/// Falsifiers: append a read and write grant on `STORAGE_PARENT` (WP88); the
/// sibling `init` then succeeds, so the loop records every call that is not
/// refused and the one assertion names them all. Remove the storage-root
/// grant (WP18); the granted `init` fails, so this test fails on its ok.
#[test]
fn account_operations_beneath_storage_parent_are_refused() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    // `<STORAGE_PARENT>/Sibling`: beneath the granted parent and outside
    // `STORAGE_ROOT`, which is `<STORAGE_PARENT>/Wallet`.
    let sibling = wallet_dir(&root)
        .parent()
        .expect("wallet parent")
        .join("Sibling");
    let sibling_wallet = wallet_dir(&sibling);
    fs::create_dir_all(&sibling_wallet).expect("precreate the sibling wallet directory");
    let mut provider = ConfinedProvider::start(&root);

    let denied = provider.init(&sibling);

    // The four account edits of task 080, the four managed-recovery calls of
    // task 081, the four EVM proof and link calls of task 082, the two
    // Bitcoin proof calls of task 083 and the four managed approval calls of
    // task 084 come first, so a grant on `STORAGE_PARENT` answers these calls
    // without the refusal this test requires.
    let operations = [
        WalletProviderOperationV2::RenameAccount {
            account_id: "wallet:eip155:20:0xabc".to_string(),
            label: "Outside".to_string(),
        },
        WalletProviderOperationV2::RevokeAccount {
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::DefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
        },
        WalletProviderOperationV2::ExportManagedRecoveryKey {
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::ImportManagedRecoveryKey {
            recovery_key: json!({}),
            label: Some("Outside".to_string()),
        },
        WalletProviderOperationV2::ExportManagedRecoverySet {},
        WalletProviderOperationV2::ImportManagedRecoverySet {
            recovery_set: ManagedRecoverySetV1::new(vec![ManagedRecoveryKeyEntryV1 {
                account_id: "wallet:eip155:20:0xabc".to_string(),
                recovery_key: json!({}),
                label: Some("Outside".to_string()),
            }])
            .expect("the outside fixture set must be well formed"),
        },
        WalletProviderOperationV2::Challenge {
            domain: "http://elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: "0x00000000000000000000000000000000000000ab".to_string(),
            chain_id: 20,
            resources: vec![],
        },
        WalletProviderOperationV2::VerifyProof {
            message: "Outside EVM proof".to_string(),
            signature: "0x01020304".to_string(),
        },
        WalletProviderOperationV2::VerifyContractProof {
            message: "Outside EVM proof".to_string(),
            signature: "0x01020304".to_string(),
            evidence: erc1271_evidence(
                "Outside EVM proof",
                "0x01020304",
                "0x00000000000000000000000000000000000000cc",
            ),
        },
        WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".to_string(),
            chain_namespace: "eip155:20".to_string(),
            address: "0xabc".to_string(),
            proof_type: "siwe".to_string(),
            label: Some("Outside".to_string()),
        },
        WalletProviderOperationV2::BitcoinChallenge {
            domain: "elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            network: PublicNetwork::bitcoin(),
            resources: vec!["elastos://wallet/account/link".to_string()],
        },
        WalletProviderOperationV2::VerifyBip322Proof {
            message: "Outside Bitcoin proof".to_string(),
            signature: "signature".to_string(),
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            ),
        },
        personal_sign_approval(
            "wallet:eip155:20:0xabc",
            "0x00000000000000000000000000000000000000ab",
            "Outside approval",
        ),
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside approval".to_string(),
        },
        WalletProviderOperationV2::RejectApproval {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside rejection".to_string(),
        },
        WalletProviderOperationV2::ListApprovals {
            include_resolved: false,
        },
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside connector approval".to_string(),
        },
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: "wallet-request:outside".to_string(),
            payload_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: CONNECTOR_ADDRESS.to_string(),
            transaction_hash: Some(CONNECTOR_TRANSACTION_HASH.to_string()),
        },
        WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: external_chain_outcome(
                "wallet-request:00000000000000000000000000000000",
                &format!("wallet:eip155:20:{CONNECTOR_ADDRESS}"),
                CONNECTOR_TRANSACTION_HASH,
            ),
        },
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id: "wallet:eip155:20:0xabc".to_string(),
            canonical_rights_request_hex: hex::encode(
                protected_content_rights_request(
                    "0x00000000000000000000000000000000000000ab",
                    now_ts(),
                    now_ts().saturating_add(120),
                    0x52,
                )
                .canonical_bytes()
                .expect("the outside rights request must encode canonically"),
            ),
            reason: "Outside protected-content rights request".to_string(),
        },
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Outside".to_string()),
            create_new: false,
        },
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ];
    let mut not_refused = Vec::new();
    for operation in operations {
        let kind = operation_kind(&operation);
        let request = wallet_request(operation);
        let answer = provider.send(&json!({
            "op": "wallet_contract",
            "request": request,
            "_runtime_invocation": runtime_invocation_envelope(),
        }));
        let result = answer.get("data").and_then(|data| data.get("result"));
        let refused = answer.get("status").and_then(Value::as_str) == Some("ok")
            && result
                .and_then(|result| result.get("status"))
                .and_then(Value::as_str)
                == Some("error")
            && result
                .and_then(|result| result.get("code"))
                .and_then(Value::as_str)
                == Some("not_initialized")
            && result
                .and_then(|result| result.get("message"))
                .and_then(Value::as_str)
                .is_some_and(|message| !message.is_empty());
        if !refused {
            not_refused.push((
                kind,
                refusal_field(result.and_then(|result| result.get("status"))),
                refusal_field(result.and_then(|result| result.get("code"))),
            ));
        }
    }
    assert!(
        not_refused.is_empty(),
        "every call beneath STORAGE_PARENT must be refused with not_initialized; \
         calls not refused: {}",
        not_refused
            .iter()
            .map(|(kind, status, code)| format!("{kind} (status {status}, code {code})"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // The refused `init` is why every call above answered `not_initialized`.
    assert_storage_error(&denied);
    let message = denied["message"]
        .as_str()
        .expect("storage refusal must carry a reason");
    assert!(
        message.starts_with("failed to inspect wallet storage directory"),
        "the refused step must be the inspect beneath STORAGE_PARENT: {message}"
    );

    assert!(
        !sibling_wallet.join(WALLET_KEY_FILE).exists(),
        "the refused account call must create no key: {}",
        sibling_wallet.display()
    );
    assert!(
        !sibling_wallet.join("wallet-state.json").exists(),
        "the refused account call must create no store: {}",
        sibling_wallet.display()
    );

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "the granted root must serve: {init}");
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Inside".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    assert!(
        data["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "the created managed account must be listed: {data}"
    );
    let store = read_store(&root);
    assert!(
        store["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "account state must land under the wallet root: {store}"
    );

    provider.shutdown();
}

/// The serde `kind` tag of one wallet operation, so a failure names it.
fn operation_kind(operation: &WalletProviderOperationV2) -> String {
    serde_json::to_value(operation)
        .expect("the operation must serialize")
        .get("kind")
        .and_then(Value::as_str)
        .expect("the operation must serialize with its kind tag")
        .to_string()
}

/// The text a refusal record prints for a result status or code.
fn refusal_field(field: Option<&Value>) -> String {
    field
        .and_then(Value::as_str)
        .map_or_else(|| "none".to_string(), |text| text.to_string())
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
        let mut provider =
            ConfinedProvider::start_under(&profile, &bindings, Path::new(PROVIDER_BINARY));
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

/// The lab writer refuses an unnamed right and writes no profile, so the start
/// under that unwritten path is refused before the provider runs.
///
/// Both cases read the real wallet declared-rights file and add one entry: a
/// rights entry `unnamed-right` (case (a)) or a platform-baseline entry
/// `unnamed-baseline` with the wallet justification prefix and a reason (case
/// (b)). `write_generated_profile` returns the existing unnamed-id refusal,
/// creates no path, and the confined start under that missing path exits
/// non-zero before any request; `try_send` of `init` fails naming the request,
/// the exit status and the missing path, and no wallet directory is created.
/// On a host without the sandbox gate the file half still runs and the start
/// half is skipped through the existing gate only.
///
/// Falsifier: WP106 makes the rights-list id refusal in `declared_entries`
/// never fire, so case (a) writes a profile and fails the no-file assertion;
/// WP107 makes the platform-baseline id refusal never fire, so case (b) fails
/// the same way; WP108 makes `write_generated_profile` create the path before
/// it calls `generate_profile`, so both cases fail the no-file assertion.
#[test]
fn generator_refuses_an_unnamed_right_and_the_start_is_refused() {
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let declared_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/confine/declared-rights.json");
    let declared = read_declared_rights("wallet-provider", &declared_path)
        .unwrap_or_else(|err| panic!("{err}"));
    let rule = r#"(allow file-read* (literal "/private/var/cc-confine-unnamed"))"#;
    let prefix = platform_baseline_justification("wallet-provider");
    let cases: [(&str, &str, Value); 2] = [
        (
            "(a) an unnamed right",
            "unnamed-right",
            json!({ "id": "unnamed-right", "rules": [rule] }),
        ),
        (
            "(b) an unnamed platform-baseline rule",
            "unnamed-baseline",
            json!({
                "id": "unnamed-baseline",
                "justification": format!(
                    "{prefix}a declared right that the shared contract does not name"
                ),
                "rules": [rule],
            }),
        ),
    ];
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_root = resolved(profile_root.path());
    let canonical = canonical_bindings(&base);
    create_shared_ancestors(&canonical);
    let wallet_root = wallet_dir(&base);
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });
    for (case, id, entry) in cases {
        let mut declared = declared.clone();
        if id == "unnamed-right" {
            declared["rights"]
                .as_array_mut()
                .expect("wallet declared rights")
                .push(entry);
        } else {
            declared[PLATFORM_BASELINE]["rules"]
                .as_array_mut()
                .expect("wallet platform-baseline rules")
                .push(entry);
        }
        let path = profile_root.join(format!("{id}-profile.sb"));
        let refusal = write_generated_profile("wallet-provider", &declared, &path)
            .expect_err("an unnamed right must be refused");
        assert_eq!(
            refusal,
            format!("wallet-provider declares {id}, which the shared contract does not name"),
            "{case}: the refusal must be the one unnamed-id reason"
        );
        eprintln!("{case} refusal: {refusal}");
        assert!(
            !path.exists(),
            "{case}: a refused profile must create no file: {}",
            path.display()
        );
        if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
            continue;
        }
        let bindings: Vec<(&str, &Path)> = canonical
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        let mut provider =
            ConfinedProvider::start_under(&path, &bindings, Path::new(PROVIDER_BINARY));
        let exit = provider.wait_for_exit();
        assert!(
            exit.code().is_some(),
            "{case}: sandbox-exec must exit instead of starting the provider: {exit}"
        );
        assert_ne!(
            exit.code(),
            Some(0),
            "{case}: sandbox-exec must refuse the missing profile: {exit}"
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
            failure.contains(&path.display().to_string()),
            "{case}: the failure must name the missing path: {failure}"
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
        let fixture = tempfile::tempdir().expect("temporary wallet base");
        let base = resolved(fixture.path());
        let binary = resolved(Path::new(PROVIDER_BINARY));
        let bindings = canonical_bindings(&base);
        create_shared_ancestors(&bindings);
        let storage = wallet_dir(&base);
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
/// Falsifier: append one `(allow process-exec)` after the exec rule (WP56);
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
        "config": { "base_path": stored.base.display().to_string() }
    });
    let canonical = canonical_bindings(&stored.base);
    let bindings: Vec<(&str, &Path)> = canonical
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut refused =
        ConfinedProvider::start_under(Path::new(PROFILE_PATH), &bindings, &stored.copy);

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
/// `base_path` as the fixture base answers `ok`, a following `status` answers
/// `ok`, and `shutdown` exits 0. The binding is the only difference between
/// the two runs.
#[test]
fn bound_copy_serves_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare();
    let bound: Vec<(&str, PathBuf)> = canonical_bindings(&stored.base)
        .into_iter()
        .map(|(name, path)| match name {
            "PROVIDER_EXECUTABLE" => (name, stored.copy.clone()),
            _ => (name, path),
        })
        .collect();
    let bindings: Vec<(&str, &Path)> = bound
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut provider =
        ConfinedProvider::start_under(Path::new(PROFILE_PATH), &bindings, &stored.copy);
    let init = provider.init(&stored.base);
    assert_eq!(
        init["status"], "ok",
        "the bound copy must answer init: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the bound copy must answer status: {status}"
    );
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
/// Falsifier: use a fixed `Operation not permitted` instead of the child's
/// standard error in `unanswered` (WP42); the denied start's failure names no
/// `execvp()` denial, so this test fails on that assertion at the first case.
#[test]
fn startup_denial_reports_its_reason() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile = resolved(profile_root.path()).join("deny-all.sb");
    fs::write(&profile, "(version 1)\n(deny default)\n").expect("fixture profile must be writable");
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });

    // The denied provider exits before it reads the request, so the harness
    // cannot write it. It reports the exit status and the sandbox denial.
    let canonical = canonical_bindings(&base);
    create_shared_ancestors(&canonical);
    let bindings: Vec<(&str, &Path)> = canonical
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut denied = ConfinedProvider::start_under(&profile, &bindings, Path::new(PROVIDER_BINARY));
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

/// The harness drains standard error while the child runs.
///
/// The fixture writes 128 KiB, more than the pipe buffer, to standard error and
/// exits with status 7. The harness must reach that status within its bounded
/// deadline and collect every byte.
///
/// Falsifier: start reading only after `wait_for_exit` has returned (WP41);
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
/// (WP43); the answer loses its parse error and says the provider did not
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
    let request = json!({ "op": "status" });
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

/// Whether `form` is a top-level allow rule that grants `process-exec`: one of
/// its operation names, the bare tokens directly inside the allow form before
/// or after a nested filter or a string, is `process*` or starts with
/// `process-exec`, and each of those grants it. An allow form may write its
/// first filter directly after `allow`. A token inside a nested filter is that
/// filter's argument and a token inside a string is text, so neither names an
/// operation. `profile_characters` is the one string reader, so an escaped
/// quote or parenthesis reads here as `profile_forms` reads it. This is the one
/// copy of the rule, used by the shared file-profile contract check (P10).
fn is_exec_allow(form: &str) -> bool {
    let Some(rest) = form.strip_prefix("(allow") else {
        return false;
    };
    if !rest.starts_with([' ', '(']) {
        return false;
    }
    let mut operations: Vec<String> = Vec::new();
    let mut operation = String::new();
    let mut depth = 0usize;
    for (ch, in_string) in profile_characters(rest) {
        if in_string {
            flush_operation(&mut operation, depth, &mut operations);
            continue;
        }
        match ch {
            '(' | ')' => {
                flush_operation(&mut operation, depth, &mut operations);
                depth = if ch == '(' {
                    depth + 1
                } else {
                    depth.saturating_sub(1)
                };
            }
            _ if ch.is_whitespace() => {
                flush_operation(&mut operation, depth, &mut operations);
            }
            _ => operation.push(ch),
        }
    }
    flush_operation(&mut operation, depth, &mut operations);
    operations
        .iter()
        .any(|operation| operation == "process*" || operation.starts_with("process-exec"))
}

/// Records one finished operation token when it sits directly inside the allow
/// form, and drops it when it sits inside a nested filter.
fn flush_operation(operation: &mut String, depth: usize, operations: &mut Vec<String>) {
    if depth == 0 && !operation.is_empty() {
        operations.push(std::mem::take(operation));
    } else {
        operation.clear();
    }
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
/// The three head forms every file profile starts with, in profile order.
const PROFILE_HEAD: [&str; 3] = ["(version 1)", "(deny default)", "(deny network*)"];
/// The right ids the shared contract names. A declared-rights file may claim
/// only these.
const CONTRACT_RIGHTS: [&str; 2] = ["storage", "bound-executable"];
/// The two allow forms did and wallet hold for startup: the provider reads the
/// root directory to resolve its own path, and reads kernel facts before the
/// protocol starts.
const STARTUP_RULES: [&str; 2] = [
    r#"(allow file-read* (literal "/"))"#,
    r#"(allow sysctl-read)"#,
];
/// The platform-baseline ids the shared contract names. A declared-rights file
/// may claim only these under its platform baseline; they are the Runtime
/// platform baseline for the provider executable on macOS, not approved rights.
const PLATFORM_BASELINE_IDS: [&str; 2] = ["startup-root-directory", "startup-sysctl"];
/// The one id the shared contract names for each pinned allow rule: the three
/// shared rules and the two startup forms. A shared rule must be claimed by its
/// id, and a startup form must be claimed by its id whenever the profile holds
/// it. The model profile's root read, `(allow file-read-data (literal "/"))`,
/// is a different form and stays out of the table.
const PINNED_RULES: &[(&str, &str)] = &[
    (SHARED_RULES[0], "bound-executable"),
    (SHARED_RULES[1], "storage"),
    (SHARED_RULES[2], "storage"),
    (STARTUP_RULES[0], "startup-root-directory"),
    (STARTUP_RULES[1], "startup-sysctl"),
];
/// The sentence a declared-rights file gives for its own role.
const DECLARED_RIGHTS_ROLE: &str =
    "lab stand-in for the Runtime generator's input, not a manifest field";
/// The one key a declared-rights file holds its platform baseline under.
const PLATFORM_BASELINE: &str = "platform_baseline";
/// The status sentence a declared-rights file gives its platform baseline for
/// `name`, the provider executable the Runtime binds on macOS.
fn platform_baseline_status(name: &str) -> String {
    format!("Runtime platform baseline for the {name} executable on macOS, not approved rights")
}
/// The prefix every platform-baseline justification starts with, naming the
/// provider executable the Runtime binds as PROVIDER_EXECUTABLE.
fn platform_baseline_justification(name: &str) -> String {
    format!("macOS {name} executable bound as PROVIDER_EXECUTABLE: ")
}
/// The file profiles the one contract check requires. Every one of them must
/// present the contract, in this order.
const FILE_PROFILES: [&str; 3] = ["did-provider", "wallet-provider", "model-provider"];

/// The one file-profile contract every file profile declares: `(version 1)`
/// first, `(deny default)` second, an explicit `(deny network*)`, no
/// `(allow default)`, no network allow, exactly one `process-exec` allow (the
/// shared exec rule), only the canonical parameter tokens, and the three
/// shared rules verbatim. The profile the Runtime generates must
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
    let mut exec_allows = Vec::new();
    for form in &forms {
        if is_default_allow(form) {
            return Err(format!("{name} must reject (allow default): {form}"));
        }
        if is_network_allow(form) {
            return Err(format!(
                "{name} must not grant network access; a network allow is refused: {form}"
            ));
        }
        if is_exec_allow(form) {
            exec_allows.push(form.as_str());
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
    if exec_allows.len() > 1 {
        let shared = exec_allows.iter().position(|form| *form == SHARED_RULES[0]);
        let quoted = exec_allows
            .iter()
            .enumerate()
            .filter(|(index, _)| Some(*index) != shared)
            .map(|(_, form)| format!("`{form}`"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "{name} holds more than one process-exec allow, so it has a second exec path (P10); \
             the extra rules are {quoted}"
        ));
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

/// One declared entry of a declared-rights file: its id and the allow rules it
/// claims.
#[derive(Debug)]
struct DeclaredClaim {
    id: String,
    rules: Vec<String>,
}

/// The one declared-rights check for the did and wallet profiles: every
/// top-level allow form of `profile` traces to exactly one right the shared
/// contract names or to one platform-baseline rule, every declared rule is
/// exactly one allow form of that profile, no id or rule is declared twice, and
/// every platform-baseline entry gives a justification that starts with its
/// provider's executable prefix.
///
/// The check reads no file. It refuses, in this order: a document without the
/// role, provider, rights list or platform baseline; a platform baseline
/// without its own status sentence; a platform baseline without its rules
/// list; an entry of the declared rights list or the platform-baseline rules
/// list without a string id, whose reason names that list and the entry; an
/// entry without a rules list; a rule that is not a string; an id the shared
/// contract does not name; a platform-baseline entry without a justification
/// that starts with the provider's prefix and gives a reason; an entry with no
/// rules; an id declared more than once; a rule repeated inside one entry; an
/// allow form the profile holds more than once; an allow form with no claimant
/// or with more than one; a declared rule that is not exactly one allow form;
/// and a rule the pin table names for one id that the file claims for another.
/// The pin table holds the three shared rules and the two startup forms: a
/// shared rule must be claimed by its id, and a startup form must be claimed by
/// its id whenever the profile holds it. Each refusal starts with the provider
/// name and quotes the rule or names the id (P11).
fn check_declared_rights(name: &str, profile: &str, declared: &Value) -> Result<(), String> {
    let (rights, baseline) = declared_entries(name, declared)?;
    let claims: Vec<&DeclaredClaim> = rights.iter().chain(baseline.iter()).collect();
    for claim in &claims {
        if claim.rules.is_empty() {
            return Err(format!("{name} declares {} with no rules", claim.id));
        }
    }
    for (index, claim) in claims.iter().enumerate() {
        if claims[..index].iter().any(|earlier| earlier.id == claim.id) {
            return Err(format!("{name} declares {} more than once", claim.id));
        }
    }
    for claim in &claims {
        for (index, rule) in claim.rules.iter().enumerate() {
            if claim.rules[..index].contains(rule) {
                return Err(format!(
                    "{name} declares {} with the rule {rule} more than once",
                    claim.id
                ));
            }
        }
    }
    let forms = allow_forms(profile);
    for (index, form) in forms.iter().enumerate() {
        if forms[..index].contains(form) {
            return Err(format!(
                "{name} profile holds the allow rule {form} more than once"
            ));
        }
    }
    for form in &forms {
        let claimants: Vec<&str> = claims
            .iter()
            .filter(|claim| claim.rules.iter().any(|rule| rule == form))
            .map(|claim| claim.id.as_str())
            .collect();
        match claimants.len() {
            0 => {
                return Err(format!(
                    "{name} allow rule has no declared right and no platform-baseline rule: {form}"
                ))
            }
            1 => {}
            _ => {
                return Err(format!(
                    "{name} allow rule is claimed more than once: {form} ({})",
                    claimants.join(", ")
                ))
            }
        }
    }
    for claim in &claims {
        for rule in &claim.rules {
            if forms.iter().filter(|form| *form == rule).count() != 1 {
                return Err(format!(
                    "{name} declared rule is not an allow rule of its profile: {rule}"
                ));
            }
        }
    }
    for &(rule, expected) in PINNED_RULES {
        // A startup form is pinned only when the profile holds it; the model
        // profile reads the root directory with its own form.
        if !forms.iter().any(|form| form == rule) && !SHARED_RULES.contains(&rule) {
            continue;
        }
        let claimant = claims
            .iter()
            .find(|claim| claim.rules.iter().any(|candidate| candidate == rule))
            .map(|claim| claim.id.as_str());
        if claimant != Some(expected) {
            return Err(format!("{name} rule {rule} must be claimed by {expected}"));
        }
    }
    Ok(())
}

/// The rights claims and the platform-baseline claims of `declared`, each
/// proven to hold an id the shared contract names and a rules list of strings,
/// and each platform-baseline entry proven to give a justification that starts
/// with the provider's executable prefix and a reason after it.
///
/// The one declared-rights check and the one lab generator both read the
/// declared entries through this function (P10). It refuses, in this order: a
/// document without the role, provider, rights list or platform baseline; a
/// platform baseline without its own status sentence; a platform baseline
/// without its rules list; an entry of the declared rights list or the
/// platform-baseline rules list without a string id, whose reason names that
/// list and the entry; an entry without a rules list; a rule that is not a
/// string; an id the shared contract does not name; and a platform-baseline
/// entry without a justification that starts with the provider's prefix and
/// gives a reason. Each refusal starts with the provider name and quotes the
/// rule or names the id (P11).
fn declared_entries(
    name: &str,
    declared: &Value,
) -> Result<(Vec<DeclaredClaim>, Vec<DeclaredClaim>), String> {
    if declared["role"].as_str() != Some(DECLARED_RIGHTS_ROLE) {
        return Err(format!(
            "{name} declared-rights file must give the role {DECLARED_RIGHTS_ROLE:?}"
        ));
    }
    if declared["provider"].as_str() != Some(name) {
        return Err(format!(
            "{name} declared-rights file must name the provider {name}"
        ));
    }
    let Some(rights) = declared["rights"].as_array() else {
        return Err(format!(
            "{name} declared-rights file must hold a rights list"
        ));
    };
    let Some(baseline) = declared[PLATFORM_BASELINE].as_object() else {
        return Err(format!(
            "{name} declared-rights file must hold a platform baseline"
        ));
    };
    let status = platform_baseline_status(name);
    if baseline.get("status").and_then(Value::as_str) != Some(status.as_str()) {
        return Err(format!(
            "{name} platform baseline must give the status {status:?}"
        ));
    }
    let Some(baseline_rules) = baseline.get("rules").and_then(Value::as_array) else {
        return Err(format!("{name} platform baseline must hold a rules list"));
    };
    let rights = declared_claims(name, "declared rights list", rights)?;
    let baseline = declared_claims(name, "platform baseline rules", baseline_rules)?;
    for claim in &rights {
        if !CONTRACT_RIGHTS.contains(&claim.id.as_str()) {
            return Err(format!(
                "{name} declares {}, which the shared contract does not name",
                claim.id
            ));
        }
    }
    for claim in &baseline {
        if !PLATFORM_BASELINE_IDS.contains(&claim.id.as_str()) {
            return Err(format!(
                "{name} declares {}, which the shared contract does not name",
                claim.id
            ));
        }
    }
    let prefix = platform_baseline_justification(name);
    for (entry, claim) in baseline_rules.iter().zip(&baseline) {
        let Some(justification) = entry["justification"].as_str() else {
            return Err(format!(
                "{name} platform baseline {} must give a string justification",
                claim.id
            ));
        };
        if !justification.starts_with(&prefix) {
            return Err(format!(
                "{name} platform baseline {} justification must start with {prefix:?}",
                claim.id
            ));
        }
        if justification[prefix.len()..].trim().is_empty() {
            return Err(format!(
                "{name} platform baseline {} justification gives no reason after {prefix:?}",
                claim.id
            ));
        }
    }
    Ok((rights, baseline))
}

/// The one lab generator for a file profile: the contract head, then every
/// rule of every rights claim in file order, then every rule of every
/// platform-baseline claim in file order, one form per line. It emits no
/// comment and nothing else, it reads and writes no file, and it refuses an id
/// the shared contract does not name through `declared_entries`.
fn generate_profile(name: &str, declared: &Value) -> Result<String, String> {
    let (rights, baseline) = declared_entries(name, declared)?;
    let mut profile = String::new();
    for form in PROFILE_HEAD {
        profile.push_str(form);
        profile.push('\n');
    }
    for claim in rights.iter().chain(&baseline) {
        for rule in &claim.rules {
            profile.push_str(rule);
            profile.push('\n');
        }
    }
    Ok(profile)
}

/// The one lab writer of a generated profile: it calls `generate_profile`
/// first and returns that refusal unchanged, before it creates, opens or
/// truncates `path`; only a generated profile is written, and a write failure
/// is a refusal that names the provider and the path. It adds no validation of
/// its own: every refusal reason comes from `declared_entries`.
fn write_generated_profile(name: &str, declared: &Value, path: &Path) -> Result<(), String> {
    let profile = generate_profile(name, declared)?;
    fs::write(path, profile).map_err(|err| {
        format!(
            "{name} generated profile {} must be writable: {err}",
            path.display()
        )
    })
}

/// The declared entries of `entries`, each proven to hold a string id and a
/// rules list of strings. `label` names the list in the missing-id refusal, so
/// the reader knows which of the two lists holds the entry; the index names
/// the entry. The two other refusals name the id.
fn declared_claims(
    name: &str,
    label: &str,
    entries: &[Value],
) -> Result<Vec<DeclaredClaim>, String> {
    let mut claims = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let Some(id) = entry["id"].as_str() else {
            return Err(format!(
                "{name} {label} entry {index} must give a string id"
            ));
        };
        let Some(rules) = entry["rules"].as_array() else {
            return Err(format!("{name} declares {id} without a rules list"));
        };
        let mut claimed = Vec::with_capacity(rules.len());
        for rule in rules {
            let Some(rule) = rule.as_str() else {
                return Err(format!(
                    "{name} declares {id} with a rule that is not a string"
                ));
            };
            claimed.push(rule.to_owned());
        }
        claims.push(DeclaredClaim {
            id: id.to_owned(),
            rules: claimed,
        });
    }
    Ok(claims)
}

/// Reads one provider's declared-rights file. A missing, unreadable or invalid
/// file is a refusal that names the path; there is no skip path.
fn read_declared_rights(name: &str, path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "{name} declared-rights file {} must be readable: {err}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map_err(|err| {
        format!(
            "{name} declared-rights file {} must be valid JSON: {err}",
            path.display()
        )
    })
}

/// Selects the removal check's profiles from the one file-profile list. The
/// model profile has its own removals in
/// `capsules/model-provider/confine-falsifiers.json` under that lane's bar.
fn allow_rule_profiles() -> impl Iterator<Item = &'static str> {
    FILE_PROFILES
        .into_iter()
        .filter(|name| *name != "model-provider")
}

/// The real profiles the removal check reads and the parsed entries of their
/// two lists. The entries are one list because wallet's list records the did
/// profile's `STORAGE_PARENT` removal (WP11).
#[derive(Debug)]
struct AllowRuleSources {
    profiles: Vec<(&'static str, String)>,
    entries: Vec<Value>,
}

/// One provider's falsifier list and its registered ids, in list order.
#[derive(Debug)]
struct FalsifierList {
    name: &'static str,
    ids: Vec<String>,
    entries: Vec<Value>,
}

/// Reads every `capsules/<name>/falsifiers.json` list selected by
/// `allow_rule_profiles` and returns each list's entries and ids.
///
/// A missing or unreadable list, a list that is not JSON, a document
/// without a `falsifiers` list and an entry whose `id` is missing or is not a
/// JSON string are refusals with distinct reasons that name the path; the
/// entry refusal also names the entry's position in the list. There is no
/// skip path. Both checks read the lists through this one function (P10).
fn read_falsifier_lists(capsules: &Path) -> Result<Vec<FalsifierList>, String> {
    let mut lists = Vec::new();
    for name in allow_rule_profiles() {
        let path = capsules.join(name).join("falsifiers.json");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                return Err(format!(
                    "{name} falsifier list {} must be readable: {err}",
                    path.display()
                ))
            }
        };
        let doc: Value = match serde_json::from_str(&text) {
            Ok(doc) => doc,
            Err(err) => {
                return Err(format!(
                    "{name} falsifier list {} must be valid JSON: {err}",
                    path.display()
                ))
            }
        };
        let Some(list) = doc.get("falsifiers").and_then(Value::as_array) else {
            return Err(format!(
                "{name} falsifier list {} must hold a falsifiers list",
                path.display()
            ));
        };
        let entries: Vec<Value> = list.iter().cloned().collect();
        let mut ids = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let Some(id) = entry["id"].as_str() else {
                return Err(format!(
                    "{name} falsifier list {} must give entry {index} a string id",
                    path.display()
                ));
            };
            ids.push(id.to_owned());
        }
        lists.push(FalsifierList { name, ids, entries });
    }
    Ok(lists)
}

/// Reads `capsules/<name>/confine.sb` and `capsules/<name>/falsifiers.json`
/// for the profiles selected by `allow_rule_profiles`.
///
/// A missing or unreadable profile, a profile that does not parse, a missing
/// or unreadable list, a list that is not JSON, a document without a
/// `falsifiers` list and an entry without a string id are refusals with
/// distinct reasons that name the path. There is no skip path.
fn read_allow_rule_sources(capsules: &Path) -> Result<AllowRuleSources, String> {
    let mut profiles = Vec::new();
    for name in allow_rule_profiles() {
        let path = capsules.join(name).join("confine.sb");
        profiles.push((name, read_allow_rule_profile(name, &path)?));
    }
    let entries = read_falsifier_lists(capsules)?
        .into_iter()
        .flat_map(|list| list.entries)
        .collect();
    Ok(AllowRuleSources { profiles, entries })
}

/// Reads one profile for the removal check and proves that `profile_forms`
/// accepts it, or refuses with a reason that names the profile and its path.
/// There is no skip path.
fn read_allow_rule_profile(name: &str, path: &Path) -> Result<String, String> {
    let profile = fs::read_to_string(path).map_err(|err| {
        format!(
            "{name} allow-rule profile {} must be readable: {err}",
            path.display()
        )
    })?;
    std::panic::catch_unwind(|| profile_forms(&profile))
        .map_err(|reason| {
            let detail = reason
                .downcast_ref::<String>()
                .map(String::as_str)
                .unwrap_or("the profile does not parse");
            format!(
                "{name} allow-rule profile {} must parse: {detail}",
                path.display()
            )
        })
        .map(|_forms| profile)
}

/// The one heading line every confinement document uses for its falsifier
/// section.
const FALSIFIER_HEADING: &str = "## Falsifiers";

/// The heading line every operations table uses.
const OPERATIONS_HEADING: &str = "## Operations and the rights they need";

/// The providers whose `CONFINEMENT.md` operations table names the tests it
/// cites.
const OPERATIONS_TABLES: &[&str] = &["did-provider", "wallet-provider"];

/// Whether `character` can sit directly beside a falsifier id token.
fn falsifier_id_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// Every `DID` or `WP` id token in `text`, in the order it appears.
///
/// An id is a whole token: `DID` or `WP` followed by one or more digits, with
/// no letter, digit or `_` directly before or after it. So `DID10` does not
/// name `DID1`, and `WP45 to WP48` names only `WP45` and `WP48`.
fn falsifier_id_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for (index, _) in text.char_indices() {
        if text[..index]
            .chars()
            .next_back()
            .is_some_and(falsifier_id_character)
        {
            continue;
        }
        let rest = &text[index..];
        let prefix = if rest.starts_with("DID") {
            "DID"
        } else if rest.starts_with("WP") {
            "WP"
        } else {
            continue;
        };
        let digits_start = index + prefix.len();
        let digits = text[digits_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if digits == 0 {
            continue;
        }
        let end = digits_start + digits;
        if text[end..]
            .chars()
            .next()
            .is_some_and(falsifier_id_character)
        {
            continue;
        }
        tokens.push(&text[index..end]);
    }
    tokens
}

/// Whether `section` names `id` as a whole token.
fn names_falsifier_id(section: &str, id: &str) -> bool {
    falsifier_id_tokens(section)
        .iter()
        .any(|token| *token == id)
}

/// The section of `document` under its one `heading` line, or every problem
/// with that heading.
///
/// The document must hold exactly one line equal to `heading`. Its section runs
/// from that line to the next line that starts with `## `, or to the end of the
/// file. Each refusal names the document.
fn section_under_one_heading(
    document_name: &str,
    document: &str,
    heading: &str,
) -> Result<String, Vec<String>> {
    let lines: Vec<&str> = document.lines().collect();
    let heading_lines: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == heading)
        .map(|(index, _)| index)
        .collect();
    let Some(only) = heading_lines.first().copied() else {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md must hold one line {heading}; found none"
        )]);
    };
    if heading_lines.len() > 1 {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md must hold one line {heading}; found {}",
            heading_lines.len()
        )]);
    }
    let section_start = only + 1;
    let section_end = lines[section_start..]
        .iter()
        .position(|line| line.starts_with("## "))
        .map_or(lines.len(), |offset| section_start + offset);
    Ok(lines[section_start..section_end].join("\n"))
}

/// Every problem with one document's falsifier section, each naming the
/// document.
///
/// The document must hold exactly one line `## Falsifiers`. Its section runs
/// from that line to the next line that starts with `## `, or to the end of
/// the file. Every id of `own_ids` must be named in the section as a whole
/// token, and every id-shaped token there must appear in `registered_ids`,
/// which holds both lists' ids. An id may be named more than once.
fn falsifier_section_problems(
    document_name: &str,
    document: &str,
    own_ids: &[String],
    registered_ids: &[String],
) -> Vec<String> {
    let section = match section_under_one_heading(document_name, document, FALSIFIER_HEADING) {
        Ok(section) => section,
        Err(problems) => return problems,
    };
    let mut problems = Vec::new();
    for id in own_ids {
        if !names_falsifier_id(&section, id) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: own falsifier id {id} is not named in \
                 {FALSIFIER_HEADING}"
            ));
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for token in falsifier_id_tokens(&section) {
        if registered_ids.iter().any(|id| id == token) || seen.contains(&token) {
            continue;
        }
        seen.push(token);
        problems.push(format!(
            "{document_name} CONFINEMENT.md: {FALSIFIER_HEADING} names {token}, which neither \
             falsifier list registers"
        ));
    }
    problems
}

/// Reads `capsules/<name>/CONFINEMENT.md`, or refuses with a reason that names
/// its path. There is no skip path.
fn read_confinement_document(capsules: &Path, name: &str) -> Result<String, String> {
    let path = capsules.join(name).join("CONFINEMENT.md");
    fs::read_to_string(&path).map_err(|err| {
        format!(
            "{name} confinement document {} must be readable: {err}",
            path.display()
        )
    })
}

/// Every backtick-delimited span in `text`, in order.
fn backtick_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        spans.push(&after[..close]);
        rest = &after[close + 1..];
    }
    spans
}

/// Every problem with one operations table's test citations, each naming the
/// document and the citation.
///
/// The section under `OPERATIONS_HEADING` must cite at least one backtick span
/// that holds a file relative to `capsule_dir`, two colons and a function
/// name. A cited path must be relative and resolve beneath `capsule_dir`,
/// including through symbolic links, before its file is read. The file must
/// hold `fn <fn>(`. The check does not decide whether it is a `#[test]`.
fn operations_table_citation_problems(
    document_name: &str,
    document: &str,
    capsule_dir: &Path,
) -> Vec<String> {
    let section = match section_under_one_heading(document_name, document, OPERATIONS_HEADING) {
        Ok(section) => section,
        Err(problems) => return problems,
    };
    let provider_root = match fs::canonicalize(capsule_dir) {
        Ok(root) => root,
        Err(err) => {
            return vec![format!(
                "{document_name} CONFINEMENT.md: provider directory {} cannot be resolved: {err}",
                capsule_dir.display()
            )];
        }
    };
    let mut problems = Vec::new();
    let mut citations: Vec<&str> = Vec::new();
    for span in backtick_spans(&section) {
        let Some((file, function)) = span.split_once("::") else {
            continue;
        };
        if citations.contains(&span) {
            continue;
        }
        citations.push(span);
        if Path::new(file).is_absolute() {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} names an absolute path; \
                 cited files must be relative to the provider directory"
            ));
            continue;
        }
        let path = capsule_dir.join(file);
        let resolved = match fs::canonicalize(&path) {
            Ok(resolved) => resolved,
            Err(err) => {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {span} names a file that is not \
                     readable because its path cannot be resolved: {} ({err})",
                    path.display()
                ));
                continue;
            }
        };
        if !resolved.starts_with(&provider_root) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} resolves outside the provider directory: \
                 {} (provider directory {})",
                resolved.display(),
                provider_root.display()
            ));
            continue;
        }
        let source = match fs::read_to_string(&resolved) {
            Ok(source) => source,
            Err(err) => {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {span} names a file that is not \
                     readable: {} ({err})",
                    path.display()
                ));
                continue;
            }
        };
        if !source.contains(&format!("fn {function}(")) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} names a function that {} does not hold",
                path.display()
            ));
        }
    }
    if citations.is_empty() {
        problems.push(format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} cites no file::fn test"
        ));
    }
    problems
}

/// The top-level allow forms of `profile`, in profile order. This is the one
/// selector, used by the removal check and the declared-rights check (P10).
fn allow_forms(profile: &str) -> Vec<String> {
    profile_forms(profile)
        .into_iter()
        .filter(|form| form.starts_with("(allow "))
        .collect()
}

/// The top-level allow forms of `profile` that no `entries` item removes.
///
/// An entry removes a form only when it expects a catch and one of its edits
/// names this profile's `confine.sb` by the one runner's path rule, holds the
/// form in its `old` forms and not in its `new` forms. A form that no entry
/// removes comes back by name, so a new grant cannot enter a profile silently.
///
/// Falsifier: WP45 to WP48 drop each removal condition in turn;
/// `allow_rule_removal_check_reports_an_unremoved_rule` fails on each.
fn unremoved_allow_forms(name: &str, profile: &str, entries: &[Value]) -> Vec<String> {
    let target = runner_edit_path(&format!("../../capsules/{name}/confine.sb"));
    allow_forms(profile)
        .into_iter()
        .filter(|form| {
            !target.as_ref().is_some_and(|target| {
                entries
                    .iter()
                    .any(|entry| entry_removes(entry, target, form))
            })
        })
        .collect()
}

/// Whether one list entry removes `form`. `expect` must be `caught`, because
/// an entry that expects no catch proves nothing about a form.
fn entry_removes(entry: &Value, target: &Path, form: &str) -> bool {
    entry["expect"].as_str() == Some("caught")
        && entry["edits"]
            .as_array()
            .is_some_and(|edits| edits.iter().any(|edit| edit_removes(edit, target, form)))
}

/// Whether one edit removes `form`: its file must name the profile by the
/// runner's path rule, its `old` forms must include the form and its `new`
/// forms must not.
fn edit_removes(edit: &Value, target: &Path, form: &str) -> bool {
    let Some(file) = edit["file"].as_str() else {
        return false;
    };
    if runner_edit_path(file).as_deref() != Some(target) {
        return false;
    }
    let old = edit["old"].as_str().unwrap_or_default();
    let new = edit["new"].as_str().unwrap_or_default();
    profile_forms(old).iter().any(|candidate| candidate == form)
        && !profile_forms(new).iter().any(|candidate| candidate == form)
}

/// Uses the runner's `examples/agent-host` base and filesystem resolution.
/// Like Python's `Path`, components discard `.` and repeated separators while
/// preserving the root and `..`. The runner replaces the final directory entry,
/// so resolve its parent, retaining a final symlink's own name.
fn runner_edit_path(file: &str) -> Option<PathBuf> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/agent-host")
        .join(file)
        .components()
        .collect();
    if !path.is_file() {
        return None;
    }
    Some(path.parent()?.canonicalize().ok()?.join(path.file_name()?))
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

/// The contract fixture profile plus the two allow forms did and wallet get for
/// startup, so the declared-rights fixture can trace all five forms.
fn declared_rights_fixture_profile() -> String {
    let mut profile = contract_fixture_profile(true);
    for rule in STARTUP_RULES {
        profile.push_str(rule);
        profile.push('\n');
    }
    profile
}

/// The declared-rights fixture for `provider`: the two rights and the two
/// platform-baseline rules, each holding the allow forms of
/// `declared_rights_fixture_profile` and a justification for its provider.
fn declared_rights_fixture(provider: &str) -> Value {
    let mut fixture = json!({
        "role": DECLARED_RIGHTS_ROLE,
        "provider": provider,
        "rights": [
            {"id": "storage", "rules": [SHARED_RULES[1], SHARED_RULES[2]]},
            {"id": "bound-executable", "rules": [SHARED_RULES[0]]},
        ],
    });
    let prefix = platform_baseline_justification(provider);
    fixture[PLATFORM_BASELINE] = json!({
        "status": platform_baseline_status(provider),
        "rules": [
            {
                "id": "startup-root-directory",
                "justification": format!(
                    "{prefix}file-read* of literal / is the startup root-directory read."
                ),
                "rules": [STARTUP_RULES[0]],
            },
            {
                "id": "startup-sysctl",
                "justification": format!(
                    "{prefix}sysctl-read is the startup read of kernel facts by the loader \
                     and the allocator."
                ),
                "rules": [STARTUP_RULES[1]],
            },
        ],
    });
    fixture
}

/// Writes `declared` as
/// `capsules/<provider>/tests/fixtures/confine/declared-rights.json` under a
/// temporary directory.
fn write_declared_rights(capsules: &Path, provider: &str, declared: &Value) {
    let dir = capsules.join(provider).join("tests/fixtures/confine");
    fs::create_dir_all(&dir).expect("fixture declared-rights directory");
    fs::write(dir.join("declared-rights.json"), declared.to_string())
        .expect("fixture declared rights");
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

/// Every top-level allow rule of the did and wallet profiles traces to exactly
/// one right the shared contract names, or to one platform-baseline rule.
///
/// The check reads `capsules/did-provider/confine.sb`,
/// `capsules/wallet-provider/confine.sb` and each provider's
/// `tests/fixtures/confine/declared-rights.json`. That file is a lab stand-in
/// for the Runtime generator's input and not a manifest field; the profile
/// rules are evidence for Anders to review and not accepted rights. Each
/// profile's allow forms and each declared rule meet one to one, the shared
/// rules keep their named rights, the two startup forms are claimed by
/// `startup-root-directory` and `startup-sysctl` whenever the profile holds
/// them, no id or rule is declared twice, and each platform-baseline entry
/// gives a justification that names the provider executable the Runtime binds.
/// An unreadable profile, an unreadable or invalid declared-rights file and
/// every refusal of the one check fail the test with the provider name and the
/// rule or id. The model profile is not read here. The test reads files and
/// starts no process, so it runs on every platform.
///
/// Falsifier: WP84 appends
/// `(allow file-read* (literal "/private/var/cc-confine-unnamed"))` to the did
/// profile, and WP85 appends the same rule to the wallet profile; this test
/// fails because no declared right and no platform-baseline rule claims that
/// form. WP86 renames the one platform-baseline key the check reads; this test
/// fails because the did and wallet files no longer hold it.
#[test]
fn every_did_and_wallet_allow_rule_traces_to_one_declared_right() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    for name in allow_rule_profiles() {
        let profile_path = capsules.join(name).join("confine.sb");
        let profile =
            read_allow_rule_profile(name, &profile_path).unwrap_or_else(|err| panic!("{err}"));
        let declared_path = capsules
            .join(name)
            .join("tests/fixtures/confine/declared-rights.json");
        let declared =
            read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
        check_declared_rights(name, &profile, &declared).unwrap_or_else(|err| panic!("{err}"));
    }
}

/// The one lab generator builds each did and wallet profile from its
/// declared-rights file and the contract head, and the generated profile
/// equals that provider's committed `confine.sb`, the test oracle.
///
/// The test reads `capsules/did-provider/confine.sb` and
/// `capsules/wallet-provider/confine.sb` with `read_allow_rule_profile`, reads
/// each provider's `tests/fixtures/confine/declared-rights.json` with
/// `read_declared_rights`, then requires `check_profile_contract` and
/// `check_declared_rights` to accept the generated profile. The committed
/// profile holds only allow forms after its head, so the order of those forms
/// does not change what is granted and the test compares them as sorted
/// lists; the head keeps its order. A mismatch fails with the provider name,
/// the forms only the generated profile holds and the forms only the committed
/// one holds. The Runtime's own generator and its comparison are not built.
/// The test reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP105 makes `generate_profile` emit
/// `(allow file-read* (literal "/private/var/cc-confine-generated"))` after
/// the head; this test fails because that rule is in neither declared-rights
/// file. WP109 makes `generate_profile` emit
/// `(deny file-write* (literal "/private/var/cc-confine-generated"))` after the
/// declared rules; this test fails only at the sorted-tail comparison, because
/// the head keeps its order and neither contract check reads a deny form.
#[test]
fn generated_did_and_wallet_profiles_match_their_committed_oracles() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    for name in allow_rule_profiles() {
        let profile_path = capsules.join(name).join("confine.sb");
        let committed =
            read_allow_rule_profile(name, &profile_path).unwrap_or_else(|err| panic!("{err}"));
        let declared_path = capsules
            .join(name)
            .join("tests/fixtures/confine/declared-rights.json");
        let declared =
            read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
        let generated = generate_profile(name, &declared).unwrap_or_else(|err| panic!("{err}"));
        check_profile_contract(name, &generated).unwrap_or_else(|err| panic!("{err}"));
        check_declared_rights(name, &generated, &declared).unwrap_or_else(|err| panic!("{err}"));
        let generated_forms = profile_forms(&generated);
        let committed_forms = profile_forms(&committed);
        let head = |forms: &[String]| {
            forms
                .iter()
                .take(PROFILE_HEAD.len())
                .map(String::as_str)
                .eq(PROFILE_HEAD)
        };
        assert!(
            head(&generated_forms),
            "{name} generated profile must start with {PROFILE_HEAD:?}: {generated}"
        );
        assert!(
            head(&committed_forms),
            "{name} committed profile must start with {PROFILE_HEAD:?}: {committed}"
        );
        let mut generated_rest: Vec<String> = generated_forms
            .iter()
            .skip(PROFILE_HEAD.len())
            .cloned()
            .collect();
        let mut committed_rest: Vec<String> = committed_forms
            .iter()
            .skip(PROFILE_HEAD.len())
            .cloned()
            .collect();
        generated_rest.sort();
        committed_rest.sort();
        if generated_rest != committed_rest {
            let only_generated: Vec<&String> = generated_rest
                .iter()
                .filter(|form| !committed_rest.contains(form))
                .collect();
            let only_committed: Vec<&String> = committed_rest
                .iter()
                .filter(|form| !generated_rest.contains(form))
                .collect();
            panic!(
                "{name} generated profile differs from its committed oracle: only in generated \
                 {only_generated:?}, only in committed {only_committed:?}"
            );
        }
    }
}

/// The model provider's declared-rights file uses the same template as did and
/// wallet, and the one check reads it unchanged.
///
/// The test reads `capsules/model-provider/confine.sb` with
/// `read_allow_rule_profile` and the model's
/// `tests/fixtures/confine/declared-rights.json` with `read_declared_rights`,
/// then requires `check_declared_rights("model-provider", ...)` to return
/// `Ok`. A missing profile or declared-rights file fails with its path, as the
/// contract check fails on a missing model profile. `allow_rule_profiles()`
/// stays did and wallet, so the removal and trace checks do not read the model
/// pair. The test reads files and starts no process, so it runs on every
/// platform.
///
/// Falsifier: WP86 renames the one platform-baseline key the check reads; this
/// test fails because the model file no longer holds that key.
#[test]
fn model_declared_rights_read_on_the_did_and_wallet_template() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let name = "model-provider";
    let profile_path = capsules.join(name).join("confine.sb");
    let profile =
        read_allow_rule_profile(name, &profile_path).unwrap_or_else(|err| panic!("{err}"));
    let declared_path = capsules
        .join(name)
        .join("tests/fixtures/confine/declared-rights.json");
    let declared = read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
    check_declared_rights(name, &profile, &declared).unwrap_or_else(|err| panic!("{err}"));
}

/// The declared-rights check refuses each bad input with a reason that starts
/// with the provider name and names the rule or id.
///
/// A temporary `capsules/` directory holds the passing fixture for all three
/// required file profiles and the two platform-baseline allow forms, plus a
/// declared-rights file for each of did and wallet. The valid pair passes.
/// Then one case for each refusal, in the check's order: a file without the
/// lab role, a file that names another provider, a file without a rights list,
/// a file without a platform baseline, a platform baseline without its status
/// sentence, a platform baseline without its rules list, a right without a
/// rules list, a right with a rule that is not a string, a platform-baseline
/// entry without a string id whose reason names the platform-baseline rules
/// list and the entry, a right id and a platform-baseline id the shared
/// contract does not name, a platform-baseline entry with no justification, an
/// entry whose justification names another provider or gives no reason, an
/// entry with no rules, an id declared twice in the rights list, a rule
/// repeated inside one entry, an allow form the profile holds twice, an allow
/// form with no claimant and one with two claimants, a declared rule that is
/// not an allow form, a shared rule claimed by the wrong id, the two startup
/// rules swapped between their ids, the startup root read claimed by
/// `storage`, and the startup sysctl read claimed by `storage` while its
/// platform-baseline entry is removed. The fixtures are built in the test and
/// no process starts.
///
/// Falsifier: WP87 drops the justification refusal, so this test fails on its
/// missing-justification case. WP93 drops the prefix refusal, so the
/// justification that names another provider passes, and WP94 drops the
/// empty-reason refusal, so the bare prefix passes. WP95 drops the role
/// refusal, WP96 the provider refusal and WP97 the status refusal, so each
/// wrong value passes and the matching case finds no refusal. WP89 drops the
/// pin table's two startup rows, so the swap and moved-root-read cases pass.
/// WP90 drops the repeated-id refusal, WP91 the repeated-rule refusal, and
/// WP92 the duplicate-form refusal, so the profile that holds
/// `(allow sysctl-read)` twice reads "declared rule is not an allow rule of
/// its profile". WP98 drops the missing rights-list refusal, WP99 the missing
/// platform-baseline refusal and WP100 the missing baseline rules-list
/// refusal, each replaced with an empty value, so the check goes on and
/// refuses later with other words, and the case finds no refusal in its own
/// words. WP101 replaces the missing-id refusal with an empty id, so the
/// platform-baseline entry case reads the unnamed-id refusal instead. WP102
/// replaces the missing-rules-list refusal with an empty list, so the right
/// without its rules list reads "with no rules". WP103 skips a rule that is
/// not a string, so the right with a non-string rule passes the check. WP104
/// drops only the pin table's `startup-sysctl` row, so the sysctl read claimed
/// by `storage` passes.
#[test]
fn declared_rights_trace_refuses_each_bad_input() {
    let capsules = contract_fixture_capsules();
    let profile = declared_rights_fixture_profile();
    for name in allow_rule_profiles() {
        write_fixture_profile(capsules.path(), name, &profile);
        write_declared_rights(capsules.path(), name, &declared_rights_fixture(name));
    }
    let name = "did-provider";
    let declared_path = capsules
        .path()
        .join(name)
        .join("tests/fixtures/confine/declared-rights.json");
    let read = || {
        read_declared_rights(name, &declared_path)
            .expect("the fixture declared-rights file must be readable JSON")
    };
    check_declared_rights(name, &profile, &read()).expect("the full fixture must pass");

    let refuse = |declared: &Value, profile: &str| {
        let reason = check_declared_rights(name, profile, declared)
            .expect_err("a bad declared-rights input must be refused");
        assert!(
            reason.starts_with(name),
            "the refusal must start with the provider name: {reason}"
        );
        reason
    };

    let mut declared = read();
    declared["role"] = json!("approved rights");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must give the role"),
        "a declared-rights file without the lab role must be refused by its role: {reason}"
    );

    let mut declared = read();
    declared["provider"] = json!("wallet-provider");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must name the provider did-provider"),
        "a declared-rights file that names another provider must be refused by its provider: {reason}"
    );

    let mut declared = read();
    declared
        .as_object_mut()
        .expect("fixture declared rights")
        .remove("rights");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must hold a rights list"),
        "a declared-rights file without a rights list must be refused by its rights: {reason}"
    );

    let mut declared = read();
    declared
        .as_object_mut()
        .expect("fixture declared rights")
        .remove(PLATFORM_BASELINE);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must hold a platform baseline"),
        "a declared-rights file without a platform baseline must be refused by its baseline: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["status"] =
        json!(platform_baseline_status(name).replace(", not approved rights", ""));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must give the status"),
        "a platform baseline without its status sentence must be refused by its status: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]
        .as_object_mut()
        .expect("fixture platform baseline")
        .remove("rules");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("platform baseline must hold a rules list"),
        "a platform baseline without a rules list must be refused by its rules: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]
        .as_object_mut()
        .expect("fixture storage right")
        .remove("rules");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("without a rules list"),
        "a right without a rules list must be refused by id and words: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([SHARED_RULES[1], 42, SHARED_RULES[2]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("not a string"),
        "a right with a rule that is not a string must be refused by id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][1]
        .as_object_mut()
        .expect("fixture platform-baseline entry")
        .remove("id");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("platform baseline rules")
            && reason.contains("entry 1")
            && reason.contains("string id"),
        "a platform-baseline entry without a string id must name the list and the entry: {reason}"
    );

    let mut declared = read();
    declared["rights"]
        .as_array_mut()
        .expect("fixture rights")
        .push(json!({"id": "network", "rules": [SHARED_RULES[1]]}));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("network") && reason.contains("does not name"),
        "an unnamed right id must be refused by name: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .push(json!({"id": "startup-clock", "rules": ["(allow sysctl-read)"]}));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("startup-clock") && reason.contains("does not name"),
        "an unnamed platform-baseline id must be refused by name: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]
        .as_object_mut()
        .expect("fixture platform-baseline entry")
        .remove("justification");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("startup-root-directory") && reason.contains("justification"),
        "a platform-baseline entry without a justification must be refused by id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["justification"] = json!(format!(
        "{}the kernel resolves every absolute path through the root directory.",
        platform_baseline_justification("wallet-provider")
    ));
    let reason = check_declared_rights(name, &profile, &declared).expect_err(
        "a justification that starts with another provider's executable prefix must be refused",
    );
    assert!(
        reason.starts_with(name)
            && reason.contains("startup-root-directory")
            && reason.contains("must start with")
            && !reason.contains("gives no reason after"),
        "a justification with another provider's prefix must be refused by its prefix: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["justification"] =
        json!(platform_baseline_justification("did-provider"));
    let reason = check_declared_rights(name, &profile, &declared)
        .expect_err("a justification that gives no reason must be refused");
    assert!(
        reason.starts_with(name)
            && reason.contains("startup-root-directory")
            && reason.contains("gives no reason after")
            && !reason.contains("must start with"),
        "a platform-baseline justification without a reason must be refused as giving \
         no reason: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("no rules"),
        "an entry with no rules must be refused by id: {reason}"
    );

    let mut declared = read();
    declared["rights"] = json!([
        {"id": "storage", "rules": [SHARED_RULES[1]]},
        {"id": "storage", "rules": [SHARED_RULES[2]]},
        {"id": "bound-executable", "rules": [SHARED_RULES[0]]},
    ]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("more than once"),
        "an id declared twice in the rights list must be refused by id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(SHARED_RULES[1]));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage")
            && reason.contains(SHARED_RULES[1])
            && reason.contains("more than once"),
        "a rule repeated inside one entry must be refused by id and rule: {reason}"
    );

    let mut duplicated = profile.clone();
    duplicated.push_str(STARTUP_RULES[1]);
    duplicated.push('\n');
    let reason = refuse(&read(), &duplicated);
    assert!(
        reason.contains(STARTUP_RULES[1])
            && reason.contains("profile holds the allow rule")
            && reason.contains("more than once"),
        "an allow form the profile holds twice must be refused with its rule: {reason}"
    );

    let mut widened = profile.clone();
    widened.push_str("(allow file-read* (literal \"/private/var/cc-confine-unnamed\"))\n");
    let reason = refuse(&read(), &widened);
    assert!(
        reason.contains("(allow file-read* (literal \"/private/var/cc-confine-unnamed\"))")
            && reason.contains("no declared right"),
        "an unclaimed allow form must be refused with its rule: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][1]["rules"] = json!([SHARED_RULES[1]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(SHARED_RULES[1])
            && reason.contains("storage")
            && reason.contains("startup-sysctl")
            && reason.contains("more than once"),
        "a form with two claimants must name the rule and both ids: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!("(allow file-read* (literal \"/etc\"))"));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("(allow file-read* (literal \"/etc\"))"),
        "a rule that is not an allow form must be refused with its text: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([SHARED_RULES[0]]);
    declared["rights"][1]["rules"] = json!([SHARED_RULES[1], SHARED_RULES[2]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(SHARED_RULES[0]) && reason.contains("bound-executable"),
        "a shared rule claimed by the wrong id must name the rule and the id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["rules"] = json!([STARTUP_RULES[1]]);
    declared[PLATFORM_BASELINE]["rules"][1]["rules"] = json!([STARTUP_RULES[0]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[0])
            && reason.contains("startup-root-directory")
            && reason.contains("must be claimed by"),
        "the two startup rules swapped between their ids must be refused by rule and id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(STARTUP_RULES[0]));
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .remove(0);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[0])
            && reason.contains("startup-root-directory")
            && reason.contains("must be claimed by"),
        "the startup root read moved under storage must be refused by rule and id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(STARTUP_RULES[1]));
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .remove(1);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[1])
            && reason.contains("startup-sysctl")
            && reason.contains("must be claimed by"),
        "the startup sysctl read moved under storage must be refused by rule and id: {reason}"
    );
}

/// Every top-level allow rule of the did and wallet profiles has a registered
/// removal falsifier in one of their two lists.
///
/// The check reads `capsules/did-provider/confine.sb`,
/// `capsules/wallet-provider/confine.sb` and those two providers'
/// `falsifiers.json`. A form that no entry removes fails the test with its
/// profile name and asks for a registered removal falsifier or deletion. An
/// unreadable or unparsable source fails with its path; there is no skip path.
/// The model profile is not read, because
/// `capsules/model-provider/confine-falsifiers.json` holds its own bar. The
/// test reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP44 appends `(allow file-read* (literal "/etc"))` to the did
/// profile; this test fails on that form. WP49 to WP53 make each source
/// refusal a skip, so `allow_rule_removal_check_rejects_bad_inputs` fails.
#[test]
fn every_did_and_wallet_allow_rule_has_a_registered_removal() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let sources = read_allow_rule_sources(capsules).unwrap_or_else(|err| panic!("{err}"));
    for (name, profile) in &sources.profiles {
        let unremoved = unremoved_allow_forms(name, profile, &sources.entries);
        assert!(
            unremoved.is_empty(),
            "{name}: every top-level allow rule must get a registered removal \
             falsifier or be deleted; no entry removes: {unremoved:?}"
        );
    }
}

/// Every falsifier id registered for did or wallet is named in its own
/// document's `## Falsifiers` section, and neither section names an id that
/// neither list registers.
///
/// The check reads `capsules/did-provider/CONFINEMENT.md`,
/// `capsules/wallet-provider/CONFINEMENT.md` and both `falsifiers.json` lists
/// through the removal check's one list reader. A missing document or list is
/// a refusal that names its path, and there is no skip path. The test reads
/// files and starts no process, so it runs on every platform.
///
/// Before the document edits of task 061 this test failed with DID19, DID20
/// and every missing wallet id.
///
/// Falsifier: WP58 drops the own-id rule, WP59 the unregistered-id rule, WP60
/// matches an id as a substring, WP61 runs a section to the end of the file,
/// and WP62 to WP64 bypass each refusal; the fixture tests catch each one.
#[test]
fn every_falsifier_id_is_named_in_its_confinement_document() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let lists = read_falsifier_lists(capsules).unwrap_or_else(|err| panic!("{err}"));
    let registered: Vec<String> = lists
        .iter()
        .flat_map(|list| list.ids.iter().cloned())
        .collect();
    let mut problems = Vec::new();
    for list in &lists {
        let document =
            read_confinement_document(capsules, list.name).unwrap_or_else(|err| panic!("{err}"));
        problems.extend(falsifier_section_problems(
            list.name,
            &document,
            &list.ids,
            &registered,
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every test cited in an operations table exists where the table says.
///
/// The check reads `capsules/<name>/CONFINEMENT.md` for each name in
/// `OPERATIONS_TABLES`, cuts the section under `OPERATIONS_HEADING`, and
/// requires every backtick span of the form `<file>::<fn>` to name a file under
/// `capsules/<name>/` that holds `fn <fn>(`. A missing section, a section that
/// cites no test, a missing file and a missing function each fail with one
/// line. The check does not decide whether the function is a `#[test]`. The
/// test reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP78 renames `outside_write_denied` in did's `tests/confine.rs`,
/// so the did table's citation names a function that file does not hold and
/// this test fails. WP83 renames `confined_outside_write_is_denied` in this
/// provider's `tests/confine.rs`, so the wallet table's citation names a
/// function that file does not hold and this test fails.
#[test]
fn every_operations_table_cites_existing_tests() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let mut problems = Vec::new();
    for name in OPERATIONS_TABLES {
        let document =
            read_confinement_document(capsules, name).unwrap_or_else(|err| panic!("{err}"));
        problems.extend(operations_table_citation_problems(
            name,
            &document,
            &capsules.join(name),
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The removal check reports an allow form that no entry removes, and only a
/// complete removal counts.
///
/// A fixture profile of `(version 1)`, `(deny default)`, `(allow sysctl-read)`
/// and `(allow process-exec)` with one entry that removes the sysctl rule
/// returns exactly `(allow process-exec)`. An entry whose `new` still holds the
/// form, whose `expect` is not `caught`, whose edit names the other provider's
/// `confine.sb`, or whose `old` does not hold the form removes nothing. One
/// entry for each form leaves nothing. The profile and list contents are built
/// in memory; only path resolution uses the filesystem. No process starts.
///
/// Falsifier: WP45 drops the `expect` condition, WP46 the profile-path
/// condition, WP47 the `old` condition and WP48 the `new` condition; this test
/// fails on each because the bypassing entry then counts as a removal.
#[test]
fn allow_rule_removal_check_reports_an_unremoved_rule() {
    let profile = "(version 1)\n(deny default)\n(allow sysctl-read)\n(allow process-exec)\n";
    let removes_sysctl = json!({
        "id": "F01",
        "expect": "caught",
        "edits": [{
            "file": "../../capsules/did-provider/confine.sb",
            "old": "(allow sysctl-read)",
            "new": ";; Removed: sysctl-read grant.",
        }],
        "tests": ["every_did_and_wallet_allow_rule_has_a_registered_removal"],
    });
    assert_eq!(
        unremoved_allow_forms(
            "did-provider",
            profile,
            std::slice::from_ref(&removes_sysctl)
        ),
        vec!["(allow process-exec)"],
        "the one entry removes only the sysctl rule"
    );

    let removes_exec = json!({
        "id": "F02",
        "expect": "caught",
        "edits": [{
            "file": "../../capsules/did-provider/confine.sb",
            "old": "(allow process-exec)",
            "new": ";; Removed: process-exec grant.",
        }],
        "tests": ["every_did_and_wallet_allow_rule_has_a_registered_removal"],
    });
    assert!(
        unremoved_allow_forms(
            "did-provider",
            profile,
            &[removes_sysctl.clone(), removes_exec.clone()]
        )
        .is_empty(),
        "a complete removal for each rule leaves no form"
    );

    for file in [
        "../../capsules/./did-provider/../did-provider/confine.sb".to_string(),
        "../../capsules//did-provider/confine.sb/.".to_string(),
        format!("{}/../did-provider/confine.sb", env!("CARGO_MANIFEST_DIR")),
    ] {
        let mut removal = removes_exec.clone();
        removal["edits"][0]["file"] = json!(file);
        assert!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl.clone(), removal])
                .is_empty(),
            "a path that resolves to the same profile must count: {file}"
        );
    }

    let bypasses = [
        (
            "expect",
            json!({
                "id": "F03",
                "expect": "survives",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "profile path",
            json!({
                "id": "F04",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/wallet-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "old",
            json!({
                "id": "F05",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(deny default)",
                    "new": ";; Removed: default denial.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "new",
            json!({
                "id": "F06",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": "(allow process-exec)\n(allow sysctl-read)",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "absolute profile path",
            json!({
                "id": "F07",
                "expect": "caught",
                "edits": [{
                    "file": "/../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "repository-relative profile path",
            json!({
                "id": "F08",
                "expect": "caught",
                "edits": [{
                    "file": "capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "non-directory profile-path component",
            json!({
                "id": "F09",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/Cargo.toml/../confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
    ];
    for (condition, bypass) in bypasses {
        let entries = [removes_sysctl.clone(), bypass];
        assert_eq!(
            unremoved_allow_forms("did-provider", profile, &entries),
            vec!["(allow process-exec)"],
            "an entry that bypasses the {condition} condition must not remove the rule"
        );
    }

    #[cfg(unix)]
    {
        let aliases = tempfile::tempdir().expect("temporary path aliases");
        let provider_alias = aliases.path().join("provider");
        std::os::unix::fs::symlink(env!("CARGO_MANIFEST_DIR"), &provider_alias)
            .expect("create a provider directory alias");
        let mut removal = removes_exec.clone();
        removal["edits"][0]["file"] = json!(provider_alias.join("../did-provider/confine.sb"));
        assert!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl.clone(), removal])
                .is_empty(),
            "the runner resolves a parent after following its directory symlink"
        );

        let profile_alias = aliases.path().join("confine.sb");
        std::os::unix::fs::symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../did-provider/confine.sb"),
            &profile_alias,
        )
        .expect("create a profile file alias");
        let mut removal = removes_exec;
        removal["edits"][0]["file"] = json!(profile_alias);
        assert_eq!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl, removal]),
            vec!["(allow process-exec)"],
            "the runner replaces the final symlink itself, leaving the profile unchanged"
        );
    }
}

/// The one source reader refuses each bad input with its own path-bearing
/// reason.
///
/// A temporary `capsules/` directory holds one fixture profile and one fixture
/// list per required provider: the valid pair returns both profiles and the
/// combined entries. A missing profile, a profile that does not parse, a
/// missing list, a list that is not JSON, a document without a `falsifiers`
/// list, an entry without an `id` and an entry whose `id` is a number are each
/// a refusal with a distinct reason that names the offending path; an entry
/// refusal also holds the words `string id`. There is no skip path. The
/// fixtures are built in the test and no process starts.
///
/// Falsifier: WP49 turns the unreadable-profile refusal into a skip, WP53 the
/// parse refusal, WP50 the unreadable-list one, WP51 the not-JSON one, WP52
/// the missing-list one and WP66 the string-id refusal; this test fails on
/// each because the refusal does not come.
#[test]
fn allow_rule_removal_check_rejects_bad_inputs() {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let profile = "(version 1)\n(deny default)\n(allow sysctl-read)\n";
    let list = r#"{"about": "fixture", "falsifiers": []}"#;
    for name in FILE_PROFILES {
        write_fixture_profile(capsules.path(), name, profile);
        fs::write(capsules.path().join(name).join("falsifiers.json"), list)
            .expect("fixture falsifier list");
    }
    let sources = read_allow_rule_sources(capsules.path()).expect("a valid fixture pair must read");
    assert_eq!(
        sources.profiles.len(),
        FILE_PROFILES.len() - 1,
        "the reader must return both profiles"
    );
    assert_eq!(
        sources
            .profiles
            .iter()
            .map(|(name, _)| *name)
            .chain(std::iter::once("model-provider"))
            .collect::<Vec<_>>(),
        FILE_PROFILES,
        "the reader must cover the file-profile list apart from model"
    );
    assert!(
        sources.entries.is_empty(),
        "the fixture lists carry no entries"
    );

    let wallet_list = capsules
        .path()
        .join("wallet-provider")
        .join("falsifiers.json");
    let wallet_entry = json!({"id": "wallet-fixture"});
    fs::write(
        &wallet_list,
        json!({"falsifiers": [wallet_entry.clone()]}).to_string(),
    )
    .expect("write a wallet fixture entry");
    let sources =
        read_allow_rule_sources(capsules.path()).expect("the wallet fixture list must read");
    assert_eq!(
        sources.entries,
        vec![wallet_entry],
        "the reader must include the wallet list's entries"
    );
    fs::write(wallet_list, list).expect("restore the empty wallet fixture list");

    let did_profile = capsules.path().join("did-provider").join("confine.sb");
    fs::remove_file(&did_profile).expect("remove the fixture did profile");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a missing profile must be refused");
    assert!(
        refusal.contains(&did_profile.display().to_string())
            && refusal.contains("must be readable"),
        "the refusal must name the missing profile path: {refusal}"
    );
    fs::write(&did_profile, "(deny default").expect("write a malformed fixture profile");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a malformed profile must be refused");
    assert!(
        refusal.contains(&did_profile.display().to_string()) && refusal.contains("must parse"),
        "the refusal must name the malformed profile path: {refusal}"
    );
    write_fixture_profile(capsules.path(), "did-provider", profile);

    let did_list = capsules.path().join("did-provider").join("falsifiers.json");
    fs::remove_file(&did_list).expect("remove the fixture did list");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a missing list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the missing list path: {refusal}"
    );
    fs::write(&did_list, "{").expect("write a malformed fixture list");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a malformed list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string()) && refusal.contains("must be valid JSON"),
        "the refusal must name the malformed list path: {refusal}"
    );
    fs::write(&did_list, r#"{"about": "fixture"}"#).expect("write a fixture list without entries");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("a list without a falsifiers list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must hold a falsifiers list"),
        "the refusal must name the list path: {refusal}"
    );

    let missing_id = json!({"about": "fixture", "falsifiers": [{"title": "no id"}]});
    fs::write(&did_list, missing_id.to_string()).expect("write an entry without an id");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("an entry without an id must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must give entry 0 a string id"),
        "the refusal must name the list path and the missing string id: {refusal}"
    );
    let numeric_id = json!({"about": "fixture", "falsifiers": [{"id": 7}]});
    fs::write(&did_list, numeric_id.to_string()).expect("write an entry with a number id");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("an entry with a number id must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must give entry 0 a string id"),
        "the refusal must name the list path and the non-string id: {refusal}"
    );
}

/// The section check reports an own id that the section does not name and an
/// id-shaped token that neither list registers. It reports no problem when a
/// section names every id as a whole token.
///
/// The list holds `DID1`, `DID2` and `DID10`, and the section names `DID2`,
/// `DID10` and the unregistered `WP9`. `DID1` is missing even though `DID10`
/// appears, because an id counts only as a whole token. The check returns
/// exactly those two problems. A later case has a letter directly before the
/// token, `XDID1`, and another has a letter or `_` directly after its digits,
/// `DID1a` and `DID1_x`; each section names only `DID2`, so each returns
/// exactly the one problem that own id `DID1` is not named, and neither
/// reports its own token as unregistered. The fixtures are built in memory;
/// no file is read and no process starts.
///
/// Falsifier: WP58 drops the own-id rule, WP59 the unregistered-id rule and
/// WP60 matches an id as a substring; this test fails on each because the
/// corresponding problem does not come. WP67 drops the character-before check,
/// so `XDID1` then names `DID1`, and WP68 drops the character-after check, so
/// `DID1a` then names `DID1`; the test fails on the matching case because the
/// missing-id problem does not come.
#[test]
fn falsifier_section_check_reports_missing_and_stale_ids() {
    let own = vec!["DID1".to_string(), "DID2".to_string()];
    let registered = vec!["DID1".to_string(), "DID2".to_string(), "DID10".to_string()];
    let incomplete = "## Falsifiers\n\n- DID2 is named\n- DID10 is named\n- WP9 is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", incomplete, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
            "fixture-provider CONFINEMENT.md: ## Falsifiers names WP9, which neither falsifier list registers"
                .to_string(),
        ],
        "the check must report the missing own id and the unregistered id"
    );

    let prefixed = "## Falsifiers\n\n- DID2 is named\n- XDID1 is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", prefixed, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
        ],
        "a token with a letter directly before it must not name its own id"
    );

    let suffixed = "## Falsifiers\n\n- DID2 is named\n- DID1a is named\n- DID1_x is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", suffixed, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
        ],
        "a token with a letter or _ directly after its digits must not name its own id"
    );

    let complete = "## Tests\n\n- DID2 is named\n\n## Falsifiers\n\n- DID1\n- DID2\n- DID10\n";
    assert!(
        falsifier_section_problems("fixture-provider", complete, &own, &registered).is_empty(),
        "a section that names every id whole must report no problem"
    );
}

/// The section check refuses a document without its section, one with two
/// sections, and one whose id appears only after the section's next heading.
///
/// A document with no `## Falsifiers` line and one with two such lines each
/// return one problem that names the document and says how many headings were
/// found. A document whose section names `DID1` and whose `## Other` section
/// names `DID2` reports `DID2` as missing, because the section ends at the next
/// line that starts with `## `. The fixtures are built in memory; no file is
/// read and no process starts.
///
/// Falsifier: WP61 runs the section to the end of the file, WP62 bypasses the
/// missing-heading refusal and WP63 the duplicate-heading refusal; this test
/// fails on each because the expected problem does not come.
#[test]
fn falsifier_section_check_rejects_a_document_without_its_section() {
    let own = vec!["DID1".to_string(), "DID2".to_string()];
    let registered = own.clone();

    let missing = "## Tests\n\n- DID1 and DID2 are named\n";
    let problems = falsifier_section_problems("fixture-provider", missing, &own, &registered);
    assert_eq!(
        problems.len(),
        1,
        "no heading must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("found none"),
        "the reason must name the document and the missing heading: {}",
        problems[0]
    );

    let doubled = "## Falsifiers\n\n- DID1\n\n## Falsifiers\n\n- DID2\n";
    let problems = falsifier_section_problems("fixture-provider", doubled, &own, &registered);
    assert_eq!(
        problems.len(),
        1,
        "two headings must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("found 2"),
        "the reason must name the document and the heading count: {}",
        problems[0]
    );

    let later = "## Falsifiers\n\n- DID1\n\n## Other\n\n- DID2\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", later, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID2 is not named in ## Falsifiers"
                .to_string()
        ],
        "an id after the next ## heading is outside the section"
    );
}

/// The document reader refuses a missing document and a document it cannot
/// read, each with a reason that names its path, and reads a present one.
///
/// The real-document test reads through this same function, so no unreadable
/// document can become an empty one there. The fixtures are a temporary
/// directory; no process starts.
///
/// Falsifier: WP64 skips an unreadable `CONFINEMENT.md` and returns an empty
/// document; this test fails because the refusal does not come.
#[test]
fn falsifier_document_read_rejects_unreadable_source() {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let provider = capsules.path().join("did-provider");
    let path = provider.join("CONFINEMENT.md");
    let refusal = read_confinement_document(capsules.path(), "did-provider")
        .expect_err("a missing document must be refused");
    assert!(
        refusal.contains(&path.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the document path: {refusal}"
    );

    fs::create_dir_all(&provider).expect("fixture provider directory");
    fs::write(&path, "## Falsifiers\n").expect("fixture document");
    assert_eq!(
        read_confinement_document(capsules.path(), "did-provider")
            .expect("a readable document must load"),
        "## Falsifiers\n",
        "the reader must return the document's text"
    );

    fs::remove_file(&path).expect("remove the fixture document");
    fs::create_dir(&path).expect("make the document path a directory");
    let refusal = read_confinement_document(capsules.path(), "did-provider")
        .expect_err("an unreadable document must be refused");
    assert!(
        refusal.contains(&path.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the unreadable path: {refusal}"
    );
}

/// The operations-table check reports one line for each missing citation kind.
///
/// A temporary provider folder holds `tests/confine.rs` with `fn present_case()`
/// and `src/main.rs` with `fn unit_case()`. A document whose section cites
/// `tests/confine.rs::present_case` returns no problem. A cited function the
/// file does not hold, a cited file that is absent, a document without the
/// section and a section that cites no test each return one problem that names
/// the document, the citation and the reason. The fixtures are a temporary
/// directory; no process starts.
///
/// Falsifier: WP78 renames `outside_write_denied` in did's `tests/confine.rs`,
/// so the real document's citation names a missing function; the real-document
/// test above fails on it. WP79 bypasses the unresolved-file refusal and WP80
/// bypasses the no-citation refusal; this fixture test catches both.
#[test]
fn operations_table_check_reports_each_missing_citation() {
    let capsule = tempfile::tempdir().expect("temporary provider folder");
    fs::create_dir_all(capsule.path().join("tests")).expect("fixture tests folder");
    fs::create_dir_all(capsule.path().join("src")).expect("fixture src folder");
    fs::write(
        capsule.path().join("tests/confine.rs"),
        "fn present_case() {}\n",
    )
    .expect("fixture integration test file");
    fs::write(capsule.path().join("src/main.rs"), "fn unit_case() {}\n")
        .expect("fixture unit test file");

    let present = "## Operations and the rights they need\n\n| `tests/confine.rs::present_case` |\n\n## Host-OS status\n";
    assert!(
        operations_table_citation_problems("fixture-provider", present, capsule.path()).is_empty(),
        "a citation of a present function must pass"
    );

    let missing_function = "## Operations and the rights they need\n\n| `tests/confine.rs::absent_case` |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_function, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing function must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains("tests/confine.rs::absent_case")
            && problems[0].contains("does not hold"),
        "the reason must name the document, the citation and the missing function: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec![format!(
            "fixture-provider CONFINEMENT.md: tests/confine.rs::absent_case names a function that {} does not hold",
            capsule.path().join("tests/confine.rs").display()
        )]
    );

    let missing_file = "## Operations and the rights they need\n\n| `tests/absent.rs::present_case` |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_file, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing file must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains("tests/absent.rs::present_case")
            && problems[0].contains("not readable"),
        "the reason must name the document, the citation and the missing file: {}",
        problems[0]
    );
    let absent_path = capsule.path().join("tests/absent.rs");
    let absent_error = fs::canonicalize(&absent_path).expect_err("fixture file is absent");
    assert_eq!(
        problems,
        vec![format!(
            "fixture-provider CONFINEMENT.md: tests/absent.rs::present_case names a file that is not readable because its path cannot be resolved: {} ({absent_error})",
            absent_path.display()
        )]
    );

    for file in ["tests", "tests/invalid-utf8.rs"] {
        let path = capsule.path().join(file);
        if file.ends_with(".rs") {
            fs::write(&path, [0xff]).expect("fixture invalid UTF-8 file");
        }
        let read_error = fs::read_to_string(&path).expect_err("fixture source is unreadable");
        let document = format!("{OPERATIONS_HEADING}\n\n`{file}::present_case`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, capsule.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {file}::present_case names a file that is not readable: {} ({read_error})",
                path.display()
            )]
        );
    }

    let missing_section = "## Tests\n\n- `tests/confine.rs::present_case` is cited\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_section, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing section must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains(OPERATIONS_HEADING)
            && problems[0].contains("found none"),
        "the reason must name the document and the missing heading: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec!["fixture-provider CONFINEMENT.md must hold one line ## Operations and the rights they need; found none"]
    );

    let duplicate_section = format!("{present}\n{present}");
    assert_eq!(
        operations_table_citation_problems("fixture-provider", &duplicate_section, capsule.path()),
        vec!["fixture-provider CONFINEMENT.md must hold one line ## Operations and the rights they need; found 2"]
    );

    let no_citation = "## Operations and the rights they need\n\n| init |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", no_citation, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a section without a citation must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("cites no file::fn test"),
        "the reason must name the document and the missing citation: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec!["fixture-provider CONFINEMENT.md: ## Operations and the rights they need cites no file::fn test"]
    );

    let absent_provider = capsule.path().join("absent-provider");
    let provider_error =
        fs::canonicalize(&absent_provider).expect_err("fixture provider is absent");
    assert_eq!(
        operations_table_citation_problems("fixture-provider", present, &absent_provider),
        vec![format!(
            "fixture-provider CONFINEMENT.md: provider directory {} cannot be resolved: {provider_error}",
            absent_provider.display()
        )]
    );
}

/// Citation evidence belongs to its named provider, including after resolving
/// a file link or a directory link. Absolute paths have their own refusal.
/// Every outside file holds the cited function, so accepting one loses the
/// containment refusal. A link to an inside file remains valid.
///
/// WP81 bypasses the absolute-path refusal and WP82 bypasses the resolved-path
/// containment refusal; this test catches each mutation. No process starts.
#[test]
fn operations_table_check_rejects_paths_outside_provider() {
    let capsules = tempfile::tempdir().expect("temporary capsules folder");
    let provider = capsules.path().join("fixture-provider");
    // The sibling shares the provider's string prefix but is a different path component.
    let sibling = capsules.path().join("fixture-provider-sibling");
    for dir in [&provider, &sibling] {
        fs::create_dir_all(dir.join("tests")).expect("fixture tests folder");
        fs::write(dir.join("tests/confine.rs"), "fn present_case() {}\n")
            .expect("fixture test source");
    }
    for file in [
        provider.join("tests/confine.rs"),
        sibling.join("tests/confine.rs"),
    ] {
        let span = format!("{}::present_case", file.display());
        let document = format!("{OPERATIONS_HEADING}\n\n`{span}`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, &provider),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {span} names an absolute path; cited files must be relative to the provider directory"
            )]
        );
    }

    let mut outside = vec!["../fixture-provider-sibling/tests/confine.rs"];
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(
            sibling.join("tests/confine.rs"),
            provider.join("tests/outside.rs"),
        )
        .expect("fixture file link outside the provider");
        symlink(sibling.join("tests"), provider.join("linked-tests"))
            .expect("fixture directory link outside the provider");
        outside.extend(["tests/outside.rs", "linked-tests/confine.rs"]);
        symlink("confine.rs", provider.join("tests/inside.rs"))
            .expect("fixture file link inside the provider");
        let inside = format!("{OPERATIONS_HEADING}\n\n`tests/inside.rs::present_case`\n");
        assert!(
            operations_table_citation_problems("fixture-provider", &inside, &provider).is_empty(),
            "a relative citation that resolves inside the provider must pass"
        );
        // A provider directory reached through a link has the same canonical boundary.
        let provider_alias = capsules.path().join("provider-alias");
        symlink(&provider, &provider_alias).expect("fixture provider directory link");
        assert!(
            operations_table_citation_problems("fixture-provider", &inside, &provider_alias)
                .is_empty(),
            "the provider directory and citation must use the same resolved boundary"
        );
    }
    let root = fs::canonicalize(&provider).expect("fixture provider resolves");
    let escaped = fs::canonicalize(sibling.join("tests/confine.rs"))
        .expect("fixture outside source resolves");
    for file in outside {
        let span = format!("{file}::present_case");
        let document = format!("{OPERATIONS_HEADING}\n\n`{span}`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, &provider),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {span} resolves outside the provider directory: {} (provider directory {})",
                escaped.display(),
                root.display()
            )]
        );
    }
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

/// The one contract check refuses a profile that holds a second exec allow,
/// whichever form grants it, wherever it sits, and names the profile, every
/// extra rule and the reason. A fixture profile that appends `(allow
/// process-exec (literal "/bin/sh"))` keeps its own removal for the 055 removal
/// check, and the 056 and 059 copy tests still launch and refuse copies of the
/// provider binary, because `PROVIDER_EXECUTABLE` stays the only bound binary,
/// so neither test sees a second exec path. The unfiltered forms put the
/// operation name directly before the closing parenthesis, which `profile_forms`
/// keeps attached, so the predicate must read `)` as a token boundary too.
/// An allow form may put its first filter directly after `allow`, and an
/// escaped quote or parenthesis inside a string must stay inside that string.
/// `/usr/bin/sandbox-exec` loads `(version 1)(deny default)(allow file-read*
/// (literal "/x") process-exec)` without a load error: it attempts to start
/// `/usr/bin/true`, whose exec fails with `execvp() of '/usr/bin/true' failed:
/// Operation not permitted` and exit 71. The check refuses that form either
/// way, because it does not depend on what `sandbox-exec` accepts. The
/// fixtures are built in the test; no file is read and no process starts.
///
/// Falsifiers: WP69 disables the second-exec-allow refusal in
/// `check_profile_contract`; this test fails because the `/bin/sh` fixture
/// passes. WP70 does not read `)` as a token boundary, so the unfiltered
/// `(allow process*)` form passes. WP71 quotes every exec allow after the
/// first, so the fixture with `/bin/sh` before the shared rule quotes the
/// shared rule and misses the extra one. WP72 reads only the operation names
/// before the first filter, so the after-filter `process-exec` form passes.
/// WP73 quotes only the first extra rule, so the fixture with two extras and
/// no shared rule loses the second quote. WP74 counts a token inside a nested
/// filter as an operation, so the passing `(process-exec "/x")` fixture is
/// refused. WP75 counts text inside a string as an operation, so the passing
/// `(allow "process-exec")` fixture is refused. WP76 drops the escape flag in
/// `profile_characters`, so the escaped-string fixture parses differently and
/// this test and `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
/// fail. WP77 requires `(allow ` with a space, so the flush-head form passes.
#[test]
fn file_profile_contract_rejects_a_second_exec_allow() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    for grant in [
        r#"(allow process-exec (literal "/bin/sh"))"#,
        SHARED_RULES[0],
        r#"(allow process* (literal "/bin/sh"))"#,
        r#"(allow process-exec)"#,
        r#"(allow process*)"#,
        r#"(allow file-read* process*)"#,
    ] {
        let profile = format!("{complete}{grant}\n");
        let refusal = check_profile_contract("fixture-provider", &profile)
            .expect_err("a profile with a second exec allow must fail");
        assert!(
            refusal.contains("fixture-provider")
                && refusal.contains(&format!("the extra rules are `{grant}`")),
            "the refusal must name the profile and quote the extra rule: {refusal}"
        );
        assert!(
            refusal.contains("more than one process-exec allow"),
            "the refusal must say there is more than one process-exec allow: {refusal}"
        );
        assert_generated_reason_has_no_failure(&refusal);
    }

    // The extra exec rule sits before the shared one, so a refusal that quotes
    // `exec_allows[1..]` names the shared rule and misses the extra one.
    let extra_before_shared = r#"(allow process-exec (literal "/bin/sh"))"#;
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    profile.push_str(extra_before_shared);
    profile.push('\n');
    for rule in SHARED_RULES {
        profile.push_str(rule);
        profile.push('\n');
    }
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an extra exec rule before the shared one must fail");
    assert!(
        refusal.contains(&format!("the extra rules are `{extra_before_shared}`")),
        "the refusal must quote the extra rule that sits before the shared one: {refusal}"
    );
    assert!(
        !refusal.contains(SHARED_RULES[0]),
        "the refusal must not quote the one shared exec rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // An operation name after a filter still names the allow form's operation.
    let after_filter = r#"(allow file-read* (literal "/x") process-exec)"#;
    let profile = format!("{complete}{after_filter}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation name after a filter must still be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{after_filter}`")),
        "the refusal must quote the after-filter rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // The first filter may sit directly after `allow`, so the allow head is
    // `(allow(` and the operation after the filter still counts.
    let flush_head = r#"(allow(literal "/x") process-exec)"#;
    let profile = format!("{complete}{flush_head}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation after a filter that follows allow directly must be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{flush_head}`")),
        "the refusal must quote the flush-head rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // An escaped quote and a parenthesis inside a string leave the following
    // operation outside the string, so the one string reader must keep them.
    let escaped_string = r#"(allow file-read* (literal "a\"b)") process-exec)"#;
    let profile = format!("{complete}{escaped_string}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation after an escaped string must still be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{escaped_string}`")),
        "the refusal must quote the rule after the escaped string: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // With no shared exec rule, every exec allow is an extra rule.
    let first_extra = r#"(allow process-exec (literal "/bin/sh"))"#;
    let second_extra = r#"(allow process* (literal "/bin/ksh"))"#;
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    for rule in [first_extra, second_extra, SHARED_RULES[1], SHARED_RULES[2]] {
        profile.push_str(rule);
        profile.push('\n');
    }
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile without the shared exec rule still holds two exec allows");
    assert!(
        refusal.contains(&format!(
            "the extra rules are `{first_extra}`, `{second_extra}`"
        )),
        "the refusal must quote every exec allow when none is the shared one: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // A token inside a string or a nested filter names text or a filter
    // argument, not an operation, so these profiles keep one exec allow. An
    // escaped quote stays inside its string, so the text after it is text too.
    for passing in [
        r#"(allow file-read* (literal "/process-exec"))"#,
        r#"(allow file-read* (process-exec "/x"))"#,
        r#"(allow file-read* (require-all (process*)))"#,
        r#"(allow "process-exec")"#,
        r#"(allow file-read* (literal "a\" process-exec "))"#,
    ] {
        let profile = format!("{complete}{passing}\n");
        check_profile_contract("fixture-provider", &profile)
            .expect("a token inside a string or a nested filter must not count as an operation");
    }
}

/// The part of the refusal the one check generates, before the rules it quotes.
/// The `error: ` ban covers that generated text; a quoted rule may hold any
/// path text of its own.
fn assert_generated_reason_has_no_failure(refusal: &str) {
    let generated = refusal
        .split("; the extra rules are ")
        .next()
        .unwrap_or_default();
    assert!(
        !generated.contains("error: "),
        "the generated reason must hold no failure text: {refusal}"
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
