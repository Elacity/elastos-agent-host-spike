//! Confinement proof for model-provider.
//!
//! The behaviour tests start the real provider binary under
//! `capsules/model-provider/confine.sb` with `/usr/bin/sandbox-exec` and drive
//! it over its normal stdin/stdout protocol. `sandbox-exec` reads the profile
//! from `CARGO_MANIFEST_DIR` at every launch, so an edit to `confine.sb` takes
//! effect without a rebuild.
//!
//! `Provider` is the crate's one sandboxed launcher. Its unconfined launch
//! runs the same binary with the same pipes and differs only by the profile,
//! so a control run shows what the profile stops. Its fixture launch runs a
//! test-time copy of `confine.sb` with fixture rules appended; the copy is
//! made from the one profile source, so a `confine.sb` edit reaches it too.
//! Its program launch binds one path as `PROVIDER_EXECUTABLE` and starts the
//! program it names, that path or another, under the profile path that launch
//! carries, so the profile's exec rule alone decides whether that program runs. Before
//! `spawn`, a launch that binds `PROVIDER_EXECUTABLE` records that file's
//! sha256 and refuses to start when the file no longer has that digest.
//! The profile binds PROVIDER_EXECUTABLE by path. That refusal is a lab
//! stand-in for the Runtime's launch-by-hash check, not the Runtime's check.
//! This stand-in counts toward no M1 check.
//! `Unconfined` and `Idle` do not bind the parameter. Its profile launch
//! starts the real provider binary under a given profile path with exactly
//! the bindings it is given. Its idle launch starts `/bin/sleep` on
//! the same pipes and never writes an answer, so a test can run the one
//! receive to its timeout without the provider binary.
//!
//! On a declared host OS a missing `/usr/bin/sandbox-exec` fails the test,
//! and `sandbox_available` is the call that fails it. On any other OS, when
//! `sandbox-exec` is missing, the test prints why it did not run and returns.
//! The one profile-shape check is
//! `both_file_profiles_bind_one_storage_parameter_contract` in
//! `capsules/wallet-provider/tests/confine.rs`; this target adds none.

#![cfg(unix)]

// This target uses only the temporary root helper, the request id helper, the
// event timeout, the fake engine writer and the file digest.
#[allow(dead_code)]
#[path = "../../src/test_support.rs"]
mod test_support;

use elastos_model_contract::{
    model_input_hash, model_run_id, RuntimeAccessBinding, RuntimeCreateBinding,
    RUNTIME_ACCESS_BINDING_SCHEMA, RUNTIME_CREATE_BINDING_SCHEMA, TEXT_INPUT_V1_SCHEMA,
};
use serde_json::{json, Value};
use std::any::Any;
use std::cell::RefCell;
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use test_support::FIXTURE_EVENT_TIMEOUT;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The host OSes where `CONFINEMENT.md` says the confinement tests exercise
/// these profiles through `/usr/bin/sandbox-exec`, so a test there must run,
/// not skip.
const DECLARED_CONFINED_OS: [&str; 1] = ["macos"];
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_model-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
const DECLARED_RIGHTS_FIXTURE: &str = "tests/fixtures/confine/declared-rights.json";
const HOSTED_OFFER: &str = "confine-hosted-text";

/// Whether a sandbox test runs on this host.
///
/// A present `sandbox_exec` runs the test on any OS. A missing one is an error
/// on an OS where `CONFINEMENT.md` says the confinement tests exercise these
/// profiles, because a test there must run, not skip, and a skip would pass a
/// profile that was never exercised (P11). On any other OS it is a skip.
/// `sandbox_gate` prints nothing.
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

/// Returns `true` when the confined test can run.
///
/// On `Err` from `sandbox_gate` this fails the test with that reason. It does
/// not return `false` for an error. It prints the skip line only when the gate
/// answers `Ok(false)`.
fn sandbox_available(os: &str, sandbox_exec: &Path) -> bool {
    match sandbox_gate(os, sandbox_exec) {
        Ok(true) => true,
        Ok(false) => {
            eprintln!(
                "SKIP model-provider confinement test: {} is absent; \
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
/// A missing `sandbox-exec` on `macos` is a refusal that names the OS and the
/// path, a missing one on `linux` is a skip, and a present one on `macos` runs
/// the test. The test calls `sandbox_gate`, which prints nothing, so the
/// `linux` case prints no skip line. It starts no process, so it runs on every
/// Unix host.
///
/// Falsifier: F-cc17a returns `Ok(false)` from the declared-OS branch; the
/// `macos` case fails because a missing `sandbox-exec` is no longer `Err`.
#[test]
fn sandbox_gate_fails_instead_of_skipping_on_a_declared_os() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/confine/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = Path::new(PROVIDER_BINARY);
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
        sandbox_gate("macos", present),
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
/// Falsifier: F-cc17b returns `false` from the error arm of
/// `sandbox_available`, so a missing `sandbox-exec` on macos returns and this
/// test fails.
#[test]
fn sandbox_available_fails_for_macos_when_sandbox_exec_is_missing() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/confine/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = Path::new(PROVIDER_BINARY);
    assert!(
        present.is_file(),
        "the present fixture must be a file: {}",
        present.display()
    );

    let settled =
        std::panic::catch_unwind(AssertUnwindSafe(|| sandbox_available("macos", &missing)));
    let failure = match settled {
        Err(payload) => panic_text(payload),
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
        sandbox_available("macos", present),
        "a present sandbox-exec on macos must let the confined test run"
    );
}

/// Seatbelt matches resolved paths and macOS `/var` is `/private/var`, so
/// every bound path is canonical.
fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|err| panic!("{} must resolve: {err}", path.display()))
}

/// The storage one launch binds under the shared file-profile contract.
/// `STORAGE_PARENT` exists before launch. `STORAGE_ROOT` is the model journal root,
/// `base_path/providers/model-provider`, and the provider creates it.
struct Storage {
    base: PathBuf,
    parent: PathBuf,
    root: PathBuf,
}

impl Storage {
    fn prepare(label: &str) -> Self {
        let base = test_support::temp_root_path("model-provider-confine", label);
        fs::create_dir_all(base.join("providers")).expect("prepare STORAGE_PARENT");
        let base = resolved(&base);
        let parent = base.join("providers");
        let root = parent.join("model-provider");
        Self { base, parent, root }
    }
}

/// How a test starts the provider binary.
enum Launch<'a> {
    /// Under `confine.sb`, with the contract's three parameters bound.
    Confined(&'a Storage),
    /// Under a test-time copy of `confine.sb` with fixture rules appended,
    /// with the contract's three parameters and the fixture's own bound.
    Fixture(&'a Storage, &'a FixtureProfile),
    /// Under `profile`, starting `program` with `executable` bound as
    /// `PROVIDER_EXECUTABLE` and the storage parameters bound as usual.
    /// `bound_digest` is a sha256 recorded earlier for `executable`. `None`
    /// records the file at this launch.
    Program {
        storage: &'a Storage,
        executable: &'a Path,
        program: &'a Path,
        profile: &'a Path,
        bound_digest: Option<String>,
    },
    /// The real provider binary under `profile`, with exactly `bindings`.
    Profile {
        profile: &'a Path,
        bindings: &'a [(&'static str, PathBuf)],
    },
    /// The same binary and pipes without the profile: a control run.
    Unconfined,
    /// `/bin/sleep` on the same pipes. It holds them open and writes nothing,
    /// so the one receive can run out of time. The provider binary is not
    /// started.
    Idle,
}

/// A test-time copy of one profile source with fixture rules appended. The
/// copy is read from the source path the caller passes when the test writes
/// it, so a `confine.sb` edit reaches a fixture launch that passes that file.
/// A fixture rule grants only what one test needs to reach the operation it
/// proves refused.
struct FixtureProfile {
    path: PathBuf,
    parameters: Vec<(&'static str, PathBuf)>,
}

impl FixtureProfile {
    fn write(
        source: &Path,
        storage: &Storage,
        rules: &str,
        parameters: Vec<(&'static str, PathBuf)>,
    ) -> Self {
        let profile = fs::read_to_string(source).expect("the profile source");
        let path = storage.base.join("fixture-confine.sb");
        fs::write(&path, format!("{profile}\n{rules}\n")).expect("fixture profile");
        Self { path, parameters }
    }
}

/// The three parameter bindings one storage and one executable make, in the
/// order every confined launch binds them: `PROVIDER_EXECUTABLE`,
/// `STORAGE_ROOT`, then `STORAGE_PARENT`.
fn canonical_bindings(storage: &Storage, executable: &Path) -> [(&'static str, PathBuf); 3] {
    [
        ("PROVIDER_EXECUTABLE", executable.to_path_buf()),
        ("STORAGE_ROOT", storage.root.clone()),
        ("STORAGE_PARENT", storage.parent.clone()),
    ]
}

thread_local! {
    static APPLIED_PROFILE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Records the profile path the one launch builder applies on this thread.
///
/// The stand-in file and the committed oracle both refuse an unbound copy
/// with exit 71. `generated_profile_refuses_an_unbound_copy` reads the record
/// and requires the stand-in file.
fn note_applied_profile(profile: &Path) {
    APPLIED_PROFILE.with(|slot| *slot.borrow_mut() = Some(profile.to_path_buf()));
}

fn applied_profile() -> PathBuf {
    APPLIED_PROFILE.with(|slot| {
        slot.borrow()
            .clone()
            .expect("the launch must record the profile it applies")
    })
}

/// The one launch builder. `sandbox-exec` starts `program` under `profile`,
/// with one `-D name=value` for each binding, in list order. It applies the
/// profile to its own process before it executes `program`, so the profile's
/// exec rule checks that exec as it checks any exec by the confined provider.
/// It records `profile` so a launch can require the stand-in file.
fn sandboxed(profile: &Path, bindings: &[(&'static str, PathBuf)], program: &Path) -> Command {
    note_applied_profile(profile);
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-f").arg(profile);
    for (name, value) in bindings {
        command.arg("-D").arg(format!("{name}={}", value.display()));
    }
    command.arg(program);
    command
}

/// The sha256 of the file a launch binds as `PROVIDER_EXECUTABLE`.
fn record_provider_executable(path: &Path) -> String {
    test_support::sha256_file(path)
}

/// Refuses the launch when `path` no longer has the digest `bound`.
fn refuse_changed_provider_executable(path: &Path, bound: &str) {
    let now = test_support::sha256_file(path);
    if now != bound {
        panic!(
            "PROVIDER_EXECUTABLE digest mismatch: {} was bound as {bound} and is now {now}",
            path.display()
        );
    }
}

/// Records `path` when this launch has no earlier digest, then refuses a file
/// that no longer has the digest bound for `PROVIDER_EXECUTABLE`.
fn check_provider_executable(path: &Path, recorded: Option<&str>) {
    match recorded {
        Some(recorded) => refuse_changed_provider_executable(path, recorded),
        None => {
            let recorded = record_provider_executable(path);
            refuse_changed_provider_executable(path, &recorded);
        }
    }
}

/// The real provider binary speaking its line-delimited JSON protocol, or the
/// idle hold, which never writes an answer.
struct Provider {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<Value>,
    stderr: Receiver<String>,
}

impl Provider {
    fn start(launch: Launch<'_>) -> Self {
        let binary = resolved(Path::new(PROVIDER_BINARY));
        let mut command = match launch {
            Launch::Confined(storage) => {
                check_provider_executable(&binary, None);
                let bindings = canonical_bindings(storage, &binary);
                sandboxed(Path::new(PROFILE_PATH), &bindings, &binary)
            }
            Launch::Fixture(storage, fixture) => {
                check_provider_executable(&binary, None);
                let mut bindings = canonical_bindings(storage, &binary).to_vec();
                bindings.extend(fixture.parameters.iter().cloned());
                sandboxed(&fixture.path, &bindings, &binary)
            }
            Launch::Program {
                storage,
                executable,
                program,
                profile,
                bound_digest,
            } => {
                check_provider_executable(executable, bound_digest.as_deref());
                let bindings = canonical_bindings(storage, executable);
                sandboxed(profile, &bindings, program)
            }
            Launch::Profile { profile, bindings } => {
                if let Some((_, path)) = bindings
                    .iter()
                    .find(|(name, _)| *name == "PROVIDER_EXECUTABLE")
                {
                    check_provider_executable(path, None);
                }
                sandboxed(profile, bindings, &binary)
            }
            Launch::Unconfined => Command::new(&binary),
            Launch::Idle => {
                let mut command = Command::new("/bin/sleep");
                command.arg("60");
                command
            }
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the launch must start a process");
        let stdout = child.stdout.take().expect("provider stdout");
        let (response_tx, responses) = mpsc::channel();
        thread::spawn(move || {
            // One JSON answer per line; anything else ends the stream.
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(response) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                if response_tx.send(response).is_err() {
                    break;
                }
            }
        });
        // The provider logs a fault's detail only on stderr. Failure messages
        // quote its fault lines, never the whole stream: a startup panic there
        // would read as a harness error to the falsifier runner.
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
            stdin: child.stdin.take(),
            child,
            responses,
            stderr: stderr_rx,
        }
    }

    /// Sends one request and returns its answer, or `None` when the process
    /// closes its stdout before it answers. A process that does neither
    /// within `FIXTURE_EVENT_TIMEOUT` fails the test.
    fn answer(&mut self, request: &Value) -> Option<Value> {
        match self.answer_within(request, FIXTURE_EVENT_TIMEOUT) {
            Ok(response) => Some(response),
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => panic!(
                "the provider did not answer {} within {FIXTURE_EVENT_TIMEOUT:?}",
                request["op"]
            ),
        }
    }

    /// The one receive on the request path. Sends one request and waits at
    /// most `wait` for its answer. `answer` uses it with
    /// `FIXTURE_EVENT_TIMEOUT`. A shorter wait is the time left until a run's
    /// deadline: `Timeout` is not an answer, and the wait loop names that
    /// deadline.
    fn answer_within(
        &mut self,
        request: &Value,
        wait: Duration,
    ) -> Result<Value, RecvTimeoutError> {
        let stdin = self.stdin.as_mut().expect("provider stdin is open");
        // A closed pipe shows up below as an exit without an answer.
        let _ = writeln!(stdin, "{request}").and_then(|()| stdin.flush());
        self.responses.recv_timeout(wait)
    }

    /// Sends one request and returns its answer. A process that exits first
    /// fails the test with its exit status: `sandbox-exec` exits 71 when the
    /// profile refuses to execute the binary, and a startup the profile breaks
    /// aborts before the first answer.
    fn request(&mut self, request: &Value) -> Value {
        match self.answer(request) {
            Some(response) => response,
            None => self.exited(request),
        }
    }

    fn exited(&mut self, request: &Value) -> ! {
        panic!(
            "the provider process exited before answering {}: {}",
            request["op"],
            describe(self.wait(FIXTURE_EVENT_TIMEOUT))
        )
    }

    /// How a process ended that closed its stdout without answering: its exit
    /// status from `wait`, and the stderr lines no earlier read took, read
    /// from the stderr channel until the stream closes.
    fn ended(&mut self) -> Ended {
        let status = self.wait(FIXTURE_EVENT_TIMEOUT);
        let stderr = self.collect_stderr(FIXTURE_EVENT_TIMEOUT);
        Ended { status, stderr }
    }

    /// Sends one request that must succeed and returns its data.
    fn ok(&mut self, request: &Value) -> Value {
        let response = self.request(request);
        self.accepted(request, response)
    }

    /// `ok` with its own wait: the data, or `None` when no answer comes within
    /// `wait`. That answer may still arrive, so a caller that gets `None`
    /// sends no other request. A process that exits first fails the test as
    /// `request` does.
    fn ok_within(&mut self, request: &Value, wait: Duration) -> Option<Value> {
        let response = match self.answer_within(request, wait) {
            Ok(response) => response,
            Err(RecvTimeoutError::Timeout) => return None,
            Err(RecvTimeoutError::Disconnected) => self.exited(request),
        };
        Some(self.accepted(request, response))
    }

    fn accepted(&self, request: &Value, response: Value) -> Value {
        if response["status"] != "ok" {
            let logged = response["code"]
                .as_str()
                .and_then(|code| self.logged_fault(code))
                .unwrap_or_default();
            panic!(
                "{} must succeed: {response}; provider log: {logged}",
                request["op"]
            );
        }
        response["data"].clone()
    }

    /// The provider's next stderr line for `code`, in its fault format
    /// `[model-provider] <code>: <detail>`. The JSON answer carries the code
    /// alone; the detail, with the OS error, is only here.
    fn logged_fault(&self, code: &str) -> Option<String> {
        let prefix = format!("[model-provider] {code}: ");
        let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.stderr.recv_timeout(left) {
                Ok(line) if line.starts_with(&prefix) => return Some(line),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        None
    }

    fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match self
                .child
                .try_wait()
                .expect("provider status must be readable")
            {
                Some(status) => return Some(status),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => return None,
            }
        }
    }

    /// Collects the remaining stderr lines, waiting at most `limit` for the
    /// stream to close. A zero limit drains only the lines already queued.
    fn collect_stderr(&self, limit: Duration) -> Vec<String> {
        let deadline = Instant::now() + limit;
        let mut stderr = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(line) => stderr.push(line),
                Err(_) => break,
            }
        }
        stderr
    }

    /// The exit status if the process ends within `limit`, and the stderr
    /// lines read by then. `None` means the process is still running after
    /// `limit`. After an exit, stderr is read until the stream closes, so a
    /// refusal line is not lost. A process still running is not waited past
    /// `limit`.
    fn outcome_within(&mut self, limit: Duration) -> (Option<ExitStatus>, Vec<String>) {
        let status = self.wait(limit);
        let stderr = self.collect_stderr(if status.is_some() {
            limit
        } else {
            Duration::ZERO
        });
        (status, stderr)
    }

    /// Stops a process `start` returned. A process that has already exited is
    /// waited. This does not ask the process to answer `shutdown`.
    fn kill_and_wait(&mut self) {
        self.stdin.take();
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    /// Stops the provider through its protocol and requires a clean exit.
    fn shutdown(mut self) {
        let data = self.ok(&json!({ "op": "shutdown" }));
        assert_eq!(data["shutdown"], true, "shutdown must be acknowledged");
        self.stdin.take();
        let status = self.wait(FIXTURE_EVENT_TIMEOUT);
        assert!(
            status.is_some_and(|status| status.success()),
            "the provider must exit cleanly after shutdown: {}",
            describe(status)
        );
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

/// What `Provider::ended` read from a launch that never answered.
struct Ended {
    status: Option<ExitStatus>,
    stderr: Vec<String>,
}

fn describe(status: Option<ExitStatus>) -> String {
    status.map_or_else(|| "still running".to_string(), |status| status.to_string())
}

/// A hosted text offer. It touches no file at `init`, and `init`, `status`
/// and `offers_list` never contact its endpoint. A local engine offer would
/// read artifacts outside `STORAGE_ROOT`, which this profile does not grant.
fn hosted_offer() -> Value {
    json!({
        "id": HOSTED_OFFER,
        "title": "Confined Hosted Text",
        "operation": "text.generate",
        "input_modalities": ["text/plain"],
        "output_modalities": ["text/plain"],
        "policy": {
            "concurrency_limit": 1,
            "input_bytes_limit": 4096,
            "inline_output_bytes_limit": 4096,
            "event_bytes_limit": 4096,
            "runtime_ms_limit": 10000,
            "retention_secs": 60,
            "cancel_settlement_timeout_ms": 100
        },
        "adapter": {
            "kind": "open_ai_compatible_text",
            "api_url": "https://hosted.invalid/v1/chat/completions",
            "model": "confine/text",
            "hosted": {
                "backend_provider_label": "Confine Fixture",
                "selection_mode": "pinned",
                "privacy_policy_ref": "fixture:privacy:confine",
                "terms_ref": "fixture:terms:confine",
                "upstream_routing_fallback_assertion": "operator_asserted_disabled"
            }
        },
        "enabled": true
    })
}

/// A local llama.cpp text offer for the engine and model at these paths, in
/// the offer shape `tests/process.rs` sends. Its `init` check resolves
/// `base_path` and reads both files, outside `STORAGE_ROOT`.
fn local_offer(engine: &Path, model: &Path) -> Value {
    json!({
        "id": "confine-local-text",
        "title": "Confined Local Text",
        "operation": "text.generate",
        "input_modalities": ["text/plain"],
        "output_modalities": ["text/plain"],
        "policy": {
            "concurrency_limit": 1,
            "input_bytes_limit": 8192,
            "inline_output_bytes_limit": 8192,
            "event_bytes_limit": 8192,
            "runtime_ms_limit": 30000,
            "retention_secs": 60,
            "cancel_settlement_timeout_ms": 20
        },
        "adapter": {
            "kind": "local_llama_cpp_text",
            "engine": {
                "path": engine,
                "sha256": test_support::sha256_file(engine)
            },
            "model": {
                "path": model,
                "sha256": test_support::sha256_file(model)
            },
            "settings": {
                "context_size": 256,
                "parallel": 1,
                "threads": 1,
                "batch_threads": 1,
                "gpu_layers": 0,
                "health_timeout_ms": FIXTURE_EVENT_TIMEOUT.as_millis() as u64,
                "shutdown_timeout_ms": 250,
                "enable_thinking": false
            }
        },
        "enabled": true
    })
}

/// An `init` for `storage`. Without `journal_dir` the provider derives its
/// journal root, `STORAGE_ROOT`, from `base_path`.
fn init_request(storage: &Storage, journal_dir: Option<&Path>) -> Value {
    let mut extra = json!({ "provider_id": "model-provider", "offers": [hosted_offer()] });
    if let Some(journal_dir) = journal_dir {
        extra["journal_dir"] = json!(journal_dir);
    }
    json!({
        "op": "init",
        "config": {
            "base_path": storage.base,
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": extra
        }
    })
}

/// `init` and `status` report the provider with its one offer ready.
fn assert_serving(data: &Value) {
    assert_eq!(data["provider"], "model-provider", "{data}");
    assert_eq!(data["offers_ready"], 1, "{data}");
}

/// One run of the hosted offer: the `runs_create` that stores it and the
/// `runs_get` that reads it back from the journal. Without
/// `runtime_hosted_socket` the binary refuses hosted dispatch before any
/// socket, so the run is stored as failed and needs no backend. With it, the
/// run is sent to that socket and may still be running when `runs_create`
/// answers; `settle` waits for its end.
struct HostedRun {
    create: Value,
    get: Value,
}

impl HostedRun {
    fn new(label: &str) -> Self {
        let input = json!({ "schema": TEXT_INPUT_V1_SCHEMA, "prompt": "confined read" });
        let binding = RuntimeCreateBinding {
            schema: RUNTIME_CREATE_BINDING_SCHEMA.into(),
            principal_id: "person:local:confine".into(),
            session_id: "session:confine".into(),
            capsule_id: "assistant".into(),
            grant_id: "grant:confine".into(),
            request_id: test_support::fixture_model_request_id(label),
            offer_id: HOSTED_OFFER.into(),
            operation: "text.generate".into(),
            input_hash: model_input_hash(&input).expect("fixture input hash"),
        };
        let access = RuntimeAccessBinding {
            schema: RUNTIME_ACCESS_BINDING_SCHEMA.into(),
            principal_id: binding.principal_id.clone(),
            session_id: binding.session_id.clone(),
            capsule_id: binding.capsule_id.clone(),
            grant_id: binding.grant_id.clone(),
            request_id: binding.request_id.clone(),
            run_id: model_run_id(&binding),
        };
        Self {
            create: json!({
                "op": "runs_create",
                "offer_id": HOSTED_OFFER,
                "operation": "text.generate",
                "input": input,
                "runtime_binding": binding
            }),
            get: json!({
                "op": "runs_get",
                "run_id": access.run_id,
                "runtime_binding": access
            }),
        }
    }

    /// Reads the run with `runs_get` until it is terminal and returns it. A
    /// run that does not settle within `FIXTURE_EVENT_TIMEOUT` fails the test.
    fn settle(&self, provider: &mut Provider) -> Value {
        let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
        self.settle_within(provider, deadline, FIXTURE_EVENT_TIMEOUT)
    }

    /// `settle` with the deadline the caller names. `within` is that budget,
    /// the one the deadline message names.
    fn settle_within(&self, provider: &mut Provider, deadline: Instant, within: Duration) -> Value {
        wait_for_terminal(deadline, within, |left| provider.ok_within(&self.get, left))
    }
}

/// The one wait loop for a hosted run. Each call of `poll` gets only the time
/// left until `deadline`. `poll` returns `None` when that time runs out with
/// no answer. The loop checks the deadline after every reply, terminal or
/// not, before it returns the run, so a reply read at or after the deadline
/// fails the test. `within` is the budget the deadline was built from.
fn wait_for_terminal(
    deadline: Instant,
    within: Duration,
    mut poll: impl FnMut(Duration) -> Option<Value>,
) -> Value {
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Some(run) = poll(left) else {
            break;
        };
        assert!(
            Instant::now() < deadline,
            "the run must settle within {within:?}: {run}"
        );
        if run["terminal"].is_object() {
            return run;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the run must settle within {within:?}: no terminal reply came before the deadline")
}

/// Every cited test in "Operations and the rights they need" is a function
/// in this file. The check covers `model_` names, `generated_` names, and
/// `allow_rules_trace_to_declared_rights`.
///
/// The section is `CONFINEMENT.md` from that heading through the next heading
/// line. `cited_test_name` is true for that exact span. Otherwise a backtick
/// span needs a `model_` or `generated_` prefix and a non-empty tail of
/// lowercase letters, digits and underscores, so the spans `model_` and
/// `generated_` stay uncited. `cited_test_names` scans backtick spans for test
/// names. `cell_backtick_names` scans the backtick spans of one Inputs cell.
/// `missing_cited_tests` is that list filtered to names the source
/// does not contain as `fn <name>(`. An in-memory section whose only span is
/// `generated_profile_denies_the_hosted_connect`, read against a source that
/// has no such function, fails first. The panic contains
/// `the stand-in citation must be a required test name`. The same shape for
/// `allow_rules_trace_to_declared_rights` fails with
/// `the trace citation must be a required test name`. The same shape for
/// `model_provider_ops_under_profile` fails with
/// `missing test: model_provider_ops_under_profile`. A span `not_a_test` is
/// not cited. This test starts no process and needs no sandbox.
///
/// `operations_table_cells_stay_lab_claims` runs on that same section after
/// the real-file missing-test check and returns ok. A data row starts with
/// `| ` and its first non-empty cell is not `Operation` and not `---`. The
/// Right cell is the fourth non-empty cell and the Linux cell is the seventh:
/// `designed, not enforced`.
///
/// `match_operation` is false for the in-memory rows: the Right cell passes
/// when `entry_id` read that id from the fixture's `rights` array, or the cell
/// is `none: needs no declared right`. The phrase `no named test shows this`
/// does not pass. `match_operation` is true for the real section: the Right
/// cell of `status`, `shutdown`, `offers_list` and `unsupported` is exactly
/// `none: needs no declared right`, and the Right cell of `init`,
/// `runs_create`, `runs_get`, `runs_events` and `runs_cancel` is exactly
/// `storage`. An in-memory row whose Right cell is `network` panics, and the
/// panic contains `network` and `right`. A `storage` cell whose id list is
/// only `bound-executable` panics with `storage` and `right`. The enforced
/// panic contains the backticked cell `` `enforced` ``. An in-memory row with
/// the old phrase panics with that phrase and `right`. In the true mode, a
/// wrong Right cell panics with the operation and the rejected cell.
///
/// `operations_inputs_match_the_request_structs` reads each Inputs cell's
/// backtick names and the fields of that operation's request struct in
/// `src/contract.rs` through `struct_field_names`. A row with no such struct
/// names `op` alone. A missing name, an extra name or a swap fails with the
/// operation and the name that has no partner. In-memory sources cover the
/// matching cell, the missing and extra names, a swap, a rename on both
/// sides, the complete default attribute forms, a missing struct, two
/// structs, two attribute lines, invalid body lines, an unfinished body,
/// an attribute without a field and unsupported attributes such as
/// `#[serde(skip)]` or combined rename options.
///
/// `operations_outputs_match_the_answers` splits each Outputs cell at its
/// first `error:`, holds the error spans to `error_response`'s keys and the
/// ok spans to `ok_response`'s keys followed by that row's `from` struct or
/// its one `json!`. It reads `fn handle_offers_list` in `src/state.rs` and the
/// `ProviderOperation::Shutdown =>` arm in `src/execution.rs` through the one
/// `json_literal_keys` reader. In-memory answers cover the matching cell, a
/// missing and an extra struct field, a dropped error key, a changed wrapper
/// key, reordered keys, a nested key, a dropped `json!` key, zero and two
/// literals, character and raw string literals, a prefix declaration name,
/// a doubled declaration, a nested declaration, a nested arm block, a later
/// attributed declaration, an unbraced region, the `unsupported` ok side and
/// a row without `from`.
///
/// Falsifier: F-cc31a renames `model_provider_ops_under_profile`, so this
/// test no longer finds that function. F-cc49a drops the `generated_`
/// acceptance, so the in-memory stand-in citation fails. F-cc50a drops the
/// exact `allow_rules_trace_to_declared_rights` return, so the in-memory
/// trace citation fails.
#[test]
fn operations_section_cites_existing_tests() {
    fn cited_test_name(span: &str) -> bool {
        if span == "allow_rules_trace_to_declared_rights" {
            return true;
        }
        let Some(tail) = span
            .strip_prefix("model_")
            .or_else(|| span.strip_prefix("generated_"))
        else {
            return false;
        };
        !tail.is_empty()
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }
    fn cited_test_names(section: &str) -> Vec<&str> {
        let mut cited = Vec::new();
        let mut rest = section;
        while let Some(start) = rest.find('`') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('`') else {
                break;
            };
            let span = &rest[..end];
            rest = &rest[end + 1..];
            if cited_test_name(span) && !cited.contains(&span) {
                cited.push(span);
            }
        }
        cited
    }
    fn missing_cited_tests<'a>(cited: &[&'a str], source: &str) -> Vec<&'a str> {
        cited
            .iter()
            .copied()
            .filter(|name| !source.contains(&format!("fn {name}(")))
            .collect()
    }
    // The stand-in and trace names fail before the generic missing-test
    // report, so dropping either acceptance is this test's failure.
    fn require_cited_tests(section: &str, source: &str) {
        let missing = missing_cited_tests(&cited_test_names(section), source);
        if missing.contains(&"generated_profile_denies_the_hosted_connect") {
            panic!("the stand-in citation must be a required test name");
        }
        if missing.contains(&"allow_rules_trace_to_declared_rights") {
            panic!("the trace citation must be a required test name");
        }
        assert!(missing.is_empty(), "missing test: {}", missing.join(", "));
    }
    fn caught_citation_failure(section: &str, source: &str) -> String {
        match catch_unwind(AssertUnwindSafe(|| require_cited_tests(section, source))) {
            Err(payload) => panic_text(payload),
            Ok(()) => String::new(),
        }
    }
    fn operations_section_text(doc: &str) -> &str {
        const HEADING: &str = "## Operations and the rights they need";
        let Some(start) = doc.find(HEADING) else {
            panic!("missing heading: {HEADING}");
        };
        let after = start + HEADING.len();
        let Some(next) = doc[after..].find("\n## ") else {
            panic!("the operations section has no following heading");
        };
        let heading_at = after + next + 1;
        let line_end = doc[heading_at..]
            .find('\n')
            .map(|index| heading_at + index)
            .unwrap_or(doc.len());
        &doc[start..line_end]
    }
    // One data row starts with `| ` and its first non-empty cell is not
    // `Operation` and not `---`. The cell check and `operation_row_names`
    // both use this filter, so there is one row rule.
    fn operation_row_cells(line: &str) -> Option<Vec<&str>> {
        if !line.starts_with("| ") {
            return None;
        }
        let cells: Vec<&str> = line
            .split('|')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect();
        match cells.first() {
            Some(&first) if first != "Operation" && first != "---" => Some(cells),
            _ => None,
        }
    }
    fn operation_row_names(section: &str) -> Vec<&str> {
        section
            .lines()
            .filter_map(operation_row_cells)
            .map(|cells| cells[0])
            .collect()
    }
    // Right is the fourth non-empty cell. Linux is the seventh. Header and
    // separator rows are not data rows, so their cells are not claims.
    fn operations_table_cells_stay_lab_claims(
        section: &str,
        right_ids: &[&str],
        match_operation: bool,
    ) -> Result<(), String> {
        const RIGHT_PLACE: usize = 4;
        const LINUX_PLACE: usize = 7;
        const UNSHOWN_RIGHT: &str = "no named test shows this";
        const NO_DECLARED_RIGHT: &str = "none: needs no declared right";
        const LINUX_CLAIM: &str = "designed, not enforced";
        const NO_RIGHT_OPERATIONS: [&str; 4] = ["status", "shutdown", "offers_list", "unsupported"];
        const STORAGE_OPERATIONS: [&str; 5] = [
            "init",
            "runs_create",
            "runs_get",
            "runs_events",
            "runs_cancel",
        ];
        for cells in section.lines().filter_map(operation_row_cells) {
            let first = cells[0];
            let right = cells.get(RIGHT_PLACE - 1).copied().unwrap_or("");
            if match_operation {
                if NO_RIGHT_OPERATIONS.contains(&first) {
                    if right != NO_DECLARED_RIGHT {
                        return Err(format!(
                            "operation `{first}` needs right cell `{NO_DECLARED_RIGHT}`, not `{right}`"
                        ));
                    }
                } else if STORAGE_OPERATIONS.contains(&first) {
                    if right != "storage" {
                        return Err(format!(
                            "operation `{first}` needs right cell `storage`, not `{right}`"
                        ));
                    }
                }
            } else if right == UNSHOWN_RIGHT {
                return Err(format!(
                    "right cell `{UNSHOWN_RIGHT}` does not pass; a shown call says `{NO_DECLARED_RIGHT}`"
                ));
            }
            if !right_ids.contains(&right) && right != NO_DECLARED_RIGHT {
                return Err(format!("right cell `{right}` is not an approved right id"));
            }
            let linux = cells.get(LINUX_PLACE - 1).copied().unwrap_or("");
            if linux != LINUX_CLAIM {
                return Err(format!(
                    "Linux cell `{linux}` is not designed, not enforced"
                ));
            }
        }
        Ok(())
    }
    fn caught_lab_claim_panic(section: &str, right_ids: &[&str], match_operation: bool) -> String {
        match catch_unwind(AssertUnwindSafe(|| {
            if let Err(reason) =
                operations_table_cells_stay_lab_claims(section, right_ids, match_operation)
            {
                panic!("{reason}");
            }
        })) {
            Err(payload) => panic_text(payload),
            Ok(()) => String::new(),
        }
    }
    // The declaration body after one leading `#[...]` attribute, one leading
    // `pub(...)` group or `pub` word, and one leading `async`, `unsafe` or
    // `const` word. A line whose body starts with `fn ` starts a function.
    fn after_declaration_prefix(mut rest: &str) -> &str {
        rest = rest.trim();
        if let Some(attribute) = rest.strip_prefix("#[") {
            if let Some(end) = attribute.find(']') {
                rest = attribute[end + 1..].trim();
            }
        }
        if let Some(after) = rest.strip_prefix("pub(") {
            if let Some(end) = after.find(')') {
                rest = after[end + 1..].trim();
            }
        } else if let Some(after) = rest.strip_prefix("pub") {
            if after.is_empty() || after.starts_with(|c: char| c.is_whitespace()) {
                rest = after.trim_start();
            }
        }
        for keyword in ["async", "unsafe", "const"] {
            if let Some(after) = rest.strip_prefix(keyword) {
                if after.is_empty() || after.starts_with(|c: char| c.is_whitespace()) {
                    rest = after.trim_start();
                    break;
                }
            }
        }
        rest
    }
    /// The arm names of `parse_request`'s `match op`, in source order.
    ///
    /// The cut starts at the `fn parse_request(` signature line and stops
    /// before the next function declaration. A later line is a declaration
    /// when `after_declaration_prefix` leaves a `fn ` prefix, so `pub(crate)`,
    /// `pub(super)`, `pub(in crate::here)`, a same-line or previous-line
    /// attribute, `async`, `pub async`, `unsafe` and `const` all end the cut.
    /// Each arm line permits one `=>`; a second one refuses the layout.
    ///
    /// The compare reads the match as text. It shows the Operation cells
    /// equal those arms, in order. It does not show that every arm is
    /// reachable, and it does not read `src/execution.rs`.
    fn parse_request_operation_names(source: &str) -> Result<Vec<&str>, String> {
        let declarations = source.matches("fn parse_request(").count();
        if declarations == 0 {
            return Err("parse_request: missing fn parse_request(".to_string());
        }
        if declarations > 1 {
            return Err("parse_request: has a second fn parse_request(".to_string());
        }
        let lines: Vec<&str> = source.lines().collect();
        let signature = lines
            .iter()
            .position(|line| line.contains("fn parse_request("))
            .expect("the declaration count found the signature");
        let end = lines[signature + 1..]
            .iter()
            .position(|line| after_declaration_prefix(line).starts_with("fn "))
            .map(|offset| signature + 1 + offset)
            .unwrap_or(lines.len());
        let cut = &lines[signature + 1..end];
        let match_op_count: usize = cut
            .iter()
            .map(|line| line.matches("match op").count())
            .sum();
        if match_op_count == 0 {
            return Err("parse_request: has no match op".to_string());
        }
        if match_op_count > 1 {
            return Err("parse_request: has a second match op".to_string());
        }
        let Some(match_at) = cut.iter().position(|line| line.contains("match op {")) else {
            return Err("parse_request: has no match op".to_string());
        };
        let (_, after_open) = cut[match_at]
            .split_once("match op {")
            .expect("the line contains the opening");
        if !after_open.trim().is_empty() {
            return Err("parse_request: an arm on the match op line".to_string());
        }
        let mut arms = Vec::new();
        let mut other_seen = false;
        for line in &cut[match_at + 1..] {
            let trimmed = line.trim();
            if trimmed == "};" {
                break;
            }
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains('{') || trimmed.contains('}') {
                return Err("parse_request: an arm line contains a brace".to_string());
            }
            if trimmed.matches("=>").count() > 1 {
                return Err("parse_request: an arm line contains a second `=>`".to_string());
            }
            if let Some(rest) = trimmed.strip_prefix('"') {
                let Some(close) = rest.find('"') else {
                    return Err(
                        "parse_request: an arm is not a quoted name and not `other =>`".to_string(),
                    );
                };
                if !rest[close + 1..].trim_start().starts_with("=>") {
                    return Err(
                        "parse_request: an arm is not a quoted name and not `other =>`".to_string(),
                    );
                }
                arms.push(&rest[..close]);
            } else if trimmed.starts_with("other =>") {
                if other_seen {
                    return Err("parse_request: has a second `other =>` arm".to_string());
                }
                other_seen = true;
                arms.push("unsupported");
            } else {
                return Err(
                    "parse_request: an arm is not a quoted name and not `other =>`".to_string(),
                );
            }
        }
        Ok(arms)
    }
    // One compare: the Operation cells and the arms must name the same
    // operations in the same order. A mismatch names the operation that has
    // no partner.
    fn operations_match_parse_request(section: &str, source: &str) -> Result<(), String> {
        let rows = operation_row_names(section);
        let arms = parse_request_operation_names(source)?;
        for index in 0..rows.len().max(arms.len()) {
            match (rows.get(index), arms.get(index)) {
                (Some(row), Some(arm)) if row == arm => {}
                (Some(row), Some(arm)) => {
                    return Err(format!(
                        "operation row `{row}` has no parse_request arm; the arm there is `{arm}`"
                    ));
                }
                (Some(row), None) => {
                    return Err(format!("operation row `{row}` has no parse_request arm"));
                }
                (None, Some(arm)) => {
                    return Err(format!("parse_request arm `{arm}` has no operation row"));
                }
                (None, None) => break,
            }
        }
        Ok(())
    }
    /// The wire field names of one request struct in `source`, in source
    /// order.
    ///
    /// Zero occurrences of `struct {struct_name} {` return `Ok(None)`. A
    /// second occurrence, a second attribute line above one field, an
    /// unsupported attribute line and any other body line are errors that
    /// name the struct. The body runs from that `{` to the line whose trim is
    /// `}`. A blank line or a line whose trim starts with `//` is skipped. One
    /// attribute line above a field may be `#[serde(rename = "...")]`, which
    /// gives the wire name, or `#[serde(default)]`,
    /// `#[serde(default, skip_serializing_if = "...")]` or
    /// `#[serde(skip_serializing_if = "...")]`, which keep the Rust name and
    /// keep the key required. These are complete attribute forms with one
    /// non-empty, unescaped quoted value; extra options are rejected. A field
    /// line's trim starts with `pub `, then the name, then `:`.
    ///
    /// The compare reads struct text, not serde's output. A later
    /// `#[serde(skip)]` is rejected, so a field the answer leaves out is a
    /// refusal and no pass. A `#[serde(default)]` field is required. A nested
    /// type stays one name. This reader does not read `src/execution.rs` or
    /// `src/state.rs`; the Outputs compare reads both beside it.
    fn struct_field_names(source: &str, struct_name: &str) -> Result<Option<Vec<String>>, String> {
        let marker = format!("struct {struct_name} {{");
        let occurrences = source.matches(&marker).count();
        if occurrences == 0 {
            return Ok(None);
        }
        if occurrences > 1 {
            return Err(format!(
                "struct {struct_name}: has a second `struct {struct_name} {{`"
            ));
        }
        let lines: Vec<&str> = source.lines().collect();
        let declaration = lines
            .iter()
            .position(|line| line.contains(&marker))
            .expect("the occurrence count found the struct");
        let mut names = Vec::new();
        let mut attribute: Option<&str> = None;
        for line in &lines[declaration + 1..] {
            let trimmed = line.trim();
            if trimmed == "}" {
                if let Some(line) = attribute {
                    return Err(format!(
                        "struct {struct_name}: attribute line has no field `{line}`"
                    ));
                }
                return Ok(Some(names));
            }
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("#[") {
                if attribute.is_some() {
                    return Err(format!(
                        "struct {struct_name}: a field has a second attribute line `{trimmed}`"
                    ));
                }
                attribute = Some(trimmed);
                continue;
            }
            let Some(field) = trimmed.strip_prefix("pub ") else {
                return Err(format!(
                    "struct {struct_name}: body line is not a field line `{trimmed}`"
                ));
            };
            let Some((rust_name, _)) = field.split_once(':') else {
                return Err(format!(
                    "struct {struct_name}: field line has no `:` `{trimmed}`"
                ));
            };
            let wire_name = match attribute.take() {
                Some(line) if line == "#[serde(default)]" => rust_name.trim().to_string(),
                Some(line) => {
                    let quoted_value = |prefix| {
                        line.strip_prefix(prefix)
                            .and_then(|rest| rest.strip_suffix("\")]"))
                            .filter(|value| !value.is_empty() && !value.contains(['"', '\\']))
                    };
                    match (
                        quoted_value("#[serde(rename = \""),
                        quoted_value("#[serde(default, skip_serializing_if = \""),
                        quoted_value("#[serde(skip_serializing_if = \""),
                    ) {
                        (Some(wire_name), _, _) => wire_name.to_string(),
                        (_, Some(_), _) => rust_name.trim().to_string(),
                        (_, _, Some(_)) => rust_name.trim().to_string(),
                        _ => {
                            return Err(format!(
                                "struct {struct_name}: unsupported attribute line `{line}`"
                            ))
                        }
                    }
                }
                None => rust_name.trim().to_string(),
            };
            names.push(wire_name);
        }
        Err(format!(
            "struct {struct_name}: body has no line whose trim is `}}`"
        ))
    }
    // The backtick spans of one Inputs cell, in order.
    fn cell_backtick_names(cell: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let mut rest = cell;
        while let Some(start) = rest.find('`') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('`') else {
                break;
            };
            names.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
        names
    }
    // `runs_events` -> `RunsEventsRequest`.
    fn request_struct_name(operation: &str) -> String {
        let mut name = String::new();
        for part in operation.split('_') {
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                name.extend(first.to_uppercase());
                name.push_str(chars.as_str());
            }
        }
        name.push_str("Request");
        name
    }
    // Each Inputs cell's backtick names, in order, equal the fields of that
    // operation's request struct in `source`; a row with no such struct names
    // `op` alone. A mismatch names the operation and the name with no partner.
    fn operations_inputs_match_the_request_structs(
        section: &str,
        source: &str,
    ) -> Result<(), String> {
        const INPUTS_PLACE: usize = 2;
        for cells in section.lines().filter_map(operation_row_cells) {
            let operation = cells[0];
            let cell_names =
                cell_backtick_names(cells.get(INPUTS_PLACE - 1).copied().unwrap_or(""));
            let struct_name = request_struct_name(operation);
            let field_names = match struct_field_names(source, &struct_name)? {
                Some(names) => names,
                None => vec!["op".to_string()],
            };
            for index in 0..cell_names.len().max(field_names.len()) {
                match (cell_names.get(index).copied(), field_names.get(index)) {
                    (Some(cell_name), Some(field_name)) if cell_name == field_name.as_str() => {}
                    (Some(cell_name), Some(field_name)) => {
                        return Err(format!(
                            "operation `{operation}` Inputs name `{cell_name}` has no partner; the field there is `{field_name}`"
                        ));
                    }
                    (Some(cell_name), None) => {
                        return Err(format!(
                            "operation `{operation}` Inputs name `{cell_name}` has no partner in `{struct_name}`"
                        ));
                    }
                    (None, Some(field_name)) => {
                        return Err(format!(
                            "operation `{operation}` field `{field_name}` has no partner in the Inputs cell"
                        ));
                    }
                    (None, None) => break,
                }
            }
        }
        Ok(())
    }
    fn reader_failure(source: &str) -> String {
        match parse_request_operation_names(source) {
            Err(reason) => reason,
            Ok(arms) => panic!("the reader accepts: {arms:?} in {source}"),
        }
    }
    fn compare_failure(section: &str, source: &str) -> String {
        match operations_match_parse_request(section, source) {
            Err(reason) => reason,
            Ok(()) => panic!("the compare accepts: {section} {source}"),
        }
    }
    fn inputs_row(operation: &str, inputs: &str) -> String {
        format!(
            "| {operation} | {inputs} | out | storage | effect | rule | designed, not enforced |"
        )
    }
    fn inputs_failure(section: &str, source: &str) -> String {
        match operations_inputs_match_the_request_structs(section, source) {
            Err(reason) => reason,
            Ok(()) => panic!("the compare accepts: {section} {source}"),
        }
    }
    // The answer source at `path`, or an error that names that path.
    fn read_answer_source(path: &Path) -> Result<String, String> {
        fs::read_to_string(path)
            .map_err(|err| format!("answer source {} must be readable: {err}", path.display()))
    }
    /// The top-level `"key":` names of the one `json!({` literal in `region`,
    /// in source order.
    ///
    /// A region with no `json!({` and a region with two are separate errors,
    /// and both name `json`. The reader returns the top-level names and does
    /// not descend into a value, so a nested object's keys stay inside that
    /// value. It skips a string whole, so a `{` inside one is no brace. A
    /// call such as `ok_response(` is not a second literal.
    /// Regions with `//` or `/*` are refused, including those markers inside
    /// strings. This check applies before the literal count and body scan. A
    /// character literal in the body is refused, because `'}'` can hide the
    /// closing brace or a later key. Raw string literals (including raw byte
    /// and C strings, with any number of hashes) are also refused: their
    /// internal quotes and backslashes follow different rules.
    ///
    /// Honesty limit: this reads literal text, not a serialized answer. A key
    /// a helper adds at run time is not read. Nested values (`offers`,
    /// `terminal`, `events`, `config`) stay one name. A `#[serde(skip)]`
    /// attribute is rejected by the shared `struct_field_names`, not counted.
    /// The reader does not read the keys inside `result` or inside an event's
    /// `data`.
    fn json_literal_keys(region: &str) -> Result<Vec<String>, String> {
        const OPENER: &str = "json!({";
        if region.contains("//") {
            return Err("json: line-comment marker `//` is unsupported in the region".to_string());
        }
        if region.contains("/*") {
            return Err("json: block-comment marker `/*` is unsupported in the region".to_string());
        }
        let openings = region.matches(OPENER).count();
        if openings == 0 {
            return Err("json: the region has no `json!({` literal".to_string());
        }
        if openings > 1 {
            return Err(format!(
                "json: the region has {openings} `json!({{` literals, not one"
            ));
        }
        let body =
            &region[region.find(OPENER).expect("the count found one opener") + OPENER.len()..];
        let bytes = body.as_bytes();
        let mut keys = Vec::new();
        let mut depth = 1usize;
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'r' => {
                    let mut quote = index + 1;
                    while bytes.get(quote) == Some(&b'#') {
                        quote += 1;
                    }
                    if bytes.get(quote) == Some(&b'"') {
                        return Err("json: a raw string literal is not supported".to_string());
                    }
                    index += 1;
                }
                b'"' => {
                    let mut end = index + 1;
                    let mut escaped = false;
                    while end < bytes.len() {
                        match bytes[end] {
                            b'\\' if !escaped => {
                                escaped = true;
                                end += 1;
                                continue;
                            }
                            b'"' if !escaped => break,
                            _ => {}
                        }
                        escaped = false;
                        end += 1;
                    }
                    if end >= bytes.len() {
                        return Err("json: a string in the literal never closes".to_string());
                    }
                    let mut next = end + 1;
                    while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                        next += 1;
                    }
                    if depth == 1 && next < bytes.len() && bytes[next] == b':' {
                        keys.push(body[index + 1..end].to_string());
                    }
                    index = end + 1;
                }
                b'\'' => {
                    return Err("json: a character literal is not supported".to_string());
                }
                b'{' | b'[' => {
                    depth += 1;
                    index += 1;
                }
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
        if depth != 0 {
            return Err("json: the literal never closes".to_string());
        }
        Ok(keys)
    }
    // The lines of the region that starts at `start`, through the brace that
    // closes the first `{` at or after it.
    //
    // A string, a character literal, a line comment and a block comment are
    // skipped whole, so a brace inside one does not move the boundary. A
    // region with no opening brace and a region whose first brace never
    // closes are refused with their own reasons.
    fn braced_region(source: &str, start: usize) -> Result<&str, String> {
        let bytes = source.as_bytes();
        let mut opened = false;
        let mut depth = 0usize;
        let mut index = start;
        while index < bytes.len() {
            match bytes[index] {
                b'"' => {
                    index += 1;
                    while index < bytes.len() {
                        match bytes[index] {
                            b'\\' => index += 2,
                            b'"' => {
                                index += 1;
                                break;
                            }
                            _ => index += 1,
                        }
                    }
                }
                b'\'' => {
                    index += 1;
                    while index < bytes.len() {
                        match bytes[index] {
                            b'\\' => index += 2,
                            b'\'' => {
                                index += 1;
                                break;
                            }
                            _ => index += 1,
                        }
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'{' => {
                    opened = true;
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    if depth == 0 {
                        return Err("the region has no opening `{`".to_string());
                    }
                    depth -= 1;
                    index += 1;
                    if depth == 0 {
                        return Ok(&source[start..index]);
                    }
                }
                _ => index += 1,
            }
        }
        if !opened {
            return Err("the region has no opening `{`".to_string());
        }
        Err("the region has no closing `}` for its first `{`".to_string())
    }
    // The lines of the one function whose declaration line starts with
    // `marker` through the brace that closes that function's body.
    //
    // A declaration is what `after_declaration_prefix` leaves, so a same-line
    // attribute, `pub`, `pub(crate)`, `pub(super)`, `pub(in ...)`, `async`,
    // `unsafe` and `const` are all read by that one rule. Only a declaration
    // line matches, so a longer name such as `ok_response_example` is not
    // `fn ok_response(`. Zero and two such declarations are refused with their
    // own reasons. The region ends at the function's own closing brace, so a
    // nested declaration or a later function never supplies the keys.
    fn function_region<'a>(source: &'a str, marker: &str) -> Result<&'a str, String> {
        let mut starts = Vec::new();
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            if after_declaration_prefix(line).starts_with(marker) {
                starts.push(offset);
            }
            offset += line.len();
        }
        if starts.len() > 1 {
            return Err(format!(
                "the source has {} `{marker}` declarations, not one",
                starts.len()
            ));
        }
        let Some(&start) = starts.first() else {
            return Err(format!("the source has no `{marker}` declaration"));
        };
        braced_region(source, start)
    }
    // The lines of the one `ProviderOperation::Shutdown =>` match arm, through
    // the brace that closes that arm. The arm's own body boundary is that
    // brace, so a nested block's close does not end the arm.
    fn shutdown_arm_region(source: &str) -> Result<&str, String> {
        const MARKER: &str = "ProviderOperation::Shutdown =>";
        let occurrences = source.matches(MARKER).count();
        if occurrences == 0 {
            return Err(format!("`src/execution.rs` has no `{MARKER}`"));
        }
        if occurrences > 1 {
            return Err(format!(
                "`src/execution.rs` has {occurrences} `{MARKER}` arms"
            ));
        }
        let at = source.find(MARKER).expect("the count found one arm");
        let start = source[..at].rfind('\n').map_or(0, |index| index + 1);
        braced_region(source, start)
    }
    // The backtick names of one side equal the keys of one answer `json!`, in
    // order. A mismatch names the operation and the name or key with no
    // partner.
    fn compare_output_keys(
        operation: &str,
        side: &str,
        names: &[&str],
        keys: &[String],
    ) -> Result<(), String> {
        for index in 0..names.len().max(keys.len()) {
            match (names.get(index), keys.get(index)) {
                (Some(name), Some(key)) if *name == key.as_str() => {}
                (Some(name), Some(key)) => {
                    return Err(format!(
                        "operation `{operation}` {side} name `{name}` has no partner; the key there is `{key}`"
                    ));
                }
                (Some(name), None) => {
                    return Err(format!(
                        "operation `{operation}` {side} name `{name}` has no partner in the answer"
                    ));
                }
                (None, Some(key)) => {
                    return Err(format!(
                        "operation `{operation}` {side} key `{key}` has no partner in the cell"
                    ));
                }
                (None, None) => break,
            }
        }
        Ok(())
    }
    /// Each Outputs cell's error backtick spans equal the keys of the one
    /// `json!` in `error_response`; its ok spans start with the keys of
    /// `ok_response` and then equal that row's `from` struct or its one
    /// `json!`.
    ///
    /// The cell is split at its first `error:`. A `from` row's last span is a
    /// struct in `src/contract.rs`, read through `struct_field_names`, and the
    /// spans between `data` and that name equal its fields. A row without
    /// `from` is `offers_list`, read from `fn handle_offers_list` in
    /// `src/state.rs`, or `shutdown`, read from the
    /// `ProviderOperation::Shutdown =>` arm in `src/execution.rs`; any other
    /// row without `from` fails. The `unsupported` row has an empty ok side,
    /// and an ok side on it fails.
    ///
    /// Honesty limit: this reads struct text and `json!` literals, not
    /// serialized output. A key a helper adds at run time is not read. Nested
    /// values (`offers`, `terminal`, `events`, `config`) stay one name. A
    /// `#[serde(skip)]` attribute is rejected by the shared reader, so the
    /// check refuses a field the answer leaves out instead of counting it.
    /// The check does not read the keys inside `result` or inside an event's
    /// `data`.
    fn operations_outputs_match_the_answers(
        section: &str,
        contract_source: &str,
        state_source: &str,
        execution_source: &str,
    ) -> Result<(), String> {
        const OUTPUTS_PLACE: usize = 3;
        let ok_keys = json_literal_keys(function_region(contract_source, "fn ok_response(")?)?;
        let error_keys =
            json_literal_keys(function_region(contract_source, "fn error_response(")?)?;
        for cells in section.lines().filter_map(operation_row_cells) {
            let operation = cells[0];
            let cell = cells.get(OUTPUTS_PLACE - 1).copied().unwrap_or("");
            let Some((ok_side, error_side)) = cell.split_once("error:") else {
                return Err(format!(
                    "operation `{operation}` Outputs cell has no `error:` side"
                ));
            };
            compare_output_keys(
                operation,
                "error",
                &cell_backtick_names(error_side),
                &error_keys,
            )?;
            let names = cell_backtick_names(ok_side);
            if operation == "unsupported" {
                if ok_side.trim().is_empty() {
                    continue;
                }
                return Err(format!(
                    "operation `unsupported` has an ok side: {}",
                    ok_side.trim()
                ));
            }
            if names.len() < 2 {
                return Err(format!(
                    "operation `{operation}` Outputs ok side has fewer than two names"
                ));
            }
            compare_output_keys(operation, "ok", &names[..2], &ok_keys)?;
            if ok_side.contains("from") {
                if names.len() < 3 {
                    return Err(format!(
                        "operation `{operation}` Outputs ok side has `from` without a struct name"
                    ));
                }
                let struct_name = names[names.len() - 1];
                let Some(struct_fields) = struct_field_names(contract_source, struct_name)? else {
                    return Err(format!(
                        "operation `{operation}` names struct `{struct_name}`, which `src/contract.rs` does not declare"
                    ));
                };
                compare_output_keys(
                    operation,
                    "ok `data`",
                    &names[2..names.len() - 1],
                    &struct_fields,
                )?;
            } else {
                let answer_keys = match operation {
                    "offers_list" => {
                        json_literal_keys(function_region(state_source, "fn handle_offers_list(")?)?
                    }
                    "shutdown" => json_literal_keys(shutdown_arm_region(execution_source)?)?,
                    other => {
                        return Err(format!(
                            "operation `{other}` Outputs ok side names no `from` struct and no answer `json!`"
                        ));
                    }
                };
                compare_output_keys(operation, "ok `data`", &names[2..], &answer_keys)?;
            }
        }
        Ok(())
    }
    fn rows(names: &[&str]) -> String {
        names.iter().map(|name| format!("| {name} |\n")).collect()
    }
    fn source_cut_before(declaration: &str, arms: &str) -> String {
        format!(
            "fn parse_request() {{}}\n{declaration} unrelated() {{\n    let operation = match op {{\n{arms}\n    }};\n}}\n"
        )
    }

    let source_without_the_function = "";
    let stand_in_failure = caught_citation_failure(
        "`generated_profile_denies_the_hosted_connect`",
        source_without_the_function,
    );
    assert!(
        stand_in_failure.contains("the stand-in citation must be a required test name"),
        "the stand-in citation must be a required test name: {stand_in_failure}"
    );
    let trace_failure = caught_citation_failure(
        "`allow_rules_trace_to_declared_rights`",
        source_without_the_function,
    );
    assert!(
        trace_failure.contains("the trace citation must be a required test name"),
        "the trace citation must be a required test name: {trace_failure}"
    );
    let model_failure = caught_citation_failure(
        "`model_provider_ops_under_profile`",
        source_without_the_function,
    );
    assert!(
        model_failure.contains("missing test: model_provider_ops_under_profile"),
        "{model_failure}"
    );
    assert!(
        cited_test_names("`not_a_test`").is_empty(),
        "a span not_a_test is not cited"
    );
    assert!(!cited_test_name("not_a_test"));
    assert!(!cited_test_name("model_"));
    assert!(!cited_test_name("generated_"));
    assert!(cited_test_names("`model_`").is_empty());
    assert!(cited_test_names("`generated_`").is_empty());
    assert!(cited_test_name("allow_rules_trace_to_declared_rights"));
    require_cited_tests("`not_a_test`", source_without_the_function);
    require_cited_tests("`model_`", source_without_the_function);
    require_cited_tests("`generated_`", source_without_the_function);

    let approved_ids = ["storage", "bound-executable"];
    let network_row = "| init | in | out | network | effect | rule | designed, not enforced |";
    let network_panic = caught_lab_claim_panic(network_row, &approved_ids, false);
    assert!(
        network_panic.contains("network") && network_panic.contains("right"),
        "{network_panic}"
    );
    let storage_row = "| init | in | out | storage | effect | rule | designed, not enforced |";
    let storage_panic = caught_lab_claim_panic(storage_row, &["bound-executable"], false);
    assert!(
        storage_panic.contains("storage") && storage_panic.contains("right"),
        "{storage_panic}"
    );
    let bound_row =
        "| init | in | out | bound-executable | effect | rule | designed, not enforced |";
    assert_eq!(
        operations_table_cells_stay_lab_claims(bound_row, &approved_ids, false),
        Ok(())
    );
    let none_row =
        "| status | in | out | none: needs no declared right | effect | rule | designed, not enforced |";
    assert_eq!(
        operations_table_cells_stay_lab_claims(none_row, &approved_ids, false),
        Ok(())
    );
    let unshown_row =
        "| status | in | out | no named test shows this | effect | rule | designed, not enforced |";
    let unshown_panic = caught_lab_claim_panic(unshown_row, &approved_ids, false);
    assert!(
        unshown_panic.contains("no named test shows this") && unshown_panic.contains("right"),
        "{unshown_panic}"
    );
    let startup_row =
        "| init | in | out | startup-root-directory | effect | rule | designed, not enforced |";
    let startup_panic = caught_lab_claim_panic(startup_row, &approved_ids, false);
    assert!(
        startup_panic.contains("startup-root-directory") && startup_panic.contains("right"),
        "{startup_panic}"
    );
    let enforced_row = "| init | in | out | storage | effect | rule | enforced |";
    let enforced_panic = caught_lab_claim_panic(enforced_row, &approved_ids, false);
    assert!(enforced_panic.contains("`enforced`"), "{enforced_panic}");

    // In the real-section mode each operation has one right cell, so a row
    // with the other cell, or with another approved id, must fail. Dropping
    // any operation from either list would let that row pass.
    let no_right_operations = ["status", "shutdown", "offers_list", "unsupported"];
    let storage_operations = [
        "init",
        "runs_create",
        "runs_get",
        "runs_events",
        "runs_cancel",
    ];
    for operation in no_right_operations {
        for wrong in ["storage", "bound-executable", "no named test shows this"] {
            let row = format!(
                "| {operation} | in | out | {wrong} | effect | rule | designed, not enforced |"
            );
            let panic = caught_lab_claim_panic(&row, &approved_ids, true);
            assert!(
                panic.contains(operation) && panic.contains(wrong),
                "{operation} with `{wrong}`: {panic}"
            );
        }
        let row = format!(
            "| {operation} | in | out | none: needs no declared right | effect | rule | designed, not enforced |"
        );
        assert_eq!(
            operations_table_cells_stay_lab_claims(&row, &approved_ids, true),
            Ok(())
        );
    }
    for operation in storage_operations {
        for wrong in [
            "bound-executable",
            "none: needs no declared right",
            "no named test shows this",
        ] {
            let row = format!(
                "| {operation} | in | out | {wrong} | effect | rule | designed, not enforced |"
            );
            let panic = caught_lab_claim_panic(&row, &approved_ids, true);
            assert!(
                panic.contains(operation) && panic.contains("storage") && panic.contains(wrong),
                "{operation} with `{wrong}`: {panic}"
            );
        }
        let row = format!(
            "| {operation} | in | out | storage | effect | rule | designed, not enforced |"
        );
        assert_eq!(
            operations_table_cells_stay_lab_claims(&row, &["bound-executable"], true),
            Err("right cell `storage` is not an approved right id".to_string()),
            "{operation} requires storage in the approved rights"
        );
        assert_eq!(
            operations_table_cells_stay_lab_claims(&row, &approved_ids, true),
            Ok(())
        );
    }

    // The cut stops before the next function declaration. The old four
    // prefixes and every form `after_declaration_prefix` removes end it, so a
    // later `match op` supplies no arm.
    let two_rows = rows(&["init", "unsupported"]);
    let cut_arms = "        \"init\" => ProviderOperation::Init,\n        other => ProviderOperation::Unsupported(other.to_string()),";
    for declaration in [
        "pub(crate) fn",
        "pub(super) fn",
        "pub(in crate::here) fn",
        "#[inline]\npub(crate) fn",
        "#[inline] pub(crate) fn",
        "async fn",
        "pub async fn",
        "unsafe fn",
        "const fn",
    ] {
        let source = source_cut_before(declaration, cut_arms);
        let failure = compare_failure(&two_rows, &source);
        assert!(
            failure.contains("parse_request")
                && failure.contains("match op")
                && failure.contains("has no match op"),
            "`{declaration}` must end the cut: {failure}"
        );
    }
    let own_cut = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let later_ping = format!(
        r#"{own_cut}pub(crate) fn unrelated() {{
    let operation = match op {{
        "ping" => ProviderOperation::Ping,
    }};
}}
"#
    );
    assert_eq!(
        parse_request_operation_names(&later_ping),
        Ok(vec!["init", "unsupported"])
    );

    let commented_match = r#"fn parse_request() {
    /*
    match op {
        "stale" => ProviderOperation::Stale,
    }
    */
    let operation = match op {
        "init" => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(commented_match);
    assert!(
        failure.contains("parse_request") && failure.contains("second match op"),
        "{failure}"
    );
    let arm_on_match_line = r#"fn parse_request() {
    let operation = match op { "init" => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(arm_on_match_line);
    assert!(
        failure.contains("parse_request") && failure.contains("arm on the match op line"),
        "{failure}"
    );
    let arm_with_open_brace = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init { value: 1 },
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(arm_with_open_brace);
    assert!(
        failure.contains("parse_request") && failure.contains("arm line contains a brace"),
        "{failure}"
    );
    let arm_with_close_brace = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init },
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(arm_with_close_brace);
    assert!(
        failure.contains("parse_request") && failure.contains("arm line contains a brace"),
        "{failure}"
    );

    assert_eq!(operations_match_parse_request(&two_rows, own_cut), Ok(()));
    let status_row = rows(&["init", "status"]);
    let failure = compare_failure(&status_row, own_cut);
    assert!(failure.contains("unsupported"), "{failure}");
    let ping_arm = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
        "ping" => ProviderOperation::Ping,
    };
}
"#;
    let failure = compare_failure(&two_rows, ping_arm);
    assert!(failure.contains("ping"), "{failure}");
    for (first_arm, extra_arm) in [
        (
            "\"init\" => ProviderOperation::Init,",
            "\"ping\" => ProviderOperation::Status,",
        ),
        (
            "\"init\" => ProviderOperation::Init,",
            "other => ProviderOperation::Unsupported(other.to_string()),",
        ),
        (
            "other => ProviderOperation::Unsupported(other.to_string()),",
            "\"ping\" => ProviderOperation::Status,",
        ),
        (
            "other => ProviderOperation::Unsupported(other.to_string()),",
            "other => ProviderOperation::Unsupported(other.to_string()),",
        ),
    ] {
        let same_line_arms = own_cut.replace(first_arm, &format!("{first_arm} {extra_arm}"));
        assert_eq!(
            compare_failure(&two_rows, &same_line_arms),
            "parse_request: an arm line contains a second `=>`",
            "{same_line_arms}"
        );
    }
    let swapped_rows = rows(&["unsupported", "init"]);
    let failure = compare_failure(&swapped_rows, own_cut);
    assert!(
        failure.contains("init") && failure.contains("unsupported"),
        "{failure}"
    );
    let init_only_arm = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init,
    };
}
"#;
    let failure = compare_failure(&two_rows, init_only_arm);
    assert!(failure.contains("unsupported"), "{failure}");

    let failure = reader_failure("pub fn unrelated() {}\n");
    assert!(
        failure.contains("parse_request") && failure.contains("missing fn parse_request("),
        "{failure}"
    );
    let failure = reader_failure("fn parse_request() {}\nfn parse_request() {}\n");
    assert!(
        failure.contains("parse_request") && failure.contains("second fn parse_request("),
        "{failure}"
    );
    let unquoted_arm = r#"fn parse_request() {
    let operation = match op {
        init => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(unquoted_arm);
    assert!(
        failure.contains("parse_request") && failure.contains("not a quoted name"),
        "{failure}"
    );
    let double_other = r#"fn parse_request() {
    let operation = match op {
        "init" => ProviderOperation::Init,
        other => ProviderOperation::Unsupported(other.to_string()),
        other => ProviderOperation::Unsupported(other.to_string()),
    };
}
"#;
    let failure = reader_failure(double_other);
    assert!(
        failure.contains("parse_request") && failure.contains("second `other =>` arm"),
        "{failure}"
    );

    let init_source = "pub struct InitRequest {\n    pub op: String,\n    pub config: String,\n}\n";
    let init_match = inputs_row("init", "`op`, `config`");
    assert_eq!(
        operations_inputs_match_the_request_structs(&init_match, init_source),
        Ok(())
    );
    let failure = inputs_failure(&inputs_row("init", "`op`"), init_source);
    assert_eq!(
        failure,
        "operation `init` field `config` has no partner in the Inputs cell"
    );
    assert!(
        failure.contains("init") && failure.contains("config"),
        "{failure}"
    );
    let failure = inputs_failure(&inputs_row("init", "`op`, `config`, `extra`"), init_source);
    assert_eq!(
        failure,
        "operation `init` Inputs name `extra` has no partner in `InitRequest`"
    );
    assert!(
        failure.contains("init") && failure.contains("extra"),
        "{failure}"
    );
    let failure = inputs_failure(&inputs_row("init", "`config`, `op`"), init_source);
    assert_eq!(
        failure,
        "operation `init` Inputs name `config` has no partner; the field there is `op`"
    );
    assert!(failure.contains("init"), "{failure}");

    // A rename gives the wire name on both sides: the Rust name fails and the
    // wire name passes.
    let renamed_source = "pub struct InitRequest {\n    pub op: String,\n    #[serde(rename = \"wire_name\")]\n    pub config: String,\n}\n";
    let failure = inputs_failure(&inputs_row("init", "`op`, `config`"), renamed_source);
    assert_eq!(
        failure,
        "operation `init` Inputs name `config` has no partner; the field there is `wire_name`"
    );
    assert!(
        failure.contains("init") && failure.contains("wire_name"),
        "{failure}"
    );
    assert_eq!(
        operations_inputs_match_the_request_structs(
            &inputs_row("init", "`op`, `wire_name`"),
            renamed_source
        ),
        Ok(())
    );

    // Default attributes keep the Rust field name only in the complete
    // supported forms. Extra options in either quoted form are refused.
    for attribute in [
        "#[serde(default)]",
        r#"#[serde(default, skip_serializing_if = "Option::is_none")]"#,
    ] {
        let source = format!(
            "pub struct InitRequest {{\n    pub op: String,\n    {attribute}\n    pub config: Option<String>,\n}}\n"
        );
        assert_eq!(
            operations_inputs_match_the_request_structs(&init_match, &source),
            Ok(()),
            "{attribute}"
        );
    }
    for attribute in [
        r#"#[serde(default, skip_serializing_if = "Option::is_none", rename = "wire_name")]"#,
        r#"#[serde(default, skip_serializing_if = "Option::is_none", skip)]"#,
        r#"#[serde(default, rename = "wire_name")]"#,
        r#"#[serde(rename = "wire_name", skip_serializing_if = "Option::is_none")]"#,
        r#"#[serde(rename = "wire_name", alias = "config")]"#,
        r#"#[serde(rename = "wire_name", default)]"#,
        r#"#[serde(rename = "")]"#,
        r#"#[serde(default, skip_serializing_if = "")]"#,
        r#"#[serde(rename = "wire\x5fname")]"#,
        r#"#[serde(default, skip_serializing_if = "Option\x3a\x3ais_none")]"#,
        r#"#[serde(rename = "wire_name")"#,
        r#"#[serde(default, skip_serializing_if = "Option::is_none")"#,
    ] {
        let source = format!(
            "pub struct InitRequest {{\n    pub op: String,\n    {attribute}\n    pub config: Option<String>,\n}}\n"
        );
        assert_eq!(
            inputs_failure(&init_match, &source),
            format!("struct InitRequest: unsupported attribute line `{attribute}`")
        );
    }

    // A row with no request struct names `op` alone.
    assert_eq!(
        operations_inputs_match_the_request_structs(&inputs_row("status", "`op`"), init_source),
        Ok(())
    );
    let failure = inputs_failure(&inputs_row("status", "`op`, `body`"), init_source);
    assert_eq!(
        failure,
        "operation `status` Inputs name `body` has no partner in `StatusRequest`"
    );
    assert!(
        failure.contains("status") && failure.contains("body"),
        "{failure}"
    );

    // A second struct, a second attribute line, a body line that is not a
    // field, and an unsupported attribute each fail with their own reason.
    let duplicate_source = "pub struct InitRequest {\n    pub op: String,\n}\npub struct InitRequest {\n    pub op: String,\n}\n";
    let failure = inputs_failure(&init_match, duplicate_source);
    assert_eq!(
        failure,
        "struct InitRequest: has a second `struct InitRequest {`"
    );
    assert!(
        failure.contains("InitRequest") && failure.contains("second `struct InitRequest {`"),
        "{failure}"
    );
    let stacked_attribute_source = "pub struct InitRequest {\n    #[serde(default)]\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    pub op: String,\n}\n";
    let failure = inputs_failure(&init_match, stacked_attribute_source);
    assert_eq!(
        failure,
        "struct InitRequest: a field has a second attribute line `#[serde(skip_serializing_if = \"Option::is_none\")]`"
    );
    assert!(
        failure.contains("InitRequest") && failure.contains("second attribute line"),
        "{failure}"
    );
    let invalid_body_source =
        "pub struct InitRequest {\n    pub op: String,\n    let config = 1;\n}\n";
    let failure = inputs_failure(&init_match, invalid_body_source);
    assert_eq!(
        failure,
        "struct InitRequest: body line is not a field line `let config = 1;`"
    );
    assert!(
        failure.contains("InitRequest") && failure.contains("not a field line"),
        "{failure}"
    );
    let skipped_field_source =
        "pub struct InitRequest {\n    #[serde(skip)]\n    pub config: String,\n}\n";
    let failure = inputs_failure(&init_match, skipped_field_source);
    assert_eq!(
        failure,
        "struct InitRequest: unsupported attribute line `#[serde(skip)]`"
    );
    assert!(
        failure.contains("InitRequest") && failure.contains("unsupported attribute line"),
        "{failure}"
    );
    let missing_colon_source = "pub struct InitRequest {\n    pub op String,\n}\n";
    assert_eq!(
        inputs_failure(&init_match, missing_colon_source),
        "struct InitRequest: field line has no `:` `pub op String,`"
    );
    let unfinished_source = "pub struct InitRequest {\n    pub op: String,\n";
    assert_eq!(
        inputs_failure(&init_match, unfinished_source),
        "struct InitRequest: body has no line whose trim is `}`"
    );
    let dangling_attribute_source =
        "pub struct InitRequest {\n    pub op: String,\n    #[serde(default)]\n}\n";
    assert_eq!(
        inputs_failure(&inputs_row("init", "`op`"), dangling_attribute_source),
        "struct InitRequest: attribute line has no field `#[serde(default)]`"
    );

    // The Outputs compare reads the ok side and the error side against the one
    // answer writer. Each in-memory row uses the same writer text.
    fn outputs_row(operation: &str, outputs: &str) -> String {
        format!(
            "| {operation} | in | {outputs} | none: needs no declared right | effect | rule | designed, not enforced |"
        )
    }
    fn answer_contract(structs: &str) -> String {
        const WRITERS: &str = r#"pub fn ok_response(data: Value) -> Value {
    serde_json::json!({
        "status": "ok",
        "data": data,
    })
}

pub fn error_response(code: &str, message: &str) -> Value {
    serde_json::json!({
        "status": "error",
        "code": code,
        "message": message,
    })
}

"#;
        format!("{WRITERS}{structs}")
    }
    fn outputs_failure(
        section: &str,
        contract_source: &str,
        state_source: &str,
        execution_source: &str,
    ) -> String {
        match operations_outputs_match_the_answers(
            section,
            contract_source,
            state_source,
            execution_source,
        ) {
            Err(reason) => reason,
            Ok(()) => panic!("the compare accepts: {section}"),
        }
    }
    let status_struct = "pub struct StatusResponse {\n    pub provider: String,\n    pub protocol_version: String,\n    pub offers_ready: usize,\n}\n";
    let init_outputs = "ok: `status`, `data` (`provider`, `protocol_version`, `offers_ready` from `StatusResponse`). error: `status`, `code`, `message`.";
    let init_row = outputs_row("init", init_outputs);
    let answers = answer_contract(status_struct);
    assert_eq!(
        operations_outputs_match_the_answers(&init_row, &answers, "", ""),
        Ok(())
    );

    // A struct field the cell does not name, and a cell name the struct does
    // not have, each fail with the operation and that name.
    let short_status = status_struct.replace("    pub offers_ready: usize,\n", "");
    let failure = outputs_failure(&init_row, &answer_contract(&short_status), "", "");
    assert_eq!(
        failure,
        "operation `init` ok `data` name `offers_ready` has no partner in the answer"
    );
    assert!(
        failure.contains("init") && failure.contains("offers_ready"),
        "{failure}"
    );
    let long_status = status_struct.replace(
        "    pub offers_ready: usize,\n",
        "    pub offers_ready: usize,\n    pub extra: bool,\n",
    );
    let failure = outputs_failure(&init_row, &answer_contract(&long_status), "", "");
    assert_eq!(
        failure,
        "operation `init` ok `data` key `extra` has no partner in the cell"
    );
    assert!(
        failure.contains("init") && failure.contains("extra"),
        "{failure}"
    );
    // A standalone `skip_serializing_if` keeps the field's key required.
    let run_view_struct = "pub struct RunView {\n    pub schema: String,\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    pub terminal: Option<String>,\n}\n";
    let run_view_row = outputs_row(
        "runs_get",
        "ok: `status`, `data` (`schema`, `terminal` from `RunView`). error: `status`, `code`, `message`.",
    );
    assert_eq!(
        operations_outputs_match_the_answers(
            &run_view_row,
            &answer_contract(run_view_struct),
            "",
            ""
        ),
        Ok(())
    );

    // An error side that drops a key fails.
    let missing_message = init_outputs.replace(
        "error: `status`, `code`, `message`.",
        "error: `status`, `code`.",
    );
    let failure = outputs_failure(&outputs_row("init", &missing_message), &answers, "", "");
    assert_eq!(
        failure,
        "operation `init` error key `message` has no partner in the cell"
    );
    assert!(failure.contains("message"), "{failure}");

    // A changed wrapper key and a reordered pair each fail.
    let renamed_ok = answers.replace("\"data\": data,", "\"result\": data,");
    let failure = outputs_failure(&init_row, &renamed_ok, "", "");
    assert_eq!(
        failure,
        "operation `init` ok name `data` has no partner; the key there is `result`"
    );
    assert!(
        failure.contains("init") && failure.contains("result"),
        "{failure}"
    );
    let reordered_ok = answers.replace(
        "\"status\": \"ok\",\n        \"data\": data,",
        "\"data\": data,\n        \"status\": \"ok\",",
    );
    assert_ne!(reordered_ok, answers, "the reorder must change the writer");
    let failure = outputs_failure(&init_row, &reordered_ok, "", "");
    assert_eq!(
        failure,
        "operation `init` ok name `status` has no partner; the key there is `data`"
    );
    assert!(
        failure.contains("init") && failure.contains("status") && failure.contains("data"),
        "{failure}"
    );

    // The two `json!` rows read their one literal.
    let offers_outputs = "ok: `status`, `data` (`schema`, `provider`, `protocol_version`, `offers`). error: `status`, `code`, `message`.";
    let offers_full = "ok: `status`, `data` (`schema`, `provider`, `protocol_version`, `offers`, `offer_revisions`). error: `status`, `code`, `message`.";
    let offers_state = r#"    pub fn handle_offers_list(&self, request: OffersListRequest) -> Result<Value, ProviderFault> {
        Ok(ok_response(json!({
            "schema": crate::contract::OFFERS_LIST_SCHEMA,
            "provider": PROVIDER_ID,
            "protocol_version": PROVIDER_PROTOCOL_VERSION,
            "offers": offers,
            "offer_revisions": offer_revisions,
        })))
    }

    pub fn handle_runs_create(
"#;
    assert_eq!(
        operations_outputs_match_the_answers(
            &outputs_row("offers_list", offers_full),
            &answers,
            offers_state,
            ""
        ),
        Ok(())
    );
    let failure = outputs_failure(
        &outputs_row("offers_list", offers_outputs),
        &answers,
        offers_state,
        "",
    );
    assert_eq!(
        failure,
        "operation `offers_list` ok `data` key `offer_revisions` has no partner in the cell"
    );
    assert!(
        failure.contains("offers_list") && failure.contains("offer_revisions"),
        "{failure}"
    );
    let shutdown_outputs = "ok: `status`, `data` (`shutdown`). error: `status`, `code`, `message`.";
    let shutdown_arm = r#"            ProviderOperation::Status => self.status_response(),
            ProviderOperation::Shutdown => Ok(ok_response(serde_json::json!({
                "shutdown": true
            }))),
            ProviderOperation::OffersList => {
"#;
    assert_eq!(
        operations_outputs_match_the_answers(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            shutdown_arm
        ),
        Ok(())
    );

    // Commented keys and comment braces cannot make a stale Outputs cell pass.
    // Both comment forms go through the same reader used by every answer.
    for (commented_key, shutdown_value, reason) in [
        (
            "// \"offer_revisions\": offer_revisions,",
            "\"shutdown\": true, // }\n                \"extra\": true",
            "json: line-comment marker `//` is unsupported in the region",
        ),
        (
            "/* \"offer_revisions\": offer_revisions, */",
            "\"shutdown\": true, /* } */\n                \"extra\": true",
            "json: block-comment marker `/*` is unsupported in the region",
        ),
    ] {
        let commented_offers =
            offers_state.replace("\"offer_revisions\": offer_revisions,", commented_key);
        assert_ne!(commented_offers, offers_state);
        assert_eq!(
            outputs_failure(
                &outputs_row("offers_list", offers_full),
                &answers,
                &commented_offers,
                ""
            ),
            reason
        );
        let commented_shutdown = shutdown_arm.replace("\"shutdown\": true", shutdown_value);
        assert_ne!(commented_shutdown, shutdown_arm);
        assert_eq!(
            outputs_failure(
                &outputs_row("shutdown", shutdown_outputs),
                &answers,
                "",
                &commented_shutdown
            ),
            reason
        );
    }

    // The `unsupported` row has only the error side. Any other row without
    // `from` fails.
    assert_eq!(
        operations_outputs_match_the_answers(
            &outputs_row("unsupported", "error: `status`, `code`, `message`."),
            &answers,
            "",
            ""
        ),
        Ok(())
    );
    let failure = outputs_failure(
        &outputs_row(
            "unsupported",
            "ok: `status`, `data`. error: `status`, `code`, `message`.",
        ),
        &answers,
        "",
        "",
    );
    assert!(failure.contains("unsupported"), "{failure}");
    assert_eq!(
        failure,
        "operation `unsupported` has an ok side: ok: `status`, `data`."
    );
    for ok_side in ["ok: success.", "ok:", "success."] {
        assert_eq!(
            outputs_failure(
                &outputs_row(
                    "unsupported",
                    &format!("{ok_side} error: `status`, `code`, `message`.")
                ),
                &answers,
                "",
                ""
            ),
            format!("operation `unsupported` has an ok side: {ok_side}")
        );
    }
    assert_eq!(
        operations_outputs_match_the_answers(
            &outputs_row("unsupported", " \t error: `status`, `code`, `message`."),
            &answers,
            "",
            ""
        ),
        Ok(())
    );
    let failure = outputs_failure(
        &outputs_row(
            "runs_get",
            "ok: `status`, `data` (`schema`). error: `status`, `code`, `message`.",
        ),
        &answers,
        "",
        "",
    );
    assert!(failure.contains("runs_get"), "{failure}");
    assert_eq!(
        failure,
        "operation `runs_get` Outputs ok side names no `from` struct and no answer `json!`"
    );

    // Every cell-layout refusal reports its own exact reason, including a
    // `from` side that lacks the final struct-name span.
    for (cell, reason) in [
        (
            "ok: `status`, `data`.",
            "operation `init` Outputs cell has no `error:` side",
        ),
        (
            "error: `status`, `code`, `message`.",
            "operation `init` Outputs ok side has fewer than two names",
        ),
        (
            "ok: `status`. error: `status`, `code`, `message`.",
            "operation `init` Outputs ok side has fewer than two names",
        ),
        (
            "ok: `status`, `data` from. error: `status`, `code`, `message`.",
            "operation `init` Outputs ok side has `from` without a struct name",
        ),
        (
            "ok: `status`, `data` from `MissingResponse`. error: `status`, `code`, `message`.",
            "operation `init` names struct `MissingResponse`, which `src/contract.rs` does not declare",
        ),
    ] {
        assert_eq!(
            outputs_failure(&outputs_row("init", cell), &answers, "", ""),
            reason
        );
    }

    // The one json reader refuses zero and two literals with separate
    // reasons, and it keeps a nested key inside its value.
    let no_literal = json_literal_keys("fn answer() {}")
        .expect_err("a region with no `json!({` must be refused");
    assert_eq!(no_literal, "json: the region has no `json!({` literal");
    assert!(no_literal.contains("json"), "{no_literal}");
    let two_literals = json_literal_keys("json!({}) json!({})")
        .expect_err("a region with two `json!({` must be refused");
    assert_eq!(
        two_literals,
        "json: the region has 2 `json!({` literals, not one"
    );
    assert!(two_literals.contains("json"), "{two_literals}");
    assert_ne!(
        no_literal, two_literals,
        "each refusal states its own reason"
    );
    assert_eq!(
        json_literal_keys("json!({ \"outer\": { \"inner\": true }, \"next\": 1 })"),
        Ok(vec!["outer".to_string(), "next".to_string()])
    );
    for (region, reason) in [
        (
            "json!({ \"unfinished",
            "json: a string in the literal never closes",
        ),
        ("json!({ \"key\": true", "json: the literal never closes"),
    ] {
        assert_eq!(json_literal_keys(region), Err(reason.to_string()));
    }
    // The refusal covers the whole region: before, within and after the
    // literal, between a key and its colon, and within nested values. The
    // conservative marker rule also refuses markers inside quoted strings.
    for (marker, reason) in [
        (
            "//",
            "json: line-comment marker `//` is unsupported in the region",
        ),
        (
            "/*",
            "json: block-comment marker `/*` is unsupported in the region",
        ),
    ] {
        for region in [
            format!("{marker} json!({{\"key\": true}}) */"),
            format!("{marker} comment */\njson!({{\"key\": true}})"),
            format!("json!({{\"key\": true}}) {marker} comment */"),
            format!("json!({{\"key\" {marker} comment */\n: true}})"),
            format!("json!({{\"outer\": {{{marker} }} */\n\"inner\": true}}}})"),
            format!("json!({{\"key\": \"{marker}\"}})"),
        ] {
            assert_eq!(
                json_literal_keys(&region),
                Err(reason.to_string()),
                "{region}"
            );
        }
    }

    // A character literal cannot hide a key: the reader refuses it, so the
    // stale `shutdown` cell does not pass.
    let hidden_key_arm = r#"            ProviderOperation::Shutdown => Ok(ok_response(serde_json::json!({
                "shutdown": '}' == '}',
                "extra": true
            }))),
            ProviderOperation::OffersList => {
"#;
    assert_eq!(
        outputs_failure(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            hidden_key_arm
        ),
        "json: a character literal is not supported"
    );
    assert_eq!(
        json_literal_keys("json!({ \"shutdown\": '}' == '}', \"extra\": true })"),
        Err("json: a character literal is not supported".to_string())
    );

    // Raw string quotes and backslashes cannot hide an added answer key.
    // Check the reported literal through both the reader and the shutdown
    // compare, then cover raw keys, nested values and all raw string prefixes.
    let raw_shutdown_literal = r##"json!({ "shutdown": r#""}"#, "extra": true })"##;
    assert_eq!(
        json_literal_keys(raw_shutdown_literal),
        Err("json: a raw string literal is not supported".to_string())
    );
    let raw_shutdown_arm = shutdown_arm.replace(
        "json!({\n                \"shutdown\": true\n            })",
        raw_shutdown_literal,
    );
    assert_ne!(raw_shutdown_arm, shutdown_arm);
    assert_eq!(
        outputs_failure(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            &raw_shutdown_arm
        ),
        "json: a raw string literal is not supported"
    );
    for prefix in ["r", "br", "cr"] {
        for hash_count in [0, 1, 2, 255] {
            let hashes = "#".repeat(hash_count);
            // A trailing backslash is literal even with zero hashes. With
            // hashes, an internal quote followed by `}` hides later keys
            // from a scanner that treats it as a normal string's end.
            let contents = if hash_count == 0 { "\\" } else { "\"}" };
            let raw = format!("{prefix}{hashes}\"{contents}\"{hashes}");
            for region in [
                format!("json!({{ \"shutdown\": {raw}, \"extra\": true }})"),
                format!("json!({{ \"shutdown\": {{ \"nested\": {raw} }}, \"extra\": true }})"),
                format!("json!({{ \"shutdown\": [{raw}], \"extra\": true }})"),
                format!("json!({{ {raw}: true, \"extra\": true }})"),
            ] {
                assert_eq!(
                    json_literal_keys(&region),
                    Err("json: a raw string literal is not supported".to_string()),
                    "{region}"
                );
            }
        }
    }
    // Normal strings can contain the same characters, and raw identifiers
    // remain ordinary value expressions.
    assert_eq!(
        json_literal_keys(r##"json!({ "shutdown": "r#\"}\"#", "extra": r#value })"##),
        Ok(vec!["shutdown".to_string(), "extra".to_string()])
    );

    // A function whose name merely starts with the marker's name is not that
    // function: the example's stale keys must not be read.
    let prefix_ok_contract = "\
pub fn ok_response_example(data: Value) -> Value {
    serde_json::json!({
        \"status\": \"ok\",
        \"data\": data,
    })
}

pub fn ok_response(data: Value) -> Value {
    serde_json::json!({
        \"status\": \"ok\",
        \"result\": data,
    })
}

pub fn error_response(code: &str, message: &str) -> Value {
    serde_json::json!({
        \"status\": \"error\",
        \"code\": code,
        \"message\": message,
    })
}
"
    .to_string()
        + status_struct;
    assert_eq!(
        outputs_failure(&init_row, &prefix_ok_contract, "", ""),
        "operation `init` ok name `data` has no partner; the key there is `result`"
    );
    let prefix_error_contract = "\
pub fn ok_response(data: Value) -> Value {
    serde_json::json!({
        \"status\": \"ok\",
        \"data\": data,
    })
}

pub fn error_response_example(code: &str, message: &str) -> Value {
    serde_json::json!({
        \"status\": \"error\",
        \"code\": code,
        \"message\": message,
    })
}

pub fn error_response(code: &str, message: &str) -> Value {
    serde_json::json!({
        \"status\": \"error\",
        \"code\": code,
    })
}
"
    .to_string()
        + status_struct;
    assert_eq!(
        outputs_failure(&init_row, &prefix_error_contract, "", ""),
        "operation `init` error name `message` has no partner in the answer"
    );
    let prefix_offers_state = "\
    pub fn handle_offers_list_example(&self) -> Value {
        json!({
            \"schema\": schema,
            \"provider\": provider,
            \"protocol_version\": version,
            \"offers\": offers,
            \"offer_revisions\": revisions,
        })
    }

    pub fn handle_offers_list(&self) -> Value {
        json!({
            \"schema\": schema,
            \"provider\": provider,
            \"protocol_version\": version,
            \"offers\": offers,
        })
    }
";
    assert_eq!(
        outputs_failure(
            &outputs_row("offers_list", offers_full),
            &answers,
            prefix_offers_state,
            ""
        ),
        "operation `offers_list` ok `data` name `offer_revisions` has no partner in the answer"
    );

    // A missing or doubled declaration is refused with its own reason rather
    // than selecting the first match.
    assert_eq!(
        outputs_failure(&init_row, "pub fn error_response() {}\n", "", ""),
        "the source has no `fn ok_response(` declaration"
    );
    assert_eq!(
        outputs_failure(
            &init_row,
            "pub fn ok_response() {}\npub fn ok_response() {}\n",
            "",
            ""
        ),
        "the source has 2 `fn ok_response(` declarations, not one"
    );
    // The arm selector matches the exact arm name and refuses zero or two.
    assert_eq!(
        outputs_failure(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            "            ProviderOperation::ShutdownExtra => Ok(()),\n"
        ),
        "`src/execution.rs` has no `ProviderOperation::Shutdown =>`"
    );
    assert_eq!(
        outputs_failure(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            "ProviderOperation::Shutdown => x,\nProviderOperation::Shutdown => y,\n"
        ),
        "`src/execution.rs` has 2 `ProviderOperation::Shutdown =>` arms"
    );

    // The region ends at the function's own brace, so a later function with a
    // same-line attribute never supplies the keys.
    let later_declaration_state = "\
    pub fn handle_offers_list() {}

    #[inline] pub fn handle_runs_create(&self) -> Value {
        json!({
            \"schema\": schema,
            \"provider\": provider,
            \"protocol_version\": version,
            \"offers\": offers,
            \"offer_revisions\": revisions,
        })
    }
";
    assert_eq!(
        outputs_failure(
            &outputs_row("offers_list", offers_full),
            &answers,
            later_declaration_state,
            ""
        ),
        "json: the region has no `json!({` literal"
    );

    // A nested declaration does not end the function: both literals are read,
    // so a discarded one cannot stand in for the returned one.
    let nested_ok_contract = "\
pub fn ok_response(data: Value) -> Value {
    let _ = serde_json::json!({
        \"status\": \"ok\",
        \"data\": data,
    });
    fn unused() {}
    serde_json::json!({
        \"status\": \"ok\",
        \"result\": data,
    })
}

pub fn error_response(code: &str, message: &str) -> Value {
    serde_json::json!({
        \"status\": \"error\",
        \"code\": code,
        \"message\": message,
    })
}
"
    .to_string()
        + status_struct;
    assert_eq!(
        outputs_failure(&init_row, &nested_ok_contract, "", ""),
        "json: the region has 2 `json!({` literals, not one"
    );

    // A nested block's close is not the arm's close: both literals are read.
    let nested_shutdown_arm = "\
ProviderOperation::Shutdown => {
    if false {
        let _ = json!({\"shutdown\": true});
    }
    Ok(ok_response(json!({\"renamed\": true})))
}
ProviderOperation::OffersList => {
";
    assert_eq!(
        outputs_failure(
            &outputs_row("shutdown", shutdown_outputs),
            &answers,
            "",
            nested_shutdown_arm
        ),
        "json: the region has 2 `json!({` literals, not one"
    );

    // A region with no opening brace or with no closing brace is refused.
    assert_eq!(
        outputs_failure(&init_row, "pub fn ok_response() ;\n", "", ""),
        "the region has no opening `{`"
    );
    assert_eq!(
        outputs_failure(&init_row, "pub fn ok_response() {\n", "", ""),
        "the region has no closing `}` for its first `{`"
    );

    // An unreadable answer source is an error that names its path.
    let missing_answer = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/no_such_answer_source.rs");
    let failure =
        read_answer_source(&missing_answer).expect_err("a missing answer source must be refused");
    assert!(
        failure.contains(&missing_answer.display().to_string()),
        "{failure}"
    );

    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("CONFINEMENT.md");
    let doc = fs::read_to_string(&doc_path).unwrap_or_else(|err| {
        panic!(
            "CONFINEMENT.md must be readable ({}): {err}",
            doc_path.display()
        )
    });
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/confine/main.rs");
    let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
        panic!(
            "tests/confine/main.rs must be readable ({}): {err}",
            source_path.display()
        )
    });
    let contract_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/contract.rs");
    let contract_source = fs::read_to_string(&contract_path).unwrap_or_else(|err| {
        panic!(
            "src/contract.rs must be readable ({}): {err}",
            contract_path.display()
        )
    });
    let section = operations_section_text(&doc);
    let cited = cited_test_names(section);
    assert!(
        cited.contains(&"generated_profile_denies_the_hosted_connect"),
        "the stand-in citation must be a required test name"
    );
    assert!(
        cited.contains(&"allow_rules_trace_to_declared_rights"),
        "the trace citation must be a required test name"
    );
    require_cited_tests(section, &source);
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let rights = fixture
        .get("rights")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("declared rights must be an array"));
    let right_ids: Vec<&str> = rights.iter().map(entry_id).collect();
    operations_table_cells_stay_lab_claims(section, &right_ids, true)
        .expect("the real operations section keeps its Right and Linux lab claims");
    operations_match_parse_request(section, &contract_source)
        .expect("the real Operation cells equal the parse_request arms");
    operations_inputs_match_the_request_structs(section, &contract_source)
        .expect("the real Inputs cells equal each operation's request struct fields");
    let state_answer_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state.rs");
    let state_answer_source =
        read_answer_source(&state_answer_path).unwrap_or_else(|reason| panic!("{reason}"));
    let execution_answer_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execution.rs");
    let execution_answer_source =
        read_answer_source(&execution_answer_path).unwrap_or_else(|reason| panic!("{reason}"));
    operations_outputs_match_the_answers(
        section,
        &contract_source,
        &state_answer_source,
        &execution_answer_source,
    )
    .expect("the real Outputs cells equal the answer keys");
}

/// The Id cells in `section` are the same set as `ids`.
///
/// An Id cell is the trimmed first cell of a line that starts with `| F-cc`.
/// `Ok` means those cells and `ids` name the same ids. Otherwise one error
/// names each id that is only in the table with `falsifier id is not in the
/// list`, and each id that is only in the list with `falsifier id is not in
/// the table`.
fn falsifier_section_ids_match(section: &str, ids: &[String]) -> Result<(), String> {
    let table: std::collections::BTreeSet<String> = section
        .lines()
        .filter(|line| line.starts_with("| F-cc"))
        .map(|line| line.split('|').nth(1).unwrap_or("").trim().to_string())
        .collect();
    let registered: std::collections::BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    let mut problems = Vec::new();
    for id in &table {
        if !registered.contains(id.as_str()) {
            problems.push(format!("{id} falsifier id is not in the list"));
        }
    }
    for id in &registered {
        if !table.contains(*id) {
            problems.push(format!("{id} falsifier id is not in the table"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// The `## Falsifiers` Id column names each id in `confine-falsifiers.json`.
///
/// The section runs from the heading `## Falsifiers` to the next heading line
/// that starts with `## `, or to the end of the file. The file's Id cells must
/// match the list. A copy of that section that replaces `| F-cc39a |` with
/// `| F-cc-missing |` must report both ids. This test starts no process and
/// needs no sandbox.
///
/// Falsifier: F-cc40a makes `falsifier_section_ids_match` return `Ok` before
/// it compares, so a table that drops `F-cc39a` is accepted.
#[test]
fn falsifier_section_names_every_list_id() {
    fn falsifiers_section(doc: &str) -> String {
        let lines: Vec<&str> = doc.lines().collect();
        let start = lines
            .iter()
            .position(|line| *line == "## Falsifiers")
            .expect("CONFINEMENT.md must hold the heading ## Falsifiers");
        let end = lines[start + 1..]
            .iter()
            .position(|line| line.starts_with("## "))
            .map(|offset| start + 1 + offset)
            .unwrap_or(lines.len());
        lines[start..end].join("\n")
    }

    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("CONFINEMENT.md");
    let doc = fs::read_to_string(&doc_path).unwrap_or_else(|err| {
        panic!(
            "CONFINEMENT.md must be readable ({}): {err}",
            doc_path.display()
        )
    });
    let list_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("confine-falsifiers.json");
    let list_text = fs::read_to_string(&list_path).unwrap_or_else(|err| {
        panic!(
            "confine-falsifiers.json must be readable ({}): {err}",
            list_path.display()
        )
    });
    let list: Value = serde_json::from_str(&list_text)
        .unwrap_or_else(|err| panic!("confine-falsifiers.json must parse: {err}"));
    let entries = list["falsifiers"]
        .as_array()
        .expect("confine-falsifiers.json must hold a falsifiers array");
    let ids: Vec<String> = entries
        .iter()
        .map(|entry| {
            entry["id"]
                .as_str()
                .expect("each falsifier must name an id")
                .to_string()
        })
        .collect();
    let section = falsifiers_section(&doc);
    falsifier_section_ids_match(&section, &ids).expect("the Id column must match the list");
    assert_eq!(
        section.matches("| F-cc39a |").count(),
        1,
        "the section must hold one | F-cc39a | cell"
    );
    let dropped = section.replacen("| F-cc39a |", "| F-cc-missing |", 1);
    let reason = falsifier_section_ids_match(&dropped, &ids)
        .expect_err("a table that drops F-cc39a must be refused");
    assert!(reason.contains("F-cc39a"), "{reason}");
    assert!(reason.contains("F-cc-missing"), "{reason}");
    assert!(
        reason.contains("falsifier id is not in the list"),
        "{reason}"
    );
    assert!(
        reason.contains("falsifier id is not in the table"),
        "{reason}"
    );
    assert!(doc.contains("| F-cc39a |"), "{doc_path:?}");
    assert!(!doc.contains("F-cc-missing"), "{doc_path:?}");
}

/// The confined provider serves `init`, `status` and `offers_list`, and
/// `init` creates the journal root with `runs/` under `STORAGE_ROOT`.
///
/// Every allow rule in `confine.sb` is load-bearing here: each `F-cc1-rm-*`
/// entry in `confine-falsifiers.json` removes one rule and this test fails.
#[test]
fn model_provider_ops_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let storage = Storage::prepare("ops");
    assert!(
        !storage.root.exists(),
        "STORAGE_ROOT must not exist at launch; the provider creates it"
    );
    let mut provider = Provider::start(Launch::Confined(&storage));

    let init = provider.ok(&init_request(&storage, None));
    assert_serving(&init);
    assert!(
        storage.root.join("runs").is_dir(),
        "init must create runs/ under STORAGE_ROOT"
    );

    let status = provider.ok(&json!({ "op": "status" }));
    assert_eq!(status, init, "status must report the initialized provider");

    let listed = provider.ok(&json!({ "op": "offers_list" }));
    let ids: Vec<&Value> = listed["offers"]
        .as_array()
        .expect("offers_list must return an offer array")
        .iter()
        .map(|offer| &offer["id"])
        .collect();
    assert_eq!(
        ids,
        [HOSTED_OFFER],
        "offers_list must return the configured offer: {listed}"
    );

    provider.shutdown();
}

/// After a hosted `init`, an unknown `op` is refused under the oracle and
/// under the stand-in file, and the storage tree is unchanged.
///
/// The request is `{"op":"not_an_op"}`. The answer is `status` `error`,
/// `code` `unsupported_operation`, and message
/// `unsupported model provider operation`. The oracle case uses
/// `Launch::Confined` with `Storage::prepare("unknown-op")`. The stand-in
/// case reads the declared fixture, calls `standin_profile` once, writes
/// that text with `write_standin_profile` under
/// `Storage::prepare("unknown-op-standin")`, and starts with
/// `Launch::Profile` and `canonical_bindings`. The written file has no line
/// that starts with `;;`, and `collect_allow_lines` on that file, sorted,
/// equals the oracle's allow lines, sorted. Both cases pass `assert_serving`
/// on `init`, create `runs/`, take `tree_snapshot` of `STORAGE_ROOT`, send
/// the request, require that snapshot to be unchanged, and call `shutdown`.
/// A launch of the oracle still returns `unsupported_operation`, so this
/// test adds no falsifier. On a host where `sandbox_available` fails, the
/// test returns. This does not say B4 is met.
#[test]
fn model_unknown_op_is_refused_under_profile() {
    /// Hosted `init`, then `{"op":"not_an_op"}`. The storage snapshot stays
    /// the snapshot taken after `init`. Then `shutdown`.
    fn assert_unknown_op_is_refused(case: &str, storage: &Storage, mut provider: Provider) {
        let init = provider.ok(&init_request(storage, None));
        assert_serving(&init);
        assert!(
            storage.root.join("runs").is_dir(),
            "{case}: init must create runs/ under STORAGE_ROOT"
        );
        let after_init = tree_snapshot(&storage.root);

        let refused = provider.request(&json!({ "op": "not_an_op" }));
        assert_eq!(
            refused,
            json!({
                "status": "error",
                "code": "unsupported_operation",
                "message": "unsupported model provider operation"
            }),
            "{case}: an unknown op must be refused: {refused}"
        );
        assert_eq!(
            tree_snapshot(&storage.root),
            after_init,
            "{case}: the unknown op must leave the storage tree after init unchanged"
        );
        provider.shutdown();
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let storage = Storage::prepare("unknown-op");
    let provider = Provider::start(Launch::Confined(&storage));
    assert_unknown_op_is_refused("oracle", &storage, provider);

    let storage = Storage::prepare("unknown-op-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let launched = fs::read_to_string(&profile).unwrap_or_else(|err| {
        panic!("stand-in: the file passed to Launch::Profile must be readable: {err}")
    });
    assert!(
        launched.lines().all(|line| !line.starts_with(";;")),
        "stand-in: the file passed to Launch::Profile has no line that starts with ;;"
    );
    let mut launched_lines = collect_allow_lines(&launched);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("stand-in: the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    launched_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        launched_lines, oracle_lines,
        "stand-in: sorted allow lines must equal the oracle's"
    );
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    assert_unknown_op_is_refused("stand-in", &storage, provider);
}

/// The redirect fixture shared by `model_outside_write_denied`,
/// `model_outside_create_reports_access_denied` and their unconfined control.
/// It creates `STORAGE_ROOT` to hold the link
/// `STORAGE_ROOT/escape`, which points at `STORAGE_PARENT/outside`, a sibling
/// of the journal root. The configured journal path
/// `STORAGE_ROOT/escape/inner` names a place inside the root while it leads
/// outside. `journal.rs` refuses a symlinked journal root, run directory or
/// run file, so the link is an intermediate; it also refuses to create a
/// directory under a symlinked parent, so `outside/inner` is an existing
/// owner-only directory.
struct Redirect {
    storage: Storage,
    outside: PathBuf,
    journal_dir: PathBuf,
    request: Value,
}

impl Redirect {
    fn prepare(label: &str) -> Self {
        let storage = Storage::prepare(label);
        let outside = storage.parent.join("outside");
        owner_only_directory(&storage.root);
        owner_only_directory(&outside.join("inner"));
        fs::write(outside.join("sibling-state"), b"outside sibling state\n")
            .expect("outside sibling file");
        let escape = storage.root.join("escape");
        std::os::unix::fs::symlink(&outside, &escape).expect("escape link");
        let journal_dir = escape.join("inner");
        let request = init_request(&storage, Some(&journal_dir));
        Self {
            storage,
            outside,
            journal_dir,
            request,
        }
    }
}

fn owner_only_directory(path: &Path) {
    fs::create_dir_all(path).expect("fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("owner-only directory");
}

/// Every entry under `dir`, sorted, as its relative path, mode (type and
/// permission bits) and file bytes. Links are recorded, not followed.
fn tree_snapshot(dir: &Path) -> Vec<(PathBuf, u32, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).expect("readable fixture directory") {
            let path = entry.expect("fixture entry").path();
            let metadata = fs::symlink_metadata(&path).expect("fixture metadata");
            let bytes = if metadata.is_file() {
                fs::read(&path).expect("fixture file")
            } else {
                Vec::new()
            };
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            let relative = path.strip_prefix(dir).expect("entry under dir");
            entries.push((relative.to_path_buf(), metadata.mode(), bytes));
        }
    }
    entries.sort();
    entries
}

/// Under the oracle and under the generated stand-in file, an `init` whose
/// journal path leaves `STORAGE_ROOT` through a symlinked intermediate is
/// refused at the metadata inspect. The answer is `journal_corrupt`, the
/// provider's code for an unavailable journal; the provider's log names the
/// redirected path with EPERM (`Operation not permitted`), which is how the
/// macOS sandbox refuses; the outside sibling keeps its entries, modes and
/// bytes; `STORAGE_ROOT/runs` stays absent; a later normal `init` on
/// `STORAGE_ROOT` succeeds; and `shutdown` exits cleanly. The oracle case
/// uses `Launch::Confined`. The generated case reads the declared fixture,
/// writes the stand-in text under that case's storage, and applies that file
/// with `Launch::Profile` and `canonical_bindings`. Each case has its own
/// redirect fixture. The evidence is the lab launcher's. It makes no claim
/// that the Runtime enforced the profile or that B3 is complete.
/// `redirect_journal_materializes_outside_when_unconfined` runs the same
/// fixture and request without the profile, and the journal lands outside.
///
/// Falsifiers: F-cc1a (`(allow default)`) and F-cc1b (the read/write grant
/// widened to `STORAGE_PARENT`) let the oracle case's redirected `init`
/// succeed. F-cc42a makes `write_standin_profile` write an allow-default
/// profile, so the generated case's redirected `init` answers `ok` and this
/// test fails at its refusal assertion.
#[test]
fn model_outside_write_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    for (case, label) in [
        ("oracle", "outside-write-oracle"),
        ("generated", "outside-write-generated"),
    ] {
        let fixture = Redirect::prepare(label);
        let before = tree_snapshot(&fixture.outside);
        let mut provider = match case {
            "oracle" => Provider::start(Launch::Confined(&fixture.storage)),
            "generated" => {
                let fixture_path =
                    Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
                let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
                    panic!(
                        "{case}: the declared-rights fixture {} must be readable: {err}",
                        fixture_path.display()
                    )
                });
                let declared: Value = serde_json::from_str(&fixture_text).unwrap_or_else(|err| {
                    panic!("{case}: the declared-rights fixture must be JSON: {err}")
                });
                let generated = standin_profile(&declared).unwrap_or_else(|err| {
                    panic!("{case}: declared rights must build a profile: {err}")
                });
                let profile = fixture.storage.base.join("standin.sb");
                write_standin_profile(&profile, &generated);
                let binary = resolved(Path::new(PROVIDER_BINARY));
                let bindings = canonical_bindings(&fixture.storage, &binary);
                Provider::start(Launch::Profile {
                    profile: &profile,
                    bindings: &bindings,
                })
            }
            _ => panic!("{case}: the journey names the oracle and the generated case"),
        };

        let denied = provider.request(&fixture.request);
        assert_eq!(
            denied["status"], "error",
            "{case}: the redirected journal write must be refused: {denied}"
        );
        assert_eq!(
            denied["code"], "journal_corrupt",
            "{case}: the refusal must use the provider's unavailable-journal code: {denied}"
        );

        let logged = provider
            .logged_fault("journal_corrupt")
            .unwrap_or_else(|| panic!("{case}: the provider must log the journal_corrupt detail"));
        let refused = format!("{}: Operation not permitted", fixture.journal_dir.display());
        assert!(
            logged.contains(&refused),
            "{case}: the sandbox must refuse the redirected journal path with EPERM: {logged}"
        );

        assert_eq!(
            tree_snapshot(&fixture.outside),
            before,
            "{case}: the outside sibling must keep its entries, modes and bytes"
        );

        assert!(
            !fixture.storage.root.join("runs").exists(),
            "{case}: STORAGE_ROOT/runs must be absent after the refusal"
        );
        let init = provider.request(&init_request(&fixture.storage, None));
        assert_eq!(
            init["status"], "ok",
            "{case}: the later normal init must succeed: {init}"
        );
        assert_serving(&init["data"]);
        assert!(
            fixture.storage.root.join("runs").is_dir(),
            "{case}: the later normal init must use STORAGE_ROOT"
        );
        provider.shutdown();
    }
}

/// The control for `model_outside_write_denied`: the same fixture and
/// request without the profile succeed, and the journal is created under the
/// outside sibling. The profile is the only difference between the two runs.
#[test]
fn redirect_journal_materializes_outside_when_unconfined() {
    let fixture = Redirect::prepare("outside-write-control");
    let mut provider = Provider::start(Launch::Unconfined);

    let init = provider.ok(&fixture.request);
    assert_serving(&init);
    assert!(
        fixture.outside.join("inner").join("runs").is_dir(),
        "without the profile the redirected journal must land under the outside sibling"
    );

    provider.shutdown();
}

/// After `init`, the storage tree is the same after `status`, `offers_list`
/// and `shutdown`, under the committed oracle and under the stand-in file.
///
/// The oracle case calls `Launch::Confined` with
/// `Storage::prepare("status-offers-shutdown")`. The generated case reads the
/// declared fixture, calls `standin_profile`, writes that text with
/// `write_standin_profile` under a fresh
/// `Storage::prepare("status-offers-shutdown-standin")` base, and starts with
/// `Launch::Profile` and `canonical_bindings`. The file passed to
/// `Launch::Profile` has no line that starts with `;;`, and
/// `collect_allow_lines` on that file, sorted, equals the oracle's allow
/// lines, sorted. One local function holds the journey, and both cases call
/// it. The two local compare functions stay in this test; the journey calls
/// them for both cases. Each case answers `init`, then `status` data equals
/// that `init` data, `offers_list` returns the hosted offer id, and the
/// storage-root snapshot after `status`, after `offers_list`, and after
/// `provider.shutdown()` returns equals the snapshot taken after `init`. A
/// failure names the case. The compare uses `tree_snapshot`. The test starts
/// no run and sets no `runtime_hosted_socket`. This is lab stand-in evidence.
///
/// `tree_snapshot` records each relative path, its mode and its file bytes
/// under `storage.root`. A difference names the case, the call, and the
/// relative paths whose mode or bytes differ. On a host where
/// `sandbox_available` fails, the test returns.
#[test]
fn model_status_offers_and_shutdown_leave_storage_unchanged() {
    fn storage_tree_changes(
        before: &[(PathBuf, u32, Vec<u8>)],
        after: &[(PathBuf, u32, Vec<u8>)],
    ) -> Vec<String> {
        let mut changes = Vec::new();
        let mut left = 0;
        let mut right = 0;
        while left < before.len() || right < after.len() {
            match (before.get(left), after.get(right)) {
                (Some(earlier), Some(later)) if earlier.0 == later.0 => {
                    if earlier.1 != later.1 || earlier.2 != later.2 {
                        changes.push(earlier.0.display().to_string());
                    }
                    left += 1;
                    right += 1;
                }
                (Some(earlier), Some(later)) if earlier.0 < later.0 => {
                    changes.push(earlier.0.display().to_string());
                    left += 1;
                }
                (Some(_), Some(later)) => {
                    changes.push(later.0.display().to_string());
                    right += 1;
                }
                (Some(earlier), None) => {
                    changes.push(earlier.0.display().to_string());
                    left += 1;
                }
                (None, Some(later)) => {
                    changes.push(later.0.display().to_string());
                    right += 1;
                }
                (None, None) => break,
            }
        }
        changes
    }

    fn same_storage_tree(
        case: &str,
        call: &str,
        before: &[(PathBuf, u32, Vec<u8>)],
        after: &[(PathBuf, u32, Vec<u8>)],
    ) {
        let paths = storage_tree_changes(before, after).join(", ");
        assert_eq!(
            after, before,
            "{case}: {call} changed the storage tree; relative paths whose mode or bytes differ: {paths}"
        );
    }

    /// `init`, then `status`, `offers_list` and `shutdown`. Each snapshot
    /// after those calls equals the snapshot taken after `init`.
    fn status_offers_and_shutdown(case: &str, storage: &Storage, mut provider: Provider) {
        let init = provider.ok(&init_request(storage, None));
        assert!(
            storage.root.join("runs").is_dir(),
            "{case}: init must create runs/ under STORAGE_ROOT"
        );
        let after_init = tree_snapshot(&storage.root);

        let status = provider.ok(&json!({ "op": "status" }));
        assert_eq!(status, init, "{case}: status data must equal the init data");
        same_storage_tree(case, "status", &after_init, &tree_snapshot(&storage.root));

        let listed = provider.ok(&json!({ "op": "offers_list" }));
        let ids: Vec<&Value> = listed["offers"]
            .as_array()
            .unwrap_or_else(|| panic!("{case}: offers_list must return an offer array"))
            .iter()
            .map(|offer| &offer["id"])
            .collect();
        assert_eq!(
            ids,
            [HOSTED_OFFER],
            "{case}: offers_list must return the configured offer: {listed}"
        );
        same_storage_tree(
            case,
            "offers_list",
            &after_init,
            &tree_snapshot(&storage.root),
        );

        provider.shutdown();
        same_storage_tree(case, "shutdown", &after_init, &tree_snapshot(&storage.root));
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let storage = Storage::prepare("status-offers-shutdown");
    let provider = Provider::start(Launch::Confined(&storage));
    status_offers_and_shutdown("oracle", &storage, provider);

    let storage = Storage::prepare("status-offers-shutdown-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let launched = fs::read_to_string(&profile).unwrap_or_else(|err| {
        panic!("generated: the file passed to Launch::Profile must be readable: {err}")
    });
    assert!(
        launched.lines().all(|line| !line.starts_with(";;")),
        "generated: the file passed to Launch::Profile has no line that starts with ;;"
    );
    let mut launched_lines = collect_allow_lines(&launched);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("generated: the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    launched_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        launched_lines, oracle_lines,
        "generated: sorted allow lines must equal the oracle's"
    );
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    status_offers_and_shutdown("generated", &storage, provider);
}

/// The outside-read fixture's one rule: metadata, never content, of the run
/// record at its outside path. `runs_get` checks that the record exists and
/// is a private regular file before it opens it; this rule lets those checks
/// pass, so the operation the profile refuses is the open that reads the
/// record.
const READ_FIXTURE_RULE: &str =
    r#"(allow file-read-metadata (literal (param "READ_FIXTURE_RECORD")))"#;

/// The one record a single stored run leaves under `runs/`.
fn only_record(runs: &Path) -> PathBuf {
    let records: Vec<PathBuf> = fs::read_dir(runs)
        .expect("readable run directory")
        .map(|entry| entry.expect("run directory entry").path())
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one stored run must leave one record: {records:?}"
    );
    assert!(
        records[0].is_file(),
        "the run record is a file: {records:?}"
    );
    records.into_iter().next().expect("one record")
}

/// Under the profile `runs_get` reads a stored run back from `STORAGE_ROOT`,
/// and the sandbox refuses the same read once the record lives outside it.
/// The outside content open is refused under the oracle and under the
/// stand-in file plus the one metadata rule. The launched stand-in profile
/// has no `;;` line. This evidence is for the lab launcher.
///
/// A first launch under `confine.sb` stores one run of the hosted offer and
/// reads it back: a real content read inside the root. A second launch runs a
/// fixture copy of that oracle that adds only `READ_FIXTURE_RULE`. After its
/// `init`, the test moves `STORAGE_ROOT/runs` to `STORAGE_PARENT/outside/runs`,
/// under a sibling of the journal root, and links `STORAGE_ROOT/runs` to it, so
/// the record's path still names a place inside the root. The link comes after
/// `init` because the provider itself refuses a symlinked run directory
/// there; this test needs the sandbox to decide. The same `runs_get` then
/// answers `journal_corrupt` with no run data, the provider logs EPERM
/// (`Operation not permitted`) for the open that reads the record, the outside
/// sibling keeps its entries and bytes, and the provider still answers
/// `offers_list`. Moved back, the record reads as before.
///
/// After that shutdown, a fresh storage stores the run and reads it back
/// under `Launch::Profile` on the file `standin_profile` writes. The outside
/// denial then runs under `Launch::Fixture` on that file with
/// `READ_FIXTURE_RULE`. The profile that launch applies contains the rule and
/// has no line that starts with `;;`. The in-root create's message is
/// `Hosted external HTTPS is paused.`
///
/// Falsifiers: F-cc1c (the `STORAGE_PARENT` read widened to a subpath) lets
/// the outside read return the run; F-cc1d (the `STORAGE_ROOT` grant without
/// `file-read*`) fails the first `init`, which cannot inspect the journal
/// root; F-cc1e (no fixture rule) stops `runs_get` at the record's existence
/// check (`model run is unreadable`), before the open.
#[test]
fn model_outside_read_denied() {
    /// Both outside denials: `journal_corrupt` with no run data, the open
    /// refused with EPERM, the outside tree unchanged, `offers_list` answered,
    /// and the record read back from `STORAGE_ROOT` after the move. `case`
    /// names a failure.
    #[allow(clippy::too_many_arguments)]
    fn assert_outside_content_read_denied(
        case: &str,
        provider: &mut Provider,
        storage: &Storage,
        run: &HostedRun,
        stored: &Value,
        runs: &Path,
        outside: &Path,
        outside_runs: &Path,
    ) {
        let init = provider.request(&init_request(storage, None));
        assert_eq!(init["status"], "ok", "{case}: init must succeed: {init}");
        assert_serving(&init["data"]);
        owner_only_directory(outside);
        fs::rename(runs, outside_runs)
            .unwrap_or_else(|err| panic!("{case}: move the run directory outside: {err}"));
        std::os::unix::fs::symlink(outside_runs, runs)
            .unwrap_or_else(|err| panic!("{case}: link the run directory: {err}"));
        let before = tree_snapshot(outside);

        let denied = provider.request(&run.get);
        assert_eq!(
            denied["status"], "error",
            "{case}: the outside read must be refused: {denied}"
        );
        assert_eq!(
            denied["code"], "journal_corrupt",
            "{case}: the refusal must use the provider's unavailable-journal code: {denied}"
        );
        assert!(
            denied.get("data").is_none(),
            "{case}: the refusal must return no run data: {denied}"
        );
        let logged = provider
            .logged_fault("journal_corrupt")
            .unwrap_or_else(|| panic!("{case}: the provider must log the journal_corrupt detail"));
        assert!(
            logged.contains("failed to open model run journal: Operation not permitted"),
            "{case}: the sandbox must refuse the open that reads the record with EPERM: {logged}"
        );
        assert_eq!(
            tree_snapshot(outside),
            before,
            "{case}: the outside sibling must keep its entries and bytes"
        );
        let listed = provider.request(&json!({ "op": "offers_list" }));
        assert_eq!(
            listed["status"], "ok",
            "{case}: offers_list must succeed: {listed}"
        );

        fs::remove_file(runs)
            .unwrap_or_else(|err| panic!("{case}: remove the run directory link: {err}"));
        fs::rename(outside_runs, runs)
            .unwrap_or_else(|err| panic!("{case}: move the run directory back: {err}"));
        let reread = provider.request(&run.get);
        assert_eq!(
            reread["status"], "ok",
            "{case}: the record must read back from STORAGE_ROOT: {reread}"
        );
        assert_eq!(
            reread.get("data"),
            Some(stored),
            "{case}: the record must read back from STORAGE_ROOT"
        );
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let storage = Storage::prepare("outside-read");
    let runs = storage.root.join("runs");
    let run = HostedRun::new("request:outside-read");

    let mut provider = Provider::start(Launch::Confined(&storage));
    assert_serving(&provider.ok(&init_request(&storage, None)));
    let created = provider.ok(&run.create);
    assert_eq!(
        created["terminal"]["error"]["message"], "Hosted external HTTPS is paused.",
        "oracle: the binary must refuse hosted dispatch before any socket: {created}"
    );
    let record = only_record(&runs);
    let stored = provider.ok(&run.get);
    assert_eq!(
        stored, created,
        "oracle: runs_get must return the stored run"
    );
    provider.shutdown();

    // The fixture binds the record's exact outside path at launch, which the
    // first launch's stored record names.
    let outside = storage.parent.join("outside");
    let outside_runs = outside.join("runs");
    let outside_record = outside_runs.join(record.file_name().expect("oracle: record name"));
    let fixture = FixtureProfile::write(
        Path::new(PROFILE_PATH),
        &storage,
        READ_FIXTURE_RULE,
        vec![("READ_FIXTURE_RECORD", outside_record)],
    );
    let mut provider = Provider::start(Launch::Fixture(&storage, &fixture));
    assert_outside_content_read_denied(
        "oracle",
        &mut provider,
        &storage,
        &run,
        &stored,
        &runs,
        &outside,
        &outside_runs,
    );
    provider.shutdown();

    let storage = Storage::prepare("outside-read-standin");
    let runs = storage.root.join("runs");
    let run = HostedRun::new("request:outside-read-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let standin = storage.base.join("standin.sb");
    write_standin_profile(&standin, &generated);
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &standin,
        bindings: &bindings,
    });
    assert_serving(&provider.ok(&init_request(&storage, None)));
    let created = provider.ok(&run.create);
    assert_eq!(
        created["terminal"]["error"]["message"], "Hosted external HTTPS is paused.",
        "stand-in: the binary must refuse hosted dispatch before any socket: {created}"
    );
    let record = only_record(&runs);
    let stored = provider.ok(&run.get);
    assert_eq!(
        stored, created,
        "stand-in: runs_get must return the stored run"
    );
    provider.shutdown();

    let outside = storage.parent.join("outside");
    let outside_runs = outside.join("runs");
    let outside_record = outside_runs.join(record.file_name().expect("stand-in: record name"));
    let read_fixture = FixtureProfile::write(
        &standin,
        &storage,
        READ_FIXTURE_RULE,
        vec![("READ_FIXTURE_RECORD", outside_record)],
    );
    let launched = fs::read_to_string(&read_fixture.path)
        .unwrap_or_else(|err| panic!("stand-in: the launched profile must be readable: {err}"));
    assert!(
        launched.contains(READ_FIXTURE_RULE),
        "stand-in: the launched profile must contain the metadata rule"
    );
    assert!(
        launched.lines().all(|line| !line.starts_with(";;")),
        "stand-in: the launched profile must have no line that starts with ;;: {launched}"
    );
    let mut provider = Provider::start(Launch::Fixture(&storage, &read_fixture));
    assert_outside_content_read_denied(
        "stand-in",
        &mut provider,
        &storage,
        &run,
        &stored,
        &runs,
        &outside,
        &outside_runs,
    );
    provider.shutdown();
}

/// Under the oracle and under the generated stand-in file, `runs_events`
/// and a terminal `runs_cancel` load the stored failed run and leave the
/// storage tree unchanged.
///
/// The oracle case is `Launch::Confined` with
/// `Storage::prepare("terminal-read")`. The generated case reads the
/// declared fixture, calls `standin_profile`, writes that text with
/// `write_standin_profile` under a fresh
/// `Storage::prepare("terminal-read-standin")`, and starts with
/// `Launch::Profile` and `canonical_bindings`. The file passed to
/// `Launch::Profile` has no line that starts with `;;`, and its sorted
/// allow lines equal the oracle's. One local function holds the page and
/// cancel assertions, and both cases call it.
///
/// Each case stores one run. `runs_create` sets no `runtime_hosted_socket`
/// and stores the run as failed before any socket. The create data's
/// `terminal.error.message` is `Hosted external HTTPS is paused.`
/// `runs_events` with `after_sequence` 0 returns schema
/// `elastos.model.run-events/v1`, that run's `run_id`, `has_more` false,
/// and a last event whose `kind` is `failed`. `runs_cancel` returns the
/// create data. The storage tree after both calls equals the tree after
/// create. Then `offers_list` answers and `shutdown` exits cleanly. A
/// failure names the case. The test does not call `settle`. A live cancel
/// is not shown: the run is already terminal, so the call does not reach
/// the adapter. This evidence is for the lab launcher.
#[test]
fn model_terminal_run_page_and_cancel_read_under_profile() {
    /// The stored run's page and terminal cancel. `runs_events` and
    /// `runs_cancel` are built from `run.get`, with `after_sequence` 0.
    /// `offers_list` answers and `shutdown` exits cleanly. A failure names
    /// `case`.
    fn assert_terminal_page_and_cancel(
        case: &str,
        mut provider: Provider,
        storage: &Storage,
        run: &HostedRun,
    ) {
        let init = provider.request(&init_request(storage, None));
        assert_eq!(init["status"], "ok", "{case}: init must succeed: {init}");
        assert_serving(&init["data"]);

        let created_response = provider.request(&run.create);
        assert_eq!(
            created_response["status"], "ok",
            "{case}: runs_create must store the run: {created_response}"
        );
        let created = &created_response["data"];
        assert_eq!(
            created["terminal"]["error"]["message"], "Hosted external HTTPS is paused.",
            "{case}: the binary must refuse hosted dispatch before any socket: {created}"
        );
        let after_create = tree_snapshot(&storage.root);

        let events_response = provider.request(&json!({
            "op": "runs_events",
            "run_id": run.get["run_id"].clone(),
            "after_sequence": 0,
            "runtime_binding": run.get["runtime_binding"].clone()
        }));
        assert_eq!(
            events_response["status"], "ok",
            "{case}: runs_events must answer: {events_response}"
        );
        let events = &events_response["data"];
        assert_eq!(
            events["schema"], "elastos.model.run-events/v1",
            "{case}: runs_events must use the run-events schema: {events}"
        );
        assert_eq!(
            events["run_id"], created["run_id"],
            "{case}: runs_events must name the stored run: {events}"
        );
        assert_eq!(
            events["has_more"], false,
            "{case}: the terminal page must not continue: {events}"
        );
        let last = events["events"]
            .as_array()
            .and_then(|page| page.last())
            .unwrap_or_else(|| panic!("{case}: the stored run must keep a last event"));
        assert_eq!(
            last["kind"], "failed",
            "{case}: the last event kind must be failed: {events}"
        );

        let cancelled_response = provider.request(&json!({
            "op": "runs_cancel",
            "run_id": run.get["run_id"].clone(),
            "runtime_binding": run.get["runtime_binding"].clone()
        }));
        assert_eq!(
            cancelled_response["status"], "ok",
            "{case}: runs_cancel must answer: {cancelled_response}"
        );
        assert_eq!(
            &cancelled_response["data"], created,
            "{case}: a terminal runs_cancel must return the stored run"
        );
        assert_eq!(
            tree_snapshot(&storage.root),
            after_create,
            "{case}: runs_events and a terminal runs_cancel must not write"
        );

        let listed = provider.request(&json!({ "op": "offers_list" }));
        assert_eq!(
            listed["status"], "ok",
            "{case}: offers_list must answer: {listed}"
        );
        provider.shutdown();
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let storage = Storage::prepare("terminal-read");
    let run = HostedRun::new("request:terminal-read");
    let provider = Provider::start(Launch::Confined(&storage));
    assert_terminal_page_and_cancel("oracle", provider, &storage, &run);

    let storage = Storage::prepare("terminal-read-standin");
    let run = HostedRun::new("request:terminal-read-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let launched = fs::read_to_string(&profile).unwrap_or_else(|err| {
        panic!("generated: the file passed to Launch::Profile must be readable: {err}")
    });
    assert!(
        launched.lines().all(|line| !line.starts_with(";;")),
        "generated: the file passed to Launch::Profile has no line that starts with ;;: {launched}"
    );
    let mut launched_lines = collect_allow_lines(&launched);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("generated: the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    launched_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        launched_lines, oracle_lines,
        "generated: the stand-in file's allow lines must equal the oracle's"
    );
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    assert_terminal_page_and_cancel("generated", provider, &storage, &run);
}

/// The outside-create fixture's one rule: metadata, never content, of the
/// redirected journal root `STORAGE_PARENT/outside/inner`. `RunJournal::open`
/// inspects that directory, as the journal root and again as the parent of
/// `runs/`, before it creates `runs/`; this rule lets those inspects pass, so
/// the operation the profile refuses is the create. The inspect of `runs/`,
/// which does not exist yet, needs no rule: the sandbox answers it with
/// not-found, and the provider goes on to create it.
const CREATE_FIXTURE_RULE: &str =
    r#"(allow file-read-metadata (literal (param "CREATE_FIXTURE_JOURNAL")))"#;

/// Under the profile the sandbox refuses the redirected journal at the write
/// itself, and the provider then says that access was denied.
///
/// The same journey runs under the oracle copy and under the stand-in file
/// plus the one metadata rule, `CREATE_FIXTURE_RULE`. The oracle case calls
/// `FixtureProfile::write` on `confine.sb` and starts under `Launch::Fixture`.
/// The generated case reads the declared fixture, calls `standin_profile`,
/// writes that text with `write_standin_profile` under that case's storage,
/// and calls the same writer on that file. `Launch::Fixture` applies the
/// file. The launched stand-in copy contains the rule and has no line that
/// starts with `;;`. Each case has its own `Redirect` fixture. With the rule,
/// the `Redirect` request's `init` passes the inspect that
/// `model_outside_write_denied` is refused at, and the refused step is the
/// create of `<journal_dir>/runs` (`fs::create_dir` in
/// `create_missing_journal_directory`, `src/journal.rs`). The answer is
/// `journal_access_denied` with message `model run journal is not writable`.
/// The provider logs that create with EPERM (`Operation not permitted`). The
/// outside sibling keeps its entries, modes and bytes. `STORAGE_ROOT/runs`
/// stays absent. A later normal `init` on `STORAGE_ROOT` succeeds, and
/// `shutdown` exits cleanly. This evidence is for the lab launcher.
/// `redirect_journal_materializes_outside_when_unconfined` is the control: the
/// same fixture and request without a profile create the journal under the
/// outside sibling.
///
/// Falsifiers: F-cc8a (`(allow default)`) edits `confine.sb`, so the oracle
/// copy's redirected `init` answers ok. The stand-in case launches the
/// generated file. F-cc8c keeps `(deny default)` and adds only a `file-write*`
/// grant on `STORAGE_PARENT` in `confine.sb`; the oracle copy's create then
/// succeeds, `runs/` appears under the outside sibling, and the answer is no
/// longer `journal_access_denied`, so this test watches the write grant
/// itself. F-cc8-rm-journal removes the fixture rule; the sandbox then refuses
/// the inspect first, and `init` answers `journal_corrupt`.
#[test]
fn model_outside_create_reports_access_denied() {
    /// Both create denials. `case` names a failure.
    fn assert_outside_create_denied(case: &str, mut provider: Provider, fixture: &Redirect) {
        let before = tree_snapshot(&fixture.outside);
        let denied = provider.request(&fixture.request);
        assert_eq!(
            denied,
            json!({
                "status": "error",
                "code": "journal_access_denied",
                "message": "model run journal is not writable"
            }),
            "{case}: the redirected journal create must be refused as access denied: {denied}"
        );
        let logged = provider
            .logged_fault("journal_access_denied")
            .unwrap_or_else(|| {
                panic!("{case}: the provider must log the journal_access_denied detail")
            });
        let refused = format!(
            "create provider journal directory {} (Operation not permitted",
            fixture.journal_dir.join("runs").display()
        );
        assert!(
            logged.contains(&refused),
            "{case}: the sandbox must refuse the create of runs/ with EPERM: {logged}"
        );
        assert_eq!(
            tree_snapshot(&fixture.outside),
            before,
            "{case}: the outside sibling must keep its entries, modes and bytes"
        );
        assert!(
            !fixture.storage.root.join("runs").exists(),
            "{case}: STORAGE_ROOT/runs must be absent after the refusal"
        );
        let init = provider.request(&init_request(&fixture.storage, None));
        assert_eq!(
            init["status"], "ok",
            "{case}: the later normal init must succeed: {init}"
        );
        assert_serving(&init["data"]);
        assert!(
            fixture.storage.root.join("runs").is_dir(),
            "{case}: the later normal init must use STORAGE_ROOT"
        );
        provider.shutdown();
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let redirect = Redirect::prepare("outside-create");
    // `Storage` resolves its paths, so this is the path the sandbox matches.
    let profile = FixtureProfile::write(
        Path::new(PROFILE_PATH),
        &redirect.storage,
        CREATE_FIXTURE_RULE,
        vec![("CREATE_FIXTURE_JOURNAL", redirect.outside.join("inner"))],
    );
    let provider = Provider::start(Launch::Fixture(&redirect.storage, &profile));
    assert_outside_create_denied("oracle", provider, &redirect);

    let redirect = Redirect::prepare("outside-create-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let standin = redirect.storage.base.join("standin.sb");
    write_standin_profile(&standin, &generated);
    let profile = FixtureProfile::write(
        &standin,
        &redirect.storage,
        CREATE_FIXTURE_RULE,
        vec![("CREATE_FIXTURE_JOURNAL", redirect.outside.join("inner"))],
    );
    let launched = fs::read_to_string(&profile.path)
        .unwrap_or_else(|err| panic!("stand-in: the launched profile must be readable: {err}"));
    assert!(
        launched.contains(CREATE_FIXTURE_RULE),
        "stand-in: the launched profile must contain the metadata rule"
    );
    assert!(
        launched.lines().all(|line| !line.starts_with(";;")),
        "stand-in: the launched profile must have no line that starts with ;;: {launched}"
    );
    let provider = Provider::start(Launch::Fixture(&redirect.storage, &profile));
    assert_outside_create_denied("stand-in", provider, &redirect);
}

/// The local engine fixture shared by
/// `model_local_offer_fails_closed_under_profile` and its unconfined control.
/// The fake engine `base_path/bin/fake-llama-server` and the model
/// `base_path/models/fake.gguf` lie under `base_path`, outside `STORAGE_ROOT`.
/// The request is `init_request` with its offers replaced by the one local
/// offer. Both tests send `init` only, so the engine never starts and its mode
/// is never read.
struct LocalEngine {
    storage: Storage,
    engine_dir: PathBuf,
    model_dir: PathBuf,
    request: Value,
}

impl LocalEngine {
    fn prepare(label: &str) -> Self {
        let storage = Storage::prepare(label);
        let (engine, model, _) = test_support::write_fake_llama_server(&storage.base, "healthy");
        let mut request = init_request(&storage, None);
        request["config"]["extra"]["offers"] = json!([local_offer(&engine, &model)]);
        Self {
            engine_dir: engine.parent().expect("engine folder").to_path_buf(),
            model_dir: model.parent().expect("model folder").to_path_buf(),
            storage,
            request,
        }
    }
}

/// Under the profile, an `init` with a local engine offer fails closed. Its
/// check (`validate_local_artifact` in `src/config.rs`) resolves `base_path`
/// before it reads the engine or the model, and the profile grants no read of
/// `base_path` or the directories above it. So `init` answers
/// `internal_error` within the request timeout, the provider logs
/// `base_path is unavailable`, nothing is written (`STORAGE_ROOT` is never
/// created, and the engine and model folders keep their entries and bytes),
/// and the provider stays in service.
/// `model_local_offer_accepted_when_unconfined` sends the same `init` without
/// the profile, and it succeeds.
///
/// The provider drops the OS error from that step, so the log carries no
/// EPERM. The control and the falsifiers show that the sandbox refused:
/// F-cc7a (`(allow default)`) and F-cc7b (`(deny default)` kept, one
/// `(allow file-read*)` added) each let the same `init` answer ok, and this
/// test fails.
#[test]
fn model_local_offer_fails_closed_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = LocalEngine::prepare("local-offer");
    let engine_before = tree_snapshot(&fixture.engine_dir);
    let model_before = tree_snapshot(&fixture.model_dir);
    let mut provider = Provider::start(Launch::Confined(&fixture.storage));

    let refused = provider.request(&fixture.request);
    assert_eq!(
        refused,
        json!({
            "status": "error",
            "code": "internal_error",
            "message": "model provider failed"
        }),
        "the local offer's init must fail closed"
    );
    // The refused step: `validate_local_artifact` cannot resolve `base_path`.
    let logged = provider
        .logged_fault("internal_error")
        .expect("the provider must log the internal_error detail");
    assert!(
        logged.contains("invalid model provider init config: base_path is unavailable"),
        "init must stop where it resolves base_path: {logged}"
    );

    assert!(
        !fixture.storage.root.exists(),
        "the refused init must write nothing, not even STORAGE_ROOT"
    );
    assert_eq!(
        tree_snapshot(&fixture.engine_dir),
        engine_before,
        "the engine folder must keep its entries and bytes"
    );
    assert_eq!(
        tree_snapshot(&fixture.model_dir),
        model_before,
        "the model folder must keep its entries and bytes"
    );

    assert_serving(&provider.ok(&init_request(&fixture.storage, None)));
    provider.ok(&json!({ "op": "offers_list" }));
    provider.shutdown();
}

/// The control for `model_local_offer_fails_closed_under_profile`: the same
/// fixture and the same `init` without the profile answer ok with the local
/// offer ready. It sends no `runs_create`, so no engine starts. The profile
/// is the only difference between the two runs.
#[test]
fn model_local_offer_accepted_when_unconfined() {
    let fixture = LocalEngine::prepare("local-offer-control");
    let mut provider = Provider::start(Launch::Unconfined);

    assert_serving(&provider.ok(&fixture.request));

    provider.shutdown();
}

/// A stand-in for the Runtime-owned hosted effect socket that an init config
/// names in `runtime_hosted_socket`. It is bound under `/tmp`: the provider
/// refuses a socket path of 104 bytes or more, and a path under the fixture's
/// temporary root comes close to that. It counts each connection when
/// `accept` returns it, before anything is read from it. Then it serves that
/// connection on its own thread, so a connection that sends nothing holds up
/// neither the accept loop nor the final observation: it reads the request to
/// its end, records its request line, and answers as the Runtime refuses one
/// before dispatch, `403` with `X-Elastos-Hosted-Access: refused`. `observe`
/// first takes every connection still queued, so a count of zero means no
/// connection came.
struct RuntimeHostedSocket {
    path: PathBuf,
    listener: Arc<UnixListener>,
    record: Arc<Mutex<Observation>>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

/// What the Runtime socket stand-in saw: every connection it accepted,
/// counted when `accept` returned it, and the request line of each request it
/// read to its end.
#[derive(Clone, Debug, Default, PartialEq)]
struct Observation {
    connections: usize,
    requests: Vec<String>,
}

const STAND_IN_RECORD: &str = "the Runtime socket stand-in's record";

/// The stand-in's one answer: the Runtime's refusal before dispatch.
const HOSTED_EFFECT_REFUSAL: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nX-Elastos-Hosted-Access: refused\r\n\
      Content-Length: 0\r\nConnection: close\r\n\r\n";

impl RuntimeHostedSocket {
    fn bind(label: &str) -> Self {
        let path = resolved(Path::new("/tmp"))
            .join(format!("mp-confine-{label}-{}.sock", std::process::id()));
        // Only a killed run of this process id can have left this path.
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the Runtime socket stand-in");
        listener
            .set_nonblocking(true)
            .expect("a stoppable Runtime socket stand-in");
        let listener = Arc::new(listener);
        let record = Arc::new(Mutex::new(Observation::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let listener = Arc::clone(&listener);
            let record = Arc::clone(&record);
            let stopping = Arc::clone(&stop);
            thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    take_queued(&listener, &record);
                    thread::sleep(Duration::from_millis(10));
                }
            })
        };
        Self {
            path,
            listener,
            record,
            stop,
            server: Some(server),
        }
    }

    /// Stops the accept loop and waits for it to end. A connection that comes
    /// later stays queued on the listener until `observe` takes it.
    fn stop_accepting(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }

    /// The final observation. It stops the accept loop, then accepts every
    /// connection still queued on the listener and counts each one, and
    /// returns the connections counted and the request lines read so far. It
    /// waits for no connection's request.
    fn observe(mut self) -> Observation {
        self.stop_accepting();
        take_queued(&self.listener, &self.record);
        self.record.lock().expect(STAND_IN_RECORD).clone()
    }
}

impl Drop for RuntimeHostedSocket {
    fn drop(&mut self) {
        self.stop_accepting();
        let _ = fs::remove_file(&self.path);
    }
}

/// Accepts the connections queued on `listener` one by one, and admits each,
/// until `accept` returns no connection: none is left, or it failed, as for a
/// connection that gave up before it was accepted. A failed `accept` counts
/// nothing.
fn take_queued(listener: &UnixListener, record: &Arc<Mutex<Observation>>) {
    while let Ok((stream, _)) = listener.accept() {
        admit(stream, record);
    }
}

/// Counts a connection as soon as `accept` returns it, before anything is
/// read from it, then serves it on its own thread, so a connection that sends
/// nothing holds up no other.
fn admit(stream: UnixStream, record: &Arc<Mutex<Observation>>) {
    let record = Arc::clone(record);
    record.lock().expect(STAND_IN_RECORD).connections += 1;
    let serve = move || {
        let request_line = read_request(&stream);
        // The line is recorded before the answer, so a run that settles on
        // this answer always finds it recorded.
        record
            .lock()
            .expect(STAND_IN_RECORD)
            .requests
            .push(request_line);
        let _ = (&stream).write_all(HOSTED_EFFECT_REFUSAL);
    };
    thread::spawn(serve);
}

/// Reads one request to its end, waiting at most `FIXTURE_EVENT_TIMEOUT` for
/// each read, and returns its request line.
fn read_request(stream: &UnixStream) -> String {
    // On macOS an accepted socket keeps the listener's non-blocking mode.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(FIXTURE_EVENT_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let _ = reader.read_line(&mut request_line);
    let mut body_bytes = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                body_bytes = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let _ = reader.read_exact(&mut vec![0; body_bytes]);
    request_line.trim_end().to_string()
}

/// The hosted transport fixture shared by
/// `model_hosted_run_fails_closed_under_profile` and its unconfined control:
/// the Runtime socket stand-in, `init_request` with `runtime_hosted_socket`
/// set to that socket, and one run of the hosted offer.
struct HostedTransport {
    storage: Storage,
    socket: RuntimeHostedSocket,
    request: Value,
    run: HostedRun,
}

impl HostedTransport {
    fn prepare(label: &str) -> Self {
        let storage = Storage::prepare(label);
        let socket = RuntimeHostedSocket::bind(label);
        let mut request = init_request(&storage, None);
        request["config"]["extra"]["runtime_hosted_socket"] = json!(socket.path);
        Self {
            run: HostedRun::new(&format!("request:{label}")),
            storage,
            socket,
            request,
        }
    }
}

/// Under the profile, a hosted run fails closed at its transport. With
/// `runtime_hosted_socket` set, the provider on macOS sends a hosted run's
/// effect request over that Runtime-owned Unix socket
/// (`backend_client_with_socket` and `effect_request` in `src/adapters.rs`),
/// and the profile refuses the connect. The run settles within
/// `FIXTURE_EVENT_TIMEOUT` as `failed`, with `transport_interrupted` and
/// "model backend transport was interrupted"; the socket stand-in's final
/// observation counts no connection; and the provider stays in service.
/// `model_hosted_run_reaches_runtime_socket_when_unconfined` sends the same
/// fixture and requests without the profile, and the request reaches the
/// socket.
///
/// The provider logs no adapter fault, so the evidence is the run's terminal
/// error, the stand-in's count and the control. F-cc10a (`(allow default)`,
/// with `(deny network*)` removed) and F-cc10b (`(deny network*)` becomes
/// `(allow network*)`, nothing else changes) each let the request reach the
/// socket, and this test fails. `(allow default)` alone does not:
/// `(deny network*)` still refuses the connect.
#[test]
fn model_hosted_run_fails_closed_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = HostedTransport::prepare("hosted-run");
    let mut provider = Provider::start(Launch::Confined(&fixture.storage));
    assert_serving(&provider.ok(&fixture.request));

    provider.ok(&fixture.run.create);
    let settled = fixture.run.settle(&mut provider);
    assert_eq!(
        fixture.socket.observe().connections,
        0,
        "the profile must refuse the connect, so no connection reaches the Runtime socket"
    );
    assert_eq!(settled["status"], "failed", "the run must fail: {settled}");
    assert_eq!(
        settled["terminal"]["error"],
        json!({
            "class": "transport_interrupted",
            "code": "transport_interrupted",
            "message": "model backend transport was interrupted"
        }),
        "the refused connect must fail the run closed"
    );

    provider.ok(&json!({ "op": "offers_list" }));
    provider.shutdown();
}

/// The control for `model_hosted_run_fails_closed_under_profile`: the same
/// fixture and requests without the profile. The Runtime socket stand-in
/// counts one connection, whose one request line starts with
/// `POST /v1/hosted-effect `, and the stand-in's refusal settles the run as
/// `hosted_effect_refused`. The profile is the only difference between the
/// two runs. Off macOS the provider refuses every hosted run itself, before
/// any socket, so there this control prints why it did not run.
#[test]
fn model_hosted_run_reaches_runtime_socket_when_unconfined() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted transport control: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let fixture = HostedTransport::prepare("hosted-run-control");
    let mut provider = Provider::start(Launch::Unconfined);
    assert_serving(&provider.ok(&fixture.request));

    provider.ok(&fixture.run.create);
    let settled = fixture.run.settle(&mut provider);
    let observed = fixture.socket.observe();
    assert_eq!(
        observed.connections, 1,
        "without the profile the run must reach the Runtime socket over one connection"
    );
    let received = observed.requests;
    assert!(
        received.len() == 1 && received[0].starts_with("POST /v1/hosted-effect "),
        "without the profile the run's one request must reach the Runtime socket: {received:?}"
    );
    assert_eq!(settled["status"], "failed", "the run must fail: {settled}");
    assert_eq!(
        settled["terminal"]["error"],
        json!({
            "class": "access_refused",
            "code": "hosted_effect_refused",
            "message": "Runtime refused the hosted request before provider dispatch."
        }),
        "the Runtime socket's refusal must settle the run"
    );

    provider.shutdown();
}

/// The Runtime socket stand-in counts a connection when `accept` returns it,
/// before it reads anything. One client connects, sends nothing and stays
/// open. The final observation counts that one connection, with no request
/// line, and it returns in less than half of `FIXTURE_EVENT_TIMEOUT`, the
/// stand-in's read timeout, so it waits for no request. The test uses no
/// provider and no sandbox, so it runs on every Unix host.
///
/// Falsifier: F-cc15a moves the count back to after the request has been
/// read. The silent connection is then not counted, or counted only once its
/// read times out, and this test fails.
#[test]
fn runtime_socket_stand_in_counts_a_silent_connection() {
    let socket = RuntimeHostedSocket::bind("silent-connection");
    let _silent = UnixStream::connect(&socket.path).expect("a silent client of the stand-in");

    let started = Instant::now();
    let observed = socket.observe();
    let took = started.elapsed();
    assert_eq!(
        observed,
        Observation {
            connections: 1,
            requests: Vec::new(),
        },
        "the stand-in must count the silent connection when it accepts it"
    );
    assert!(
        took < FIXTURE_EVENT_TIMEOUT / 2,
        "the final observation must not wait for a request, but it took {took:?}"
    );
}

/// The final observation first takes every connection still queued on the
/// listener. The test stops the stand-in's accept loop, then connects two
/// clients that send nothing. A Unix socket `connect` returns once the
/// connection is queued, so both are still queued when `observe` starts, and
/// only its own accepts can count them. The observation counts two
/// connections and no request line. The test uses no provider and no sandbox.
///
/// Falsifier: F-cc15b removes that first step, so the observation counts
/// neither queued connection, and this test fails.
#[test]
fn runtime_socket_stand_in_drains_queued_connections() {
    let mut socket = RuntimeHostedSocket::bind("queued-connections");
    socket.stop_accepting();
    let _queued: Vec<UnixStream> = (0..2)
        .map(|_| UnixStream::connect(&socket.path).expect("a client queued on the stand-in"))
        .collect();

    assert_eq!(
        socket.observe(),
        Observation {
            connections: 2,
            requests: Vec::new(),
        },
        "the final observation must take and count every connection still queued"
    );
}

/// A connection that sends nothing does not hold up the stand-in's accept
/// loop. A first client connects and stays silent. A second client then sends
/// a whole hosted effect request, and it gets the stand-in's whole `403`
/// answer within half of `FIXTURE_EVENT_TIMEOUT`, the stand-in's read
/// timeout. The final observation counts both connections and records the
/// second one's request line. The test uses no provider and no sandbox.
///
/// Falsifier: F-cc15c serves each connection on the accept loop itself, as
/// the stand-in did before it counted at the accept. The second client then
/// waits behind the silent one's read, and this test fails.
#[test]
fn runtime_socket_stand_in_accepts_behind_a_silent_connection() {
    let socket = RuntimeHostedSocket::bind("behind-silent-connection");
    let _silent = UnixStream::connect(&socket.path).expect("a silent client of the stand-in");
    let mut client = UnixStream::connect(&socket.path).expect("a second client of the stand-in");
    let limit = FIXTURE_EVENT_TIMEOUT / 2;
    client
        .set_read_timeout(Some(limit))
        .expect("a bounded wait for the answer");

    let started = Instant::now();
    client
        .write_all(b"POST /v1/hosted-effect HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        .expect("send the second client's request");
    let mut answer = Vec::new();
    // A read that times out leaves the answer short, and the check says so.
    let _ = client.read_to_end(&mut answer);
    let took = started.elapsed();
    assert!(
        answer == HOSTED_EFFECT_REFUSAL && took < limit,
        "the stand-in must answer a request behind a silent connection within {limit:?}, \
         but it sent {} of {} answer bytes in {took:?}",
        answer.len(),
        HOSTED_EFFECT_REFUSAL.len()
    );

    assert_eq!(
        socket.observe(),
        Observation {
            connections: 2,
            requests: vec!["POST /v1/hosted-effect HTTP/1.1".to_string()],
        },
        "the stand-in must count both connections and record the second one's request line"
    );
}

/// The text a caught panic carries.
fn panic_text(payload: Box<dyn Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .unwrap_or_default()
}

/// The hosted run's wait loop checks its deadline after every reply, terminal
/// or not, and gives each poll only the time left. The test gives the loop a
/// deadline 50 ms ahead and a poll that records the wait it was given, sleeps
/// 100 ms and returns a terminal run. The loop fails with the deadline
/// message, and the first poll was given no more than 50 ms. The test uses no
/// provider and no sandbox, so it runs on every Unix host.
///
/// Falsifiers: F-cc16a returns a terminal reply before the deadline check, so
/// the late run is accepted and this test fails. F-cc16b gives each poll
/// `FIXTURE_EVENT_TIMEOUT` instead of the time left, so the first poll is
/// given more than 50 ms and this test fails.
#[test]
fn hosted_run_wait_fails_a_reply_after_its_deadline() {
    let within = Duration::from_millis(50);
    let deadline = Instant::now() + within;
    let late = json!({ "status": "failed", "terminal": {} });
    let mut waits = Vec::new();
    let settled = catch_unwind(AssertUnwindSafe(|| {
        wait_for_terminal(deadline, within, |wait| {
            waits.push(wait);
            thread::sleep(Duration::from_millis(100));
            Some(late.clone())
        })
    }));
    let failure = match settled {
        Ok(run) => panic!("the wait loop must fail a reply read after its deadline: {run}"),
        Err(payload) => panic_text(payload),
    };
    assert_eq!(
        failure,
        format!("the run must settle within {within:?}: {late}"),
        "a reply read after the deadline must fail with the deadline message"
    );
    assert!(
        waits.first().is_some_and(|wait| *wait <= within),
        "the first poll must be given at most {within:?}, but the polls were given {waits:?}"
    );
}

/// Each `runs_get` of the hosted run's wait loop waits only the time left,
/// on the one receive `answer` uses. The test runs that loop with a deadline
/// 50 ms ahead against the idle launch, which never answers, so `runs_get`
/// gets no answer. The loop fails with the deadline message, and the wait is
/// at least 30 ms and less than half of `FIXTURE_EVENT_TIMEOUT`. The test
/// does not start the provider binary and it needs no sandbox.
///
/// Falsifier: F-cc16c gives that receive `FIXTURE_EVENT_TIMEOUT` again instead
/// of the wait it is given, so `runs_get` waits that long and this test fails.
#[test]
fn hosted_run_wait_times_out_without_a_reply() {
    let mut idle = Provider::start(Launch::Idle);
    let run = HostedRun::new("request:idle-wait");
    let within = Duration::from_millis(50);
    let started = Instant::now();
    let settled = catch_unwind(AssertUnwindSafe(|| {
        run.settle_within(&mut idle, Instant::now() + within, within)
    }));
    let took = started.elapsed();
    let failure = match settled {
        Ok(settled) => panic!("a run with no answer must not settle: {settled}"),
        Err(payload) => panic_text(payload),
    };
    assert_eq!(
        failure,
        format!(
            "the run must settle within {within:?}: no terminal reply came before the deadline"
        ),
        "a run with no answer before the deadline must fail with the deadline message"
    );
    assert!(
        took >= Duration::from_millis(30),
        "the runs_get must wait out the time left ({within:?}), but the wait took {took:?}"
    );
    assert!(
        took < FIXTURE_EVENT_TIMEOUT / 2,
        "the runs_get must wait only the time left ({within:?}), but the wait took {took:?}"
    );
}

/// The stored-copy fixture shared by
/// `model_unbound_program_refused_under_profile` and its control. It creates
/// `STORAGE_ROOT` owner-only, as `Redirect` does, and copies the provider
/// binary directly into it, the one place the profile lets the provider
/// write. `fs::copy` keeps the binary's mode, and the copy has the binary's
/// SHA-256, so the two files differ only by path.
struct StoredCopy {
    storage: Storage,
    binary: PathBuf,
    copy: PathBuf,
}

impl StoredCopy {
    fn prepare(label: &str) -> Self {
        let storage = Storage::prepare(label);
        owner_only_directory(&storage.root);
        let binary = resolved(Path::new(PROVIDER_BINARY));
        let copy = storage
            .root
            .join(binary.file_name().expect("the provider binary's file name"));
        fs::copy(&binary, &copy).expect("copy the provider binary under STORAGE_ROOT");
        let copy = resolved(&copy);
        assert_eq!(
            test_support::sha256_file(&copy),
            test_support::sha256_file(&binary),
            "the copy must be byte-identical to the bound binary"
        );
        Self {
            storage,
            binary,
            copy,
        }
    }
}

/// Under the profile, only the path bound as `PROVIDER_EXECUTABLE` can be
/// started. The test runs `confine.sb` itself, with no fixture rule. It binds
/// the real provider binary as `PROVIDER_EXECUTABLE` and the storage
/// parameters as usual, and starts the byte-identical copy under
/// `STORAGE_ROOT`. `sandbox-exec` applies the profile before it executes its
/// program, so the refused step is that exec of the copy, checked by the same
/// `process-exec` rule as any exec by the confined provider. The copy never
/// answers `init`; `sandbox-exec` exits 71 and logs
/// `execvp() of '<copy>' failed: Operation not permitted`; and `STORAGE_ROOT`
/// keeps only the copy, with no `runs/`. A missing program also exits 71, but
/// with `No such file or directory`, so the test checks the EPERM line.
/// `model_bound_copy_serves_under_profile` is the control: a copy from the
/// same fixture, bound and started, serves.
///
/// Falsifiers: F-cc14a (`(allow default)`), F-cc14b (one `(allow process-exec)`
/// added after the exec rule) and F-cc14c (one
/// `(allow process-exec (subpath (param "STORAGE_ROOT")))` added after it)
/// each let the copy start and answer `init`, and this test fails. F-cc14b and
/// F-cc14c keep the exec rule word for word, so the one shape check still
/// passes them.
#[test]
fn model_unbound_program_refused_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = StoredCopy::prepare("unbound-program");
    let before = tree_snapshot(&fixture.storage.root);
    let mut provider = Provider::start(Launch::Program {
        storage: &fixture.storage,
        executable: &fixture.binary,
        program: &fixture.copy,
        profile: Path::new(PROFILE_PATH),
        bound_digest: None,
    });

    if let Some(answer) = provider.answer(&init_request(&fixture.storage, None)) {
        panic!(
            "the profile must refuse to execute the unbound copy, but it started and \
             answered init with status {} and code {}",
            answer["status"], answer["code"]
        );
    }
    let ended = provider.ended();
    assert_eq!(
        ended.status.and_then(|status| status.code()),
        Some(71),
        "sandbox-exec must exit 71 when the profile refuses the exec: {}",
        describe(ended.status)
    );
    // Quote only `sandbox-exec`'s exec lines, never the whole stream.
    let copy = fixture.copy.display().to_string();
    let execs: Vec<&String> = ended
        .stderr
        .iter()
        .filter(|line| line.contains("execvp()"))
        .collect();
    assert!(
        execs
            .iter()
            .any(|line| line.contains(&copy) && line.contains("Operation not permitted")),
        "sandbox-exec must log the refused exec of {copy} with EPERM: {execs:?}"
    );

    let after = tree_snapshot(&fixture.storage.root);
    let entries: Vec<&Path> = after.iter().map(|(path, ..)| path.as_path()).collect();
    let copy_name = Path::new(fixture.copy.file_name().expect("the copy's file name"));
    assert_eq!(
        entries,
        [copy_name],
        "STORAGE_ROOT must hold only the copy, with no runs/"
    );
    assert!(after == before, "the copy must keep its mode and bytes");
}

/// The control for `model_unbound_program_refused_under_profile`: the same
/// fixture, with the copy at the same place under `STORAGE_ROOT` bound as
/// `PROVIDER_EXECUTABLE` and started under the same `confine.sb`. The copy
/// answers `init` with its offer ready, creates `runs/` beside itself, and
/// exits cleanly after `shutdown`. The binding is the only difference between
/// the two runs. When `sandbox-exec` is missing on a host OS other than macOS
/// it prints a skip reason and returns. On macOS a missing `sandbox-exec`
/// fails the test.
#[test]
fn model_bound_copy_serves_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = StoredCopy::prepare("bound-copy");
    let mut provider = Provider::start(Launch::Program {
        storage: &fixture.storage,
        executable: &fixture.copy,
        program: &fixture.copy,
        profile: Path::new(PROFILE_PATH),
        bound_digest: None,
    });

    assert_serving(&provider.ok(&init_request(&fixture.storage, None)));
    assert!(
        fixture.storage.root.join("runs").is_dir(),
        "init must create runs/ under STORAGE_ROOT beside the copy"
    );
    provider.shutdown();
}

/// The stand-in file refuses an unbound copy.
///
/// The oracle launch stays `model_unbound_program_refused_under_profile`.
/// This launch is the stand-in file. `standin_profile` builds the text,
/// `write_standin_profile` writes it under the storage base, and the written
/// file has no `;;` line. Its sorted allow lines equal the oracle's. The
/// real binary is bound as `PROVIDER_EXECUTABLE` and the copy is started.
/// `init` gets no answer. `sandbox-exec` exits 71 and logs `execvp()` of the
/// copy with `Operation not permitted`. `STORAGE_ROOT` holds only the copy.
/// The launch records the profile path it applies, and that path is the
/// stand-in file.
///
/// Falsifier: F-cc46a makes `Launch::Program` pass the committed oracle to
/// `sandboxed` instead of the profile it was given, so the recorded path is
/// the oracle and this test fails.
#[test]
fn generated_profile_refuses_an_unbound_copy() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = StoredCopy::prepare("standin-unbound-copy");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let declared: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&declared).expect("declared rights build a profile");
    let written = fixture.storage.base.join("standin.sb");
    write_standin_profile(&written, &generated);
    let written_text = fs::read_to_string(&written)
        .unwrap_or_else(|err| panic!("the stand-in file must be readable: {err}"));
    assert!(
        written_text.lines().all(|line| !line.starts_with(";;")),
        "the stand-in file has no comment line"
    );
    let mut written_lines = collect_allow_lines(&written_text);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    written_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        written_lines, oracle_lines,
        "the stand-in file's allow lines must equal the oracle's"
    );

    let before = tree_snapshot(&fixture.storage.root);
    let mut provider = Provider::start(Launch::Program {
        storage: &fixture.storage,
        executable: &fixture.binary,
        program: &fixture.copy,
        profile: &written,
        bound_digest: None,
    });

    if let Some(answer) = provider.answer(&init_request(&fixture.storage, None)) {
        panic!(
            "the profile must refuse to execute the unbound copy, but it started and \
             answered init with status {} and code {}",
            answer["status"], answer["code"]
        );
    }
    let ended = provider.ended();
    assert_eq!(
        ended.status.and_then(|status| status.code()),
        Some(71),
        "sandbox-exec must exit 71 when the profile refuses the exec: {}",
        describe(ended.status)
    );
    let copy = fixture.copy.display().to_string();
    let execs: Vec<&String> = ended
        .stderr
        .iter()
        .filter(|line| line.contains("execvp()"))
        .collect();
    assert!(
        execs
            .iter()
            .any(|line| line.contains(&copy) && line.contains("Operation not permitted")),
        "sandbox-exec must log the refused exec of {copy} with EPERM: {execs:?}"
    );
    assert_eq!(
        applied_profile(),
        written,
        "the launch must apply the stand-in file"
    );

    let after = tree_snapshot(&fixture.storage.root);
    let entries: Vec<&Path> = after.iter().map(|(path, ..)| path.as_path()).collect();
    let copy_name = Path::new(fixture.copy.file_name().expect("the copy's file name"));
    assert_eq!(
        entries,
        [copy_name],
        "STORAGE_ROOT must hold only the copy, with no runs/"
    );
    assert!(after == before, "the copy must keep its mode and bytes");
}

/// The stand-in file serves the copy bound as `PROVIDER_EXECUTABLE`.
///
/// The oracle launch stays `model_bound_copy_serves_under_profile`, which
/// starts the copy under `PROFILE_PATH`. `standin_profile` builds the text,
/// `write_standin_profile` writes it under the storage base, and the written
/// file has no `;;` line. Its sorted allow lines equal the oracle's. The
/// copy is bound as `PROVIDER_EXECUTABLE` and started. `init` passes
/// `assert_serving`, `runs/` exists under `STORAGE_ROOT`, and `shutdown`
/// exits cleanly. After `start`, the recorded profile path is the stand-in
/// file. The evidence is for the lab launcher. It makes no claim that the
/// Runtime enforced the profile or that B3 is complete, and it does not
/// count toward B1. When `sandbox-exec` is missing on a host OS other than
/// macOS it prints a skip reason and returns. On macOS a missing
/// `sandbox-exec` fails the test.
///
/// A plant that points this launch at the committed oracle still answers
/// `init`, so this test has no falsifier. F-cc46a already scores that
/// substitution on `generated_profile_refuses_an_unbound_copy`.
#[test]
fn generated_profile_bound_copy_serves() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare("bound-copy-standin");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let written = stored.storage.base.join("standin.sb");
    write_standin_profile(&written, &generated);
    let written_text = fs::read_to_string(&written)
        .unwrap_or_else(|err| panic!("the stand-in file must be readable: {err}"));
    assert!(
        written_text.lines().all(|line| !line.starts_with(";;")),
        "the launched file has no ;; line"
    );
    let mut written_lines = collect_allow_lines(&written_text);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    written_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        written_lines, oracle_lines,
        "the stand-in file's allow lines must equal the oracle's"
    );

    let mut provider = Provider::start(Launch::Program {
        storage: &stored.storage,
        executable: &stored.copy,
        program: &stored.copy,
        profile: &written,
        bound_digest: None,
    });
    assert_eq!(
        applied_profile(),
        written,
        "the recorded path must be the stand-in file"
    );

    assert_serving(&provider.ok(&init_request(&stored.storage, None)));
    assert!(
        stored.storage.root.join("runs").is_dir(),
        "init must create runs/ under STORAGE_ROOT beside the copy"
    );
    provider.shutdown();
}

/// A byte-different file at the path bound as `PROVIDER_EXECUTABLE` gets past
/// the profile's exec refusal. The profile binds PROVIDER_EXECUTABLE by path.
///
/// The copy is made in a temporary directory, never at the real provider
/// binary's path and never in the directory that holds that binary. Its last
/// byte is flipped, so its digest differs from the real binary. The launch
/// binds the copy and starts it, with `bound_digest: None`, so the helper
/// records the copy as it is. The show is not exit 65, because exit 65 means
/// the profile did not apply, and it is not exit 71 with `execvp()` and
/// `Operation not permitted`. A process still running after 2 seconds, or any
/// other exit, including a signal exit whose `code()` is `None`, is the
/// outcome the test allows. Before the checks, one line starting
/// `byte-different outcome: ` prints the status and the stderr lines. The
/// real binary's digest is unchanged at the end. The test kills and waits on
/// the process `start` returned. It does not call `shutdown`.
#[test]
fn byte_different_file_at_bound_path_starts() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let recorded = record_provider_executable(&binary);
    let root = test_support::temp_root_path("model-provider-confine", "byte-different");
    fs::create_dir_all(&root).expect("temporary directory");
    let root = resolved(&root);
    let binary_dir = binary
        .parent()
        .expect("the provider binary's directory")
        .to_path_buf();
    assert_ne!(
        root, binary_dir,
        "the temporary directory must not be the directory that holds the provider binary"
    );
    let copy_path = root.join(binary.file_name().expect("the provider binary's file name"));
    fs::copy(&binary, &copy_path).expect("copy the provider binary");
    let mut flipped = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&copy_path)
        .unwrap_or_else(|err| panic!("the copy must be writable: {err}"));
    let len = flipped
        .metadata()
        .unwrap_or_else(|err| panic!("the copy's length must be readable: {err}"))
        .len();
    assert!(len > 0, "the copy must have a last byte");
    flipped
        .seek(SeekFrom::End(-1))
        .expect("the copy's last byte must be reachable");
    let mut byte = [0u8; 1];
    flipped
        .read_exact(&mut byte)
        .expect("the copy's last byte must be readable");
    byte[0] = byte[0].wrapping_add(1);
    flipped
        .seek(SeekFrom::End(-1))
        .expect("the copy's last byte must be reachable");
    flipped
        .write_all(&byte)
        .expect("the copy's last byte must change");
    drop(flipped);
    let copy = resolved(&copy_path);
    assert_ne!(
        copy, binary,
        "the copy must not be the real provider binary"
    );
    assert_ne!(
        copy.parent(),
        Some(binary_dir.as_path()),
        "the copy must not sit in the directory that holds the provider binary"
    );
    assert_ne!(
        test_support::sha256_file(&copy),
        recorded,
        "the copy's digest must differ from the real provider binary"
    );

    let storage = Storage::prepare("byte-different-launch");
    let mut provider = Provider::start(Launch::Program {
        storage: &storage,
        executable: &copy,
        program: &copy,
        profile: Path::new(PROFILE_PATH),
        bound_digest: None,
    });
    let (status, stderr) = provider.outcome_within(Duration::from_secs(2));
    println!("byte-different outcome: {status:?} {stderr:?}");
    provider.kill_and_wait();
    let code = status.and_then(|status| status.code());
    assert!(
        code != Some(65),
        "host OS {}: the profile did not apply: status {} is exit 65: {stderr:?}",
        std::env::consts::OS,
        describe(status)
    );
    let refused = code == Some(71)
        && stderr
            .iter()
            .any(|line| line.contains("execvp()") && line.contains("Operation not permitted"));
    assert!(
        !refused,
        "host OS {}: a byte-different file at the bound path gets past the profile's exec \
         refusal, so the launch must not be exit 71 with execvp() and Operation not permitted, \
         but status {} had that refusal: {stderr:?}",
        std::env::consts::OS,
        describe(status)
    );
    assert_eq!(
        test_support::sha256_file(&binary),
        recorded,
        "the real provider binary's digest must be unchanged"
    );
}

/// A byte-different file at the path bound as `PROVIDER_EXECUTABLE` gets past
/// the profile's exec refusal under the file the stand-in writes.
///
/// The oracle launch stays `byte_different_file_at_bound_path_starts`, which
/// starts the flipped copy under `PROFILE_PATH`. This test repeats that copy,
/// the last-byte flip and the directory checks in its own temporary directory.
/// `standin_profile` builds the text, `write_standin_profile` writes it under
/// the storage base, and the written file has no `;;` line. Its sorted allow
/// lines equal the oracle's. The launch binds the flipped copy and starts it,
/// with `bound_digest: None`, under the written file. After `start`, the
/// recorded profile path is that file. The show is not exit 65, because exit
/// 65 means the profile did not apply, and it is not exit 71 with `execvp()`
/// and `Operation not permitted`. Before the checks, one line starting
/// `byte-different stand-in outcome: ` prints the status and the stderr
/// lines. The test kills and waits on the process `start` returned. It does
/// not call `shutdown`. The real binary's digest is unchanged at the end.
/// The evidence is for the lab launcher. It makes no claim that the Runtime
/// enforced the profile or that B3 is complete, and it does not count toward
/// B1. When `sandbox-exec` is missing on a host OS other than macOS it prints
/// a skip reason and returns. On macOS a missing `sandbox-exec` fails the
/// test.
///
/// A plant that points this launch at the committed oracle still gets past
/// the exec refusal, so this test has no falsifier. F-cc46a already scores
/// that substitution on `generated_profile_refuses_an_unbound_copy`.
#[test]
fn generated_profile_starts_a_byte_different_file() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let recorded = record_provider_executable(&binary);
    let root = test_support::temp_root_path("model-provider-confine", "byte-different-standin");
    fs::create_dir_all(&root).expect("temporary directory");
    let root = resolved(&root);
    let binary_dir = binary
        .parent()
        .expect("the provider binary's directory")
        .to_path_buf();
    assert_ne!(
        root, binary_dir,
        "the temporary directory must not be the directory that holds the provider binary"
    );
    let copy_path = root.join(binary.file_name().expect("the provider binary's file name"));
    fs::copy(&binary, &copy_path).expect("copy the provider binary");
    let mut flipped = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&copy_path)
        .unwrap_or_else(|err| panic!("the copy must be writable: {err}"));
    let len = flipped
        .metadata()
        .unwrap_or_else(|err| panic!("the copy's length must be readable: {err}"))
        .len();
    assert!(len > 0, "the copy must have a last byte");
    flipped
        .seek(SeekFrom::End(-1))
        .expect("the copy's last byte must be reachable");
    let mut byte = [0u8; 1];
    flipped
        .read_exact(&mut byte)
        .expect("the copy's last byte must be readable");
    byte[0] = byte[0].wrapping_add(1);
    flipped
        .seek(SeekFrom::End(-1))
        .expect("the copy's last byte must be reachable");
    flipped
        .write_all(&byte)
        .expect("the copy's last byte must change");
    drop(flipped);
    let copy = resolved(&copy_path);
    assert_ne!(
        copy, binary,
        "the copy must not be the real provider binary"
    );
    assert_ne!(
        copy.parent(),
        Some(binary_dir.as_path()),
        "the copy must not sit in the directory that holds the provider binary"
    );
    assert_ne!(
        test_support::sha256_file(&copy),
        recorded,
        "the copy's digest must differ from the real provider binary"
    );

    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let storage = Storage::prepare("byte-different-standin-launch");
    let written = storage.base.join("standin.sb");
    write_standin_profile(&written, &generated);
    let written_text = fs::read_to_string(&written)
        .unwrap_or_else(|err| panic!("the stand-in file must be readable: {err}"));
    assert!(
        written_text.lines().all(|line| !line.starts_with(";;")),
        "the launched file has no ;; line"
    );
    let mut written_lines = collect_allow_lines(&written_text);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    written_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        written_lines, oracle_lines,
        "the stand-in file's allow lines must equal the oracle's"
    );

    let mut provider = Provider::start(Launch::Program {
        storage: &storage,
        executable: &copy,
        program: &copy,
        profile: &written,
        bound_digest: None,
    });
    assert_eq!(
        applied_profile(),
        written,
        "the recorded path must be the stand-in file"
    );
    let (status, stderr) = provider.outcome_within(Duration::from_secs(2));
    println!("byte-different stand-in outcome: {status:?} {stderr:?}");
    provider.kill_and_wait();
    let code = status.and_then(|status| status.code());
    assert!(
        code != Some(65),
        "host OS {}: the profile did not apply: status {} is exit 65: {stderr:?}",
        std::env::consts::OS,
        describe(status)
    );
    let refused = code == Some(71)
        && stderr
            .iter()
            .any(|line| line.contains("execvp()") && line.contains("Operation not permitted"));
    assert!(
        !refused,
        "host OS {}: a byte-different file at the bound path gets past the profile's exec \
         refusal, so the launch must not be exit 71 with execvp() and Operation not permitted, \
         but status {} had that refusal: {stderr:?}",
        std::env::consts::OS,
        describe(status)
    );
    assert_eq!(
        test_support::sha256_file(&binary),
        recorded,
        "the real provider binary's digest must be unchanged"
    );
}

/// The launch helper refuses to start when the file bound as
/// `PROVIDER_EXECUTABLE` no longer has the digest it recorded.
///
/// The test copies `/usr/bin/true` into a temporary directory, records its
/// sha256, and appends one byte. `Launch::Program` passes that recorded
/// digest and the changed path as both executable and program. The helper
/// panics before `spawn`. The panic names `PROVIDER_EXECUTABLE digest
/// mismatch`, the path, and both digests. That refusal is a lab stand-in
/// for the Runtime's launch-by-hash check, not the Runtime's check. This
/// stand-in counts toward no M1 check. If `start` returns, the test kills
/// and waits, then fails because the helper started the changed file. The
/// test does not call `sandbox_available` and does not need `sandbox-exec`.
///
/// Falsifier: F-cc29a skips the digest compare in
/// `refuse_changed_provider_executable`, so the changed file starts and this
/// test fails.
#[test]
fn bound_executable_digest_mismatch_refuses_start() {
    let root = test_support::temp_root_path("model-provider-confine", "digest-mismatch");
    fs::create_dir_all(&root).expect("temporary directory");
    let program = resolved(&root).join("true");
    fs::copy("/usr/bin/true", &program).expect("copy /usr/bin/true");
    let program = resolved(&program);
    let recorded = record_provider_executable(&program);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&program)
        .unwrap_or_else(|err| panic!("the copy must be open for append: {err}"));
    file.write_all(&[0])
        .expect("append one byte to the bound file");
    drop(file);
    let now = test_support::sha256_file(&program);
    assert_ne!(now, recorded, "the changed file's digest must differ");

    let storage = Storage::prepare("digest-mismatch");
    let path = program.display().to_string();
    let settled = catch_unwind(AssertUnwindSafe(|| {
        Provider::start(Launch::Program {
            storage: &storage,
            executable: &program,
            program: &program,
            profile: Path::new(PROFILE_PATH),
            bound_digest: Some(recorded.clone()),
        })
    }));
    match settled {
        Err(payload) => {
            let failure = panic_text(payload);
            assert!(
                failure.contains("PROVIDER_EXECUTABLE digest mismatch")
                    && failure.contains(&path)
                    && failure.contains(&recorded)
                    && failure.contains(&now),
                "the refusal must name the mismatch, the path and both digests: {failure}"
            );
        }
        Ok(mut provider) => {
            provider.kill_and_wait();
            panic!("the helper started the changed file");
        }
    }
}

/// One launch whose profile cannot be applied is refused, and the refusal
/// says why.
///
/// `answer` of `init` is `None`, then `ended` reports exit status 65. One
/// stderr line starts with `sandbox-exec: ` and contains `marker`. No stderr
/// line contains `execvp()`, and `STORAGE_PARENT` stays empty. The messages
/// name `case` and quote no `sandbox-exec` line.
fn assert_startup_is_refused(case: &str, launch: Launch<'_>, storage: &Storage, marker: &str) {
    let mut provider = Provider::start(launch);
    let answer = provider.answer(&init_request(storage, None));
    assert!(answer.is_none(), "{case}: init must get no answer");
    let ended = provider.ended();
    assert_eq!(
        ended.status.and_then(|status| status.code()),
        Some(65),
        "{case}: sandbox-exec must exit 65 when the profile cannot be applied: {}",
        describe(ended.status)
    );
    assert!(
        ended
            .stderr
            .iter()
            .any(|line| line.starts_with("sandbox-exec: ") && line.contains(marker)),
        "{case}: one stderr line must start with sandbox-exec and contain {marker:?}"
    );
    assert!(
        ended.stderr.iter().all(|line| !line.contains("execvp()")),
        "{case}: sandbox-exec must stop before it executes the provider"
    );
    let mut parent = fs::read_dir(&storage.parent)
        .unwrap_or_else(|err| panic!("{case}: STORAGE_PARENT must stay readable: {err}"));
    assert!(
        parent.next().is_none(),
        "{case}: STORAGE_PARENT must stay empty"
    );
}

/// Joins this provider's profile text from the approved declared rights.
///
/// The text is `(version 1)`, then `(deny default)`, then `(deny network*)`,
/// then each rule of each rights entry, then each rule of each
/// platform-baseline entry. It reads no file and checks no right id.
fn standin_profile(declared: &Value) -> Result<String, String> {
    let Some(rights) = declared.get("rights").and_then(Value::as_array) else {
        return Err("model-provider declared rights must hold a rights list".to_string());
    };
    let Some(baseline) = declared
        .get("platform_baseline")
        .and_then(|baseline| baseline.get("rules"))
        .and_then(Value::as_array)
    else {
        return Err("model-provider platform baseline must hold a rules list".to_string());
    };
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    for entry in rights.iter().chain(baseline) {
        let Some(rules) = entry.get("rules").and_then(Value::as_array) else {
            return Err("model-provider declares an entry without a rules list".to_string());
        };
        for rule in rules {
            let Some(rule) = rule.as_str() else {
                return Err("model-provider declares a rule that is not a string".to_string());
            };
            profile.push_str(rule);
            profile.push('\n');
        }
    }
    Ok(profile)
}

fn write_standin_profile(path: &Path, generated: &str) {
    fs::write(path, generated).expect("write the generated profile");
}

/// A launch whose profile cannot be applied never starts the provider.
///
/// The one launcher starts the real binary three ways: a profile path under
/// the test's temporary root that does not exist, a copy of `confine.sb` with
/// its last `)` removed, and `confine.sb` itself with the canonical bindings
/// minus `STORAGE_ROOT`. In each case `sandbox-exec` exits 65 before the
/// exec, `init` gets no answer, and nothing is written.
///
/// Falsifier: F-cc19a makes `sandboxed` start the program directly when the
/// profile file does not exist, so case (a) answers `init` and this test
/// fails at its first check. F-cc19b makes `Provider::ended` keep none of the
/// stderr lines it reads, so case (a) still exits 65 and this test fails
/// because no line gives the reason.
#[test]
fn startup_is_refused_when_the_profile_cannot_be_applied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let storage = Storage::prepare("profile-cannot-apply");
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let canonical = canonical_bindings(&storage, &binary);
    let missing = storage.base.join("missing.sb");
    assert!(
        !missing.exists(),
        "(a) the profile file does not exist: the profile path must be absent"
    );
    let source = fs::read_to_string(PROFILE_PATH).unwrap_or_else(|err| {
        panic!("(b) the profile does not parse: the profile source must be readable: {err}")
    });
    let trimmed = source.trim_end();
    assert!(
        trimmed.ends_with(')'),
        "(b) the profile does not parse: the profile source must end with ')'"
    );
    let broken = storage.base.join("broken.sb");
    fs::write(&broken, &trimmed[..trimmed.len() - 1]).unwrap_or_else(|err| {
        panic!("(b) the profile does not parse: the copy must be writable: {err}")
    });
    let without_root: Vec<(&'static str, PathBuf)> = canonical
        .iter()
        .filter(|(name, _)| *name != "STORAGE_ROOT")
        .cloned()
        .collect();

    assert_startup_is_refused(
        "(a) the profile file does not exist",
        Launch::Profile {
            profile: &missing,
            bindings: &canonical,
        },
        &storage,
        &missing.display().to_string(),
    );
    assert_startup_is_refused(
        "(b) the profile does not parse",
        Launch::Profile {
            profile: &broken,
            bindings: &canonical,
        },
        &storage,
        "expecting ')'",
    );
    assert_startup_is_refused(
        "(c) the profile names an unbound parameter",
        Launch::Profile {
            profile: Path::new(PROFILE_PATH),
            bindings: &without_root,
        },
        &storage,
        "invalid data type of path filter",
    );
}

/// The lab stand-in builds this provider's profile from the approved declared
/// rights, and that text's head and allow lines match the oracle.
///
/// The first three non-comment lines are `(version 1)`, `(deny default)` and
/// `(deny network*)`. The sorted allow lines equal the oracle. The sorted
/// non-comment lines equal the oracle. An in-memory extra deny appends
/// `(deny file-read* (literal "/tmp/cc-extra-deny"))`. Its sorted allow lines
/// still equal the oracle, and its sorted non-comment lines do not. The extra
/// side contains `cc-extra-deny`. A changed
/// `bound-executable` rule is reflected. A declared value with no rights
/// list, a platform baseline with no rules list, an entry with no rules list,
/// and a rule that is not a string are each refused with their reason. The
/// test starts no process and needs no sandbox.
///
/// Falsifier: F-cc41a makes `standin_profile` return the oracle file and
/// ignore the declared value, so a changed declared rule still matches the
/// oracle. F-cc48a appends
/// `(allow file-read-data (literal "/tmp/cc-standin-extra"))` after the
/// joined rules, so `generated_model_profile_matches_the_oracle` fails at
/// the sorted allow-line compare.
#[test]
fn generated_model_profile_matches_the_oracle() {
    fn non_comment_head(profile: &str) -> Vec<&str> {
        non_comment_lines(profile).into_iter().take(3).collect()
    }

    let head = vec!["(version 1)", "(deny default)", "(deny network*)"];
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    assert_eq!(non_comment_head(&generated), head);
    assert_eq!(non_comment_head(&oracle), head);
    let mut generated_lines = collect_allow_lines(&generated);
    let mut oracle_lines = collect_allow_lines(&oracle);
    generated_lines.sort();
    oracle_lines.sort();
    assert_eq!(generated_lines, oracle_lines);
    let mut generated_non_comment = non_comment_lines(&generated);
    let mut oracle_non_comment = non_comment_lines(&oracle);
    generated_non_comment.sort();
    oracle_non_comment.sort();
    assert_eq!(generated_non_comment, oracle_non_comment);

    let mut extra = generated.clone();
    extra.push_str("(deny file-read* (literal \"/tmp/cc-extra-deny\"))\n");
    let mut extra_allow = collect_allow_lines(&extra);
    extra_allow.sort();
    assert_eq!(extra_allow, oracle_lines);
    let mut extra_non_comment = non_comment_lines(&extra);
    extra_non_comment.sort();
    assert_ne!(extra_non_comment, oracle_non_comment);
    assert!(
        extra_non_comment
            .iter()
            .any(|line| line.contains("cc-extra-deny")),
        "the extra deny stays on the extra side"
    );

    let original_exec = "(allow process-exec (literal (param \"PROVIDER_EXECUTABLE\")))";
    let stub_exec = "(allow process-exec (literal \"/tmp/cc-standin-stub\"))";
    let mut changed = fixture.clone();
    let rights = changed
        .get_mut("rights")
        .and_then(Value::as_array_mut)
        .expect("declared rights must hold a rights list");
    let mut replaced = false;
    for entry in rights {
        if entry.get("id").and_then(Value::as_str) != Some("bound-executable") {
            continue;
        }
        let rules = entry
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("bound-executable holds a rules list");
        for rule in rules {
            if rule.as_str() == Some(original_exec) {
                *rule = json!(stub_exec);
                replaced = true;
            }
        }
    }
    assert!(replaced, "the bound-executable rule is replaced in memory");
    let changed_profile =
        standin_profile(&changed).expect("the changed declared value builds a profile");
    let changed_lines = collect_allow_lines(&changed_profile);
    assert_eq!(
        changed_lines
            .iter()
            .filter(|line| **line == stub_exec)
            .count(),
        1,
        "the stub exec rule is present once"
    );
    assert!(
        changed_lines.iter().all(|line| *line != original_exec),
        "the original exec rule is absent"
    );
    assert!(
        generated.lines().all(|line| !line.starts_with(";;")),
        "the stand-in profile emits no comment line"
    );

    let mut rights_not_a_list = fixture.clone();
    rights_not_a_list["rights"] = json!("not-a-list");
    assert_eq!(
        standin_profile(&rights_not_a_list).expect_err("rights that are not a list are refused"),
        "model-provider declared rights must hold a rights list"
    );
    let mut baseline_not_a_list = fixture.clone();
    baseline_not_a_list["platform_baseline"]["rules"] = json!("not-a-list");
    assert_eq!(
        standin_profile(&baseline_not_a_list)
            .expect_err("a platform baseline that is not a rules list is refused"),
        "model-provider platform baseline must hold a rules list"
    );
    let mut entry_without_rules = fixture.clone();
    entry_without_rules["rights"][0]
        .as_object_mut()
        .expect("a rights entry is an object")
        .remove("rules");
    assert_eq!(
        standin_profile(&entry_without_rules)
            .expect_err("an entry without a rules list is refused"),
        "model-provider declares an entry without a rules list"
    );
    let mut rule_not_a_string = fixture.clone();
    rule_not_a_string["rights"][0]["rules"][0] = json!(1);
    assert_eq!(
        standin_profile(&rule_not_a_string).expect_err("a rule that is not a string is refused"),
        "model-provider declares a rule that is not a string"
    );
}

/// The file `Launch::Profile` applies has the oracle's sorted allow lines
/// and its sorted non-comment lines.
///
/// `standin_profile` builds the text from the approved declared rights.
/// `write_standin_profile` writes it at `storage.base.join("standin.sb")`.
/// The written file has no `;;` line. Before `Provider::start`, that file's
/// sorted allow lines equal the oracle's, and its sorted non-comment lines
/// equal the oracle's. `Launch::Profile` applies that
/// file with `canonical_bindings`. Hosted `init` passes `assert_serving` and
/// creates `runs/`. `applied_profile()` is that path, and the bytes there
/// have the same sorted allow lines and the same sorted non-comment lines.
///
/// Falsifier: F-cc51a appends
/// `(allow file-read-data (literal "/tmp/cc-launched-extra"))` inside
/// `sandboxed` after the path is recorded, so
/// `generated_profile_launch_matches_the_oracle` fails at the post-start
/// allow-line compare. F-cc52a drops `(deny network*)` inside `sandboxed`
/// after the path is recorded, so the same test fails at the post-start
/// non-comment compare.
#[test]
fn generated_profile_launch_matches_the_oracle() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let storage = Storage::prepare("standin-launched-file");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let written = fs::read_to_string(&profile)
        .unwrap_or_else(|err| panic!("the stand-in file must be readable: {err}"));
    assert!(
        written.lines().all(|line| !line.starts_with(";;")),
        "the stand-in file has no comment line"
    );
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let mut written_lines = collect_allow_lines(&written);
    let mut oracle_lines = collect_allow_lines(&oracle);
    written_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        written_lines, oracle_lines,
        "the stand-in file's allow lines must equal the oracle's before start"
    );
    let mut written_non_comment = non_comment_lines(&written);
    let mut oracle_non_comment = non_comment_lines(&oracle);
    written_non_comment.sort();
    oracle_non_comment.sort();
    assert_eq!(
        written_non_comment, oracle_non_comment,
        "the stand-in file's non-comment lines must equal the oracle's before start"
    );
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    assert_serving(&provider.ok(&init_request(&storage, None)));
    assert!(
        storage.root.join("runs").is_dir(),
        "init must create runs/ under STORAGE_ROOT"
    );
    assert_eq!(
        applied_profile(),
        profile,
        "the launch records the stand-in file"
    );
    let launched = fs::read_to_string(applied_profile())
        .unwrap_or_else(|err| panic!("the launched profile must be readable: {err}"));
    let mut launched_lines = collect_allow_lines(&launched);
    launched_lines.sort();
    assert_eq!(
        launched_lines, oracle_lines,
        "the launched file's allow lines must equal the oracle's"
    );
    let mut launched_non_comment = non_comment_lines(&launched);
    let mut launched_oracle_non_comment = non_comment_lines(&oracle);
    launched_non_comment.sort();
    launched_oracle_non_comment.sort();
    assert_eq!(
        launched_non_comment, launched_oracle_non_comment,
        "the launched file's non-comment lines must equal the oracle's"
    );
    provider.shutdown();
}

/// The profile the stand-in builds is the file `Launch::Profile` applies.
///
/// A hosted `init` answers through `assert_serving` and creates `runs/`
/// under `STORAGE_ROOT`. A local-offer `init` answers `internal_error`
/// with message `model provider failed`, the log contains
/// `base_path is unavailable`, and `STORAGE_ROOT` does not exist. The
/// same provider then accepts a hosted `init`, `offers_list` answers, and
/// `shutdown` exits cleanly.
///
/// Falsifier: F-cc42a makes `write_standin_profile` write an allow-default
/// profile and ignore the generated text, so the local offer's `init`
/// answers ok.
#[test]
fn generated_profile_permits_init_and_denies_the_local_offer() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let binary = resolved(Path::new(PROVIDER_BINARY));

    let storage = Storage::prepare("standin-permit");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let bindings = canonical_bindings(&storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    assert_serving(&provider.ok(&init_request(&storage, None)));
    assert!(
        storage.root.join("runs").is_dir(),
        "init must create runs/ under STORAGE_ROOT"
    );
    provider.shutdown();

    let local = LocalEngine::prepare("standin-local-offer");
    let profile = local.storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let bindings = canonical_bindings(&local.storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    let refused = provider.request(&local.request);
    assert_eq!(
        refused,
        json!({
            "status": "error",
            "code": "internal_error",
            "message": "model provider failed"
        }),
        "the local offer's init must fail closed"
    );
    let logged = provider
        .logged_fault("internal_error")
        .expect("the provider must log the internal_error detail");
    assert!(
        logged.contains("invalid model provider init config: base_path is unavailable"),
        "init must stop where it resolves base_path: {logged}"
    );
    assert!(
        !local.storage.root.exists(),
        "the refused init must create no STORAGE_ROOT"
    );
    assert_serving(&provider.ok(&init_request(&local.storage, None)));
    provider.ok(&json!({ "op": "offers_list" }));
    provider.shutdown();
}

/// A declared value with no rights list is refused, and a generated profile
/// that does not parse never starts the provider.
///
/// `standin_profile` on `json!({})` returns an error that contains
/// `model-provider` and `rights`. That call starts no provider. `{}` has no
/// `rights` key. `generated_model_profile_matches_the_oracle` already refuses
/// a present `rights` value that is not a list, on this same line. When the
/// sandbox is present, the real fixture's generated text loses its last `)`,
/// `write_standin_profile` writes that text, and `assert_startup_is_refused`
/// reads exit 65 with marker `expecting ')'`.
///
/// Falsifier: F-cc43a makes `standin_profile` return an empty profile when
/// the rights list is missing, so this test fails before any launch, and
/// `generated_model_profile_matches_the_oracle` fails on the same line.
/// F-cc42a makes `write_standin_profile` write an allow-default profile and
/// ignore the generated text, so this launch does not exit 65.
#[test]
fn standin_refuses_a_start_it_cannot_apply() {
    let refused =
        standin_profile(&json!({})).expect_err("a declared value with no rights list is refused");
    assert!(
        refused.contains("model-provider") && refused.contains("rights"),
        "the refusal must name the provider and the rights list: {refused}"
    );

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let trimmed = generated.trim_end();
    assert!(
        trimmed.ends_with(')'),
        "the generated profile does not parse: the generated text must end with ')'"
    );
    let broken = &trimmed[..trimmed.len() - 1];
    let storage = Storage::prepare("standin-cannot-apply");
    let profile = storage.base.join("standin.sb");
    write_standin_profile(&profile, broken);
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    assert_startup_is_refused(
        "the generated profile does not parse",
        Launch::Profile {
            profile: &profile,
            bindings: &bindings,
        },
        &storage,
        "expecting ')'",
    );
}

/// A generated profile with `STORAGE_ROOT` unbound never starts the provider.
///
/// `standin_profile` builds the text from the approved declared rights.
/// `write_standin_profile` writes it at `storage.base.join("standin.sb")`,
/// outside `STORAGE_PARENT`. The written file has no `;;` line, and its
/// sorted allow lines equal the oracle's. The bindings are
/// `canonical_bindings` with the `STORAGE_ROOT` pair removed, so
/// `PROVIDER_EXECUTABLE` stays the real binary and `STORAGE_PARENT` stays.
/// `assert_startup_is_refused` reads exit 65 and the marker
/// `invalid data type of path filter`. The launch records the profile path
/// it applies, and that path is the stand-in file. This evidence is for the
/// lab launcher.
///
/// Falsifier: F-cc47a makes this launch use the committed oracle instead of
/// the stand-in file. Both files exit 65. The recorded path is the oracle,
/// so this test fails.
#[test]
fn generated_profile_refuses_an_unbound_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&fixture).expect("declared rights build a profile");
    let storage = Storage::prepare("standin-unbound-root");
    let unbound_root_profile = storage.base.join("standin.sb");
    write_standin_profile(&unbound_root_profile, &generated);
    let written_text = fs::read_to_string(&unbound_root_profile)
        .unwrap_or_else(|err| panic!("the stand-in file must be readable: {err}"));
    assert!(
        written_text.lines().all(|line| !line.starts_with(";;")),
        "the stand-in file has no comment line"
    );
    let mut written_lines = collect_allow_lines(&written_text);
    let oracle = fs::read_to_string(PROFILE_PATH)
        .unwrap_or_else(|err| panic!("the profile oracle must be readable: {err}"));
    let mut oracle_lines = collect_allow_lines(&oracle);
    written_lines.sort();
    oracle_lines.sort();
    assert_eq!(
        written_lines, oracle_lines,
        "the stand-in file's allow lines must equal the oracle's"
    );
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let canonical = canonical_bindings(&storage, &binary);
    let without_root: Vec<(&'static str, PathBuf)> = canonical
        .iter()
        .filter(|(name, _)| *name != "STORAGE_ROOT")
        .cloned()
        .collect();
    assert_startup_is_refused(
        "the generated profile names an unbound parameter",
        Launch::Profile {
            profile: &unbound_root_profile,
            bindings: &without_root,
        },
        &storage,
        "invalid data type of path filter",
    );
    assert_eq!(
        applied_profile(),
        unbound_root_profile,
        "the launch must apply the stand-in file"
    );
}

/// The stand-in text denies the hosted connect.
///
/// `Launch::Profile` applies the text `standin_profile` builds. The one
/// Runtime socket stand-in counts zero connections. The run settles
/// `transport_interrupted`: `status` `failed`, and `terminal.error` is
/// `class` `transport_interrupted`, `code` `transport_interrupted`,
/// `message` `model backend transport was interrupted`. `offers_list`
/// answers and `shutdown` exits cleanly. This is the stand-in's count,
/// and this is not the Runtime's refusal.
///
/// Falsifier: F-cc44a makes `standin_profile` emit `(allow network*)`
/// instead of `(deny network*)`. The stand-in then counts a connection,
/// and the generated head's third line is `(allow network*)`.
#[test]
fn generated_profile_denies_the_hosted_connect() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let declared: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let generated = standin_profile(&declared).expect("declared rights build a profile");
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let fixture = HostedTransport::prepare("standin-hosted-connect");
    let profile = fixture.storage.base.join("standin.sb");
    write_standin_profile(&profile, &generated);
    let bindings = canonical_bindings(&fixture.storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &profile,
        bindings: &bindings,
    });
    assert_serving(&provider.ok(&fixture.request));

    provider.ok(&fixture.run.create);
    let settled = fixture.run.settle(&mut provider);
    assert_eq!(
        fixture.socket.observe().connections,
        0,
        "the profile must refuse the connect, so no connection reaches the Runtime socket"
    );
    assert_eq!(settled["status"], "failed", "the run must fail: {settled}");
    assert_eq!(
        settled["terminal"]["error"],
        json!({
            "class": "transport_interrupted",
            "code": "transport_interrupted",
            "message": "model backend transport was interrupted"
        }),
        "the refused connect must fail the run closed"
    );

    provider.ok(&json!({ "op": "offers_list" }));
    provider.shutdown();
}

/// The stand-in launch uses the generated file.
///
/// A clone of the declared rights drops the storage write and keeps the
/// parent read. `standin_profile` builds that text once. `collect_allow_lines`
/// shows the write rule absent, the parent read present, and the exec rule
/// present. Those checks run before the sandbox return. `write_standin_profile`
/// writes the text, and `Launch::Profile` applies that file. `init` with no
/// journal directory answers `journal_access_denied` with message
/// `model run journal is not writable`. `storage.root` does not exist, and
/// `shutdown` exits cleanly. The committed oracle still has the write rule.
///
/// Falsifier: F-cc45a makes this launch start under the committed oracle
/// instead of the generated file, so `init` answers ok.
#[test]
fn standin_launch_uses_the_generated_profile() {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let storage_write = "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))";
    let parent_read = "(allow file-read* (literal (param \"STORAGE_PARENT\")))";
    let exec_rule = "(allow process-exec (literal (param \"PROVIDER_EXECUTABLE\")))";
    let mut dropped = fixture.clone();
    let rights = dropped
        .get_mut("rights")
        .and_then(Value::as_array_mut)
        .expect("declared rights must hold a rights list");
    let mut removed = 0;
    for entry in rights {
        if entry.get("id").and_then(Value::as_str) != Some("storage") {
            continue;
        }
        let rules = entry
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("storage holds a rules list");
        let before = rules.len();
        rules.retain(|rule| rule.as_str() != Some(storage_write));
        removed += before - rules.len();
    }
    assert_eq!(removed, 1, "the storage write rule is removed once");
    let generated = standin_profile(&dropped).expect("declared rights build a profile");
    let allow_lines = collect_allow_lines(&generated);
    assert!(
        !allow_lines.contains(&storage_write),
        "the storage write is absent"
    );
    assert!(
        allow_lines.contains(&parent_read),
        "the parent read is present"
    );
    assert!(allow_lines.contains(&exec_rule), "the exec rule is present");

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    let storage = Storage::prepare("standin-dropped-storage");
    let dropped_profile = storage.base.join("standin-dropped-storage.sb");
    write_standin_profile(&dropped_profile, &generated);
    let binary = resolved(Path::new(PROVIDER_BINARY));
    let bindings = canonical_bindings(&storage, &binary);
    let mut provider = Provider::start(Launch::Profile {
        profile: &dropped_profile,
        bindings: &bindings,
    });
    let denied = provider.request(&init_request(&storage, None));
    assert_eq!(
        denied,
        json!({
            "status": "error",
            "code": "journal_access_denied",
            "message": "model run journal is not writable"
        }),
        "init with no journal directory must answer journal_access_denied"
    );
    assert!(!storage.root.exists(), "storage.root must not exist");
    provider.shutdown();
}

fn non_comment_lines(profile: &str) -> Vec<&str> {
    // The oracle's blank line after `(deny network*)` is not a form.
    profile
        .lines()
        .filter(|line| !line.starts_with(";;"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn collect_allow_lines(profile: &str) -> Vec<&str> {
    fn allow_at(line: &str) -> Option<usize> {
        let bytes = line.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'(' {
                index += 1;
                continue;
            }
            let mut cursor = index + 1;
            // Between `(` and `allow`, one run skips a space, a tab, a
            // carriage return (byte 13), a form feed (byte 12), or a vertical
            // tab (byte 11). After `allow`, the next byte may be the end, a
            // space, a tab, or a carriage return. A form feed or a vertical
            // tab there is not a match. A letter, a digit, `-`, or `*` there
            // is not a match, so `allowing` and `allow-default` stay unseen.
            while cursor < bytes.len()
                && matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\x0c' | b'\x0b')
            {
                cursor += 1;
            }
            let allow = b"allow";
            let after = cursor + allow.len();
            if bytes.get(cursor..after) == Some(&allow[..])
                && (after == bytes.len() || matches!(bytes[after], b' ' | b'\t' | b'\r'))
            {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    let mut allow_lines: Vec<&str> = profile
        .lines()
        .filter(|line| !line.starts_with(";;"))
        .map(str::trim)
        .filter(|line| allow_at(line) == Some(0))
        .collect();
    // An allow after another form on the same line is one more allow line.
    // A suffix stays even when it equals a line already collected. A line
    // whose allow starts at index 0 is taken once, by the walk above.
    for line in profile
        .lines()
        .filter(|line| !line.starts_with(";;"))
        .map(str::trim)
    {
        let Some(start) = allow_at(line) else {
            continue;
        };
        if start == 0 {
            continue;
        }
        allow_lines.push(&line[start..]);
    }
    allow_lines
}

fn allow_form_closes(profile: &str) -> Result<(), String> {
    let lines: Vec<&str> = profile.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if line.starts_with(";;") {
            continue;
        }
        let line = line.trim();
        // A line that trims to `(` and, after a run of empty lines or lines
        // whose bytes are only spaces, tabs, form feeds, or vertical tabs, a
        // line that starts with `allow` is an allow the collector never sees.
        if line == "(" {
            let mut cursor = index + 1;
            while let Some(next) = lines.get(cursor) {
                // A line with no bytes, or whose every byte is a space, a tab,
                // a form feed (byte 12), or a vertical tab (byte 11), is part
                // of that run. A carriage return is not.
                if next
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\x0c' | b'\x0b'))
                {
                    cursor += 1;
                    continue;
                }
                if next.starts_with(";;") {
                    break;
                }
                let next = next.trim();
                if let Some(rest) = next.strip_prefix("allow") {
                    if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
                        return Err(format!("allow form does not close: {line}"));
                    }
                }
                break;
            }
        }
        if !line.contains("(allow") {
            continue;
        }
        let mut open = 0usize;
        let mut close = 0usize;
        for ch in line.chars() {
            if ch == '(' {
                open += 1;
            } else if ch == ')' {
                close += 1;
            }
        }
        if open != close {
            return Err(format!("allow form does not close: {line}"));
        }
    }
    Ok(())
}

fn entry_id(entry: &Value) -> &str {
    entry
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a declared entry has no id"))
}

/// Every allow rule in `confine.sb` traces to exactly one approved declared
/// right or one platform-baseline rule in the declared-rights fixture.
///
/// Approved rights are the objects in `rights`. Platform-baseline entries are
/// the objects in `platform_baseline.rules`. The test reads the profile and
/// the fixture from disk. It starts no process and needs no sandbox.
///
/// Falsifier: F-cc30a appends one allow rule that no declared right and no
/// platform baseline names. F-cc30b points the trace at a fixture that drops
/// the bound-executable right. F-cc30c points it at a fixture whose storage
/// right has no rule. F-cc30d points it at a fixture where two rights claim
/// the exec rule. F-cc30e points it at a fixture rule that is not an allow
/// line. F-cc30f repeats the STORAGE_ROOT allow.
#[test]
fn allow_rules_trace_to_declared_rights() {
    fn rule_strings(entry: &Value) -> Vec<&str> {
        let Some(rules) = entry.get("rules") else {
            return Vec::new();
        };
        let rules = rules
            .as_array()
            .unwrap_or_else(|| panic!("declared rules must be an array"));
        rules
            .iter()
            .map(|rule| {
                rule.as_str()
                    .unwrap_or_else(|| panic!("a declared rule is not a string"))
            })
            .collect()
    }
    fn declared_rule_match(allow_lines: &[&str], rule: &str) -> Result<(), String> {
        match allow_lines.iter().filter(|line| **line == rule).count() {
            0 => Err(format!("declared rule is not an allow line: {rule}")),
            1 => Ok(()),
            _ => Err(format!(
                "declared rule matches more than one allow line: {rule}"
            )),
        }
    }

    // Same-line copies are in memory. Neither profile reads the fixture.
    let storage_rule = "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))";
    assert_eq!(
        declared_rule_match(&collect_allow_lines(storage_rule), storage_rule),
        Ok(())
    );
    let same_line_copy = format!("{storage_rule}\n(deny network*) {storage_rule}");
    let message = declared_rule_match(&collect_allow_lines(&same_line_copy), storage_rule)
        .expect_err("a same-line copy of the storage rule must fail check 3");
    assert!(
        message.contains("declared rule matches more than one allow line")
            && message.contains(storage_rule)
            && !message.contains("allow rule has no declared right"),
        "{message}"
    );

    // A tab after `(allow`, a space in `( allow`, a deny, and a same-line tab
    // allow are in memory. None of these four calls reads the fixture.
    let tab_allow = "(allow\tfile-read* (literal \"/tmp/cc-tab-allow\"))";
    assert_eq!(collect_allow_lines(tab_allow), [tab_allow]);
    let spaced_allow = "( allow file-read* (literal \"/tmp/cc-spaced-allow\"))";
    assert_eq!(collect_allow_lines(spaced_allow), [spaced_allow]);
    assert!(
        collect_allow_lines("(deny network*)").is_empty(),
        "(deny network*) collects nothing"
    );
    let same_line_tab = format!("(deny network*) {tab_allow}");
    assert_eq!(collect_allow_lines(&same_line_tab), [tab_allow]);

    // Carriage return, form feed, and vertical tab are in memory. None of
    // these calls reads the fixture or the profile file.
    let cr_after = "(allow\rfile-read* (literal \"/tmp/cc-cr-allow\"))";
    assert_eq!(collect_allow_lines(cr_after), [cr_after]);
    let cr_before = "(\rallow file-read* (literal \"/tmp/cc-cr-before\"))";
    assert_eq!(collect_allow_lines(cr_before), [cr_before]);
    let ff_before = "(\x0callow file-read* (literal \"/tmp/cc-ff-before\"))";
    assert_eq!(collect_allow_lines(ff_before), [ff_before]);
    let vt_before = "(\x0ballow file-read* (literal \"/tmp/cc-vt-before\"))";
    assert_eq!(collect_allow_lines(vt_before), [vt_before]);
    let ff_same_suffix = "(\x0callow file-read* (literal \"/tmp/cc-ff-same\"))";
    let ff_same = format!("(deny network*) {ff_same_suffix}");
    assert_eq!(collect_allow_lines(&ff_same), [ff_same_suffix]);
    assert!(
        collect_allow_lines("(allow\x0cfile-read* (literal \"/tmp/cc-ff-after\"))").is_empty(),
        "a form feed directly after allow collects nothing"
    );
    assert!(
        collect_allow_lines("(allow\x0bfile-read* (literal \"/tmp/cc-vt-after\"))").is_empty(),
        "a vertical tab directly after allow collects nothing"
    );
    assert!(
        collect_allow_lines("(allowing file-read* (literal \"/tmp/cc-allowing\"))").is_empty(),
        "(allowing file-read* collects nothing"
    );
    assert!(
        collect_allow_lines("(allow-default)").is_empty(),
        "(allow-default) collects nothing"
    );

    let profile = fs::read_to_string(PROFILE_PATH).expect("the profile source");
    let unclosed = [
        "(allow file-read-data (literal \"/\"))",
        "(allow",
        "file-read* (literal \"/tmp/cc-unclosed\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let unclosed_message = allow_form_closes(&unclosed)
        .expect_err("an allow form that does not close must fail before check 2");
    assert!(
        unclosed_message.contains("allow form does not close")
            && unclosed_message.contains("(allow")
            && !unclosed_message.contains("allow rule has no declared right")
            && !unclosed_message.contains("startup-root-directory widened"),
        "{unclosed_message}"
    );
    // A line that trims to `(` and whose next line starts `allow` and then a
    // space or a tab is in memory. Neither call reads the fixture or the
    // profile file.
    let split_space = [
        "(allow file-read-data (literal \"/\"))",
        "(",
        "allow file-read* (literal \"/tmp/cc-split-allow\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let split_space_message = allow_form_closes(&split_space)
        .expect_err("a line ( whose next line starts allow must fail before check 2");
    assert!(
        split_space_message.contains("allow form does not close")
            && split_space_message.contains("(")
            && !split_space_message.contains("allow rule has no declared right")
            && !split_space_message.contains("startup-root-directory widened"),
        "{split_space_message}"
    );
    let split_tab = [
        "(allow file-read-data (literal \"/\"))",
        "(",
        "allow\tfile-read* (literal \"/tmp/cc-split-allow-tab\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let split_tab_message = allow_form_closes(&split_tab)
        .expect_err("a line ( whose next line starts allow must fail before check 2");
    assert!(
        split_tab_message.contains("allow form does not close")
            && split_tab_message.contains("(")
            && !split_tab_message.contains("allow rule has no declared right")
            && !split_tab_message.contains("startup-root-directory widened"),
        "{split_tab_message}"
    );
    if let Err(reason) = allow_form_closes(&profile) {
        panic!("{reason}");
    }
    let allow_lines = collect_allow_lines(&profile);
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARED_RIGHTS_FIXTURE);
    let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
        panic!(
            "the declared-rights fixture {} must be readable: {err}",
            fixture_path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&fixture_text)
        .unwrap_or_else(|err| panic!("the declared-rights fixture must be JSON: {err}"));
    let rights = fixture
        .get("rights")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("declared rights must be an array"));
    let baseline = fixture
        .get("platform_baseline")
        .and_then(|base| base.get("rules"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("platform baseline rules must be an array"));

    // The three trace checks come before the identity asserts, so a fixture
    // that drops bound-executable fails on the exec allow.
    for entry in rights {
        if rule_strings(entry).is_empty() {
            panic!("declared right has no rule: {}", entry_id(entry));
        }
    }
    for entry in baseline {
        if rule_strings(entry).is_empty() {
            panic!("platform baseline has no rule: {}", entry_id(entry));
        }
    }

    for line in allow_lines.iter() {
        let mut claimants = Vec::new();
        for entry in rights.iter().chain(baseline.iter()) {
            if rule_strings(entry).contains(line) {
                claimants.push(entry_id(entry));
            }
        }
        match claimants.len() {
            0 => panic!("allow rule has no declared right and no platform baseline: {line}"),
            1 => {}
            _ => panic!(
                "allow rule is claimed more than once: {line}: {}",
                claimants.join(", ")
            ),
        }
    }

    for entry in rights.iter().chain(baseline.iter()) {
        for rule in rule_strings(entry) {
            if let Err(reason) = declared_rule_match(&allow_lines, rule) {
                panic!("{reason}");
            }
        }
    }

    assert_eq!(
        fixture.get("role").and_then(Value::as_str),
        Some("lab stand-in for the Runtime generator's input, not a manifest field")
    );
    assert_eq!(
        fixture.get("provider").and_then(Value::as_str),
        Some("model-provider")
    );
    assert_eq!(
        fixture
            .get("platform_baseline")
            .and_then(|base| base.get("status"))
            .and_then(Value::as_str),
        Some(
            "Runtime platform baseline for the model-provider executable on macOS, not approved rights"
        )
    );
    let right_ids: Vec<&str> = rights.iter().map(entry_id).collect();
    assert_eq!(right_ids, ["storage", "bound-executable"]);
    let baseline_ids: Vec<&str> = baseline.iter().map(entry_id).collect();
    assert_eq!(baseline_ids, ["startup-root-directory", "startup-sysctl"]);
    let justifications = [
        "macOS model-provider executable bound as PROVIDER_EXECUTABLE: Process startup reads the root directory before `main` runs",
        "macOS model-provider executable bound as PROVIDER_EXECUTABLE: At startup the Rust runtime reads the page size to place its stack guard page.",
    ];
    assert_eq!(baseline.len(), justifications.len());
    for (entry, expected) in baseline.iter().zip(justifications) {
        assert_eq!(
            entry.get("justification").and_then(Value::as_str),
            Some(expected)
        );
    }
}

/// The two platform-baseline startup rules stay the narrow pins written here.
///
/// `startup-root-directory` is `(allow file-read-data (literal "/"))` and
/// `startup-sysctl` is `(allow sysctl-read)`. Each pin must occur once. The
/// pins are not read from the declared-rights fixture, so a fixture and a
/// profile that widen together still fail. A wider grant fails even when the
/// pin remains. Every file operation, including `file*`, is checked even
/// when the line contains no `file-read` or `file-write`. The test reads
/// `confine.sb` from `CARGO_MANIFEST_DIR`. It
/// starts no process and needs no sandbox.
///
/// Falsifier: F-cc35a replaces the root pin with
/// `(allow file-read* (literal "/"))`. F-cc35b appends `(allow sysctl-write)`
/// after the sysctl pin. F-cc35c, F-cc35d and F-cc35e append literal reads
/// whose filenames contain STORAGE_ROOT, STORAGE_PARENT or PROVIDER_EXECUTABLE.
/// F-cc35f keeps both pins and appends
/// `(allow file-write* (literal "/tmp/cc35-write-only"))` to the profile only.
/// F-cc35g adds `(allow file* (literal "/tmp/cc35-wildcard"))` to the profile only
/// while keeping both pins.
#[test]
fn platform_baseline_rules_stay_narrow() {
    // One check classifies every baseline refusal. The file scan below and
    // the in-memory cases call it, so a write grant is not a second path.
    fn refuse_widened_baseline(allow_lines: &[&str]) -> Result<(), String> {
        fn root_operation_widens(line: &str) -> bool {
            if line.contains("file-read*") {
                return true;
            }
            let rest = line.strip_prefix("(allow ").unwrap_or(line);
            let head = rest.split('(').next().unwrap_or(rest);
            let head = head.trim().trim_end_matches(')');
            head.split_whitespace()
                .any(|token| token != "file-read-data")
        }

        fn root_path_widens(line: &str) -> bool {
            if line.contains("subpath") {
                return true;
            }
            let mut rest = line;
            while let Some(start) = rest.find('"') {
                let after = &rest[start + 1..];
                let Some(end) = after.find('"') else {
                    return true;
                };
                if &after[..end] != "/" {
                    return true;
                }
                rest = &after[end + 1..];
            }
            false
        }

        let root_pin = "(allow file-read-data (literal \"/\"))";
        let sysctl_pin = "(allow sysctl-read)";
        // All file operations are root candidates, including file* and
        // operations outside file-read/file-write. Only the exact storage
        // grants are exempt, so a filename that contains a parameter name
        // does not exempt a wider rule.
        let root_candidates: Vec<&str> = allow_lines
            .iter()
            .copied()
            .filter(|line| {
                line.contains("file")
                    && !matches!(
                        *line,
                        "(allow file-read* (literal (param \"STORAGE_PARENT\")))"
                            | "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))"
                    )
            })
            .collect();
        let mut root_pins = 0usize;
        for line in root_candidates {
            if line == root_pin {
                root_pins += 1;
                continue;
            }
            if root_operation_widens(line) {
                return Err(format!("startup-root-directory operation widened: {line}"));
            }
            if root_path_widens(line) {
                return Err(format!("startup-root-directory path widened: {line}"));
            }
            return Err(format!("startup-root-directory widened: {line}"));
        }
        if root_pins == 0 {
            return Err("startup-root-directory widened".to_string());
        }
        if root_pins != 1 {
            return Err(format!(
                "startup-root-directory widened: pin occurs {root_pins} times"
            ));
        }

        let mut sysctl_pins = 0usize;
        for line in allow_lines {
            if !line.contains("sysctl") {
                continue;
            }
            if *line == sysctl_pin {
                sysctl_pins += 1;
                continue;
            }
            if line.contains("sysctl-write") || line.contains("sysctl*") {
                return Err(format!("startup-sysctl operation widened: {line}"));
            }
            if line.contains("sysctl-name") {
                return Err(format!("startup-sysctl sysctl name widened: {line}"));
            }
            return Err(format!("startup-sysctl widened: {line}"));
        }
        if sysctl_pins == 0 {
            return Err("startup-sysctl widened".to_string());
        }
        if sysctl_pins != 1 {
            return Err(format!(
                "startup-sysctl widened: pin occurs {sysctl_pins} times"
            ));
        }
        Ok(())
    }

    #[track_caller]
    fn must_refuse(lines: &[&str], reason: &str) {
        assert_eq!(refuse_widened_baseline(lines), Err(reason.to_string()));
    }

    let root = "(allow file-read-data (literal \"/\"))";
    let sysctl = "(allow sysctl-read)";
    let parent = "(allow file-read* (literal (param \"STORAGE_PARENT\")))";
    let storage = "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))";
    let exec = "(allow process-exec (literal (param \"PROVIDER_EXECUTABLE\")))";
    assert_eq!(
        refuse_widened_baseline(&[exec, root, sysctl, parent, storage]),
        Ok(())
    );

    must_refuse(
        &["(allow file-read* (literal \"/\"))", sysctl],
        "startup-root-directory operation widened: (allow file-read* (literal \"/\"))",
    );
    // Broader file operations reach the same check with both pins present,
    // including when a fixture declares the same extra grant.
    for (line, reason) in [
        (
            "(allow file* (literal \"/tmp/cc35-wildcard\"))",
            "startup-root-directory operation widened: (allow file* (literal \"/tmp/cc35-wildcard\"))",
        ),
        (
            "(allow file-map-executable (literal \"/tmp/cc35-executable\"))",
            "startup-root-directory operation widened: (allow file-map-executable (literal \"/tmp/cc35-executable\"))",
        ),
        (
            "(allow file-ioctl (literal \"/tmp/cc35-ioctl\"))",
            "startup-root-directory operation widened: (allow file-ioctl (literal \"/tmp/cc35-ioctl\"))",
        ),
        (
            "(allow file-test-existence (literal \"/tmp/cc35-exists\"))",
            "startup-root-directory operation widened: (allow file-test-existence (literal \"/tmp/cc35-exists\"))",
        ),
        (
            "(allow file* (subpath (param \"STORAGE_ROOT\")))",
            "startup-root-directory operation widened: (allow file* (subpath (param \"STORAGE_ROOT\")))",
        ),
    ] {
        must_refuse(&[exec, root, line, sysctl, parent, storage], reason);
    }
    // A write of the root path is an operation widen. The literal is still "/".
    must_refuse(
        &[root, "(allow file-write* (literal \"/\"))", sysctl],
        "startup-root-directory operation widened: (allow file-write* (literal \"/\"))",
    );
    // The falsifier's write-only grant. Its path is also wider; the reason is
    // the operation. The exact storage grant beside it stays exempt.
    must_refuse(
        &[
            exec,
            root,
            "(allow file-write* (literal \"/tmp/cc35-write-only\"))",
            sysctl,
            parent,
            storage,
        ],
        "startup-root-directory operation widened: (allow file-write* (literal \"/tmp/cc35-write-only\"))",
    );
    must_refuse(
        &[root, "(allow file-write-data)", sysctl],
        "startup-root-directory operation widened: (allow file-write-data)",
    );
    must_refuse(
        &[
            root,
            "(allow file-write* (subpath (param \"STORAGE_ROOT\")))",
            sysctl,
        ],
        "startup-root-directory operation widened: (allow file-write* (subpath (param \"STORAGE_ROOT\")))",
    );
    must_refuse(
        &[
            root,
            "(allow file-write* (literal \"/tmp/STORAGE_ROOT-write\"))",
            sysctl,
        ],
        "startup-root-directory operation widened: (allow file-write* (literal \"/tmp/STORAGE_ROOT-write\"))",
    );
    // The letters file-write in a filename are not a write operation.
    must_refuse(
        &[
            root,
            "(allow file-read-data (literal \"/tmp/file-write-note\"))",
            sysctl,
        ],
        "startup-root-directory path widened: (allow file-read-data (literal \"/tmp/file-write-note\"))",
    );
    must_refuse(
        &[root, "(allow file-read-data (subpath \"/\"))", sysctl],
        "startup-root-directory path widened: (allow file-read-data (subpath \"/\"))",
    );
    must_refuse(
        &[
            "(allow file-read-data (literal \"/\") (vnode-type REGULAR))",
            sysctl,
        ],
        "startup-root-directory widened: (allow file-read-data (literal \"/\") (vnode-type REGULAR))",
    );
    must_refuse(&[sysctl], "startup-root-directory widened");
    must_refuse(
        &[root, root, sysctl],
        "startup-root-directory widened: pin occurs 2 times",
    );
    must_refuse(
        &[root, sysctl, "(allow sysctl-write)"],
        "startup-sysctl operation widened: (allow sysctl-write)",
    );
    must_refuse(
        &[root, "(allow sysctl*)"],
        "startup-sysctl operation widened: (allow sysctl*)",
    );
    must_refuse(
        &[root, "(allow sysctl-read (sysctl-name \"hw.pagesize\"))"],
        "startup-sysctl sysctl name widened: (allow sysctl-read (sysctl-name \"hw.pagesize\"))",
    );
    must_refuse(
        &[root, "(allow sysctl-read (with no-log))"],
        "startup-sysctl widened: (allow sysctl-read (with no-log))",
    );
    must_refuse(&[root], "startup-sysctl widened");
    must_refuse(
        &[root, sysctl, sysctl],
        "startup-sysctl widened: pin occurs 2 times",
    );

    // A trimmed line that contains `(allow` must close on that line. The
    // file scan calls `collect_allow_lines`, so an unclosed form would
    // otherwise leave both pins in place.
    let unclosed = [
        "(allow file-read-data (literal \"/\"))",
        "(allow",
        "file-read* (literal \"/tmp/cc-unclosed\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let unclosed_message = allow_form_closes(&unclosed).unwrap_err();
    assert!(
        unclosed_message.contains("allow form does not close"),
        "{unclosed_message}"
    );
    assert!(unclosed_message.contains("(allow"), "{unclosed_message}");
    assert!(
        !unclosed_message.contains("startup-root-directory widened"),
        "{unclosed_message}"
    );
    let committed_allows = [exec, root, sysctl, parent, storage].join("\n");
    assert_eq!(allow_form_closes(&committed_allows), Ok(()));

    // A line that trims to `(` whose next line starts `allow` and a space or
    // a tab is an allow the collector never sees. Both pins stay.
    let split_space = [
        "(allow file-read-data (literal \"/\"))",
        "(",
        "allow file-read* (literal \"/tmp/cc-split-allow\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let split_space_message = allow_form_closes(&split_space).unwrap_err();
    assert!(
        split_space_message.contains("allow form does not close"),
        "{split_space_message}"
    );
    assert!(split_space_message.contains("("), "{split_space_message}");
    assert!(
        !split_space_message.contains("startup-root-directory widened"),
        "{split_space_message}"
    );
    assert!(
        !split_space_message.contains("allow rule has no declared right"),
        "{split_space_message}"
    );
    let split_tab = [
        "(allow file-read-data (literal \"/\"))",
        "(",
        "allow\tfile-read* (literal \"/tmp/cc-split-allow-tab\"))",
        "(allow sysctl-read)",
    ]
    .join("\n");
    let split_tab_message = allow_form_closes(&split_tab).unwrap_err();
    assert!(
        split_tab_message.contains("allow form does not close"),
        "{split_tab_message}"
    );
    assert!(split_tab_message.contains("("), "{split_tab_message}");
    assert!(
        !split_tab_message.contains("startup-root-directory widened"),
        "{split_tab_message}"
    );
    assert!(
        !split_tab_message.contains("allow rule has no declared right"),
        "{split_tab_message}"
    );
    let not_split = [
        "(",
        "allowing",
        "(",
        "allow-default",
        "(",
        "(deny network*)",
        "(",
    ]
    .join("\n");
    assert_eq!(allow_form_closes(&not_split), Ok(()));

    // A run of empty lines, or lines whose bytes are only spaces, tabs, form
    // feeds, or vertical tabs, between `(` and `allow` is the same allow.
    // None of these profiles reads the fixture or confine.sb.
    let skipped_before_allow = [
        [
            root,
            "(",
            "",
            "allow file-read* (literal \"/tmp/cc-blank-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "   ",
            "allow file-read* (literal \"/tmp/cc-spaces-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "",
            "",
            "allow file-read* (literal \"/tmp/cc-two-blank-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "\t",
            "allow file-read* (literal \"/tmp/cc-tab-line-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "\x0c",
            "allow file-read* (literal \"/tmp/cc-ff-line-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "\x0b",
            "allow file-read* (literal \"/tmp/cc-vt-line-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            " \t\x0c\x0b",
            "allow file-read* (literal \"/tmp/cc-mix-line-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "( ",
            "",
            "allow file-read* (literal \"/tmp/cc-sp-paren-allow\"))",
            sysctl,
        ]
        .join("\n"),
        [
            root,
            "(",
            "",
            "allow\tfile-read* (literal \"/tmp/cc-blank-tab\"))",
            sysctl,
        ]
        .join("\n"),
    ];
    for profile in skipped_before_allow {
        let message = allow_form_closes(&profile).unwrap_err();
        assert_eq!(message, "allow form does not close: (");
        assert!(
            !message.contains("startup-root-directory widened"),
            "{message}"
        );
        assert!(
            !message.contains("allow rule has no declared right"),
            "{message}"
        );
    }
    let comment_between = [
        "(",
        "",
        "allowing",
        "(",
        "",
        "allow-default",
        "(",
        "",
        ";; note",
        "allow file-read* (literal \"/tmp/cc-comment-allow\"))",
        "(",
    ]
    .join("\n");
    assert_eq!(allow_form_closes(&comment_between), Ok(()));

    let profile_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("confine.sb");
    let profile = fs::read_to_string(&profile_path).unwrap_or_else(|err| {
        panic!(
            "confine.sb must be readable at {}: {err}",
            profile_path.display()
        )
    });
    if let Err(reason) = allow_form_closes(&profile) {
        panic!("{reason}");
    }
    // Whole lines that start with `;;` are comments. Allow lines come from
    // `collect_allow_lines`.
    let allow_lines = collect_allow_lines(&profile);
    if let Err(reason) = refuse_widened_baseline(&allow_lines) {
        panic!("{reason}");
    }
}
