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
//! program it names, that path or another, under `confine.sb`, so the
//! profile's exec rule alone decides whether that program runs. Before
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
    /// Under `confine.sb`, starting `program` with `executable` bound as
    /// `PROVIDER_EXECUTABLE` and the storage parameters bound as usual.
    /// `bound_digest` is a sha256 recorded earlier for `executable`. `None`
    /// records the file at this launch.
    Program {
        storage: &'a Storage,
        executable: &'a Path,
        program: &'a Path,
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

/// A test-time copy of `confine.sb` with fixture rules appended. The copy is
/// read from the one profile source when the test writes it, so a
/// `confine.sb` edit reaches the fixture launch as it reaches the plain one.
/// A fixture rule grants only what one test needs to reach the operation it
/// proves refused.
struct FixtureProfile {
    path: PathBuf,
    parameters: Vec<(&'static str, PathBuf)>,
}

impl FixtureProfile {
    fn write(storage: &Storage, rules: &str, parameters: Vec<(&'static str, PathBuf)>) -> Self {
        let profile = fs::read_to_string(PROFILE_PATH).expect("the profile source");
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

/// The one launch builder. `sandbox-exec` starts `program` under `profile`,
/// with one `-D name=value` for each binding, in list order. It applies the
/// profile to its own process before it executes `program`, so the profile's
/// exec rule checks that exec as it checks any exec by the confined provider.
fn sandboxed(profile: &Path, bindings: &[(&'static str, PathBuf)], program: &Path) -> Command {
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
                bound_digest,
            } => {
                check_provider_executable(executable, bound_digest.as_deref());
                let bindings = canonical_bindings(storage, executable);
                sandboxed(Path::new(PROFILE_PATH), &bindings, program)
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

/// Every cited `model_` test in "Operations and the rights they need" is a
/// function in this file.
///
/// The section is `CONFINEMENT.md` from that heading through the next heading
/// line. A cited test name is a backtick span of `model_` plus lowercase
/// letters, digits and underscores. Each span must occur as `fn <name>(` in
/// this file. The failure names the missing test. This test starts no process
/// and needs no sandbox.
///
/// Falsifier: F-cc31a renames `model_provider_ops_under_profile`, so this
/// test no longer finds that function.
#[test]
fn operations_section_cites_existing_tests() {
    fn cited_model_test(span: &str) -> bool {
        let Some(tail) = span.strip_prefix("model_") else {
            return false;
        };
        !tail.is_empty()
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
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
    let section = operations_section_text(&doc);
    let mut cited = Vec::new();
    let mut rest = section;
    while let Some(start) = rest.find('`') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('`') else {
            break;
        };
        let span = &rest[..end];
        rest = &rest[end + 1..];
        if cited_model_test(span) && !cited.contains(&span) {
            cited.push(span);
        }
    }
    let missing: Vec<&str> = cited
        .iter()
        .copied()
        .filter(|name| !source.contains(&format!("fn {name}(")))
        .collect();
    assert!(missing.is_empty(), "missing test: {}", missing.join(", "));
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

/// Under the profile, an `init` whose journal path leaves `STORAGE_ROOT`
/// through a symlinked intermediate is refused by the sandbox. The answer is
/// `journal_corrupt`, the provider's code for an unavailable journal; the
/// provider's log names the redirected path with EPERM (`Operation not
/// permitted`), which is how the macOS sandbox refuses; the outside sibling
/// keeps its entries and bytes; and a later normal `init` on `STORAGE_ROOT`
/// succeeds. `redirect_journal_materializes_outside_when_unconfined` runs the
/// same fixture and request without the profile, and the journal lands
/// outside.
///
/// Falsifiers: F-cc1a (`(allow default)`) and F-cc1b (the read/write grant
/// widened to `STORAGE_PARENT`) let the redirected `init` succeed, and this
/// test fails.
#[test]
fn model_outside_write_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = Redirect::prepare("outside-write");
    let before = tree_snapshot(&fixture.outside);
    let mut provider = Provider::start(Launch::Confined(&fixture.storage));

    let denied = provider.request(&fixture.request);
    assert_eq!(
        denied["status"], "error",
        "the redirected journal write must be refused: {denied}"
    );
    assert_eq!(
        denied["code"], "journal_corrupt",
        "the refusal must use the provider's unavailable-journal code: {denied}"
    );

    let logged = provider
        .logged_fault("journal_corrupt")
        .expect("the provider must log the journal_corrupt detail");
    let refused = format!("{}: Operation not permitted", fixture.journal_dir.display());
    assert!(
        logged.contains(&refused),
        "the sandbox must refuse the redirected journal path with EPERM: {logged}"
    );

    assert_eq!(
        tree_snapshot(&fixture.outside),
        before,
        "the outside sibling must keep its entries and bytes"
    );

    assert!(!fixture.storage.root.join("runs").exists());
    let init = provider.ok(&init_request(&fixture.storage, None));
    assert_serving(&init);
    assert!(
        fixture.storage.root.join("runs").is_dir(),
        "the later normal init must use STORAGE_ROOT"
    );
    provider.shutdown();
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
///
/// A first launch under `confine.sb` stores one run of the hosted offer and
/// reads it back: a real content read inside the root. A second launch runs a
/// fixture copy of `confine.sb` that adds only `READ_FIXTURE_RULE`. After its
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
/// Falsifiers: F-cc1c (the `STORAGE_PARENT` read widened to a subpath) lets
/// the outside read return the run; F-cc1d (the `STORAGE_ROOT` grant without
/// `file-read*`) fails the first `init`, which cannot inspect the journal
/// root; F-cc1e (no fixture rule) stops `runs_get` at the record's existence
/// check (`model run is unreadable`), before the open.
#[test]
fn model_outside_read_denied() {
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
        "the binary must refuse hosted dispatch before any socket: {created}"
    );
    let record = only_record(&runs);
    let stored = provider.ok(&run.get);
    assert_eq!(stored, created, "runs_get must return the stored run");
    provider.shutdown();

    // The fixture binds the record's exact outside path at launch, which the
    // first launch's stored record names.
    let outside = storage.parent.join("outside");
    let outside_runs = outside.join("runs");
    let outside_record = outside_runs.join(record.file_name().expect("record name"));
    let fixture = FixtureProfile::write(
        &storage,
        READ_FIXTURE_RULE,
        vec![("READ_FIXTURE_RECORD", outside_record)],
    );
    let mut provider = Provider::start(Launch::Fixture(&storage, &fixture));
    assert_serving(&provider.ok(&init_request(&storage, None)));
    owner_only_directory(&outside);
    fs::rename(&runs, &outside_runs).expect("move the run directory outside");
    std::os::unix::fs::symlink(&outside_runs, &runs).expect("link the run directory");
    let before = tree_snapshot(&outside);

    let denied = provider.request(&run.get);
    assert_eq!(
        denied["status"], "error",
        "the outside read must be refused: {denied}"
    );
    assert_eq!(
        denied["code"], "journal_corrupt",
        "the refusal must use the provider's unavailable-journal code: {denied}"
    );
    assert!(
        denied.get("data").is_none(),
        "the refusal must return no run data: {denied}"
    );
    let logged = provider
        .logged_fault("journal_corrupt")
        .expect("the provider must log the journal_corrupt detail");
    assert!(
        logged.contains("failed to open model run journal: Operation not permitted"),
        "the sandbox must refuse the open that reads the record with EPERM: {logged}"
    );
    assert_eq!(
        tree_snapshot(&outside),
        before,
        "the outside sibling must keep its entries and bytes"
    );
    provider.ok(&json!({ "op": "offers_list" }));

    fs::remove_file(&runs).expect("remove the run directory link");
    fs::rename(&outside_runs, &runs).expect("move the run directory back");
    assert_eq!(
        provider.ok(&run.get),
        stored,
        "the record must read back from STORAGE_ROOT"
    );
    provider.shutdown();
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
/// The test runs a fixture copy of `confine.sb` that adds only
/// `CREATE_FIXTURE_RULE`. With it, the `Redirect` request's `init` passes the
/// inspect that `model_outside_write_denied` is refused at, and the refused
/// step is the create of `<journal_dir>/runs` (`fs::create_dir` in
/// `create_missing_journal_directory`, `src/journal.rs`). The answer is
/// `journal_access_denied`, the provider logs that create with EPERM
/// (`Operation not permitted`), the outside sibling keeps its entries, modes
/// and bytes, and a later normal `init` on `STORAGE_ROOT` succeeds.
/// `redirect_journal_materializes_outside_when_unconfined` is the control: the
/// same fixture and request without a profile create the journal under the
/// outside sibling.
///
/// Falsifiers: F-cc8a (`(allow default)`) lets the redirected `init` answer
/// ok. F-cc8c keeps `(deny default)` and adds only a `file-write*` grant on
/// `STORAGE_PARENT`; the create then succeeds, `runs/` appears under the
/// outside sibling, and the answer is no longer `journal_access_denied`, so
/// this test watches the write grant itself. F-cc8-rm-journal removes the
/// fixture rule; the sandbox then refuses the inspect first, and `init`
/// answers `journal_corrupt`.
#[test]
fn model_outside_create_reports_access_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = Redirect::prepare("outside-create");
    // `Storage` resolves its paths, so this is the path the sandbox matches.
    let profile = FixtureProfile::write(
        &fixture.storage,
        CREATE_FIXTURE_RULE,
        vec![("CREATE_FIXTURE_JOURNAL", fixture.outside.join("inner"))],
    );
    let before = tree_snapshot(&fixture.outside);
    let mut provider = Provider::start(Launch::Fixture(&fixture.storage, &profile));

    let denied = provider.request(&fixture.request);
    assert_eq!(
        denied,
        json!({
            "status": "error",
            "code": "journal_access_denied",
            "message": "model run journal is not writable"
        }),
        "the redirected journal create must be refused as access denied"
    );
    let logged = provider
        .logged_fault("journal_access_denied")
        .expect("the provider must log the journal_access_denied detail");
    let refused = format!(
        "create provider journal directory {} (Operation not permitted",
        fixture.journal_dir.join("runs").display()
    );
    assert!(
        logged.contains(&refused),
        "the sandbox must refuse the create of runs/ with EPERM: {logged}"
    );

    assert_eq!(
        tree_snapshot(&fixture.outside),
        before,
        "the outside sibling must keep its entries, modes and bytes"
    );

    assert!(!fixture.storage.root.join("runs").exists());
    assert_serving(&provider.ok(&init_request(&fixture.storage, None)));
    assert!(
        fixture.storage.root.join("runs").is_dir(),
        "the later normal init must use STORAGE_ROOT"
    );
    provider.shutdown();
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
        bound_digest: None,
    });

    assert_serving(&provider.ok(&init_request(&fixture.storage, None)));
    assert!(
        fixture.storage.root.join("runs").is_dir(),
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
/// `(deny network*)`. The sorted allow lines equal the oracle. A changed
/// `bound-executable` rule is reflected. A declared value with no rights
/// list, a platform baseline with no rules list, an entry with no rules list,
/// and a rule that is not a string are each refused with their reason. The
/// test starts no process and needs no sandbox.
///
/// Falsifier: F-cc41a makes `standin_profile` return the oracle file and
/// ignore the declared value, so a changed declared rule still matches the
/// oracle.
#[test]
fn generated_model_profile_matches_the_oracle() {
    fn non_comment_head(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .filter(|line| !line.starts_with(";;"))
            .take(3)
            .collect()
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
    assert!(
        generated.lines().all(|line| !line.starts_with(";;")),
        "the stand-in profile emits no comment line"
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
    fn entry_id(entry: &Value) -> &str {
        entry
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("a declared entry has no id"))
    }
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

    for line in allow_lines.iter().copied() {
        let mut claimants = Vec::new();
        for entry in rights.iter().chain(baseline.iter()) {
            if rule_strings(entry).iter().any(|rule| *rule == line) {
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
