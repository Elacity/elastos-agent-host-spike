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
//!
//! When `/usr/bin/sandbox-exec` is absent a confined test prints why it did
//! not run and returns; it never passes silently. The one profile-shape check
//! is `both_file_profiles_bind_one_storage_parameter_contract` in
//! `capsules/wallet-provider/tests/confine.rs`; this target adds none.

#![cfg(unix)]

// This target uses only the temporary root helper, the request id helper and
// the event timeout.
#[allow(dead_code)]
#[path = "../../src/test_support.rs"]
mod test_support;

use elastos_model_contract::{
    model_input_hash, model_run_id, RuntimeAccessBinding, RuntimeCreateBinding,
    RUNTIME_ACCESS_BINDING_SCHEMA, RUNTIME_CREATE_BINDING_SCHEMA, TEXT_INPUT_V1_SCHEMA,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use test_support::FIXTURE_EVENT_TIMEOUT;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_model-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
const HOSTED_OFFER: &str = "confine-hosted-text";

/// Returns `true` when the confined tests can run, printing why they cannot
/// otherwise.
fn sandbox_available() -> bool {
    if Path::new(SANDBOX_EXEC).is_file() {
        return true;
    }
    eprintln!(
        "SKIP model-provider confinement test: {SANDBOX_EXEC} is absent; \
         the profile was not exercised on this machine"
    );
    false
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
    /// The same binary and pipes without the profile: a control run.
    Unconfined,
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

/// `sandbox-exec` starting `binary` under `profile`, with the contract's three
/// parameters and any fixture parameters bound.
fn sandboxed(
    profile: &Path,
    storage: &Storage,
    fixture: &[(&'static str, PathBuf)],
    binary: &Path,
) -> Command {
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-f")
        .arg(profile)
        .arg("-D")
        .arg(format!("PROVIDER_EXECUTABLE={}", binary.display()))
        .arg("-D")
        .arg(format!("STORAGE_ROOT={}", storage.root.display()))
        .arg("-D")
        .arg(format!("STORAGE_PARENT={}", storage.parent.display()));
    for (name, path) in fixture {
        command.arg("-D").arg(format!("{name}={}", path.display()));
    }
    command.arg(binary);
    command
}

/// The real provider binary speaking its line-delimited JSON protocol.
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
            Launch::Confined(storage) => sandboxed(Path::new(PROFILE_PATH), storage, &[], &binary),
            Launch::Fixture(storage, fixture) => {
                sandboxed(&fixture.path, storage, &fixture.parameters, &binary)
            }
            Launch::Unconfined => Command::new(&binary),
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

    /// Sends one request and returns its answer. A process that exits first
    /// fails the test with its exit status: `sandbox-exec` exits 71 when the
    /// profile refuses to execute the binary, and a startup the profile breaks
    /// aborts before the first answer.
    fn request(&mut self, request: &Value) -> Value {
        let stdin = self.stdin.as_mut().expect("provider stdin is open");
        // A closed pipe shows up below as an exit without an answer.
        let _ = writeln!(stdin, "{request}").and_then(|()| stdin.flush());
        match self.responses.recv_timeout(FIXTURE_EVENT_TIMEOUT) {
            Ok(response) => response,
            Err(RecvTimeoutError::Disconnected) => panic!(
                "the provider process exited before answering {}: {}",
                request["op"],
                describe(self.wait())
            ),
            Err(RecvTimeoutError::Timeout) => panic!(
                "the provider did not answer {} within {FIXTURE_EVENT_TIMEOUT:?}",
                request["op"]
            ),
        }
    }

    /// Sends one request that must succeed and returns its data.
    fn ok(&mut self, request: &Value) -> Value {
        let response = self.request(request);
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

    fn wait(&mut self) -> Option<ExitStatus> {
        let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
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

    /// Stops the provider through its protocol and requires a clean exit.
    fn shutdown(mut self) {
        let data = self.ok(&json!({ "op": "shutdown" }));
        assert_eq!(data["shutdown"], true, "shutdown must be acknowledged");
        self.stdin.take();
        let status = self.wait();
        assert!(
            status.is_some_and(|status| status.success()),
            "the provider must exit cleanly after shutdown: {}",
            describe(status)
        );
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.stdin.take();
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
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
/// `runs_get` that reads it back from the journal. The binary refuses hosted
/// dispatch before any socket, so the run is stored as failed and needs no
/// backend.
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
}

/// The confined provider serves `init`, `status` and `offers_list`, and
/// `init` creates the journal root with `runs/` under `STORAGE_ROOT`.
///
/// Every allow rule in `confine.sb` is load-bearing here: each `F-cc1-rm-*`
/// entry in `confine-falsifiers.json` removes one rule and this test fails.
#[test]
fn model_provider_ops_under_profile() {
    if !sandbox_available() {
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

/// The redirect fixture shared by `model_outside_write_denied` and its
/// unconfined control. It creates `STORAGE_ROOT` to hold the link
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
    if !sandbox_available() {
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
    if !sandbox_available() {
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
