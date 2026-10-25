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
//! so a control run shows what the profile stops.
//!
//! When `/usr/bin/sandbox-exec` is absent a confined test prints why it did
//! not run and returns; it never passes silently. The one profile-shape check
//! is `both_file_profiles_bind_one_storage_parameter_contract` in
//! `capsules/wallet-provider/tests/confine.rs`; this target adds none.

#![cfg(unix)]

// This target uses only the temporary root helper and the event timeout.
#[allow(dead_code)]
#[path = "../../src/test_support.rs"]
mod test_support;

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
    /// The same binary and pipes without the profile: a control run.
    Unconfined,
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
            Launch::Confined(storage) => {
                let mut command = Command::new(SANDBOX_EXEC);
                command
                    .arg("-f")
                    .arg(PROFILE_PATH)
                    .arg("-D")
                    .arg(format!("PROVIDER_EXECUTABLE={}", binary.display()))
                    .arg("-D")
                    .arg(format!("STORAGE_ROOT={}", storage.root.display()))
                    .arg("-D")
                    .arg(format!("STORAGE_PARENT={}", storage.parent.display()))
                    .arg(&binary);
                command
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
