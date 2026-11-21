//! Provider bridge for capsule-based providers
//!
//! Manages stdin/stdout communication with a provider capsule process.
//! The runtime sends ProviderRequests and receives ProviderResponses
//! over line-delimited JSON.
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::collections::BTreeMap;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::Mutex as StdMutex;

use elastos_common::ProviderAuthority;

#[cfg(target_os = "macos")]
use elastos_model_contract::{model_input_hash, model_run_id, RuntimeCreateBinding};

use serde::{Deserialize, Serialize};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};

use super::checked_executable::PreparedExecutable;
use super::registry::{
    EntryType, Provider, ProviderError, ResourceAction, ResourceEntry, ResourceRequest,
    ResourceResponse,
};
use super::CheckedExecutable;

#[cfg(test)]
thread_local! {
    static AFTER_VERIFY_SWAP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn swap_after_verify() {
    AFTER_VERIFY_SWAP.with(|slot| {
        if let Some(swap) = slot.borrow_mut().take() {
            swap();
        }
    });
}

#[cfg(not(test))]
fn swap_after_verify() {}

/// Timeout for provider requests (30 seconds)
pub(super) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// How often a still-pending raw provider request is named at warn.
const PENDING_REQUEST_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Timeout for provider init (10 seconds)
const INIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Timeout for provider shutdown (5 seconds)
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(any(target_os = "macos", target_os = "linux"))]
const MAX_LOCAL_MODEL_SLOTS: usize = 64;
#[cfg(target_os = "macos")]
const HOSTED_RUN_BINDING_TTL: std::time::Duration = std::time::Duration::from_secs(7200);
#[cfg(target_os = "macos")]
// Bounds unobserved hosted runs as well as active runs. Terminal replies retire
// entries immediately; an unpolled completion remains until the two-hour TTL.
const MAX_HOSTED_RUN_BINDINGS: usize = 4096;

#[cfg(target_os = "macos")]
fn seatbelt_path(path: &Path) -> Result<String, BridgeError> {
    let value = path
        .to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .ok_or_else(|| BridgeError::InitFailed("invalid model sandbox path".into()))?;
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "macos")]
fn model_journal_for_sandbox(config: &ProviderConfig) -> Result<std::path::PathBuf, BridgeError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let base = Path::new(&config.base_path);
    if !base.is_absolute() || std::fs::canonicalize(base).ok().as_deref() != Some(base) {
        return Err(BridgeError::InitFailed("invalid model Runtime root".into()));
    }
    let journal = base.join("providers/model-provider/journal");
    if config.extra["journal_dir"].as_str() != journal.to_str() {
        return Err(BridgeError::InitFailed("invalid model journal root".into()));
    }
    let mut current = base.to_path_buf();
    for part in ["providers", "model-provider", "journal"] {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(BridgeError::InitFailed("unsafe model journal root".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(BridgeError::Spawn)?;
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))
                    .map_err(BridgeError::Spawn)?;
            }
            Err(error) => return Err(BridgeError::Spawn(error)),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(BridgeError::Spawn)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(BridgeError::InitFailed(
                "unsafe model journal permissions".into(),
            ));
        }
    }
    Ok(journal)
}

#[cfg(target_os = "macos")]
fn model_engine_receipt_entries(
    base: &Path,
    engine: &Path,
) -> Result<(std::path::PathBuf, Vec<serde_json::Value>), BridgeError> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let prefix = base.join("libexec/llama.cpp");
    let relative = engine
        .strip_prefix(&prefix)
        .map_err(|_| BridgeError::InitFailed("model engine bundle is unavailable".into()))?;
    let mut parts = relative.components();
    let (Some(std::path::Component::Normal(version)), Some(std::path::Component::Normal(platform))) =
        (parts.next(), parts.next())
    else {
        return Err(BridgeError::InitFailed(
            "model engine bundle is unavailable".into(),
        ));
    };
    if !parts.all(|part| matches!(part, std::path::Component::Normal(_))) {
        return Err(BridgeError::InitFailed(
            "model engine bundle is unavailable".into(),
        ));
    }
    let bundle = prefix.join(version).join(platform);
    let receipt = bundle.join(".elastos-engine.json");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&receipt)
        .map_err(BridgeError::Spawn)?;
    let before = file.metadata().map_err(BridgeError::Spawn)?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o400
        || before.len() > 256 * 1024
    {
        return Err(BridgeError::InitFailed(
            "unsafe model engine receipt".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(BridgeError::Spawn)?;
    let after = file.metadata().map_err(BridgeError::Spawn)?;
    if bytes.len() > 256 * 1024
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || std::fs::symlink_metadata(&receipt)
            .map_err(BridgeError::Spawn)?
            .ino()
            != after.ino()
    {
        return Err(BridgeError::InitFailed(
            "changed model engine receipt".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| BridgeError::InitFailed("invalid model engine receipt".into()))?;
    if value["schema"] != "elastos.local-model-engine/v2" {
        return Err(BridgeError::InitFailed(
            "invalid model engine receipt".into(),
        ));
    }
    let entries = value["entries"]
        .as_array()
        .filter(|entries| entries.len() <= 1024)
        .ok_or_else(|| BridgeError::InitFailed("invalid model engine receipt".into()))?;
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| BridgeError::InitFailed("invalid model engine receipt".into()))?;
        if path.is_empty()
            || !Path::new(path)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            || !seen.insert(path)
        {
            return Err(BridgeError::InitFailed(
                "invalid model engine receipt".into(),
            ));
        }
    }
    Ok((bundle, entries.clone()))
}

#[cfg(target_os = "macos")]
fn model_engine_receipt_file_matches(
    path: &Path,
    entry: &serde_json::Value,
) -> Result<bool, BridgeError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    if entry["type"] != "file"
        || !std::fs::symlink_metadata(path)
            .map_err(BridgeError::Spawn)?
            .is_file()
    {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path).map_err(BridgeError::Spawn)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(BridgeError::Spawn)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let expected = format!("sha256:{:x}", digest.finalize());
    Ok(entry["sha256"].as_str() == Some(expected.as_str()))
}

#[cfg(target_os = "macos")]
fn model_file_policy(
    binary_path: &Path,
    config: &ProviderConfig,
    journal: &Path,
    pinned_engine_bundle: Option<&Path>,
) -> Result<String, BridgeError> {
    let base = Path::new(&config.base_path);
    let mut files = std::collections::BTreeSet::new();
    let mut metadata_paths = base
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<std::collections::BTreeSet<_>>();
    files.insert(binary_path.to_path_buf());
    metadata_paths.extend(binary_path.ancestors().map(Path::to_path_buf));
    for offer in config.extra["offers"]
        .as_array()
        .ok_or_else(|| BridgeError::InitFailed("model offers unavailable".into()))?
    {
        if offer
            .pointer("/adapter/kind")
            .and_then(serde_json::Value::as_str)
            != Some("local_llama_cpp_text")
        {
            continue;
        }
        let engine = Path::new(
            offer
                .pointer("/adapter/engine/path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| BridgeError::InitFailed("model engine path unavailable".into()))?,
        );
        let model = Path::new(
            offer
                .pointer("/adapter/model/path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| BridgeError::InitFailed("model weights path unavailable".into()))?,
        );
        for path in [engine, model] {
            if !path.starts_with(base)
                || std::fs::canonicalize(path).ok().as_deref() != Some(path)
                || !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
            {
                return Err(BridgeError::InitFailed("unsafe model artifact path".into()));
            }
            files.insert(path.to_path_buf());
            metadata_paths.extend(path.ancestors().skip(1).map(Path::to_path_buf));
        }
        let engine_dir = engine
            .parent()
            .ok_or_else(|| BridgeError::InitFailed("model engine directory unavailable".into()))?;
        let mut dylibs = Vec::new();
        for entry in std::fs::read_dir(engine_dir).map_err(BridgeError::Spawn)? {
            let path = entry.map_err(BridgeError::Spawn)?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("dylib") {
                dylibs.push(path);
            }
        }
        let receipt = if dylibs.is_empty() {
            None
        } else {
            Some(model_engine_receipt_entries(base, engine)?)
        };
        for path in dylibs {
            let (bundle, receipt_entries) = receipt.as_ref().unwrap();
            let name = path
                .strip_prefix(bundle)
                .ok()
                .and_then(|path| path.to_str())
                .ok_or_else(|| BridgeError::InitFailed("invalid model engine file".into()))?;
            let matching = receipt_entries
                .iter()
                .filter(|entry| entry["path"].as_str() == Some(name))
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(BridgeError::InitFailed("unlisted model engine file".into()));
            }
            let entry = matching[0];
            let metadata = std::fs::symlink_metadata(&path).map_err(BridgeError::Spawn)?;
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(&path).map_err(BridgeError::Spawn)?;
                if entry["type"] != "symlink"
                    || entry["target"].as_str() != target.to_str()
                    || target.components().count() != 1
                    || !target
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
                {
                    return Err(BridgeError::InitFailed("changed model engine file".into()));
                }
            } else if !model_engine_receipt_file_matches(&path, entry)? {
                return Err(BridgeError::InitFailed("changed model engine file".into()));
            }
            let canonical = std::fs::canonicalize(&path).map_err(BridgeError::Spawn)?;
            if !canonical.starts_with(engine_dir)
                || !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file())
            {
                return Err(BridgeError::InitFailed("unsafe model engine file".into()));
            }
            if metadata.file_type().is_symlink() {
                let target = canonical
                    .strip_prefix(bundle)
                    .ok()
                    .and_then(|path| path.to_str())
                    .ok_or_else(|| BridgeError::InitFailed("unsafe model engine file".into()))?;
                let matching = receipt_entries
                    .iter()
                    .filter(|entry| entry["path"].as_str() == Some(target))
                    .collect::<Vec<_>>();
                if matching.len() != 1
                    || !model_engine_receipt_file_matches(&canonical, matching[0])?
                {
                    return Err(BridgeError::InitFailed("changed model engine file".into()));
                }
            }
            files.insert(path);
            files.insert(canonical);
        }
    }
    let mut policy = String::from(
        "(version 1)\n(allow default)\n(deny network-outbound)\n(deny file-read*)\n(deny file-write*)\n(allow file-read* (literal \"/\") (subpath \"/System\") (subpath \"/usr/lib\") (literal \"/dev/urandom\") (literal \"/dev/null\"))\n(allow file-write-data (literal \"/dev/null\"))\n",
    );
    // Runtime owns admission and descriptor verification. The child can read
    // admitted payloads created after startup, while staging and inventory stay
    // outside its file boundary. Seatbelt resolves aliases before this match.
    let admitted_parent = base.join("model-preparation");
    let mut admitted_pattern = String::from("^");
    for character in admitted_parent
        .to_str()
        .ok_or_else(|| BridgeError::InitFailed("invalid model sandbox path".into()))?
        .chars()
    {
        if "\\.^$|?*+()[]{}".contains(character) {
            admitted_pattern.push('\\');
        }
        admitted_pattern.push(character);
    }
    admitted_pattern.push_str("/admitted-");
    admitted_pattern.push_str(&"[a-f0-9]".repeat(64));
    admitted_pattern.push_str("(/|$)");
    policy.push_str(&format!(
        "(allow file-read* (regex \"{}\"))\n",
        seatbelt_path(Path::new(&admitted_pattern))?
    ));
    metadata_paths.insert(admitted_parent);
    if let Some(bundle) = pinned_engine_bundle {
        let prefix = base.join("libexec/llama.cpp");
        let relative = bundle
            .strip_prefix(&prefix)
            .map_err(|_| BridgeError::InitFailed("unsafe model engine bundle".into()))?;
        if relative.components().count() != 2
            || !relative
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return Err(BridgeError::InitFailed("unsafe model engine bundle".into()));
        }
        policy.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            seatbelt_path(bundle)?
        ));
        metadata_paths.extend(bundle.ancestors().map(Path::to_path_buf));
    }
    metadata_paths.remove(Path::new("/"));
    for ancestor in metadata_paths {
        policy.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            seatbelt_path(&ancestor)?
        ));
    }
    for path in files {
        policy.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            seatbelt_path(&path)?
        ));
    }
    let journal = seatbelt_path(journal)?;
    policy.push_str(&format!(
        "(allow file-read* (subpath \"{journal}\"))\n(allow file-write* (subpath \"{journal}\"))\n"
    ));
    Ok(policy)
}

// === Wire protocol types (mirror capsules/localhost-provider/src/main.rs) ===

/// Request from runtime to provider capsule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequest {
    /// Initialize the provider
    Init { config: ProviderConfig },

    /// Read file contents
    Read {
        path: String,
        token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        length: Option<u64>,
    },

    /// Write file contents
    Write {
        path: String,
        token: String,
        content: Vec<u8>,
        #[serde(default)]
        append: bool,
    },

    /// List directory contents
    List { path: String, token: String },

    /// Delete file or directory
    Delete {
        path: String,
        token: String,
        #[serde(default)]
        recursive: bool,
    },

    /// Get file/directory metadata
    Stat { path: String, token: String },

    /// Create directory
    Mkdir {
        path: String,
        token: String,
        #[serde(default)]
        parents: bool,
    },

    /// Check if path exists
    Exists { path: String, token: String },

    /// Shutdown the provider
    Shutdown,
}

/// Response from provider capsule to runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderResponse {
    /// Operation succeeded
    Ok {
        #[serde(default)]
        data: Option<serde_json::Value>,
    },

    /// Operation failed
    Error { code: String, message: String },
}

/// Provider configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Base path for all operations (sandbox root)
    #[serde(default)]
    pub base_path: String,

    /// Allowed path prefixes (relative to base_path)
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Read-only mode
    #[serde(default)]
    pub read_only: bool,

    /// Hex-encoded AES-256 encryption key (empty = no encryption)
    #[serde(default)]
    pub encryption_key: String,

    /// Provider-specific configuration (passed through to provider init)
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

// === Bridge errors ===

/// Errors from provider bridge operations
#[derive(Debug)]
pub enum BridgeError {
    /// Failed to spawn provider process
    Spawn(std::io::Error),
    /// Provider initialization failed
    InitFailed(String),
    /// Request timed out
    Timeout,
    /// Provider process exited unexpectedly
    ProcessExited,
    /// Failed to serialize/deserialize
    Serde(serde_json::Error),
    /// I/O error
    Io(std::io::Error),
    /// Provider returned an error
    Provider { code: String, message: String },
    /// Background provider I/O task failed
    TaskJoin(String),
    /// The Runtime refused to start a provider; it names the reason verbatim.
    Refused(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Spawn(e) => write!(f, "failed to spawn provider: {}", e),
            BridgeError::InitFailed(msg) => write!(f, "provider init failed: {}", msg),
            BridgeError::Timeout => write!(f, "provider request timed out"),
            BridgeError::ProcessExited => write!(f, "provider process exited unexpectedly"),
            BridgeError::Serde(e) => write!(f, "serialization error: {}", e),
            BridgeError::Io(e) => write!(f, "I/O error: {}", e),
            BridgeError::Provider { code, message } => {
                write!(f, "provider error [{}]: {}", code, message)
            }
            BridgeError::TaskJoin(message) => {
                write!(f, "provider bridge task failed: {}", message)
            }
            BridgeError::Refused(message) => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for BridgeError {}

// === ProviderBridge ===

/// Internal I/O state for the bridge
struct ProviderIo {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    reader: Box<dyn AsyncBufRead + Unpin + Send>,
}

/// Bridge to a provider capsule process.
///
/// Manages serial request/response communication over stdin/stdout.
/// All requests are serialized through a mutex (the provider processes
/// them one at a time).
pub struct ProviderBridge {
    io: Arc<Mutex<ProviderIo>>,
    child: Mutex<Option<Child>>,
    /// A forked provider whose pid this process owns. At most one of `child`
    /// and `fork` is set. The blocking `waitpid` task is the only reaper.
    fork: Mutex<Option<ForkChild>>,
    #[cfg(unix)]
    helper_owner: Mutex<Option<elastos_common::process_lifetime::ParentLifetime>>,
    /// True once a shutdown attempt has completed (child reaped, or the
    /// protocol shutdown was delivered on a childless bridge). Later
    /// shutdown() calls are idempotent no-ops.
    shutdown_completed: std::sync::atomic::AtomicBool,
    /// Timeout applied to each shutdown settle stage (protocol request,
    /// child wait, force reap). Tests inject a short value.
    shutdown_timeout: std::time::Duration,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    _local_brokers: Mutex<BrokerTasks>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    _local_ipc_dir: Mutex<Option<tempfile::TempDir>>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    _local_provider_pid: Arc<AtomicU32>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    _local_provider_birth: Arc<AtomicU64>,
    #[cfg(target_os = "macos")]
    hosted_run_bindings: Arc<StdMutex<BTreeMap<String, HostedRunBinding>>>,
}

#[cfg(target_os = "macos")]
struct HostedRunBinding {
    offer_id: String,
    request_id: String,
    operation: String,
    input_hash: String,
    effect_input_hash: Option<String>,
    input_schema: Option<String>,
    pending: usize,
    accepted: bool,
    dispatched: bool,
    terminal: bool,
    expires_at: std::time::Instant,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Default)]
struct BrokerTasks(Vec<tokio::task::JoinHandle<()>>);

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Drop for BrokerTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// A forked provider the Runtime owns. `status` resolves after the blocking
/// `waitpid` task reaps the pid, so that task is the only reaper.
struct ForkChild {
    pid: libc::pid_t,
    /// Opened before the wait. A later signal names this process.
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    status: oneshot::Receiver<i32>,
    /// True once the status was received; the waitpid task has reaped the pid,
    /// so `Drop` must not signal it again.
    reaped: bool,
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: libc::pid_t) -> Result<OwnedFd, BridgeError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        Err(refused(
            "provider start is refused: the process handle could not be opened",
        ))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

/// The child is still ours: it has not been waited on, so the pid cannot have
/// been reused. Reap it and refuse the start.
#[cfg(any(test, target_os = "linux"))]
fn reap_refused_child(pid: libc::pid_t) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid
            || (waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
        {
            break;
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn refuse_child_without_process_handle(pid: libc::pid_t) -> BridgeError {
    reap_refused_child(pid);
    refused("provider start is refused: the process handle could not be opened")
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static REPORT_LAUNCHED_PID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The next confined start writes the launched pid as the child's first stdin
/// line. The probe records that line.
#[cfg(all(test, target_os = "linux"))]
fn set_report_launched_pid(enabled: bool) {
    REPORT_LAUNCHED_PID.with(|cell| cell.set(enabled));
}

#[cfg(all(test, target_os = "linux"))]
fn launched_pid_line(pid: libc::pid_t) -> Option<String> {
    REPORT_LAUNCHED_PID
        .with(|cell| cell.get())
        .then(|| format!("{pid}\n"))
}

#[cfg(not(all(test, target_os = "linux")))]
fn launched_pid_line(_pid: libc::pid_t) -> Option<String> {
    None
}

#[cfg(test)]
static REAP_HOLD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Tests can hold the reaper for one pid. Production returns at once.
#[cfg(test)]
fn pause_before_reap(pid: libc::pid_t) {
    while REAP_HOLD_PID.load(std::sync::atomic::Ordering::Acquire) == pid {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(not(test))]
fn pause_before_reap(_pid: libc::pid_t) {}

#[cfg(test)]
static REAP_WAIT_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn note_reap_wait() {
    REAP_WAIT_STARTED.store(true, std::sync::atomic::Ordering::Release);
}

#[cfg(not(test))]
fn note_reap_wait() {}

#[cfg(test)]
fn swap_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().expect("cleanup swap tests")
}

#[cfg(test)]
struct HeldUnlinkSwap {
    dev: u64,
    ino: u64,
    aside: std::ffi::CString,
    canary: std::ffi::CString,
}

#[cfg(test)]
static HELD_UNLINK_SWAP: std::sync::Mutex<Option<HeldUnlinkSwap>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn arm_held_unlink_swap(dev: u64, ino: u64, aside: &std::ffi::CStr, canary: &std::ffi::CStr) {
    *HELD_UNLINK_SWAP.lock().expect("held unlink swap") = Some(HeldUnlinkSwap {
        dev,
        ino,
        aside: aside.to_owned(),
        canary: canary.to_owned(),
    });
}

#[cfg(test)]
fn held_unlink_swap_is_armed() -> bool {
    HELD_UNLINK_SWAP.lock().expect("held unlink swap").is_some()
}

/// Tests can move the live name aside and put another directory there before
/// the remove. The swap is for one directory. Production returns at once.
#[cfg(test)]
fn pause_before_held_unlink(parent: &OwnedFd, directory: &OwnedFd, name: &std::ffi::CStr) {
    let Ok(info) = stat_fd(directory.as_raw_fd()) else {
        return;
    };
    let swap = {
        let mut slot = HELD_UNLINK_SWAP.lock().expect("held unlink swap");
        if slot
            .as_ref()
            .is_some_and(|swap| swap.dev != stat_dev(&info) || swap.ino != stat_ino(&info))
        {
            return;
        }
        slot.take()
    };
    let Some(swap) = swap else {
        return;
    };
    unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            name.as_ptr(),
            parent.as_raw_fd(),
            swap.aside.as_ptr(),
        );
        libc::renameat(
            parent.as_raw_fd(),
            swap.canary.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        );
    }
}

#[cfg(not(test))]
fn pause_before_held_unlink(_parent: &OwnedFd, _directory: &OwnedFd, _name: &std::ffi::CStr) {}

#[cfg(test)]
struct MismatchSwap {
    dev: u64,
    ino: u64,
    aside: std::ffi::CString,
    canary: std::ffi::CString,
    blocker: std::ffi::CString,
}

#[cfg(test)]
static MISMATCH_SWAP: std::sync::Mutex<Option<MismatchSwap>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn arm_mismatch_swap(
    dev: u64,
    ino: u64,
    aside: &std::ffi::CStr,
    canary: &std::ffi::CStr,
    blocker: &std::ffi::CStr,
) {
    *MISMATCH_SWAP.lock().expect("mismatch swap") = Some(MismatchSwap {
        dev,
        ino,
        aside: aside.to_owned(),
        canary: canary.to_owned(),
        blocker: blocker.to_owned(),
    });
}

/// Tests can replace the private name after the rename and occupy the public
/// name. Production returns at once.
#[cfg(test)]
fn pause_after_quarantine_rename(
    parent: &OwnedFd,
    directory: &OwnedFd,
    quarantine: &std::ffi::CStr,
    name: &std::ffi::CStr,
) {
    let Ok(info) = stat_fd(directory.as_raw_fd()) else {
        return;
    };
    let swap = {
        let mut slot = MISMATCH_SWAP.lock().expect("mismatch swap");
        let matches = slot
            .as_ref()
            .is_some_and(|swap| swap.dev == stat_dev(&info) && swap.ino == stat_ino(&info));
        if !matches {
            return;
        }
        slot.take()
    };
    let Some(swap) = swap else {
        return;
    };
    let aside = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            quarantine.as_ptr(),
            parent.as_raw_fd(),
            swap.aside.as_ptr(),
        )
    };
    let canary = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            swap.canary.as_ptr(),
            parent.as_raw_fd(),
            quarantine.as_ptr(),
        )
    };
    let blocker = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            swap.blocker.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    assert_eq!(
        (aside, canary, blocker),
        (0, 0, 0),
        "the identity-check swap could not be arranged"
    );
}

#[cfg(not(test))]
fn pause_after_quarantine_rename(
    _parent: &OwnedFd,
    _directory: &OwnedFd,
    _quarantine: &std::ffi::CStr,
    _name: &std::ffi::CStr,
) {
}

#[cfg(test)]
struct PrivateUnlinkSwap {
    dev: u64,
    ino: u64,
    aside: std::ffi::CString,
    canary: std::ffi::CString,
}

#[cfg(test)]
static PRIVATE_UNLINK_SWAP: std::sync::Mutex<Option<PrivateUnlinkSwap>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn arm_private_unlink_swap(dev: u64, ino: u64, aside: &std::ffi::CStr, canary: &std::ffi::CStr) {
    *PRIVATE_UNLINK_SWAP.lock().expect("private unlink swap") = Some(PrivateUnlinkSwap {
        dev,
        ino,
        aside: aside.to_owned(),
        canary: canary.to_owned(),
    });
}

/// Tests can replace the private name after it has matched the held object.
/// Production returns at once.
#[cfg(test)]
fn pause_before_private_unlink(
    parent: &OwnedFd,
    expected: &libc::stat,
    quarantine: &std::ffi::CStr,
) {
    let swap = {
        let mut slot = PRIVATE_UNLINK_SWAP.lock().expect("private unlink swap");
        let matches = slot
            .as_ref()
            .is_some_and(|swap| swap.dev == stat_dev(expected) && swap.ino == stat_ino(expected));
        if !matches {
            return;
        }
        slot.take()
    };
    let Some(swap) = swap else {
        return;
    };
    let aside = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            quarantine.as_ptr(),
            parent.as_raw_fd(),
            swap.aside.as_ptr(),
        )
    };
    let canary = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            swap.canary.as_ptr(),
            parent.as_raw_fd(),
            quarantine.as_ptr(),
        )
    };
    assert_eq!(
        (aside, canary),
        (0, 0),
        "the private-name swap could not be arranged"
    );
}

#[cfg(not(test))]
fn pause_before_private_unlink(
    _parent: &OwnedFd,
    _expected: &libc::stat,
    _quarantine: &std::ffi::CStr,
) {
}

#[cfg(test)]
struct UnopenedSwap {
    aside: std::ffi::CString,
    canary: std::ffi::CString,
}

#[cfg(test)]
static UNOPENED_SWAP: std::sync::Mutex<Option<UnopenedSwap>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn arm_unopened_swap(aside: &std::ffi::CStr, canary: &std::ffi::CStr) {
    *UNOPENED_SWAP.lock().expect("unopened root") = Some(UnopenedSwap {
        aside: aside.to_owned(),
        canary: canary.to_owned(),
    });
}

/// Tests can replace a directory this start just created, before it is opened.
/// Production returns at once.
#[cfg(test)]
fn pause_after_creating_root(parent: &OwnedFd, name: &std::ffi::CStr) {
    let Some(swap) = UNOPENED_SWAP.lock().expect("unopened root").take() else {
        return;
    };
    let aside = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            name.as_ptr(),
            parent.as_raw_fd(),
            swap.aside.as_ptr(),
        )
    };
    let canary = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            swap.canary.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    let hidden = unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), 0, 0) };
    assert_eq!(
        (aside, canary, hidden),
        (0, 0, 0),
        "the unopened-root swap could not be arranged"
    );
}

#[cfg(not(test))]
fn pause_after_creating_root(_parent: &OwnedFd, _name: &std::ffi::CStr) {}

impl ForkChild {
    fn start(pid: libc::pid_t) -> Result<Self, BridgeError> {
        #[cfg(target_os = "linux")]
        let pidfd = match open_pidfd(pid) {
            Ok(pidfd) => pidfd,
            Err(_) => return Err(refuse_child_without_process_handle(pid)),
        };
        let (sender, status) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            pause_before_reap(pid);
            let mut word = 0;
            loop {
                let waited = unsafe { libc::waitpid(pid, &mut word, 0) };
                if waited == pid {
                    break;
                }
                if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
            let _ = sender.send(word);
        });
        Ok(Self {
            pid,
            #[cfg(target_os = "linux")]
            pidfd,
            status,
            reaped: false,
        })
    }

    fn force_kill(&self) {
        #[cfg(target_os = "linux")]
        {
            // The pid stays with the wait. The signal names the pidfd opened
            // for this process.
            let _ = self.pid;
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                )
            };
        }
        #[cfg(not(target_os = "linux"))]
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
    }
}

fn fresh_status() -> oneshot::Receiver<i32> {
    let (_sender, status) = oneshot::channel();
    status
}

/// `blocking_recv` panics on a runtime thread, so the wait runs on its own thread.
fn wait_for_reaper(status: oneshot::Receiver<i32>) {
    note_reap_wait();
    let waiting = std::thread::spawn(move || {
        let _ = status.blocking_recv();
    });
    let _ = waiting.join();
}

impl Drop for ForkChild {
    fn drop(&mut self) {
        // A received status means the waitpid task already reaped the pid.
        if self.reaped {
            return;
        }
        let pending = match self.status.try_recv() {
            Ok(_) => {
                self.reaped = true;
                false
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.reaped = true;
                false
            }
            Err(oneshot::error::TryRecvError::Empty) => true,
        };
        if pending {
            self.force_kill();
            let status = std::mem::replace(&mut self.status, fresh_status());
            wait_for_reaper(status);
            self.reaped = true;
        }
    }
}

/// A provider that was confined at launch and answered `Init`.
///
/// The field is private and `spawn_confined` is the only constructor. There is
/// no `From<ProviderBridge>`, so a plain spawn cannot be dressed as confined.
pub struct Confined {
    bridge: Arc<ProviderBridge>,
}

impl Confined {
    pub fn bridge(&self) -> &Arc<ProviderBridge> {
        &self.bridge
    }
}

impl std::fmt::Debug for Confined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Confined")
    }
}

/// A storage root this start created. Drop removes that directory through the
/// descriptor opened at creation. A root that already existed stays. A later
/// name at the same path is a different file, so it is left in place.
struct CreatedStorageRoot {
    parent: OwnedFd,
    name: std::ffi::CString,
    directory: OwnedFd,
    armed: bool,
}

impl CreatedStorageRoot {
    fn disarm(&mut self) {
        self.armed = false;
    }

    fn remove_opened_root(&self) {
        let _ = unlink_held_directory(&self.parent, &self.directory, Some(&self.name));
    }
}

/// The bridge owns the child. Dropping it reaps that child before `root`
/// removes the directory this start created.
struct ConfinedStart {
    bridge: Option<ProviderBridge>,
    root: CreatedStorageRoot,
}

impl Drop for ConfinedStart {
    fn drop(&mut self) {
        // The child is reaped before the storage root is removed.
        self.bridge.take();
    }
}

impl Drop for CreatedStorageRoot {
    fn drop(&mut self) {
        if self.armed {
            self.remove_opened_root();
        }
    }
}

#[cfg(test)]
struct CheckedLaunchSwap {
    dev: u64,
    ino: u64,
    aside: std::ffi::CString,
    canary: std::ffi::CString,
}

#[cfg(test)]
static CHECKED_LAUNCH_SWAP: std::sync::Mutex<Option<CheckedLaunchSwap>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, target_os = "linux"))]
fn arm_checked_launch_swap(dev: u64, ino: u64, aside: &std::ffi::CStr, canary: &std::ffi::CStr) {
    *CHECKED_LAUNCH_SWAP.lock().expect("checked launch") = Some(CheckedLaunchSwap {
        dev,
        ino,
        aside: aside.to_owned(),
        canary: canary.to_owned(),
    });
}

/// Tests can place another directory at the storage root after this start has
/// opened it and before the launcher opens that path. The placement is for one
/// directory. Production returns at once.
#[cfg(test)]
fn pause_before_launcher(parent: &OwnedFd, directory: &OwnedFd, name: &std::ffi::CStr) {
    let Ok(info) = stat_fd(directory.as_raw_fd()) else {
        return;
    };
    let swap = {
        let mut slot = CHECKED_LAUNCH_SWAP.lock().expect("checked launch");
        let matches = slot
            .as_ref()
            .is_some_and(|swap| swap.dev == stat_dev(&info) && swap.ino == stat_ino(&info));
        if !matches {
            return;
        }
        slot.take()
    };
    let Some(swap) = swap else {
        return;
    };
    let aside = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            name.as_ptr(),
            parent.as_raw_fd(),
            swap.aside.as_ptr(),
        )
    };
    let canary = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            swap.canary.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    assert_eq!(
        (aside, canary),
        (0, 0),
        "the checked directory could not be set aside"
    );
}

#[cfg(not(test))]
fn pause_before_launcher(_parent: &OwnedFd, _directory: &OwnedFd, _name: &std::ffi::CStr) {}

fn refused(reason: &str) -> BridgeError {
    BridgeError::Refused(reason.to_string())
}

fn open_directory(path: &Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            bytes.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn open_directory_at(parent: &OwnedFd, name: &std::ffi::CStr) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn stat_fd(fd: i32) -> std::io::Result<libc::stat> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, info.as_mut_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { info.assume_init() })
    }
}

fn stat_dev(info: &libc::stat) -> u64 {
    #[cfg(target_os = "linux")]
    {
        info.st_dev
    }
    #[cfg(not(target_os = "linux"))]
    {
        info.st_dev as u64
    }
}

fn stat_ino(info: &libc::stat) -> u64 {
    info.st_ino
}

fn lstat_at(directory: &OwnedFd, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { info.assume_init() })
    }
}

fn list_entries(directory: &OwnedFd) -> std::io::Result<Vec<std::ffi::CString>> {
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// Remove entries through `directory`. A symlink is unlinked itself.
fn remove_children(directory: &OwnedFd) {
    let Ok(names) = list_entries(directory) else {
        return;
    };
    for name in names {
        let Ok(info) = lstat_at(directory, &name) else {
            continue;
        };
        if info.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let Ok(child) = open_directory_at(directory, &name) else {
                continue;
            };
            let Ok(opened) = stat_fd(child.as_raw_fd()) else {
                continue;
            };
            if stat_dev(&opened) == stat_dev(&info) && stat_ino(&opened) == stat_ino(&info) {
                let _ = unlink_held_directory(directory, &child, Some(&name));
            }
        } else {
            unlink_listed_file(directory, &name, &info);
        }
    }
}

/// The last component of the directory this descriptor holds.
fn held_directory_name(directory: &OwnedFd) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    #[cfg(target_os = "linux")]
    let bytes = {
        let link = std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd())).ok()?;
        link.file_name()?.as_bytes().to_vec()
    };
    #[cfg(target_os = "macos")]
    let bytes = {
        let mut buf = [0u8; 1024];
        let rc = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let text = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
        let path = Path::new(std::ffi::OsStr::from_bytes(text.to_bytes()));
        path.file_name()?.as_bytes().to_vec()
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let bytes = {
        let _ = directory;
        return None;
    };
    std::ffi::CString::new(bytes).ok()
}

fn same_directory(left: &libc::stat, right: &libc::stat) -> bool {
    stat_dev(left) == stat_dev(right) && stat_ino(left) == stat_ino(right)
}

fn fill_random(bytes: &mut [u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        let wrote = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        wrote == bytes.len() as isize
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) == 0 }
    }
}

/// A sibling name that no caller chooses. The 16 hex digits come from the
/// kernel random source.
fn private_component() -> Option<std::ffi::CString> {
    let mut bytes = [0u8; 8];
    if !fill_random(&mut bytes) {
        return None;
    }
    let mut name = *b".elastos-held-0000000000000000\0";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.iter().enumerate() {
        name[14 + index * 2] = HEX[(byte >> 4) as usize];
        name[15 + index * 2] = HEX[(byte & 0xf) as usize];
    }
    std::ffi::CStr::from_bytes_with_nul(&name)
        .ok()
        .map(std::ffi::CString::from)
}

/// A parent of a storage root or of a cleanup entry is owned by the effective
/// user and has no group or other write permission.
fn parent_is_private(info: &libc::stat) -> bool {
    info.st_uid == unsafe { libc::geteuid() } && info.st_mode & 0o022 == 0
}

fn held_parent_is_private(parent: &OwnedFd) -> bool {
    stat_fd(parent.as_raw_fd()).is_ok_and(|info| parent_is_private(&info))
}

/// Rename without replacing a name that already exists. A parent that is not
/// owned by the effective user, or that is writable by group or other, stays
/// as it is.
fn rename_exclusive(parent: &OwnedFd, from: &std::ffi::CStr, to: &std::ffi::CStr) -> bool {
    if !held_parent_is_private(parent) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        const RENAME_NOREPLACE: libc::c_uint = 1;
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_NOREPLACE,
            ) == 0
        }
    }
    #[cfg(target_os = "macos")]
    {
        const RENAME_EXCL: libc::c_uint = 0x0004;
        unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_EXCL,
            ) == 0
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, from, to);
        false
    }
}

/// Put the private name back on the public name. A failed check does not remove
/// the private entry: that entry may be a different file.
fn restore_name(parent: &OwnedFd, quarantine: &std::ffi::CStr, name: &std::ffi::CStr) {
    let _ = rename_exclusive(parent, quarantine, name);
}

fn entry_matches(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    expected: &libc::stat,
) -> bool {
    if flags == libc::AT_REMOVEDIR {
        let Ok(opened) = open_directory_at(parent, name) else {
            return false;
        };
        let Ok(info) = stat_fd(opened.as_raw_fd()) else {
            return false;
        };
        return same_directory(&info, expected);
    }
    let Ok(info) = lstat_at(parent, name) else {
        return false;
    };
    same_directory(&info, expected)
}

/// Remove the private name only when it is still `expected` and the parent is
/// owned by the effective user with no group or other write permission. A
/// mismatch is renamed back and left in place. A parent that fails that check
/// is left in place.
fn release_private_name(
    parent: &OwnedFd,
    quarantine: &std::ffi::CStr,
    original: &std::ffi::CStr,
    flags: libc::c_int,
    expected: &libc::stat,
) -> bool {
    pause_before_private_unlink(parent, expected, quarantine);
    if !entry_matches(parent, quarantine, flags, expected) {
        restore_name(parent, quarantine, original);
        return false;
    }
    if !held_parent_is_private(parent) {
        return false;
    }
    unsafe { libc::unlinkat(parent.as_raw_fd(), quarantine.as_ptr(), flags) == 0 }
}

/// Move `name` to a private sibling, and remove that sibling only when it is
/// still the held directory. A different directory at the private name is
/// renamed back. `unlinkat` accepts `AT_REMOVEDIR` and rejects every other
/// flag, so the remove names the private entry and only after that check.
fn relocate_held_directory(parent: &OwnedFd, directory: &OwnedFd, name: &std::ffi::CStr) -> bool {
    let Some(quarantine) = private_component() else {
        return false;
    };
    if !rename_exclusive(parent, name, &quarantine) {
        return false;
    }
    pause_after_quarantine_rename(parent, directory, &quarantine, name);
    let Ok(held) = stat_fd(directory.as_raw_fd()) else {
        restore_name(parent, &quarantine, name);
        return false;
    };
    if !entry_matches(parent, &quarantine, libc::AT_REMOVEDIR, &held) {
        restore_name(parent, &quarantine, name);
        return false;
    }
    remove_children(directory);
    release_private_name(parent, &quarantine, name, libc::AT_REMOVEDIR, &held)
}

/// Unlink a non-directory only when its dev and inode are still the listed ones.
fn unlink_listed_file(parent: &OwnedFd, name: &std::ffi::CStr, listed: &libc::stat) -> bool {
    let Some(quarantine) = private_component() else {
        return false;
    };
    if !rename_exclusive(parent, name, &quarantine) {
        return false;
    }
    if !entry_matches(parent, &quarantine, 0, listed) {
        restore_name(parent, &quarantine, name);
        return false;
    }
    release_private_name(parent, &quarantine, name, 0, listed)
}

fn unlink_name_if_held(parent: &OwnedFd, directory: &OwnedFd, name: &std::ffi::CStr) -> bool {
    pause_before_held_unlink(parent, directory, name);
    relocate_held_directory(parent, directory, name)
}

/// Remove the directory this descriptor holds. The current name is read twice
/// so a test can move the directory aside between the reads. The remembered
/// name is the last place to look. Each attempt removes only the directory
/// this descriptor still holds.
fn unlink_held_directory(
    parent: &OwnedFd,
    directory: &OwnedFd,
    remembered: Option<&std::ffi::CStr>,
) -> bool {
    for _ in 0..2 {
        if let Some(name) = held_directory_name(directory) {
            if unlink_name_if_held(parent, directory, &name) {
                return true;
            }
        }
    }
    match remembered {
        Some(name) => unlink_name_if_held(parent, directory, name),
        None => false,
    }
}

fn create_directory_at(parent: &OwnedFd, name: &std::ffi::CStr) -> Result<bool, BridgeError> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        Ok(false)
    } else {
        Err(BridgeError::Io(error))
    }
}

/// A directory this start created and never opened stays. Removing the name
/// can remove a different directory.
fn keep_unopened_root(parent: &OwnedFd, name: &std::ffi::CStr) {
    // The name stays because this start never opened the directory.
    let _ = (parent, name);
}

fn name_is_symlink(parent: &OwnedFd, name: &std::ffi::CStr) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return false;
    }
    let info = unsafe { info.assume_init() };
    info.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// Create `storage_root` at 0700 under a parent owned by the effective user
/// with no group or other write permission, and open it with
/// `O_DIRECTORY | O_NOFOLLOW`. The returned guard holds that descriptor.
fn create_storage_root(storage_root: &Path) -> Result<CreatedStorageRoot, BridgeError> {
    use std::os::unix::ffi::OsStrExt;
    let parent_path = storage_root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            refused("provider start is refused: the storage root has no parent directory")
        })?;
    let name = storage_root.file_name().ok_or_else(|| {
        refused("provider start is refused: the storage root has no directory name")
    })?;
    let parent = open_directory(parent_path).map_err(|error| {
        let symlink = std::fs::symlink_metadata(parent_path)
            .ok()
            .is_some_and(|meta| meta.file_type().is_symlink());
        if symlink || error.raw_os_error() == Some(libc::ELOOP) {
            refused("provider start is refused: the storage root's parent is a symlink")
        } else {
            BridgeError::Io(error)
        }
    })?;
    let parent_stat = stat_fd(parent.as_raw_fd()).map_err(BridgeError::Io)?;
    if !parent_is_private(&parent_stat) {
        return Err(refused(
            if parent_stat.st_uid != unsafe { libc::geteuid() } {
                "provider start is refused: the storage root's parent is not owned by the effective user"
            } else {
                "provider start is refused: the storage root's parent is writable by group or other"
            },
        ));
    }
    let name_c = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| refused("provider start is refused: the storage root name contains NUL"))?;
    let created = create_directory_at(&parent, &name_c)?;
    if created {
        pause_after_creating_root(&parent, &name_c);
    }
    let directory = match open_directory_at(&parent, &name_c) {
        Ok(directory) => directory,
        Err(error) => {
            if created {
                keep_unopened_root(&parent, &name_c);
            }
            let symlink = name_is_symlink(&parent, &name_c);
            return Err(match error.raw_os_error() {
                _ if symlink || error.raw_os_error() == Some(libc::ELOOP) => {
                    refused("provider start is refused: the storage root is a symlink")
                }
                Some(libc::ENOTDIR) => {
                    refused("provider start is refused: the storage root is not a directory")
                }
                _ => BridgeError::Io(error),
            });
        }
    };
    let info = match stat_fd(directory.as_raw_fd()) {
        Ok(info) => info,
        Err(error) => {
            if created {
                let _ = unlink_held_directory(&parent, &directory, Some(&name_c));
            }
            return Err(BridgeError::Io(error));
        }
    };
    if info.st_uid != unsafe { libc::geteuid() } {
        // The opened directory is not ours. Removing `name` can delete a
        // different directory, so both stay.
        return Err(refused(
            "provider start is refused: the storage root is not owned by the effective user",
        ));
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } < 0
        || unsafe { libc::fsync(directory.as_raw_fd()) } < 0
    {
        let error = std::io::Error::last_os_error();
        if created {
            let _ = unlink_held_directory(&parent, &directory, Some(&name_c));
        }
        return Err(BridgeError::Io(error));
    }
    Ok(CreatedStorageRoot {
        parent,
        name: name_c,
        directory,
        armed: created,
    })
}

fn pipe_pair() -> Result<(OwnedFd, OwnedFd), BridgeError> {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(BridgeError::Spawn(std::io::Error::last_os_error()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(BridgeError::Spawn(std::io::Error::last_os_error()));
        }
        for &fd in &fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
            {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(BridgeError::Spawn(error));
            }
        }
    }
    if fds[0] < 3 || fds[1] < 3 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(refused(
            "provider start is refused: a pipe descriptor is below fd 3",
        ));
    }
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

impl ProviderBridge {
    async fn force_child_reap(
        child: &mut Child,
        shutdown_timeout: std::time::Duration,
    ) -> Result<(), BridgeError> {
        child.start_kill().map_err(BridgeError::Io)?;
        match tokio::time::timeout(shutdown_timeout, child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(BridgeError::Io(error)),
            Err(_) => Err(BridgeError::Timeout),
        }
    }

    async fn terminate_child_for_init_failure(
        child_mutex: &Mutex<Option<Child>>,
        shutdown_timeout: std::time::Duration,
    ) {
        let mut child_guard = child_mutex.lock().await;
        let Some(mut child) = child_guard.take() else {
            return;
        };

        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = Self::force_child_reap(&mut child, shutdown_timeout).await;
            }
        }
    }

    /// Spawn a provider capsule as a child process.
    ///
    /// Starts the binary, sends Init with the given config, and waits
    /// for the init response.
    pub async fn spawn(
        binary_path: &CheckedExecutable,
        config: ProviderConfig,
    ) -> Result<Self, BridgeError> {
        Self::spawn_with_timeouts(binary_path, config, INIT_TIMEOUT, SHUTDOWN_TIMEOUT).await
    }

    /// Start a rights-declaring provider through the OS entry and return
    /// `Confined` only after `Init` succeeded.
    ///
    /// The Runtime creates the fresh storage root under a parent owned by the
    /// effective user with no group or other write permission, opens that
    /// directory without following a symlink, and syncs it. The launcher
    /// receives that directory's device and inode, opens the path again, and
    /// refuses when the directory is different. That comparison happens before
    /// the plan and the fork. The child's stdin and stdout are fresh pipes. A
    /// refusal returns `Err` and starts nothing; there is no fallback to the
    /// plain `spawn`.
    pub async fn spawn_confined(
        component_key: &str,
        authority: &ProviderAuthority,
        binary_path: &CheckedExecutable,
        storage_root: &Path,
        config: ProviderConfig,
    ) -> Result<Confined, BridgeError> {
        let Some(provider) =
            super::rights_table::RuntimeProviderId::from_component_key(component_key)
        else {
            return Err(BridgeError::Refused(format!(
                "provider start is refused: component key \"{component_key}\" is not one of did-provider, wallet-provider, model-provider"
            )));
        };
        let created_root = create_storage_root(storage_root)?;
        let info = stat_fd(created_root.directory.as_raw_fd()).map_err(BridgeError::Io)?;
        let checked = super::os_entry::CheckedDirectory {
            path: storage_root,
            dev: stat_dev(&info),
            ino: stat_ino(&info),
        };
        pause_before_launcher(
            &created_root.parent,
            &created_root.directory,
            &created_root.name,
        );
        let (stdin_read, to_child) = pipe_pair()?;
        let (from_child, stdout_write) = pipe_pair()?;
        let stdio = super::os_entry::ChildStdio {
            stdin: stdin_read.as_raw_fd(),
            stdout: stdout_write.as_raw_fd(),
            to_child,
            from_child,
        };
        let launched =
            super::os_entry::start_provider(provider, authority, binary_path, checked, stdio)
                .map_err(BridgeError::Refused)?;
        // The child holds its copies; these are the parent's, and must close
        // so the child sees EOF on stdin and the parent sees EOF on stdout.
        drop(stdin_read);
        drop(stdout_write);

        let fork = ForkChild::start(launched.pid)?;
        let mut to_child = std::fs::File::from(launched.to_child);
        if let Some(line) = launched_pid_line(launched.pid) {
            use std::io::Write as _;
            if let Err(error) = to_child.write_all(line.as_bytes()) {
                drop(fork);
                return Err(BridgeError::Io(error));
            }
        }
        let from_child = std::fs::File::from(launched.from_child);
        let bridge = Self {
            io: Arc::new(Mutex::new(ProviderIo {
                writer: Box::new(tokio::fs::File::from_std(to_child)),
                reader: Box::new(tokio::io::BufReader::new(tokio::fs::File::from_std(
                    from_child,
                ))),
            })),
            child: Mutex::new(None),
            fork: Mutex::new(Some(fork)),
            #[cfg(unix)]
            helper_owner: Mutex::new(None),
            shutdown_completed: std::sync::atomic::AtomicBool::new(false),
            shutdown_timeout: SHUTDOWN_TIMEOUT,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_ipc_dir: Mutex::new(None),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_brokers: Mutex::new(BrokerTasks::default()),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_pid: Arc::new(AtomicU32::new(0)),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_birth: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "macos")]
            hosted_run_bindings: Arc::new(StdMutex::new(BTreeMap::new())),
        };
        let mut start = ConfinedStart {
            bridge: Some(bridge),
            root: created_root,
        };
        let init_result = start
            .bridge
            .as_ref()
            .expect("the confined start owns its bridge")
            .init_provider(config, INIT_TIMEOUT)
            .await;
        init_result?;
        start.root.disarm();
        let bridge = start
            .bridge
            .take()
            .expect("the confined start owns its bridge");
        Ok(Confined {
            bridge: Arc::new(bridge),
        })
    }

    /// Admit only Runtime-selected private engine sockets for the native model provider.
    #[cfg(target_os = "macos")]
    pub async fn spawn_confined_model(
        binary_path: &CheckedExecutable,
        config: ProviderConfig,
    ) -> Result<
        (
            Self,
            BTreeMap<String, String>,
            Vec<String>,
            ProviderConfig,
            tokio::net::UnixListener,
        ),
        BridgeError,
    > {
        Self::spawn_confined_model_with_engine_bundle(binary_path, config, None).await
    }

    /// Predeclare the current component-pinned engine bundle for later admission.
    /// Runtime retains verification and offer authority through every Init.
    #[cfg(target_os = "macos")]
    pub async fn spawn_confined_model_with_engine_bundle(
        binary_path: &CheckedExecutable,
        mut config: ProviderConfig,
        pinned_engine_bundle: Option<&Path>,
    ) -> Result<
        (
            Self,
            BTreeMap<String, String>,
            Vec<String>,
            ProviderConfig,
            tokio::net::UnixListener,
        ),
        BridgeError,
    > {
        let offers = config
            .extra
            .get("offers")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BridgeError::InitFailed("model offers unavailable".into()))?;
        let mut sockets = BTreeMap::new();
        let mut vacant_sockets = Vec::new();
        let mut brokers = BrokerTasks::default();
        let provider_pid = Arc::new(AtomicU32::new(0));
        let provider_birth = Arc::new(AtomicU64::new(0));
        let ipc_dir = tempfile::Builder::new()
            .prefix("em-")
            .tempdir()
            .map_err(BridgeError::Spawn)?;
        // Seatbelt resolves /var to /private/var before comparing literal paths.
        let ipc_path = std::fs::canonicalize(ipc_dir.path()).map_err(BridgeError::Spawn)?;
        let journal = model_journal_for_sandbox(&config)?;
        let prepared = binary_path
            .verify_at_spawn()
            .map_err(BridgeError::Refused)?;
        let mut policy = model_file_policy(
            prepared.exec_path(),
            &config,
            &journal,
            pinned_engine_bundle,
        )?;
        let local_ids = offers
            .iter()
            .filter(|offer| {
                offer
                    .pointer("/adapter/kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("local_llama_cpp_text")
            })
            .map(|offer| {
                offer
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| BridgeError::InitFailed("local offer id unavailable".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if local_ids.len() > MAX_LOCAL_MODEL_SLOTS {
            return Err(BridgeError::InitFailed(
                "too many local model offers".into(),
            ));
        }
        for index in 0..MAX_LOCAL_MODEL_SLOTS {
            let socket = ipc_path.join(format!("{index}.sock"));
            let engine_socket = ipc_path.join(format!("{index}.engine.sock"));
            let socket = socket
                .to_str()
                .ok_or_else(|| BridgeError::InitFailed("invalid local socket path".into()))?
                .to_string();
            if !socket.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            }) {
                return Err(BridgeError::InitFailed("unsafe local socket path".into()));
            }
            if socket.len() >= 104 {
                return Err(BridgeError::InitFailed("local socket path too long".into()));
            }
            if engine_socket.as_os_str().len() >= 104 {
                return Err(BridgeError::InitFailed(
                    "engine socket path too long".into(),
                ));
            }
            if let Some(id) = local_ids.get(index) {
                if sockets.insert((*id).to_string(), socket.clone()).is_some() {
                    return Err(BridgeError::InitFailed("duplicate local offer id".into()));
                }
            } else {
                vacant_sockets.push(socket.clone());
            }
            policy.push_str(&format!(
                "(allow network-outbound (literal \"{socket}\"))\n"
            ));
            policy.push_str(&format!(
                "(allow file-read-metadata (literal \"{0}\"))\n(allow file-write* (literal \"{0}\"))\n",
                seatbelt_path(Path::new(&engine_socket))?
            ));
            brokers.0.push(
                super::local_model_broker::start(
                    &socket,
                    engine_socket,
                    provider_pid.clone(),
                    provider_birth.clone(),
                )
                .map_err(BridgeError::Spawn)?,
            );
        }
        let hosted_socket = ipc_path.join("hosted.sock");
        let hosted_socket = hosted_socket
            .to_str()
            .ok_or_else(|| BridgeError::InitFailed("invalid hosted socket path".into()))?;
        if hosted_socket.len() >= 104
            || !hosted_socket.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            })
        {
            return Err(BridgeError::InitFailed(
                "hosted socket path too long".into(),
            ));
        }
        policy.push_str(&format!(
            "(allow network-outbound (literal \"{hosted_socket}\"))\n"
        ));
        let hosted_listener =
            tokio::net::UnixListener::bind(hosted_socket).map_err(BridgeError::Spawn)?;
        config.extra["runtime_local_sockets"] = serde_json::json!(sockets);
        config.extra["runtime_hosted_socket"] = serde_json::json!(hosted_socket);
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(policy).arg(prepared.exec_path());
        let mut bridge = Self::spawn_command(
            prepared,
            command,
            config.clone(),
            INIT_TIMEOUT,
            SHUTDOWN_TIMEOUT,
            std::process::Stdio::inherit(),
            false,
        )
        .await?;
        let pid = bridge
            .child
            .lock()
            .await
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or_else(|| BridgeError::InitFailed("model provider pid unavailable".into()))?;
        let birth = match super::local_model_broker::process_birth(pid) {
            Some(birth) => birth,
            None => {
                let _ = bridge.shutdown().await;
                return Err(BridgeError::InitFailed(
                    "model provider identity unavailable".into(),
                ));
            }
        };
        provider_birth.store(birth, Ordering::Release);
        provider_pid.store(pid, Ordering::Release);
        *bridge._local_ipc_dir.lock().await = Some(ipc_dir);
        *bridge._local_brokers.lock().await = brokers;
        bridge._local_provider_pid = provider_pid;
        bridge._local_provider_birth = provider_birth;
        Ok((bridge, sockets, vacant_sockets, config, hosted_listener))
    }

    /// Start a Linux model provider with private local Unix routes and a
    /// kernel socket filter inherited by its guard and llama.cpp descendants.
    #[cfg(target_os = "linux")]
    pub async fn spawn_confined_model_linux(
        binary_path: &CheckedExecutable,
        mut config: ProviderConfig,
    ) -> Result<(Self, BTreeMap<String, String>, Vec<String>, ProviderConfig), BridgeError> {
        let offers = config
            .extra
            .get("offers")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BridgeError::InitFailed("model offers unavailable".into()))?;
        let ipc_dir = tempfile::Builder::new()
            .prefix("em-")
            .tempdir()
            .map_err(BridgeError::Spawn)?;
        let ipc_path = std::fs::canonicalize(ipc_dir.path()).map_err(BridgeError::Spawn)?;
        let mut sockets = BTreeMap::new();
        let mut vacant_sockets = Vec::new();
        let mut brokers = BrokerTasks::default();
        let provider_pid = Arc::new(AtomicU32::new(0));
        let provider_birth = Arc::new(AtomicU64::new(0));
        let local_ids = offers
            .iter()
            .filter(|offer| {
                offer
                    .pointer("/adapter/kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("local_llama_cpp_text")
            })
            .map(|offer| {
                offer
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| BridgeError::InitFailed("local offer id unavailable".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if local_ids.len() > MAX_LOCAL_MODEL_SLOTS {
            return Err(BridgeError::InitFailed(
                "too many local model offers".into(),
            ));
        }
        for index in 0..MAX_LOCAL_MODEL_SLOTS {
            let socket = ipc_path.join(format!("{index}.sock"));
            let engine_socket = ipc_path.join(format!("{index}.engine.sock"));
            let socket = socket
                .to_str()
                .ok_or_else(|| BridgeError::InitFailed("invalid local socket path".into()))?
                .to_string();
            if socket.len() >= 104 || engine_socket.as_os_str().len() >= 104 {
                return Err(BridgeError::InitFailed("local socket path too long".into()));
            }
            if let Some(id) = local_ids.get(index) {
                if sockets.insert((*id).to_string(), socket.clone()).is_some() {
                    return Err(BridgeError::InitFailed("duplicate local offer id".into()));
                }
            } else {
                vacant_sockets.push(socket.clone());
            }
            brokers.0.push(
                super::local_model_broker::start(
                    &socket,
                    engine_socket,
                    provider_pid.clone(),
                    provider_birth.clone(),
                )
                .map_err(BridgeError::Spawn)?,
            );
        }
        config.extra["runtime_local_sockets"] = serde_json::json!(sockets);
        let prepared = binary_path
            .verify_at_spawn()
            .map_err(BridgeError::Refused)?;
        let mut command = Command::new(prepared.exec_path());
        super::linux_model_seccomp::install_on_command(&mut command).map_err(BridgeError::Spawn)?;
        let mut bridge = Self::spawn_command(
            prepared,
            command,
            config.clone(),
            INIT_TIMEOUT,
            SHUTDOWN_TIMEOUT,
            std::process::Stdio::null(),
            false,
        )
        .await?;
        let pid = bridge
            .child
            .lock()
            .await
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or_else(|| BridgeError::InitFailed("model provider pid unavailable".into()))?;
        let birth = match super::local_model_broker::process_birth(pid) {
            Some(birth) => birth,
            None => {
                let _ = bridge.shutdown().await;
                return Err(BridgeError::InitFailed(
                    "model provider identity unavailable".into(),
                ));
            }
        };
        provider_birth.store(birth, Ordering::Release);
        provider_pid.store(pid, Ordering::Release);
        *bridge._local_ipc_dir.lock().await = Some(ipc_dir);
        *bridge._local_brokers.lock().await = brokers;
        bridge._local_provider_pid = provider_pid;
        bridge._local_provider_birth = provider_birth;
        Ok((bridge, sockets, vacant_sockets, config))
    }

    #[cfg(target_os = "macos")]
    pub fn confined_model_identity(&self) -> Option<(u32, u64)> {
        let pid = self._local_provider_pid.load(Ordering::Acquire);
        let birth = self._local_provider_birth.load(Ordering::Acquire);
        (pid != 0 && super::local_model_broker::process_birth(pid) == Some(birth))
            .then_some((pid, birth))
    }

    #[cfg(target_os = "macos")]
    fn record_confined_model_run(
        &self,
        request: &serde_json::Value,
    ) -> Result<Option<String>, BridgeError> {
        if self.confined_model_identity().is_none() || request["op"] != "runs_create" {
            return Ok(None);
        }
        let Some(offer_id) = request["offer_id"].as_str() else {
            return Ok(None);
        };
        let hosted_instance = offer_id
            .strip_prefix("model:hosted-")
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        if !hosted_instance && offer_id != "model:openrouter" && offer_id != "model:venice" {
            return Ok(None);
        }
        let rejected = || BridgeError::Provider {
            code: "context_rejected".into(),
            message: "Runtime model run binding unavailable".into(),
        };
        let binding: RuntimeCreateBinding = serde_json::from_value(
            request
                .get("runtime_binding")
                .cloned()
                .ok_or_else(rejected)?,
        )
        .map_err(|_| rejected())?;
        let operation = request["operation"].as_str().ok_or_else(rejected)?;
        let input = request.get("input").ok_or_else(rejected)?;
        binding
            .validate(offer_id, operation, input)
            .map_err(|_| rejected())?;
        let run_id = model_run_id(&binding);
        let effect_input_hash = match operation {
            "text.generate" if input["schema"] == elastos_model_contract::TEXT_INPUT_V1_SCHEMA => {
                input
                    .get("prompt")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|prompt| model_input_hash(&serde_json::json!(prompt)).ok())
            }
            "text.generate" if input["schema"] == elastos_model_contract::TEXT_INPUT_V2_SCHEMA => {
                elastos_model_contract::validate_text_input_v2(input).map_err(|_| rejected())?;
                Some(model_input_hash(&input["messages"]).map_err(|_| rejected())?)
            }
            elastos_model_contract::decisions::OPERATION
                if input["schema"] == elastos_model_contract::decisions::INPUT_SCHEMA =>
            {
                input.get("state").and_then(|state| {
                    input.get("questions").and_then(|questions| {
                        model_input_hash(&serde_json::json!({
                            "state": state, "questions": questions
                        }))
                        .ok()
                    })
                })
            }
            _ => None,
        };
        let now = std::time::Instant::now();
        let mut runs = self.hosted_run_bindings.lock().map_err(|_| rejected())?;
        runs.retain(|_, run| run.expires_at > now);
        if let Some(existing) = runs.get_mut(&run_id) {
            if existing.offer_id != offer_id
                || existing.request_id != binding.request_id
                || existing.operation != operation
                || existing.input_hash != binding.input_hash
            {
                return Err(rejected());
            }
            existing.pending = existing.pending.saturating_add(1);
        } else {
            if runs.len() >= MAX_HOSTED_RUN_BINDINGS {
                return Err(rejected());
            }
            runs.insert(
                run_id.clone(),
                HostedRunBinding {
                    offer_id: offer_id.to_owned(),
                    request_id: binding.request_id,
                    operation: operation.to_owned(),
                    input_hash: binding.input_hash,
                    effect_input_hash,
                    input_schema: input["schema"].as_str().map(str::to_owned),
                    pending: 1,
                    accepted: false,
                    dispatched: false,
                    terminal: false,
                    expires_at: now + HOSTED_RUN_BINDING_TTL,
                },
            );
        }
        Ok(Some(run_id))
    }

    #[cfg(target_os = "macos")]
    fn settle_confined_model_run(&self, run_id: &str, accepted: bool) {
        if let Ok(mut runs) = self.hosted_run_bindings.lock() {
            if let Some(run) = runs.get_mut(run_id) {
                run.pending = run.pending.saturating_sub(1);
                run.accepted |= accepted;
                if run.pending == 0 && (!run.accepted || run.terminal) {
                    runs.remove(run_id);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn retire_terminal_model_run(&self, response: &serde_json::Value) {
        if response["status"] != "ok" {
            return;
        }
        let data = &response["data"];
        let terminal_status = matches!(
            data["status"].as_str(),
            Some("completed" | "failed" | "cancelled" | "settlement_unknown")
        );
        let terminal_event = data["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["terminal"] == true));
        if !(terminal_status || terminal_event) {
            return;
        }
        let Some(run_id) = data["run_id"].as_str() else {
            return;
        };
        if let Ok(mut runs) = self.hosted_run_bindings.lock() {
            if let Some(run) = runs.get_mut(run_id) {
                run.terminal = true;
                if run.pending == 0 {
                    runs.remove(run_id);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn confined_model_run_matches(
        &self,
        offer_id: &str,
        run_id: &str,
        request_id: &str,
    ) -> bool {
        self.confined_model_identity().is_some()
            && self.hosted_run_bindings.lock().is_ok_and(|runs| {
                runs.get(run_id).is_some_and(|run| {
                    run.offer_id == offer_id
                        && run.request_id == request_id
                        && run.dispatched
                        && !run.terminal
                        && run.expires_at > std::time::Instant::now()
                })
            })
    }

    #[cfg(target_os = "macos")]
    pub fn confined_model_effect_matches(
        &self,
        offer_id: &str,
        run_id: &str,
        request_id: &str,
        effect: &str,
        body: &[u8],
    ) -> bool {
        if !self.confined_model_run_matches(offer_id, run_id, request_id) {
            return false;
        }
        if effect == "job_status" {
            return body.is_empty();
        }
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(body) else {
            return false;
        };
        let Some(object) = body.as_object() else {
            return false;
        };
        self.hosted_run_bindings.lock().is_ok_and(|runs| {
            runs.get(run_id).is_some_and(|run| {
                let expected = run.effect_input_hash.as_deref();
                let bound_hash = match effect {
                    "text" if run.operation == "text.generate" => {
                        let messages = body.get("messages").and_then(serde_json::Value::as_array);
                        let message =
                            messages.and_then(|items| (items.len() == 1).then(|| &items[0]));
                        let prompt =
                            message
                                .and_then(serde_json::Value::as_object)
                                .and_then(|item| {
                                    (item.len() == 2 && item.get("role")?.as_str()? == "user")
                                        .then(|| item.get("content")?.as_str())
                                        .flatten()
                                });
                        if body["stream"] != true
                            || object.keys().any(|key| {
                                !matches!(
                                    key.as_str(),
                                    "model"
                                        | "stream"
                                        | "max_tokens"
                                        | "messages"
                                        | "venice_parameters"
                                )
                            })
                            || body.get("venice_parameters").is_some_and(|value| {
                                *value != serde_json::json!({"include_venice_system_prompt": false})
                            })
                        {
                            None
                        } else {
                            match run.input_schema.as_deref() {
                                Some(elastos_model_contract::TEXT_INPUT_V1_SCHEMA) => prompt
                                    .and_then(|value| {
                                        model_input_hash(&serde_json::json!(value)).ok()
                                    }),
                                Some(elastos_model_contract::TEXT_INPUT_V2_SCHEMA) => body
                                    .get("messages")
                                    .and_then(|messages| model_input_hash(messages).ok()),
                                _ => None,
                            }
                        }
                    }
                    "responses"
                        if run.operation == "text.generate"
                            && run.input_schema.as_deref()
                                == Some(elastos_model_contract::TEXT_INPUT_V1_SCHEMA) =>
                    {
                        if body["stream"] != true
                            || body["store"] != false
                            || object.keys().any(|key| {
                                !matches!(
                                    key.as_str(),
                                    "model" | "input" | "stream" | "store" | "max_output_tokens"
                                )
                            })
                        {
                            None
                        } else {
                            body.get("input")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|value| model_input_hash(&serde_json::json!(value)).ok())
                        }
                    }
                    "decisions"
                        if run.operation == elastos_model_contract::decisions::OPERATION =>
                    {
                        if body["provider"] != serde_json::json!({"allow_fallbacks": false})
                            || object.keys().any(|key| {
                                !matches!(
                                    key.as_str(),
                                    "model" | "state" | "questions" | "provider"
                                )
                            })
                        {
                            None
                        } else {
                            body.get("state").and_then(|state| {
                                body.get("questions").and_then(|questions| {
                                    model_input_hash(&serde_json::json!({
                                        "state": state, "questions": questions
                                    }))
                                    .ok()
                                })
                            })
                        }
                    }
                    "job_create" => {
                        return object.len() == 4
                            && body["offer_id"] == offer_id
                            && body["request_id"] == request_id
                            && body["operation"] == run.operation
                            && body.get("input").is_some_and(|input| {
                                model_input_hash(input).is_ok_and(|hash| hash == run.input_hash)
                            });
                    }
                    "job_cancel" => return object.len() == 1 && body.get("job_id").is_some(),
                    _ => None,
                };
                bound_hash
                    .as_deref()
                    .is_some_and(|hash| Some(hash) == expected)
            })
        })
    }

    async fn spawn_with_timeouts(
        binary_path: &CheckedExecutable,
        config: ProviderConfig,
        init_timeout: std::time::Duration,
        shutdown_timeout: std::time::Duration,
    ) -> Result<Self, BridgeError> {
        let prepared = binary_path
            .verify_at_spawn()
            .map_err(BridgeError::Refused)?;
        let command = Command::new(prepared.exec_path());
        Self::spawn_command(
            prepared,
            command,
            config,
            init_timeout,
            shutdown_timeout,
            std::process::Stdio::inherit(),
            false,
        )
        .await
    }

    /// Runtime owns helper lifetime even while the provider is busy launching.
    pub async fn spawn_with_owned_helpers(
        binary_path: &CheckedExecutable,
        config: ProviderConfig,
    ) -> Result<Self, BridgeError> {
        let prepared = binary_path
            .verify_at_spawn()
            .map_err(BridgeError::Refused)?;
        let command = Command::new(prepared.exec_path());
        Self::spawn_command(
            prepared,
            command,
            config,
            INIT_TIMEOUT,
            SHUTDOWN_TIMEOUT,
            std::process::Stdio::inherit(),
            true,
        )
        .await
    }

    async fn spawn_command(
        prepared: PreparedExecutable,
        mut command: Command,
        config: ProviderConfig,
        init_timeout: std::time::Duration,
        shutdown_timeout: std::time::Duration,
        stderr: std::process::Stdio,
        own_helpers: bool,
    ) -> Result<Self, BridgeError> {
        #[cfg(unix)]
        let helper_owner = if own_helpers {
            let owner = elastos_common::process_lifetime::ParentLifetime::new()
                .map_err(BridgeError::Spawn)?;
            owner
                .configure(command.as_std_mut())
                .map_err(BridgeError::Spawn)?;
            Some(owner)
        } else {
            None
        };
        #[cfg(not(unix))]
        let _ = own_helpers;
        #[cfg(target_os = "linux")]
        prepared.configure_command(&mut command);
        #[cfg(target_os = "macos")]
        let _ = &prepared; // Keep the private executable through Init.
        swap_after_verify();
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .map_err(BridgeError::Spawn)?;

        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let child = Mutex::new(Some(child));
                Self::terminate_child_for_init_failure(&child, shutdown_timeout).await;
                return Err(BridgeError::InitFailed(
                    "spawned provider missing piped stdin".to_string(),
                ));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let child = Mutex::new(Some(child));
                Self::terminate_child_for_init_failure(&child, shutdown_timeout).await;
                return Err(BridgeError::InitFailed(
                    "spawned provider missing piped stdout".to_string(),
                ));
            }
        };

        let bridge = Self {
            io: Arc::new(Mutex::new(ProviderIo {
                writer: Box::new(stdin),
                reader: Box::new(tokio::io::BufReader::new(stdout)),
            })),
            child: Mutex::new(Some(child)),
            fork: Mutex::new(None),
            #[cfg(unix)]
            helper_owner: Mutex::new(helper_owner),
            shutdown_completed: std::sync::atomic::AtomicBool::new(false),
            shutdown_timeout,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_ipc_dir: Mutex::new(None),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_brokers: Mutex::new(BrokerTasks::default()),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_pid: Arc::new(AtomicU32::new(0)),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_birth: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "macos")]
            hosted_run_bindings: Arc::new(StdMutex::new(BTreeMap::new())),
        };

        bridge.init_provider(config, init_timeout).await?;
        Ok(bridge)
    }

    /// The one Init implementation: send `Init`, bound by `init_timeout`, and
    /// settle a failed start through `shutdown`.
    async fn init_provider(
        &self,
        config: ProviderConfig,
        init_timeout: std::time::Duration,
    ) -> Result<(), BridgeError> {
        let init_req = ProviderRequest::Init { config };
        let response = match tokio::time::timeout(init_timeout, self.request_raw(init_req)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let shutdown_error = self.shutdown().await.err().map(|err| err.to_string());
                let detail = match shutdown_error {
                    Some(shutdown_error) => {
                        format!("{error}; failed to settle provider child: {shutdown_error}")
                    }
                    None => error.to_string(),
                };
                return Err(BridgeError::InitFailed(detail));
            }
            Err(_) => {
                let shutdown_error = self.shutdown().await.err().map(|err| err.to_string());
                let detail = match shutdown_error {
                    Some(shutdown_error) => {
                        format!("provider init timed out; failed to settle provider child: {shutdown_error}")
                    }
                    None => "provider init timed out".to_string(),
                };
                return Err(BridgeError::InitFailed(detail));
            }
        };

        match response {
            ProviderResponse::Ok { .. } => Ok(()),
            ProviderResponse::Error { code, message } => {
                let shutdown_error = self.shutdown().await.err().map(|err| err.to_string());
                let detail = match shutdown_error {
                    Some(shutdown_error) => {
                        format!(
                            "{code}: {message}; failed to settle provider child: {shutdown_error}"
                        )
                    }
                    None => format!("{code}: {message}"),
                };
                Err(BridgeError::InitFailed(detail))
            }
        }
    }

    /// Create a bridge from existing I/O handles (for testing).
    pub fn from_io(
        reader: impl AsyncBufRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Self {
        Self {
            io: Arc::new(Mutex::new(ProviderIo {
                writer: Box::new(writer),
                reader: Box::new(reader),
            })),
            child: Mutex::new(None),
            fork: Mutex::new(None),
            #[cfg(unix)]
            helper_owner: Mutex::new(None),
            shutdown_completed: std::sync::atomic::AtomicBool::new(false),
            shutdown_timeout: SHUTDOWN_TIMEOUT,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_ipc_dir: Mutex::new(None),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_brokers: Mutex::new(BrokerTasks::default()),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_pid: Arc::new(AtomicU32::new(0)),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            _local_provider_birth: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "macos")]
            hosted_run_bindings: Arc::new(StdMutex::new(BTreeMap::new())),
        }
    }

    /// Send a request and receive a response (with timeout).
    pub async fn request(&self, req: ProviderRequest) -> Result<ProviderResponse, BridgeError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.request_raw(req))
            .await
            .map_err(|_| BridgeError::Timeout)?
    }

    /// Send a request and receive a response (no timeout).
    async fn request_raw(&self, req: ProviderRequest) -> Result<ProviderResponse, BridgeError> {
        let line = self
            .send_json_line(req, None, super::dispatch::current())
            .await?;
        serde_json::from_str(line.trim()).map_err(BridgeError::Serde)
    }

    /// Send arbitrary JSON to the provider (bypasses typed ProviderRequest enum).
    /// Used by the generic provider proxy to forward custom ops.
    pub async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        #[cfg(target_os = "macos")]
        let recorded_run = self.record_confined_model_run(request)?;
        #[cfg(target_os = "macos")]
        let dispatch_run = recorded_run.clone();
        #[cfg(not(target_os = "macos"))]
        let dispatch_run = None;
        let line = match self
            .send_json_line(request.clone(), dispatch_run, super::dispatch::current())
            .await
        {
            Ok(line) => line,
            Err(error) => {
                #[cfg(target_os = "macos")]
                if let Some(run_id) = &recorded_run {
                    self.settle_confined_model_run(run_id, false);
                }
                return Err(error);
            }
        };
        let response: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(response) => response,
            Err(error) => {
                #[cfg(target_os = "macos")]
                if let Some(run_id) = &recorded_run {
                    self.settle_confined_model_run(run_id, false);
                }
                return Err(BridgeError::Serde(error));
            }
        };
        #[cfg(target_os = "macos")]
        if let Some(run_id) = recorded_run {
            self.settle_confined_model_run(&run_id, response["status"] != "error");
        }
        #[cfg(target_os = "macos")]
        self.retire_terminal_model_run(&response);
        Ok(response)
    }

    /// Write one request and always drain exactly one response line.
    ///
    /// This runs in a detached task so caller cancellation cannot leave a stale
    /// provider response in the pipe for the next request. Without this, a
    /// cancelled HTTP request can cause the following provider call to receive
    /// the previous call's response, crossing authority/data boundaries.
    async fn send_json_line<T>(
        &self,
        request: T,
        dispatch_run: Option<String>,
        fence: Option<super::dispatch::DispatchFence>,
    ) -> Result<String, BridgeError>
    where
        T: Serialize + Send + 'static,
    {
        let io = Arc::clone(&self.io);
        #[cfg(target_os = "macos")]
        let bindings = Arc::clone(&self.hosted_run_bindings);
        tokio::spawn(async move {
            // Serialize first so the op can be named in the trace even when
            // the request is an untyped JSON value.
            let json = serde_json::to_string(&request).map_err(BridgeError::Serde)?;
            let op = serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|value| {
                    value
                        .get("op")
                        .and_then(|op| op.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| "?".to_string());
            let started = std::time::Instant::now();
            // A raw request has no timeout (media preparation and custody
            // rounds legitimately run long) and holds this bridge's I/O
            // lock until the provider answers, so a provider that never
            // answers wedges every later call to it silently. Name the
            // wait while it lasts instead of only after it ends.
            let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
            let pending_op = op.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        _ = tokio::time::sleep(PENDING_REQUEST_WARN_INTERVAL) => {
                            tracing::warn!(
                                op = %pending_op,
                                elapsed_secs = started.elapsed().as_secs(),
                                "provider request still pending"
                            );
                        }
                    }
                }
            });
            let mut io = io.lock().await;
            tracing::debug!(
                op = %op,
                lock_wait_ms = started.elapsed().as_millis() as u64,
                "provider request sent"
            );
            let result: Result<String, BridgeError> = async {
                let dispatch_guard = match fence {
                    Some(fence) => Some(fence.enter().await.map_err(|message| {
                        BridgeError::Io(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            message,
                        ))
                    })?),
                    None => None,
                };
                io.writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(BridgeError::Io)?;
                io.writer.write_all(b"\n").await.map_err(BridgeError::Io)?;
                io.writer.flush().await.map_err(BridgeError::Io)?;
                drop(dispatch_guard);
                #[cfg(target_os = "macos")]
                if let Some(run_id) = &dispatch_run {
                    if let Ok(mut runs) = bindings.lock() {
                        if let Some(run) = runs.get_mut(run_id) {
                            run.dispatched = true;
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                let _ = dispatch_run;
                // Read response line
                let mut line = String::new();
                let n = io
                    .reader
                    .read_line(&mut line)
                    .await
                    .map_err(BridgeError::Io)?;
                if n == 0 {
                    return Err(BridgeError::ProcessExited);
                }
                Ok(line)
            }
            .await;
            let _ = stop_tx.send(());
            tracing::debug!(
                op = %op,
                elapsed_ms = started.elapsed().as_millis() as u64,
                ok = result.is_ok(),
                "provider request settled"
            );
            result
        })
        .await
        .map_err(|err| BridgeError::TaskJoin(err.to_string()))?
    }

    /// Deliver the protocol shutdown on the transport alone.
    async fn protocol_shutdown(&self) -> Result<(), BridgeError> {
        tokio::time::timeout(
            self.shutdown_timeout,
            self.request_raw(ProviderRequest::Shutdown),
        )
        .await
        .map_err(|_| BridgeError::Timeout)
        .and_then(|result| result)
        .and_then(|response| match response {
            ProviderResponse::Ok { .. } => Ok(()),
            ProviderResponse::Error { code, message } => {
                Err(BridgeError::Provider { code, message })
            }
        })
    }

    /// Gracefully shut down the provider.
    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        #[cfg(unix)]
        self.helper_owner.lock().await.take();
        if let Some(mut fork) = self.fork.lock().await.take() {
            let protocol_error = self.protocol_shutdown().await.err();
            let status_error =
                match tokio::time::timeout(self.shutdown_timeout, &mut fork.status).await {
                    Ok(status) => {
                        fork.reaped = status.is_ok();
                        match status {
                            Ok(0) => None,
                            _ => Some(BridgeError::ProcessExited),
                        }
                    }
                    Err(_) => {
                        fork.force_kill();
                        match tokio::time::timeout(self.shutdown_timeout, &mut fork.status).await {
                            Ok(status) => {
                                fork.reaped = status.is_ok();
                                Some(BridgeError::Timeout)
                            }
                            Err(_) => {
                                // The signal has been sent and the reaper has not
                                // collected the child. Wait for that collection
                                // before returning, so the caller does not remove
                                // the root while the child is still live.
                                fork.reaped = (&mut fork.status).await.is_ok();
                                Some(BridgeError::Timeout)
                            }
                        }
                    }
                };
            self.shutdown_completed
                .store(true, std::sync::atomic::Ordering::Release);
            drop(fork);
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            self.stop_local_brokers().await;
            return match (protocol_error, status_error) {
                (Some(error), _) => Err(error),
                (None, Some(error)) => Err(error),
                (None, None) => Ok(()),
            };
        }
        let mut child_guard = self.child.lock().await;
        let Some(child) = child_guard.as_mut() else {
            if self
                .shutdown_completed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                // The child was already reaped (or the protocol shutdown was
                // already delivered): shutdown is idempotent.
                return Ok(());
            }
            // Never had a child process: the transport is the only handle on
            // the provider, so the protocol shutdown must still be delivered
            // for an attached provider to stop cleanly.
            let result = tokio::time::timeout(
                self.shutdown_timeout,
                self.request_raw(ProviderRequest::Shutdown),
            )
            .await
            .map_err(|_| BridgeError::Timeout)
            .and_then(|result| result)
            .and_then(|response| match response {
                ProviderResponse::Ok { .. } => Ok(()),
                ProviderResponse::Error { code, message } => {
                    Err(BridgeError::Provider { code, message })
                }
            });
            self.shutdown_completed
                .store(true, std::sync::atomic::Ordering::Release);
            return result;
        };

        let shutdown_result = tokio::time::timeout(
            self.shutdown_timeout,
            self.request_raw(ProviderRequest::Shutdown),
        )
        .await
        .map_err(|_| BridgeError::Timeout)
        .and_then(|result| result)
        .and_then(|response| match response {
            ProviderResponse::Ok { .. } => Ok(()),
            ProviderResponse::Error { code, message } => {
                Err(BridgeError::Provider { code, message })
            }
        });

        let protocol_error = shutdown_result.err();
        let result = match tokio::time::timeout(self.shutdown_timeout, child.wait()).await {
            Ok(Ok(status)) => {
                child_guard.take();
                self.shutdown_completed
                    .store(true, std::sync::atomic::Ordering::Release);
                if let Some(error) = protocol_error {
                    Err(error)
                } else if status.success() {
                    Ok(())
                } else {
                    Err(BridgeError::ProcessExited)
                }
            }
            Ok(Err(error)) => match Self::force_child_reap(child, self.shutdown_timeout).await {
                Ok(()) => {
                    child_guard.take();
                    self.shutdown_completed
                        .store(true, std::sync::atomic::Ordering::Release);
                    Err(protocol_error.unwrap_or(BridgeError::Io(error)))
                }
                Err(reap_error) => Err(reap_error),
            },
            Err(_) => match Self::force_child_reap(child, self.shutdown_timeout).await {
                Ok(()) => {
                    child_guard.take();
                    self.shutdown_completed
                        .store(true, std::sync::atomic::Ordering::Release);
                    Err(protocol_error.unwrap_or(BridgeError::Timeout))
                }
                Err(reap_error) => Err(reap_error),
            },
        };
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if child_guard.is_none() {
            self.stop_local_brokers().await;
        }
        result
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn stop_local_brokers(&self) {
        self._local_provider_pid.store(0, Ordering::Release);
        self._local_provider_birth.store(0, Ordering::Release);
        let mut brokers = self._local_brokers.lock().await;
        for task in brokers.0.drain(..) {
            task.abort();
            let _ = task.await;
        }
        self._local_ipc_dir.lock().await.take();
    }
}

// === CapsuleProvider (implements Provider trait) ===

/// A provider that delegates to a capsule process via ProviderBridge.
pub struct CapsuleProvider {
    bridge: Arc<ProviderBridge>,
    /// Leaked once at construction — providers live for program lifetime.
    scheme_static: &'static str,
}

impl CapsuleProvider {
    /// Create a new CapsuleProvider wrapping a ProviderBridge.
    /// Defaults to the current first-party localhost provider scheme.
    pub fn new(bridge: Arc<ProviderBridge>) -> Self {
        Self::with_scheme(bridge, "localhost")
    }

    /// Create a new CapsuleProvider with a custom scheme name.
    pub fn with_scheme(bridge: Arc<ProviderBridge>, scheme: impl Into<String>) -> Self {
        let scheme_static = Box::leak(scheme.into().into_boxed_str()) as &'static str;
        Self {
            bridge,
            scheme_static,
        }
    }

    /// Create a CapsuleProvider from a provider the confined entry launched.
    /// Only `spawn_confined` can produce `Confined`.
    pub fn from_confined(confined: Confined, scheme: impl Into<String>) -> Self {
        Self::with_scheme(confined.bridge, scheme)
    }

    /// Get a reference to the underlying bridge for raw communication.
    pub fn bridge(&self) -> &Arc<ProviderBridge> {
        &self.bridge
    }

    /// Map a ResourceRequest to a ProviderRequest.
    fn to_provider_request(request: &ResourceRequest) -> ProviderRequest {
        // Runtime has already validated capabilities; provider trusts runtime
        let token = String::new();

        match request.action {
            ResourceAction::Read => ProviderRequest::Read {
                path: request.path.clone(),
                token,
                offset: None,
                length: None,
            },
            ResourceAction::Write => ProviderRequest::Write {
                path: request.path.clone(),
                token,
                content: request.content.clone().unwrap_or_default(),
                append: false,
            },
            ResourceAction::Delete => ProviderRequest::Delete {
                path: request.path.clone(),
                token,
                recursive: request.recursive,
            },
            ResourceAction::List => ProviderRequest::List {
                path: request.path.clone(),
                token,
            },
            ResourceAction::Stat => ProviderRequest::Stat {
                path: request.path.clone(),
                token,
            },
            ResourceAction::Mkdir => ProviderRequest::Mkdir {
                path: request.path.clone(),
                token,
                parents: true,
            },
            ResourceAction::Exists => ProviderRequest::Exists {
                path: request.path.clone(),
                token,
            },
        }
    }

    /// Map a ProviderResponse to a ResourceResponse, given the original action.
    fn to_resource_response(
        action: ResourceAction,
        response: ProviderResponse,
    ) -> Result<ResourceResponse, ProviderError> {
        match response {
            ProviderResponse::Error { code, message } => match code.as_str() {
                "read_failed" if message.contains("No such file") => {
                    Err(ProviderError::NotFound(message))
                }
                _ if message.contains("not found") || message.contains("No such file") => {
                    Err(ProviderError::NotFound(message))
                }
                _ if message.contains("Permission denied") || message.contains("escapes") => {
                    Err(ProviderError::PermissionDenied(message))
                }
                _ => Err(ProviderError::Provider(format!("[{}] {}", code, message))),
            },
            ProviderResponse::Ok { data } => match action {
                ResourceAction::Read => {
                    let data = data.ok_or_else(|| {
                        ProviderError::Provider("read response missing data".into())
                    })?;
                    let content = data
                        .get("content")
                        .ok_or_else(|| {
                            ProviderError::Provider("read response missing 'content'".into())
                        })?
                        .as_array()
                        .ok_or_else(|| ProviderError::Provider("'content' is not an array".into()))?
                        .iter()
                        .map(|v| v.as_u64().unwrap_or(0) as u8)
                        .collect();
                    Ok(ResourceResponse::Data(content))
                }
                ResourceAction::Write => {
                    let bytes = data
                        .and_then(|d| d.get("bytes_written").and_then(|v| v.as_u64()))
                        .unwrap_or(0) as usize;
                    Ok(ResourceResponse::Written { bytes })
                }
                ResourceAction::Delete => Ok(ResourceResponse::Deleted),
                ResourceAction::List => {
                    let data = data.ok_or_else(|| {
                        ProviderError::Provider("list response missing data".into())
                    })?;
                    let entries: Vec<serde_json::Value> = serde_json::from_value(data)
                        .map_err(|e| ProviderError::Provider(format!("parse list: {}", e)))?;
                    let resource_entries = entries
                        .iter()
                        .map(|e| ResourceEntry {
                            name: e
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            is_directory: e
                                .get("is_dir")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            size: e.get("size").and_then(|v| v.as_u64()),
                            modified: None,
                        })
                        .collect();
                    Ok(ResourceResponse::List(resource_entries))
                }
                ResourceAction::Stat => {
                    let data = data.ok_or_else(|| {
                        ProviderError::Provider("stat response missing data".into())
                    })?;
                    let is_dir = data
                        .get("is_dir")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let size = data.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                    let modified = data.get("modified").and_then(|v| v.as_u64()).unwrap_or(0);
                    let entry_type = if is_dir {
                        EntryType::Directory
                    } else {
                        EntryType::File
                    };
                    Ok(ResourceResponse::Metadata {
                        size,
                        entry_type,
                        modified,
                    })
                }
                ResourceAction::Mkdir => Ok(ResourceResponse::Created),
                ResourceAction::Exists => {
                    let exists = data
                        .and_then(|d| d.get("exists").and_then(|v| v.as_bool()))
                        .unwrap_or(false);
                    Ok(ResourceResponse::Exists(exists))
                }
            },
        }
    }
}

#[async_trait::async_trait]
impl Provider for CapsuleProvider {
    async fn handle(&self, request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        let action = request.action;
        let provider_req = Self::to_provider_request(&request);

        let response = self
            .bridge
            .request(provider_req)
            .await
            .map_err(|e| ProviderError::Provider(e.to_string()))?;

        Self::to_resource_response(action, response)
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.scheme_static]
    }

    fn name(&self) -> &'static str {
        "capsule-provider"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        self.bridge
            .send_raw(request)
            .await
            .map_err(|e| ProviderError::Provider(e.to_string()))
    }

    async fn send_raw_fenced(
        &self,
        request: &serde_json::Value,
        fence: Option<super::dispatch::DispatchFence>,
    ) -> Result<serde_json::Value, ProviderError> {
        match fence {
            Some(fence) => fence.scope(self.send_raw(request)).await,
            None => self.send_raw(request).await,
        }
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        self.bridge
            .shutdown()
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use elastos_model_contract::{model_input_hash, RUNTIME_CREATE_BINDING_SCHEMA};
    #[cfg(unix)]
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    #[cfg(unix)]
    fn write_provider_script(tempdir: &TempDir, name: &str, script: &str) -> std::path::PathBuf {
        let path = tempdir.path().join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    fn process_exists(pid: &str) -> bool {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid)
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(unix)]
    fn wait_for_file(path: &std::path::Path) {
        // Generous real-time budget: the marker is written by a freshly
        // spawned child process, which can be slow under machine load.
        for _ in 0..250 {
            if path.is_file() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("expected test provider marker {} to exist", path.display());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn confined_text_v2_requires_exact_messages_and_schema() {
        let (reader, _) = tokio::io::duplex(4096);
        let (writer, _) = tokio::io::duplex(4096);
        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(reader), writer);
        let pid = std::process::id();
        bridge._local_provider_birth.store(
            super::super::local_model_broker::process_birth(pid).unwrap(),
            Ordering::Release,
        );
        bridge._local_provider_pid.store(pid, Ordering::Release);
        let messages = serde_json::json!([
            {"role":"system","content":"Be concise."},
            {"role":"user","content":"first"},
            {"role":"assistant","content":"answer"},
            {"role":"user","content":"last"}
        ]);
        let input = serde_json::json!({"schema":elastos_model_contract::TEXT_INPUT_V2_SCHEMA,"messages":messages});
        let binding = RuntimeCreateBinding {
            schema: RUNTIME_CREATE_BINDING_SCHEMA.into(),
            principal_id: "principal:fixture".into(),
            session_id: "session:fixture".into(),
            capsule_id: "assistant".into(),
            grant_id: "grant:fixture".into(),
            request_id: "request:v2".into(),
            offer_id: "model:openrouter".into(),
            operation: "text.generate".into(),
            input_hash: model_input_hash(&input).unwrap(),
        };
        let request = serde_json::json!({"op":"runs_create","offer_id":binding.offer_id,
            "operation":binding.operation,"input":input,"runtime_binding":binding});
        let run_id = bridge.record_confined_model_run(&request).unwrap().unwrap();
        bridge
            .hosted_run_bindings
            .lock()
            .unwrap()
            .get_mut(&run_id)
            .unwrap()
            .dispatched = true;
        let body = serde_json::json!({"model":"fixture","stream":true,"max_tokens":32,"messages":messages});
        let matches = |effect, body: &serde_json::Value| {
            bridge.confined_model_effect_matches(
                &binding.offer_id,
                &run_id,
                &binding.request_id,
                effect,
                &serde_json::to_vec(body).unwrap(),
            )
        };
        assert!(matches("text", &body));
        for (pointer, value) in [
            ("/messages/2/role", serde_json::json!("user")),
            ("/messages/2/content", serde_json::json!("changed")),
            ("/stream", serde_json::json!(false)),
        ] {
            let mut changed = body.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(!matches("text", &changed));
        }
        let mut extra = body.clone();
        extra["messages"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"role":"user","content":"extra"}));
        assert!(!matches("text", &extra));
        let mut swapped = body.clone();
        swapped["messages"].as_array_mut().unwrap().swap(1, 2);
        assert!(!matches("text", &swapped));
        let mut extra_key = body.clone();
        extra_key["messages"][0]["name"] = serde_json::json!("hidden");
        assert!(!matches("text", &extra_key));
        let mut extra_top = body.clone();
        extra_top["tools"] = serde_json::json!([]);
        assert!(!matches("text", &extra_top));
        let mut venice = body.clone();
        venice["venice_parameters"] = serde_json::json!({"include_venice_system_prompt":true});
        assert!(!matches("text", &venice));
        assert!(!matches(
            "responses",
            &serde_json::json!({"model":"fixture","stream":true,"store":false,"input":messages,"max_output_tokens":32})
        ));
        assert!(!matches(
            "responses",
            &serde_json::json!({"model":"fixture","stream":true,"store":false,"input":"last","max_output_tokens":32})
        ));
        assert!(!matches(
            "text",
            &serde_json::json!({"model":"fixture","stream":true,"messages":[{"role":"user","content":"last"}]})
        ));
        let mut invalid = request.clone();
        invalid["input"]["messages"][0]["extra"] = serde_json::json!(true);
        invalid["runtime_binding"]["input_hash"] =
            serde_json::json!(model_input_hash(&invalid["input"]).unwrap());
        assert!(bridge.record_confined_model_run(&invalid).is_err());
        let mut v1 = request.clone();
        v1["input"] = serde_json::json!({"schema":elastos_model_contract::TEXT_INPUT_V1_SCHEMA,"prompt":"last"});
        v1["runtime_binding"]["request_id"] = serde_json::json!("request:v1");
        v1["runtime_binding"]["input_hash"] =
            serde_json::json!(model_input_hash(&v1["input"]).unwrap());
        let v1_id = bridge.record_confined_model_run(&v1).unwrap().unwrap();
        bridge
            .hosted_run_bindings
            .lock()
            .unwrap()
            .get_mut(&v1_id)
            .unwrap()
            .dispatched = true;
        assert!(!bridge.confined_model_effect_matches(
            &binding.offer_id,
            &v1_id,
            "request:v1",
            "text",
            &serde_json::to_vec(&body).unwrap()
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn confined_run_record_requires_a_valid_runtime_binding() {
        let (reader, _) = tokio::io::duplex(4096);
        let (writer, _) = tokio::io::duplex(4096);
        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(reader), writer);
        let pid = std::process::id();
        let birth = super::super::local_model_broker::process_birth(pid).unwrap();
        bridge._local_provider_birth.store(birth, Ordering::Release);
        bridge._local_provider_pid.store(pid, Ordering::Release);
        let input = serde_json::json!({"schema":"elastos.model.input.text/v1","prompt":"fixture"});
        let binding = RuntimeCreateBinding {
            schema: RUNTIME_CREATE_BINDING_SCHEMA.into(),
            principal_id: "principal:fixture".into(),
            session_id: "session:fixture".into(),
            capsule_id: "assistant".into(),
            grant_id: "grant:fixture".into(),
            request_id: "request:fixture".into(),
            offer_id: "model:hosted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            operation: "text.generate".into(),
            input_hash: model_input_hash(&input).unwrap(),
        };
        let run_id = model_run_id(&binding);
        let request = serde_json::json!({
            "op":"runs_create", "offer_id":binding.offer_id,
            "operation":binding.operation, "input":input,
            "runtime_binding":binding,
        });
        let hosted = "model:hosted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        let mut wrong = request.clone();
        wrong["runtime_binding"]["request_id"] = serde_json::json!("other");
        wrong["runtime_binding"]["input_hash"] = serde_json::json!("sha256:bad");
        assert!(bridge.record_confined_model_run(&wrong).is_err());
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        assert_eq!(
            bridge.record_confined_model_run(&request).unwrap(),
            Some(run_id.clone())
        );
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        bridge
            .hosted_run_bindings
            .lock()
            .unwrap()
            .get_mut(&run_id)
            .unwrap()
            .dispatched = true;
        let chat = serde_json::json!({
            "model":"fixture/model", "stream":true, "max_tokens":32,
            "messages":[{"role":"user","content":"fixture"}],
            "venice_parameters":{"include_venice_system_prompt":false}
        });
        assert!(bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "text",
            &serde_json::to_vec(&chat).unwrap()
        ));
        let mut changed_chat = chat.clone();
        changed_chat["messages"][0]["content"] = serde_json::json!("changed");
        assert!(!bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "text",
            &serde_json::to_vec(&changed_chat).unwrap()
        ));
        changed_chat["messages"][0]["content"] = serde_json::json!("fixture");
        changed_chat["messages"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"role":"system","content":"hidden instruction"}));
        assert!(!bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "text",
            &serde_json::to_vec(&changed_chat).unwrap()
        ));
        let responses = serde_json::json!({
            "model":"fixture/model", "input":"fixture", "stream":true,
            "store":false, "max_output_tokens":32
        });
        assert!(bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "responses",
            &serde_json::to_vec(&responses).unwrap()
        ));
        let mut changed_responses = responses;
        changed_responses["input"] = serde_json::json!("changed");
        assert!(!bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "responses",
            &serde_json::to_vec(&changed_responses).unwrap()
        ));
        assert!(!bridge.confined_model_effect_matches(
            hosted,
            &run_id,
            "request:fixture",
            "decisions",
            &serde_json::to_vec(&chat).unwrap()
        ));
        let mut collision = request.clone();
        collision["input"] = serde_json::json!({"prompt":"different"});
        collision["runtime_binding"]["input_hash"] =
            serde_json::json!(model_input_hash(&collision["input"]).unwrap());
        assert!(bridge.record_confined_model_run(&collision).is_err());
        assert_eq!(
            bridge.record_confined_model_run(&request).unwrap(),
            Some(run_id.clone())
        );
        bridge.settle_confined_model_run(&run_id, false);
        assert!(bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        bridge.settle_confined_model_run(&run_id, true);
        assert!(bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "other"));
        assert!(!bridge.confined_model_run_matches("other", &run_id, "request:fixture"));
        let mut local = request.clone();
        local["offer_id"] = serde_json::json!("model:smollm2");
        assert_eq!(bridge.record_confined_model_run(&local).unwrap(), None);
        let decision_input = serde_json::json!({
            "schema": elastos_model_contract::decisions::INPUT_SCHEMA,
            "state": {"context":"authorized"},
            "questions": {"q":{"type":"choice","instructions":"choose","criteria":{"yes":"yes"}}}
        });
        let mut decision_binding = binding.clone();
        decision_binding.request_id = "request:decision".into();
        decision_binding.operation = elastos_model_contract::decisions::OPERATION.into();
        decision_binding.input_hash = model_input_hash(&decision_input).unwrap();
        let decision_run_id = model_run_id(&decision_binding);
        bridge
            .record_confined_model_run(&serde_json::json!({
                "op":"runs_create", "offer_id":hosted, "operation":decision_binding.operation,
                "input":decision_input, "runtime_binding":decision_binding
            }))
            .unwrap();
        bridge
            .hosted_run_bindings
            .lock()
            .unwrap()
            .get_mut(&decision_run_id)
            .unwrap()
            .dispatched = true;
        let decision_body = serde_json::json!({
            "model":"fixture/model", "state":{"context":"authorized"},
            "questions":{"q":{"type":"choice","instructions":"choose","criteria":{"yes":"yes"}}},
            "provider":{"allow_fallbacks":false}
        });
        assert!(bridge.confined_model_effect_matches(
            hosted,
            &decision_run_id,
            "request:decision",
            "decisions",
            &serde_json::to_vec(&decision_body).unwrap()
        ));
        let mut changed_decision = decision_body;
        changed_decision["state"]["context"] = serde_json::json!("changed");
        assert!(!bridge.confined_model_effect_matches(
            hosted,
            &decision_run_id,
            "request:decision",
            "decisions",
            &serde_json::to_vec(&changed_decision).unwrap()
        ));
        bridge.retire_terminal_model_run(&serde_json::json!({
            "status":"ok", "data":{"run_id":run_id,"status":"completed"}
        }));
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
        bridge._local_provider_pid.store(0, Ordering::Release);
        assert!(!bridge.confined_model_run_matches(hosted, &run_id, "request:fixture"));
    }

    #[cfg(unix)]
    fn assert_process_absent(pid: &str) {
        if !process_exists(pid) {
            return;
        }
        for _ in 0..5 {
            if !process_exists(pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("expected provider process {pid} to be terminated and reaped");
    }

    #[cfg(unix)]
    struct ReapTestChild(Option<u32>);

    #[cfg(unix)]
    impl Drop for ReapTestChild {
        fn drop(&mut self) {
            if let Some(pid) = self.0.take() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(pid as i32, &mut status, 0);
                }
            }
        }
    }

    #[test]
    fn test_provider_request_serialization() {
        let req = ProviderRequest::Read {
            path: "test.txt".into(),
            token: "tok".into(),
            offset: None,
            length: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"read""#));
        assert!(json.contains(r#""path":"test.txt""#));

        // Init
        let req = ProviderRequest::Init {
            config: ProviderConfig {
                base_path: "/tmp".into(),
                allowed_paths: vec!["*".into()],
                read_only: false,
                encryption_key: String::new(),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"init""#));
        assert!(json.contains(r#""base_path":"/tmp""#));
    }

    #[test]
    fn test_provider_response_deserialization() {
        // Ok response
        let json = r#"{"status":"ok","data":{"content":[104,101,108,108,111],"size":5}}"#;
        let resp: ProviderResponse = serde_json::from_str(json).unwrap();
        assert!(matches!(resp, ProviderResponse::Ok { data: Some(_) }));

        // Error response
        let json = r#"{"status":"error","code":"read_failed","message":"No such file"}"#;
        let resp: ProviderResponse = serde_json::from_str(json).unwrap();
        assert!(matches!(resp, ProviderResponse::Error { .. }));
    }

    #[tokio::test]
    async fn browser_internet_queued_bridge_write_cannot_dispatch_after_stop() {
        let (client_read, _server_write) = tokio::io::duplex(4096);
        let (mut server_read, client_write) = tokio::io::duplex(4096);
        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);
        let fence = super::super::dispatch::DispatchFence::new(|| Ok(()));
        let io = bridge.io.lock().await;
        let request = serde_json::json!({"op":"connect"});
        let pending = fence.scope(bridge.send_raw(&request));
        tokio::pin!(pending);
        // Poll until the real bridge has spawned its detached write, held behind
        // its I/O lock. Revocation completes while that write is queued.
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                pending.as_mut(),
                cx
            )))
            .await
            .is_pending()
        );
        fence.revoke().await;
        drop(io);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), pending)
            .await
            .expect("revoked write must finish without waiting for a provider response");
        assert!(result.is_err());
        use tokio::io::AsyncReadExt;
        let mut bytes = [0u8; 1];
        let read = server_read.read(&mut bytes);
        tokio::pin!(read);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                read.as_mut(),
                cx
            )))
            .await
            .is_pending(),
            "revoked dispatch wrote provider bytes"
        );
    }

    #[tokio::test]
    async fn browser_internet_accepted_bridge_call_can_finish_after_stop() {
        let (client_read, mut server_write) = tokio::io::duplex(4096);
        let (server_read, client_write) = tokio::io::duplex(4096);
        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);
        let fence = super::super::dispatch::DispatchFence::new(|| Ok(()));
        let call_fence = fence.clone();
        let call = tokio::spawn(async move {
            call_fence
                .scope(bridge.send_raw(&serde_json::json!({"op":"connect"})))
                .await
        });
        let mut reader = tokio::io::BufReader::new(server_read);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
            "connect"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), fence.revoke())
            .await
            .unwrap();
        assert!(!call.is_finished());
        server_write
            .write_all(b"{\"status\":\"ok\"}\n")
            .await
            .unwrap();
        assert_eq!(call.await.unwrap().unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn test_bridge_request_response() {
        // Simulate a provider using DuplexStream
        let (client_read, mut server_write) = tokio::io::duplex(4096);
        let (mut server_read_raw, client_write) = tokio::io::duplex(4096);

        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);

        // Spawn a task to simulate the provider
        let server = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut server_read_raw);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            // Parse request
            let req: ProviderRequest = serde_json::from_str(line.trim()).unwrap();
            assert!(matches!(req, ProviderRequest::Read { .. }));

            // Send response
            let resp = ProviderResponse::Ok {
                data: Some(serde_json::json!({"content": [104, 101, 108, 108, 111], "size": 5})),
            };
            let json = serde_json::to_string(&resp).unwrap();
            server_write
                .write_all(format!("{}\n", json).as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        // Send request through bridge
        let response = bridge
            .request(ProviderRequest::Read {
                path: "test.txt".into(),
                token: String::new(),
                offset: None,
                length: None,
            })
            .await
            .unwrap();

        match response {
            ProviderResponse::Ok { data: Some(d) } => {
                assert!(d.get("content").is_some());
            }
            _ => panic!("Expected Ok response with data"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_bridge_timeout() {
        // Create a bridge where the "provider" never responds
        let (client_read, _server_write) = tokio::io::duplex(4096);
        let (_server_read, client_write) = tokio::io::duplex(4096);

        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);

        // Override timeout to 100ms for testing
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            bridge.request_raw(ProviderRequest::Exists {
                path: "test".into(),
                token: String::new(),
            }),
        )
        .await;

        assert!(result.is_err()); // Timed out
    }

    #[tokio::test]
    async fn test_cancelled_raw_request_drains_response_before_next_request() {
        let (client_read, mut server_write) = tokio::io::duplex(4096);
        let (server_read_raw, client_write) = tokio::io::duplex(4096);
        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);

        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            let mut reader = tokio::io::BufReader::new(server_read_raw);

            let mut first = String::new();
            reader.read_line(&mut first).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(first.trim()).unwrap()["op"],
                "first"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            server_write
                .write_all(b"{\"status\":\"ok\",\"data\":{\"op\":\"first\"}}\n")
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let mut second = String::new();
            reader.read_line(&mut second).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(second.trim()).unwrap()["op"],
                "second"
            );
            server_write
                .write_all(b"{\"status\":\"ok\",\"data\":{\"op\":\"second\"}}\n")
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let first = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            bridge.send_raw(&serde_json::json!({"op": "first"})),
        )
        .await;
        assert!(first.is_err());

        let second = bridge
            .send_raw(&serde_json::json!({"op": "second"}))
            .await
            .unwrap();
        assert_eq!(second["data"]["op"], "second");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_bridge_process_exit() {
        // Create a bridge where the "provider" closes immediately
        let (client_read, server_write) = tokio::io::duplex(4096);
        let (_server_read, client_write) = tokio::io::duplex(4096);

        // Drop server_write to simulate EOF
        drop(server_write);

        let bridge = ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write);

        let result = bridge
            .request(ProviderRequest::Read {
                path: "test.txt".into(),
                token: String::new(),
                offset: None,
                length: None,
            })
            .await;

        assert!(matches!(result, Err(BridgeError::ProcessExited)));
    }

    #[cfg(unix)]
    fn write_mock_provider_script(
        root: &Path,
        init_response: &str,
        shutdown_response: Option<&str>,
        shutdown_exit: i32,
    ) -> (PathBuf, PathBuf) {
        let binary = root.join("mock-provider.sh");
        let pid_file = root.join("mock-provider.pid");
        let shutdown_response = shutdown_response.unwrap_or("");
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{}'\nIFS= read -r _init || exit 1\nprintf '%s\\n' '{}'\nIFS= read -r _shutdown || exit 0\nif [ -n '{}' ]; then printf '%s\\n' '{}'; fi\nexit {}\n",
            pid_file.display(),
            init_response,
            shutdown_response,
            shutdown_response,
            shutdown_exit
        );
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        (binary, pid_file)
    }

    #[cfg(unix)]
    fn read_pid(path: &Path) -> u32 {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[cfg(unix)]
    fn process_is_running(pid: u32) -> bool {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {pid}"))
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Spawn a just-written mock provider script, tolerating Linux ETXTBSY:
    /// a concurrently forking test can briefly hold the script's write fd
    /// (fork duplicates open descriptors before exec closes them), and exec
    /// then fails with ExecutableFileBusy until that window closes.
    #[cfg(unix)]
    async fn spawn_test_bridge(
        binary: &std::path::Path,
        config: ProviderConfig,
    ) -> Result<ProviderBridge, BridgeError> {
        spawn_test_bridge_with_timeouts(binary, config, INIT_TIMEOUT, SHUTDOWN_TIMEOUT).await
    }

    #[cfg(unix)]
    async fn spawn_test_bridge_with_timeouts(
        binary: &std::path::Path,
        config: ProviderConfig,
        init_timeout: std::time::Duration,
        shutdown_timeout: std::time::Duration,
    ) -> Result<ProviderBridge, BridgeError> {
        let mut attempts = 0u32;
        loop {
            match ProviderBridge::spawn_with_timeouts(
                &CheckedExecutable::for_test(binary),
                config.clone(),
                init_timeout,
                shutdown_timeout,
            )
            .await
            {
                Err(BridgeError::Spawn(error))
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    attempts += 1;
                    if attempts >= 40 {
                        return Err(BridgeError::Spawn(error));
                    }
                    // Blocking sleep on purpose: the spawn syscall fails
                    // synchronously on the first poll, so the whole retry
                    // loop resolves within a single poll and stays correct
                    // under start_paused tests, where an async sleep could
                    // never fire while the test body blocks the runtime
                    // thread in wait_for_file.
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                result => return result,
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn checked_provider_starts_and_refuses_changed_bytes_and_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"ok"}"#,
            Some(r#"{"status":"ok"}"#),
            0,
        );
        let checked = CheckedExecutable::for_test(&binary);
        let bridge = ProviderBridge::spawn(&checked, ProviderConfig::default())
            .await
            .unwrap();
        assert!(pid_file.exists(), "the checked provider starts");
        bridge.shutdown().await.unwrap();

        let marker = temp.path().join("refused.marker");
        let replacement = format!("#!/bin/sh\nprintf bad > '{}'\n", marker.display());
        std::fs::write(&binary, &replacement).unwrap();
        let error = ProviderBridge::spawn(&checked, ProviderConfig::default())
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, BridgeError::Refused(reason) if reason == "provider executable differs from verified release checksum")
        );
        assert!(!marker.exists(), "changed bytes did not exec");

        std::fs::remove_file(&binary).unwrap();
        let alternate = temp.path().join("alternate-provider");
        std::fs::write(&alternate, replacement).unwrap();
        std::os::unix::fs::symlink(&alternate, &binary).unwrap();
        let error = ProviderBridge::spawn(&checked, ProviderConfig::default())
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, BridgeError::Refused(reason) if reason == "provider executable symlink is refused")
        );
        assert!(!marker.exists(), "symlink target did not exec");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn checked_provider_survives_after_verify_swap(symlink: bool) {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"ok"}"#,
            Some(r#"{"status":"ok"}"#),
            0,
        );
        let checked = CheckedExecutable::for_test(&binary);
        let marker = temp.path().join("substituted-ran");
        let replacement = temp.path().join("substitute");
        std::fs::write(
            &replacement,
            format!("#!/bin/sh\nprintf bad > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = temp.path().join("verified-original");
        AFTER_VERIFY_SWAP.with(|slot| {
            *slot.borrow_mut() = Some(Box::new({
                let binary = binary.clone();
                let replacement = replacement.clone();
                move || {
                    std::fs::rename(&binary, &original).unwrap();
                    if symlink {
                        std::os::unix::fs::symlink(&replacement, &binary).unwrap();
                    } else {
                        std::fs::rename(&replacement, &binary).unwrap();
                    }
                }
            }));
        });
        let bridge = ProviderBridge::spawn(&checked, ProviderConfig::default())
            .await
            .expect("the verified bytes still start after a path swap");
        assert!(pid_file.exists(), "the verified provider ran");
        assert!(!marker.exists(), "the substituted provider did not run");
        bridge.shutdown().await.unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn checked_provider_runs_verified_bytes_after_file_swap() {
        checked_provider_survives_after_verify_swap(false).await;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn checked_provider_runs_verified_bytes_after_symlink_swap() {
        checked_provider_survives_after_verify_swap(true).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_model_spawn_refuses_substituted_provider_before_exec() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("model-provider");
        let marker = temp.path().join("ran");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let checked = CheckedExecutable::for_test(&binary);
        std::fs::write(
            &binary,
            format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
        )
        .unwrap();
        let config = ProviderConfig {
            extra: serde_json::json!({"offers":[]}),
            ..Default::default()
        };
        let result = ProviderBridge::spawn_confined_model_linux(&checked, config).await;
        assert!(matches!(result, Err(BridgeError::Refused(reason))
            if reason == "provider executable differs from verified release checksum"));
        assert!(!marker.exists(), "the changed model provider did not exec");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_shutdown_requires_typed_ok_response() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"ok"}"#,
            Some(r#"{"status":"error","code":"denied","message":"no"}"#),
            0,
        );
        let bridge = spawn_test_bridge(&binary, ProviderConfig::default())
            .await
            .unwrap();
        let pid = read_pid(&pid_file);
        let error = bridge.shutdown().await.unwrap_err();
        assert!(matches!(error, BridgeError::Provider { .. }));
        assert!(!process_is_running(pid));
        bridge.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_shutdown_requires_successful_exit_status() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"ok"}"#,
            Some(r#"{"status":"ok"}"#),
            7,
        );
        let bridge = spawn_test_bridge(&binary, ProviderConfig::default())
            .await
            .unwrap();
        let pid = read_pid(&pid_file);
        let error = bridge.shutdown().await.unwrap_err();
        assert!(matches!(error, BridgeError::ProcessExited));
        assert!(!process_is_running(pid));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_shutdown_reaps_child_after_response_loss() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) =
            write_mock_provider_script(temp.path(), r#"{"status":"ok"}"#, None, 0);
        let bridge = spawn_test_bridge(&binary, ProviderConfig::default())
            .await
            .unwrap();
        let pid = read_pid(&pid_file);
        let error = bridge.shutdown().await.unwrap_err();
        assert!(matches!(error, BridgeError::ProcessExited));
        assert!(!process_is_running(pid));
        bridge.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_shutdown_kills_and_reaps_child_after_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("mock-provider-timeout.sh");
        let pid_file = temp.path().join("mock-provider-timeout.pid");
        let gate = temp.path().join("mock-provider-timeout.gate");
        let status = std::process::Command::new("mkfifo")
            .arg(&gate)
            .status()
            .unwrap();
        assert!(status.success());
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{}'\nIFS= read -r _init || exit 1\nprintf '%s\\n' '{}'\nIFS= read -r _shutdown || exit 0\nexec cat '{}'\n",
            pid_file.display(),
            r#"{"status":"ok"}"#,
            gate.display(),
        );
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();

        let bridge = spawn_test_bridge(&binary, ProviderConfig::default())
            .await
            .unwrap();
        let pid = read_pid(&pid_file);
        let error = bridge.shutdown().await.unwrap_err();
        assert!(matches!(error, BridgeError::Timeout));
        assert!(!process_is_running(pid));
        bridge.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_exclusive_bridge_reaps_blocked_request_after_caller_cancel() {
        use base64::Engine as _;

        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("blocked-provider.sh");
        let other_binary = temp.path().join("other-provider.sh");
        let pid_file = temp.path().join("blocked-provider.pid");
        let entered = temp.path().join("blocked-provider.entered");
        let gate = temp.path().join("blocked-provider.gate");
        assert!(std::process::Command::new("mkfifo")
            .arg(&gate)
            .status()
            .unwrap()
            .success());
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{}'\nIFS= read -r _init || exit 1\nprintf '%s\\n' '{}'\nIFS= read -r _read || exit 0\nprintf '%s\\n' \"$_read\" > '{}'\nexec cat '{}'\n",
            pid_file.display(),
            r#"{"status":"ok"}"#,
            entered.display(),
            gate.display(),
        );
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let payload = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 763]);
        let other_response = serde_json::json!({"status":"ok", "data":{"data":payload}});
        let other_script = format!(
            "#!/bin/sh\nset -eu\nIFS= read -r _init || exit 1\nprintf '%s\\n' '{}'\nfor _index in 1 2; do\n  IFS= read -r _read || exit 1\n  case \"$_read\" in *'\"op\":\"cat\"'*) ;; *) exit 2 ;; esac\n  case \"$_read\" in *'\"max_bytes\":763'*) ;; *) exit 2 ;; esac\n  printf '%s\\n' '{}'\ndone\nIFS= read -r _shutdown || exit 1\nprintf '%s\\n' '{}'\n",
            r#"{"status":"ok"}"#,
            other_response,
            r#"{"status":"ok"}"#,
        );
        std::fs::write(&other_binary, other_script).unwrap();
        std::fs::set_permissions(&other_binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let other_bridge = spawn_test_bridge(&other_binary, ProviderConfig::default())
            .await
            .unwrap();
        let bridge = Arc::new(
            spawn_test_bridge_with_timeouts(
                &binary,
                ProviderConfig::default(),
                INIT_TIMEOUT,
                std::time::Duration::from_millis(100),
            )
            .await
            .unwrap(),
        );
        let pid = read_pid(&pid_file);
        let mut stopped_child = ReapTestChild(Some(pid));
        let request_bridge = Arc::clone(&bridge);
        let request = tokio::spawn(async move {
            request_bridge
                .send_raw(&serde_json::json!({"op":"cat", "max_bytes":763}))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while std::fs::read_to_string(&entered)
                .map(|line| line.is_empty())
                .unwrap_or(true)
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the exclusive provider received the bounded read");
        let received: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&entered).unwrap()).unwrap();
        assert_eq!(received["op"], "cat");
        assert_eq!(received["max_bytes"], 763);
        assert!(!request.is_finished());
        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGSTOP) }, 0);
        let other_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            other_bridge.send_raw(&serde_json::json!({"op":"cat", "max_bytes":763})),
        )
        .await
        .expect("an unrelated read completed while the exclusive child was frozen")
        .unwrap();
        let other_bytes = base64::engine::general_purpose::STANDARD
            .decode(other_result["data"]["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(other_bytes, vec![b'x'; 763]);
        assert!(!request.is_finished());
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        let started = std::time::Instant::now();
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), bridge.shutdown())
            .await
            .expect("exclusive provider shutdown stayed bounded")
            .unwrap_err();
        assert!(matches!(error, BridgeError::Timeout), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_process_absent(&pid.to_string());
        stopped_child.0.take();
        let _io = tokio::time::timeout(std::time::Duration::from_secs(1), bridge.io.lock())
            .await
            .expect("the blocked request released the pipe");
        drop(_io);
        bridge.shutdown().await.unwrap();
        let after_cancel = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            other_bridge.send_raw(&serde_json::json!({"op":"cat", "max_bytes":763})),
        )
        .await
        .expect("an unrelated read completed after exclusive cancellation")
        .unwrap();
        let after_cancel_bytes = base64::engine::general_purpose::STANDARD
            .decode(after_cancel["data"]["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(after_cancel_bytes, vec![b'x'; 763]);
        other_bridge.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_shutdown_is_idempotent_after_clean_exit() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"ok"}"#,
            Some(r#"{"status":"ok"}"#),
            0,
        );
        let bridge = spawn_test_bridge(&binary, ProviderConfig::default())
            .await
            .unwrap();
        let pid = read_pid(&pid_file);
        bridge.shutdown().await.unwrap();
        assert!(!process_is_running(pid));
        bridge.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_bridge_spawn_reaps_child_after_init_failure() {
        let temp = tempfile::tempdir().unwrap();
        let (binary, pid_file) = write_mock_provider_script(
            temp.path(),
            r#"{"status":"error","code":"invalid","message":"bad init"}"#,
            None,
            0,
        );
        let error = match spawn_test_bridge(&binary, ProviderConfig::default()).await {
            Ok(_) => panic!("expected init failure"),
            Err(error) => error,
        };
        assert!(matches!(error, BridgeError::InitFailed(_)), "{error}");
        let pid = read_pid(&pid_file);
        assert!(!process_is_running(pid));
    }

    #[tokio::test]
    async fn test_spawn_reaps_provider_that_rejects_init_and_stays_alive() {
        let tempdir = TempDir::new().unwrap();
        let pid_path = tempdir.path().join("reject.pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' $$ > '{}'\nIFS= read -r _line || exit 0\nprintf '{{\"status\":\"error\",\"code\":\"invalid_config\",\"message\":\"reject\"}}\\n'\nwhile :; do :; done\n",
            pid_path.display()
        );
        let script_path = write_provider_script(&tempdir, "reject-provider.sh", &script);

        let error = match spawn_test_bridge(&script_path, ProviderConfig::default()).await {
            Ok(_) => panic!("init rejection should not return a usable bridge"),
            Err(error) => error,
        };

        assert!(matches!(error, BridgeError::InitFailed(_)), "{error}");
        let pid = std::fs::read_to_string(&pid_path).unwrap();
        assert_process_absent(pid.trim());
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn test_spawn_reaps_provider_that_never_answers_init() {
        let tempdir = TempDir::new().unwrap();
        let pid_path = tempdir.path().join("hang.pid");
        // Consumes stdin without ever answering, so init times out and the
        // settle path must force-kill and reap the child. The detached
        // request task keeps the io lock, so the protocol shutdown can never
        // be delivered to a never-answering provider.
        let script = format!(
            "#!/bin/sh\nprintf '%s' $$ > '{}'\nwhile IFS= read -r _line; do :; done\n",
            pid_path.display()
        );
        let script_path = write_provider_script(&tempdir, "hung-provider.sh", &script);

        // The paused clock freezes the init timer, so the marker wait below
        // cannot race the init timeout no matter how loaded the machine is.
        let task = tokio::spawn(async move {
            spawn_test_bridge_with_timeouts(
                &script_path,
                ProviderConfig::default(),
                INIT_TIMEOUT,
                std::time::Duration::from_secs(1),
            )
            .await
        });
        tokio::task::yield_now().await;
        wait_for_file(&pid_path);
        // Fire the init timeout deterministically, then resume real time so
        // the settle stages race real child events (SIGKILL + reap) instead
        // of the auto-advancing paused clock.
        tokio::time::advance(INIT_TIMEOUT).await;
        tokio::time::resume();
        let error = match task.await.unwrap() {
            Ok(_) => panic!("init timeout should not return a usable bridge"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            BridgeError::InitFailed(ref detail) if detail.starts_with("provider init timed out")
        ));
        let pid = std::fs::read_to_string(&pid_path).unwrap();
        assert_process_absent(pid.trim());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_spawn_success_returns_usable_bridge() {
        let tempdir = TempDir::new().unwrap();
        let pid_path = tempdir.path().join("ok.pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' $$ > '{}'\nwhile IFS= read -r line; do\ncase \"$line\" in\n  *'\"op\":\"init\"'*) printf '{{\"status\":\"ok\"}}\\n' ;;\n  *'\"op\":\"exists\"'*) printf '{{\"status\":\"ok\",\"data\":{{\"exists\":true}}}}\\n' ;;\n  *'\"op\":\"shutdown\"'*) printf '{{\"status\":\"ok\"}}\\n'; exit 0 ;;\n  *) printf '{{\"status\":\"error\",\"code\":\"unexpected\",\"message\":\"unexpected\"}}\\n'; exit 0 ;;\nesac\ndone\n",
            pid_path.display()
        );
        let script_path = write_provider_script(&tempdir, "ok-provider.sh", &script);

        let bridge = spawn_test_bridge(&script_path, ProviderConfig::default())
            .await
            .unwrap();
        let response = bridge
            .request(ProviderRequest::Exists {
                path: "test".into(),
                token: String::new(),
            })
            .await
            .unwrap();
        assert!(matches!(response, ProviderResponse::Ok { .. }));
        bridge.shutdown().await.unwrap();

        let pid = std::fs::read_to_string(&pid_path).unwrap();
        assert_process_absent(pid.trim());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_confined_model_child_and_descendant_cannot_open_external_socket() {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::Builder::new()
            .prefix("model.[probe]-")
            .tempdir()
            .unwrap();
        let unrelated = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let unrelated_port = unrelated.local_addr().unwrap().port();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("model-seatbelt-probe.c");
        std::fs::write(
            &source,
            include_str!("../../tests/fixtures/model_seatbelt_probe.c"),
        )
        .unwrap();
        let engine_dir = base.join("libexec/llama.cpp/fixture/darwin-arm64");
        let model_dir = base.join("models");
        std::fs::create_dir_all(&engine_dir).unwrap();
        std::fs::create_dir_all(&model_dir).unwrap();
        let script = engine_dir.join("model-seatbelt-probe");
        assert!(std::process::Command::new("/usr/bin/clang")
            .args(["-O2", "-Wall", "-Wextra", "-o"])
            .arg(&script)
            .arg(&source)
            .status()
            .unwrap()
            .success());
        let listed_library = engine_dir.join("libfixture.dylib");
        std::fs::write(&listed_library, b"listed fixture library").unwrap();
        let receipt_path = engine_dir.join(".elastos-engine.json");
        std::fs::write(
            &receipt_path,
            serde_json::to_vec(&serde_json::json!({
                "schema":"elastos.local-model-engine/v2",
                "entries":[{"path":"libfixture.dylib", "type":"file",
                    "sha256":format!("sha256:{:x}", Sha256::digest(b"listed fixture library"))}]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let model = model_dir.join("model.gguf");
        std::fs::write(&model, b"synthetic model").unwrap();
        let canary = base.join("canary");
        std::fs::write(&canary, b"synthetic canary").unwrap();
        let data_alias = format!("/System/Volumes/Data{}", canary.display());
        assert_eq!(std::fs::read(&data_alias).unwrap(), b"synthetic canary");
        let journal = base.join("providers/model-provider/journal");
        let config = ProviderConfig {
            base_path: base.to_string_lossy().into_owned(),
            extra: serde_json::json!({
                "journal_dir": journal,
                "offers": [{"id":"fixture-local", "adapter":{
                    "kind":"local_llama_cpp_text",
                    "engine":{"path":script}, "model":{"path":model}
                }}],
            }),
            ..Default::default()
        };
        let policy_config = config.clone();
        let rust_source = base.join("model-canonicalize-probe.rs");
        let rust_probe = base.join("model-canonicalize-probe");
        std::fs::write(
            &rust_source,
            include_str!("../../tests/fixtures/model_canonicalize_probe.rs"),
        )
        .unwrap();
        assert!(std::process::Command::new("rustc")
            .arg(&rust_source)
            .arg("-o")
            .arg(&rust_probe)
            .status()
            .unwrap()
            .success());
        let mut profile = model_file_policy(&script, &config, &journal, None).unwrap();
        profile.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            seatbelt_path(&rust_probe).unwrap()
        ));
        let profile_path = base.join("model-canonicalize-probe.sb");
        std::fs::write(&profile_path, profile).unwrap();
        let canonicalized = std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .arg(&rust_probe)
            .args([&base, &script, &model])
            .status()
            .unwrap();
        assert!(canonicalized.success());
        let (bridge, sockets, vacant, confined_config, _hosted_listener) =
            ProviderBridge::spawn_confined_model(&CheckedExecutable::for_test(&script), config)
                .await
                .unwrap();
        assert_eq!(
            confined_config.extra["runtime_local_sockets"]["fixture-local"],
            sockets["fixture-local"]
        );
        assert_eq!(vacant.len(), MAX_LOCAL_MODEL_SLOTS - 1);
        let other_socket = format!("{}.other", sockets["fixture-local"]);
        let _other_listener = std::os::unix::net::UnixListener::bind(&other_socket).unwrap();
        let response = bridge
            .request(ProviderRequest::Exists {
                path: format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    sockets["fixture-local"],
                    unrelated_port,
                    other_socket,
                    model.display(),
                    canary.display(),
                    journal.display(),
                    base.display()
                ),
                token: String::new(),
            })
            .await
            .unwrap();
        let ProviderResponse::Ok { data: Some(data) } = response else {
            panic!("expected network probe response");
        };
        assert_eq!(data["direct_errno"], libc::EPERM);
        assert_eq!(data["descendant_errno"], libc::EPERM);
        assert_eq!(data["unrelated_errno"], libc::EPERM);
        assert_eq!(data["descendant_unrelated_errno"], libc::EPERM);
        assert_eq!(data["other_socket_errno"], libc::EPERM);
        assert_eq!(data["descendant_other_socket_errno"], libc::EPERM);
        assert_eq!(data["selected_socket_errno"], 0);
        assert_eq!(data["descendant_selected_socket_errno"], 0);
        assert_eq!(data["engine_preflight_errno"], libc::ENOENT);
        assert_eq!(data["engine_bind_errno"], 0);
        assert_eq!(data["engine_stat_errno"], 0);
        assert_eq!(data["engine_unlink_errno"], 0);
        assert_eq!(data["system_read_errno"], libc::EPERM);
        assert_eq!(data["descendant_system_read_errno"], libc::EPERM);
        assert_eq!(data["model_read_errno"], 0);
        assert_eq!(data["canary_read_errno"], libc::EPERM);
        assert_eq!(data["data_alias_read_errno"], libc::EPERM);
        assert_eq!(data["descendant_canary_read_errno"], libc::EPERM);
        assert_eq!(data["model_write_errno"], libc::EPERM);
        assert_eq!(data["descendant_model_write_errno"], libc::EPERM);
        assert_eq!(data["model_link_errno"], libc::EPERM);
        assert_eq!(data["descendant_model_link_errno"], libc::EPERM);
        assert_eq!(data["model_rename_errno"], libc::EPERM);
        assert_eq!(data["descendant_model_rename_errno"], libc::EPERM);
        assert_eq!(data["journal_alias_create_errno"], 0);
        assert_eq!(data["journal_alias_write_errno"], libc::EPERM);
        assert_eq!(data["journal_write_errno"], 0);
        assert_eq!(data["base_canonical_errno"], 0);
        assert_eq!(data["inherited_writable_regular_fds"], 0);
        bridge.shutdown().await.unwrap();
        assert!(!Path::new(&sockets["fixture-local"]).exists());
        std::fs::write(&listed_library, b"changed fixture library").unwrap();
        assert!(model_file_policy(&script, &policy_config, &journal, None).is_err());

        // Keep one confined child through a zero-offer startup and files that
        // arrive later. The declared read namespace excludes mutable staging,
        // inventory and other engine versions, even with regex chars in root.
        let empty_config = ProviderConfig {
            base_path: base.to_string_lossy().into_owned(),
            extra: serde_json::json!({"offers":[], "journal_dir":journal}),
            ..Default::default()
        };
        let (empty_bridge, _, vacant, _, _hosted_listener) =
            ProviderBridge::spawn_confined_model_with_engine_bundle(
                &CheckedExecutable::for_test(&script),
                empty_config,
                Some(&engine_dir),
            )
            .await
            .unwrap();
        let preparation = base.join("model-preparation");
        let admitted = preparation.join(format!("admitted-{}", "a".repeat(64)));
        std::fs::create_dir_all(&admitted).unwrap();
        let late_model = admitted.join("weights.gguf");
        std::fs::write(&late_model, b"late synthetic model").unwrap();
        std::os::unix::fs::symlink(&canary, format!("{}.external", late_model.display())).unwrap();
        for name in [
            format!("admitted-{}", "0".repeat(63)),
            format!("admitted-{}-extra", "0".repeat(64)),
        ] {
            let invalid = preparation.join(name);
            std::fs::create_dir_all(&invalid).unwrap();
            std::fs::write(invalid.join("canary"), b"outside admission boundary").unwrap();
        }
        std::fs::create_dir_all(preparation.join("stage")).unwrap();
        std::fs::write(preparation.join("stage/canary"), b"unverified").unwrap();
        std::fs::write(preparation.join("state.json"), b"private inventory").unwrap();
        std::fs::write(preparation.join("worker"), b"private lock").unwrap();
        std::fs::write(engine_dir.join("late-engine"), b"pinned engine artifact").unwrap();
        let other_engine = base.join("libexec/llama.cpp/other/darwin-arm64");
        std::fs::create_dir_all(&other_engine).unwrap();
        std::fs::write(other_engine.join("canary"), b"other engine version").unwrap();
        let other_socket = format!("{}.other", vacant[0]);
        let _other_listener = std::os::unix::net::UnixListener::bind(&other_socket).unwrap();
        let response = empty_bridge
            .request(ProviderRequest::Exists {
                path: format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    vacant[0],
                    unrelated_port,
                    other_socket,
                    late_model.display(),
                    canary.display(),
                    journal.display(),
                    base.display()
                ),
                token: String::new(),
            })
            .await
            .unwrap();
        let ProviderResponse::Ok { data: Some(data) } = response else {
            panic!("expected native namespace probe response");
        };
        assert_eq!(data["model_read_errno"], 0);
        assert_eq!(data["late_engine_read_errno"], 0);
        for denied in [
            "stage_read_errno",
            "inventory_read_errno",
            "worker_read_errno",
            "other_engine_read_errno",
            "late_engine_write_errno",
            "admitted_alias_read_errno",
            "short_admission_read_errno",
            "suffixed_admission_read_errno",
            "canary_read_errno",
            "model_write_errno",
            "descendant_model_write_errno",
            "direct_errno",
            "descendant_errno",
        ] {
            assert_eq!(data[denied], libc::EPERM, "{denied}");
        }
        empty_bridge.shutdown().await.unwrap();
        std::fs::write(&listed_library, b"listed fixture library").unwrap();
        std::fs::write(
            engine_dir.join("unlisted.dylib"),
            b"unlisted fixture library",
        )
        .unwrap();
        assert!(model_file_policy(&script, &policy_config, &journal, None).is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    #[ignore = "requires ELASTOS_MODEL_BROKER_PROOF_CONFIG with installed provider and admitted local Smol artifacts"]
    async fn installed_model_provider_completes_smollm2_through_runtime_broker() {
        use sha2::{Digest as _, Sha256};

        let input_path = std::env::var("ELASTOS_MODEL_BROKER_PROOF_CONFIG").unwrap();
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(input_path).unwrap()).unwrap();
        let binary = Path::new(fixture["binary_path"].as_str().unwrap());
        let config: ProviderConfig =
            serde_json::from_value(fixture["provider_config"].clone()).unwrap();
        let offer_id = fixture["offer_id"].as_str().unwrap();
        #[cfg(target_os = "macos")]
        let (bridge, sockets, _, _, _hosted_listener) =
            ProviderBridge::spawn_confined_model(&CheckedExecutable::for_test(binary), config)
                .await
                .unwrap();
        #[cfg(target_os = "linux")]
        let (bridge, sockets, _, _) = ProviderBridge::spawn_confined_model_linux(
            &CheckedExecutable::for_test(binary),
            config,
        )
        .await
        .unwrap();
        let socket = sockets[offer_id].clone();
        let input = serde_json::json!({
            "schema": "elastos.model.input.text/v1",
            "prompt": "Reply with one word: local."
        });
        let input_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&input).unwrap()))
        );
        let binding = serde_json::json!({
            "schema": "elastos.model.runtime-binding/v1",
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": format!("request:broker-smol-{}", uuid::Uuid::new_v4()),
            "offer_id": offer_id,
            "operation": "text.generate",
            "input_hash": input_hash,
        });
        let created = bridge
            .send_raw(&serde_json::json!({
                "op": "runs_create", "offer_id": offer_id,
                "operation": "text.generate", "input": input,
                "runtime_binding": binding,
            }))
            .await
            .unwrap();
        assert_eq!(created["status"], "ok", "{created}");
        let run_id = created["data"]["run_id"].as_str().unwrap();
        let access = serde_json::json!({
            "schema": "elastos.model.runtime-access-binding/v1",
            "principal_id": binding["principal_id"],
            "session_id": binding["session_id"],
            "capsule_id": binding["capsule_id"],
            "grant_id": binding["grant_id"],
            "request_id": binding["request_id"],
            "run_id": run_id,
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            assert!(tokio::time::Instant::now() < deadline, "Smol run timed out");
            let result = bridge
                .send_raw(&serde_json::json!({
                    "op": "runs_get", "run_id": run_id, "runtime_binding": access,
                }))
                .await
                .unwrap();
            if result["data"]["status"] == "completed" {
                assert!(result["data"]["terminal"]["output"]["text"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()));
                break;
            }
            assert_ne!(result["data"]["status"], "failed", "{result}");
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        bridge.shutdown().await.unwrap();
        assert!(!Path::new(&socket).exists());
    }

    #[test]
    fn test_capsule_provider_request_mapping() {
        let request = ResourceRequest {
            uri: "localhost://Users/self/Documents/photos/test.jpg".into(),
            _scheme: "localhost".into(),
            path: "Users/self/Documents/photos/test.jpg".into(),
            _capsule_id: "cap-1".into(),
            action: ResourceAction::Read,
            content: None,
            recursive: false,
        };

        let provider_req = CapsuleProvider::to_provider_request(&request);
        match provider_req {
            ProviderRequest::Read { path, .. } => {
                assert_eq!(path, "Users/self/Documents/photos/test.jpg");
            }
            _ => panic!("Expected Read request"),
        }

        // Write mapping
        let request = ResourceRequest {
            uri: "localhost://Users/self/Documents/docs/file.txt".into(),
            _scheme: "localhost".into(),
            path: "Users/self/Documents/docs/file.txt".into(),
            _capsule_id: "cap-1".into(),
            action: ResourceAction::Write,
            content: Some(b"hello".to_vec()),
            recursive: false,
        };

        let provider_req = CapsuleProvider::to_provider_request(&request);
        match provider_req {
            ProviderRequest::Write { path, content, .. } => {
                assert_eq!(path, "Users/self/Documents/docs/file.txt");
                assert_eq!(content, b"hello");
            }
            _ => panic!("Expected Write request"),
        }
    }

    #[test]
    fn test_capsule_provider_response_mapping() {
        // Read response
        let resp = ProviderResponse::Ok {
            data: Some(serde_json::json!({"content": [104, 101, 108, 108, 111], "size": 5})),
        };
        let result = CapsuleProvider::to_resource_response(ResourceAction::Read, resp).unwrap();
        match result {
            ResourceResponse::Data(data) => assert_eq!(data, b"hello"),
            _ => panic!("Expected Data response"),
        }

        // List response
        let resp = ProviderResponse::Ok {
            data: Some(serde_json::json!([
                {"name": "file.txt", "is_file": true, "is_dir": false, "size": 11},
                {"name": "subdir", "is_file": false, "is_dir": true, "size": 0}
            ])),
        };
        let result = CapsuleProvider::to_resource_response(ResourceAction::List, resp).unwrap();
        match result {
            ResourceResponse::List(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].name, "file.txt");
                assert!(!entries[0].is_directory);
                assert_eq!(entries[1].name, "subdir");
                assert!(entries[1].is_directory);
            }
            _ => panic!("Expected List response"),
        }

        // Exists response
        let resp = ProviderResponse::Ok {
            data: Some(serde_json::json!({"exists": true})),
        };
        let result = CapsuleProvider::to_resource_response(ResourceAction::Exists, resp).unwrap();
        assert!(matches!(result, ResourceResponse::Exists(true)));

        // Error mapping (not found)
        let resp = ProviderResponse::Error {
            code: "read_failed".into(),
            message: "No such file or directory".into(),
        };
        let result = CapsuleProvider::to_resource_response(ResourceAction::Read, resp);
        assert!(matches!(result, Err(ProviderError::NotFound(_))));
    }

    /// Falsifier A removes the `install_on_command` attach (bridge.rs:882) and
    /// this test fails at its `no_new_privs` assertion: bridge.rs:3296:9 on the
    /// aarch64 Jetson run, bridge.rs:3308:9 on x86_64. Scope:
    /// rong-review/C9-plan-stacked-v3-20261030.md, S1a bar 5. The aarch64 Jetson
    /// run (Linux 5.15.148-tegra) is done: 1 passed, and the same falsifier
    /// failed at bridge.rs:3296:9 (c9-s1a-jetson-20261030-1640.md).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn spawn_confined_model_linux_child_inherits_socket_filter() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("linux-model-seccomp-probe.rs");
        std::fs::write(
            &source,
            include_str!("../../tests/fixtures/linux_model_seccomp_probe.rs"),
        )
        .unwrap();
        let probe = tempdir.path().join("linux-model-seccomp-probe");
        let built = std::process::Command::new("rustc")
            .args(["--edition", "2021"])
            .arg(&source)
            .arg("-o")
            .arg(&probe)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "probe build failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        // The probe reports into `<its own executable path>.observed`, so no
        // process variable is set while other tests run in this thread pool.
        let observed = probe.with_extension("observed");
        let config = ProviderConfig {
            base_path: tempdir.path().to_string_lossy().into_owned(),
            extra: serde_json::json!({
                "offers": [{"id":"fixture-local", "adapter":{"kind":"local_llama_cpp_text"}}],
            }),
            ..Default::default()
        };
        let spawned = ProviderBridge::spawn_confined_model_linux(
            &CheckedExecutable::for_test(&probe),
            config,
        )
        .await;
        let (bridge, sockets, vacant, _) = spawned.unwrap();
        let pid = bridge
            .child
            .lock()
            .await
            .as_ref()
            .unwrap()
            .id()
            .expect("egress-filtered provider pid");
        // One `name=value` line per kernel observation, each asserted alone.
        let report = std::fs::read_to_string(&observed)
            .expect("probe did not inherit the egress filter from the route");
        let inherited = report
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(inherited.get("no_new_privs"), Some(&"1"), "{report:?}");
        assert_eq!(inherited.get("seccomp"), Some(&"2"), "{report:?}");
        assert_eq!(inherited.get("inet_socket"), Some(&"EPERM"), "{report:?}");
        assert_eq!(sockets.len(), 1);
        assert!(sockets["fixture-local"].ends_with("/0.sock"));
        assert_eq!(vacant.len(), MAX_LOCAL_MODEL_SLOTS - 1);
        assert!(
            process_exists(&pid.to_string()),
            "provider exited after Init"
        );
        bridge.shutdown().await.unwrap();
        for _ in 0..250 {
            if !process_exists(&pid.to_string()) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !process_exists(&pid.to_string()),
            "provider survived shutdown"
        );
    }

    // === Slice 10: spawn_confined and Confined ===

    fn committed_authority(name: &str) -> ProviderAuthority {
        let path = format!(
            "{}/../../../capsules/{name}-provider/capsule.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let json = std::fs::read_to_string(&path).unwrap();
        let manifest: elastos_common::CapsuleManifest = serde_json::from_str(&json).unwrap();
        manifest.authority.unwrap()
    }

    #[cfg(target_os = "linux")]
    fn build_confined_probe(root: &Path, pid_file: &Path, mode: &str) -> PathBuf {
        build_confined_probe_reporting(root, pid_file, mode, "")
    }

    #[cfg(target_os = "linux")]
    fn build_confined_probe_reporting(
        root: &Path,
        pid_file: &Path,
        mode: &str,
        stderr_report: &str,
    ) -> PathBuf {
        let source = root.join("confined-provider-probe.rs");
        let binary = root.join("confined-provider-probe");
        let pid = pid_file.to_str().unwrap();
        let text = include_str!("../../tests/fixtures/confined_provider_probe.rs")
            .replace("@@PID_FILE@@", pid)
            .replace("@@MODE@@", mode)
            .replace("@@STDERR_REPORT@@", stderr_report);
        std::fs::write(&source, text).unwrap();
        let built = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-O"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "probe build failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        binary
    }

    #[cfg(target_os = "linux")]
    fn pid_gone(pid: libc::pid_t) -> bool {
        (unsafe { libc::kill(pid, 0) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(target_os = "linux")]
    fn fork_pid(bridge: &ProviderBridge) -> libc::pid_t {
        bridge
            .fork
            .try_lock()
            .expect("no live request holds the fork handle")
            .as_ref()
            .expect("a confined start keeps its fork handle")
            .pid
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn confined_start_answers_init_over_its_own_pipes() {
        let temp = tempfile::tempdir().unwrap();
        let binary = build_confined_probe(temp.path(), Path::new(""), "ok");
        let root = temp.path().join("did-root");
        let confined = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&binary),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("confined start must answer Init: {error}"));
        let pid = fork_pid(confined.bridge());
        // Row 2: the child's fd 0 and fd 1 are its own pipes, and it inherited
        // nothing else.
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            fds.iter()
                .all(|fd| fd.parse::<i32>().is_ok_and(|fd| fd <= 2)),
            "the child sees only fds 0-2: {fds:?}"
        );
        let child_stdin = std::fs::read_link(format!("/proc/{pid}/fd/0")).unwrap();
        let child_stdout = std::fs::read_link(format!("/proc/{pid}/fd/1")).unwrap();
        let parent_stdin = std::fs::read_link("/proc/self/fd/0").unwrap();
        let parent_stdout = std::fs::read_link("/proc/self/fd/1").unwrap();
        assert!(child_stdin.to_string_lossy().starts_with("pipe:"));
        assert!(child_stdout.to_string_lossy().starts_with("pipe:"));
        assert_ne!(
            child_stdin, parent_stdin,
            "the child inherited the parent's stdin"
        );
        assert_ne!(
            child_stdout, parent_stdout,
            "the child inherited the parent's stdout"
        );
        let child_stderr = std::fs::read_link(format!("/proc/{pid}/fd/2")).unwrap();
        assert_eq!(
            child_stderr,
            Path::new("/dev/null"),
            "the confined child's standard error is /dev/null"
        );
        // Row 1: Shutdown is answered, the child exits, and the pid is reaped.
        confined.bridge().shutdown().await.unwrap();
        for _ in 0..250 {
            if pid_gone(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(pid_gone(pid), "the confined child was not reaped");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refused_start_leaves_no_root_and_success_leaves_one() {
        use std::os::unix::fs::MetadataExt as _;
        let temp = tempfile::tempdir().unwrap();
        // Refused: a widened rule stops before the fork and removes the root.
        let widened = temp.path().join("widened-root");
        let mut authority = committed_authority("did");
        let storage = authority
            .rights
            .iter_mut()
            .find(|right| right.id == "storage")
            .unwrap();
        storage.rules = vec![r#"(allow file-read* file-write* (subpath "/"))"#.to_string()];
        let error = match ProviderBridge::spawn_confined(
            "did-provider",
            &authority,
            &CheckedExecutable::for_test(&temp.path().join("never-runs")),
            &widened,
            ProviderConfig::default(),
        )
        .await
        {
            Ok(_) => panic!("a widened declaration must refuse"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "provider right \"storage\" rule text differs from the Runtime template"
        );
        assert!(!widened.exists(), "a refused start leaves no root");
        // Success: the root is 0700 and owned by the euid.
        let binary = build_confined_probe(temp.path(), Path::new(""), "ok");
        let root = temp.path().join("kept-root");
        let confined = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&binary),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap();
        let metadata = std::fs::metadata(&root).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        confined.bridge().shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refused_start_never_runs_the_binary() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("ran");
        let program = temp.path().join("mark.sh");
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut authority = committed_authority("did");
        authority
            .rights
            .iter_mut()
            .find(|right| right.id == "storage")
            .unwrap()
            .rules = vec![r#"(allow file-read* file-write* (subpath "/"))"#.to_string()];
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &authority,
            &CheckedExecutable::for_test(&program),
            &temp.path().join("root"),
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider right \"storage\" rule text differs from the Runtime template"
        );
        assert!(!marker.exists(), "the provider binary never runs");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_reopened_storage_root_that_differs_from_the_checked_directory_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let canary = temp.path().join("canary");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        let marker = root.join("started");
        let program = temp.path().join("mark.sh");
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = open_directory(&root).unwrap();
        let info = stat_fd(directory.as_raw_fd()).unwrap();
        arm_checked_launch_swap(stat_dev(&info), stat_ino(&info), c"root.checked", c"canary");
        drop(directory);
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                *CHECKED_LAUNCH_SWAP.lock().expect("checked launch") = None;
            }
        }
        let _clear = Clear;
        let error = match ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&program),
            &root,
            ProviderConfig::default(),
        )
        .await
        {
            Ok(confined) => {
                let _ = confined.bridge().shutdown().await;
                panic!(
                    "a reopened storage root that differs from the checked directory is refused"
                );
            }
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "provider start is refused: the reopened storage root is not the checked directory",
            "a reopened storage root that differs from the checked directory is refused"
        );
        assert!(!marker.exists(), "the provider does not start");
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"kept");
        assert_eq!(
            std::fs::symlink_metadata(&root).unwrap().mode() & 0o777,
            0o755,
            "the canary stays unchanged"
        );
    }

    #[cfg(target_os = "linux")]
    struct ClearLaunchedPid;

    #[cfg(target_os = "linux")]
    impl Drop for ClearLaunchedPid {
        fn drop(&mut self) {
            super::set_report_launched_pid(false);
        }
    }

    #[cfg(target_os = "linux")]
    fn report_launched_pid() -> ClearLaunchedPid {
        super::set_report_launched_pid(true);
        ClearLaunchedPid
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_init_leaves_no_live_child_and_no_zombie() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let pid_file = root.join("child.pid");
        let _report = report_launched_pid();
        let binary = build_confined_probe(temp.path(), &pid_file, "reject_init");
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&binary),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, BridgeError::InitFailed(_)), "{error}");
        let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            pid_gone(pid),
            "an Init failure must reap the child: pid {pid} still visible"
        );
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn each_start_uses_its_own_root_and_plan() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("root-a");
        let root_b = temp.path().join("root-b");
        let mut pids = Vec::new();
        let _report = report_launched_pid();
        for root in [&root_a, &root_b, &root_a] {
            let pid_file = root.join("child.pid");
            let binary = build_confined_probe(temp.path(), &pid_file, "ok");
            let confined = ProviderBridge::spawn_confined(
                "did-provider",
                &committed_authority("did"),
                &CheckedExecutable::for_test(&binary),
                root,
                ProviderConfig::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("start under {}: {error}", root.display()));
            assert!(root.is_dir(), "root_a.is_dir()");
            let pid = fork_pid(confined.bridge());
            // The child writes under its own root, so a plan inherited from the
            // previous start would leave this file absent.
            let recorded: libc::pid_t = std::fs::read_to_string(&pid_file)
                .unwrap_or_else(|error| {
                    panic!("the child writes under {}: {error}", root.display())
                })
                .trim()
                .parse()
                .unwrap();
            assert_eq!(recorded, pid, "the recorded pid is the launched child");
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            assert!(
                status.lines().any(|line| line == "Seccomp:\t2"),
                "each start installs the filter: {status}"
            );
            assert!(
                status.lines().any(|line| line == "NoNewPrivs:\t1"),
                "each start sets no_new_privs: {status}"
            );
            pids.push(pid);
            confined.bridge().shutdown().await.unwrap();
            for _ in 0..250 {
                if pid_gone(pid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(pid_gone(pid));
        }
        assert_ne!(pids[0], pids[1]);
        assert_ne!(pids[1], pids[2]);
        assert!(root_a.is_dir() && root_b.is_dir());
    }

    #[tokio::test]
    async fn symlink_at_the_storage_root_refuses_and_leaves_the_canary() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        let root = temp.path().join("root");
        std::os::unix::fs::symlink(&canary, &root).unwrap();
        #[cfg(target_os = "linux")]
        let binary = build_confined_probe(temp.path(), &canary.join("child.pid"), "ok");
        #[cfg(not(target_os = "linux"))]
        let binary = temp.path().join("never-runs");
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&binary),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            std::fs::metadata(&canary).unwrap().mode() & 0o777,
            0o755,
            "the canary and its permissions stay unchanged"
        );
        assert_eq!(std::fs::read(canary.join("kept")).unwrap(), b"kept");
        assert!(
            !canary.join("child.pid").exists(),
            "the canary and its permissions stay unchanged"
        );
        assert!(
            error.to_string().contains("symlink"),
            "a symlink storage root must refuse: {error}"
        );
        assert!(std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_init_removes_the_root_a_child_wrote_into() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let binary = build_confined_probe(temp.path(), &root.join("child.pid"), "reject_init");
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&binary),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, BridgeError::InitFailed(_)), "{error}");
        assert!(
            !root.exists(),
            "a failed Init removes the root this start created"
        );
    }

    #[test]
    fn an_armed_root_removes_the_tree_and_not_a_symlink_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"stay").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        drop(guard);
        assert!(!root.exists(), "a failed start removes the created root");
        assert_eq!(std::fs::read(&outside).unwrap(), b"stay");
    }

    #[test]
    fn a_group_writable_parent_is_refused_and_a_writable_root_keeps_its_canary() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770)).unwrap();
        let root = parent.join("root");
        match create_storage_root(&root) {
            Ok(guard) => {
                drop(guard);
                panic!("a group-writable parent is refused before the storage root is created");
            }
            Err(error) => assert_eq!(
                error.to_string(),
                "provider start is refused: the storage root's parent is writable by group or other",
                "a group-writable parent is refused before the storage root is created"
            ),
        }
        assert!(
            !root.exists(),
            "a group-writable parent is refused before the storage root is created"
        );

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let guard = create_storage_root(&root).unwrap();
        assert!(guard.armed, "this start creates the root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        std::fs::write(root.join("canary"), b"kept").unwrap();
        let info = stat_fd(guard.directory.as_raw_fd()).unwrap();
        drop(guard);
        let kept = std::fs::read_dir(&parent).unwrap().any(|entry| {
            let Ok(entry) = entry else {
                return false;
            };
            let Ok(opened) = open_directory(&entry.path()) else {
                return false;
            };
            let Ok(found) = stat_fd(opened.as_raw_fd()) else {
                return false;
            };
            same_directory(&found, &info)
                && std::fs::read(entry.path().join("canary")).ok().as_deref()
                    == Some(b"kept".as_slice())
        });
        assert!(
            kept,
            "cleanup preserves the canary inside a group-writable root"
        );
    }

    #[test]
    fn a_symlink_at_the_root_path_leaves_the_canary() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        let opened = temp.path().join("root.opened");
        std::fs::rename(&root, &opened).unwrap();
        std::os::unix::fs::symlink(&canary, &root).unwrap();
        drop(guard);
        assert_eq!(std::fs::read(canary.join("kept")).unwrap(), b"kept");
        assert_eq!(
            std::fs::symlink_metadata(&canary).unwrap().mode() & 0o777,
            0o755
        );
        assert!(
            !opened.exists(),
            "cleanup removes the directory this start opened"
        );
        assert!(std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"kept");
    }

    #[test]
    fn a_renamed_root_is_removed_and_the_directory_at_the_old_name_stays() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        let opened = temp.path().join("root.opened");
        std::fs::rename(&root, &opened).unwrap();
        std::fs::rename(&canary, &root).unwrap();
        drop(guard);
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"kept");
        assert_eq!(
            std::fs::symlink_metadata(&root).unwrap().mode() & 0o777,
            0o755,
            "the directory now at the old name stays"
        );
        assert!(
            !opened.exists(),
            "cleanup removes the opened directory and leaves the directory now at its old name"
        );
    }

    #[test]
    fn a_swap_during_cleanup_keeps_the_name_and_removes_the_opened_directory() {
        use std::os::unix::fs::MetadataExt;
        let swap_tests = swap_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        struct ClearSwap;
        impl Drop for ClearSwap {
            fn drop(&mut self) {
                *HELD_UNLINK_SWAP.lock().expect("held unlink swap") = None;
            }
        }
        let _clear = ClearSwap;
        let info = stat_fd(guard.directory.as_raw_fd()).unwrap();
        arm_held_unlink_swap(stat_dev(&info), stat_ino(&info), c"root.opened", c"canary");
        drop(guard);
        assert_eq!(std::fs::read(root.join("kept")).unwrap(), b"kept");
        assert_eq!(
            std::fs::symlink_metadata(&root).unwrap().mode() & 0o777,
            0o755
        );
        assert!(
            !temp.path().join("root.opened").exists(),
            "a swap during cleanup removes the opened directory and leaves the directory now at its old name"
        );
        let leftover = std::fs::read_dir(temp.path()).unwrap().any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".elastos-held-"))
        });
        assert!(!leftover, "cleanup leaves no private name");
        drop(swap_tests);
    }

    #[test]
    fn a_private_name_that_fails_the_identity_check_stays() {
        use std::os::unix::fs::MetadataExt;
        let swap_tests = swap_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(temp.path().join("blocker"), b"block").unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        let info = stat_fd(guard.directory.as_raw_fd()).unwrap();
        arm_mismatch_swap(
            stat_dev(&info),
            stat_ino(&info),
            c"root.held",
            c"canary",
            c"blocker",
        );
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                *MISMATCH_SWAP.lock().expect("mismatch swap") = None;
            }
        }
        let _clear = Clear;
        drop(guard);
        let kept = std::fs::read_dir(temp.path()).unwrap().any(|entry| {
            let Ok(entry) = entry else {
                return false;
            };
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".elastos-held-")
                && entry.metadata().unwrap().mode() & 0o777 == 0o755
        });
        assert!(
            kept,
            "a directory that failed the identity check stays under its private name"
        );
        assert_eq!(std::fs::read(temp.path().join("root")).unwrap(), b"block");
        drop(swap_tests);
    }

    #[test]
    fn a_swap_of_the_private_name_keeps_the_directory_placed_there() {
        use std::os::unix::fs::MetadataExt;
        let swap_tests = swap_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        let info = stat_fd(guard.directory.as_raw_fd()).unwrap();
        arm_private_unlink_swap(stat_dev(&info), stat_ino(&info), c"root.held", c"canary");
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                *PRIVATE_UNLINK_SWAP.lock().expect("private unlink swap") = None;
            }
        }
        let _clear = Clear;
        drop(guard);
        assert!(
            root.is_dir(),
            "a swap of the private name keeps the directory that was placed there"
        );
        assert_eq!(
            std::fs::symlink_metadata(&root).unwrap().mode() & 0o777,
            0o755
        );
        assert!(!temp.path().join("root.held").exists());
        drop(swap_tests);
    }

    #[test]
    fn an_unopened_created_root_leaves_the_directory_now_at_its_name() {
        let swap_tests = swap_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let canary = temp.path().join("canary");
        std::fs::create_dir(&canary).unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        arm_unopened_swap(c"root.created", c"canary");
        struct Clear<'a> {
            root: &'a Path,
        }
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                *UNOPENED_SWAP.lock().expect("unopened root") = None;
                let _ = std::fs::set_permissions(self.root, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _clear = Clear { root: &root };
        assert!(
            create_storage_root(&root).is_err(),
            "an unopened root must be refused"
        );
        assert!(
            root.is_dir(),
            "a directory this start never opened stays at the storage root name"
        );
        assert!(temp.path().join("root.created").is_dir());
        drop(swap_tests);
    }

    #[test]
    fn a_swap_for_one_root_stays_armed_while_another_root_is_removed() {
        let swap_tests = swap_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("root-a");
        let root_b = temp.path().join("root-b");
        std::fs::create_dir(&root_a).unwrap();
        std::fs::create_dir(&root_b).unwrap();
        std::fs::write(root_a.join("wrote"), b"a").unwrap();
        std::fs::write(root_b.join("wrote"), b"b").unwrap();
        std::fs::create_dir(temp.path().join("canary-a")).unwrap();
        let mut guard_a = create_storage_root(&root_a).unwrap();
        let mut guard_b = create_storage_root(&root_b).unwrap();
        guard_a.armed = true;
        guard_b.armed = true;
        let info = stat_fd(guard_a.directory.as_raw_fd()).unwrap();
        arm_held_unlink_swap(stat_dev(&info), stat_ino(&info), c"aside-a", c"canary-a");
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                *HELD_UNLINK_SWAP.lock().expect("held unlink swap") = None;
            }
        }
        let _clear = Clear;
        drop(guard_b);
        assert!(
            held_unlink_swap_is_armed(),
            "a swap for one directory stays armed while another root is removed"
        );
        assert!(!root_b.exists());
        *HELD_UNLINK_SWAP.lock().expect("held unlink swap") = None;
        drop(guard_a);
        drop(swap_tests);
    }

    #[tokio::test]
    async fn dropping_a_live_child_reaps_before_the_root_goes() {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                loop {
                    libc::sleep(30);
                }
            }
        }
        assert!(pid > 0, "fork");
        struct Release(libc::pid_t);
        impl Drop for Release {
            fn drop(&mut self) {
                if REAP_HOLD_PID.load(std::sync::atomic::Ordering::Acquire) == self.0 {
                    REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
                    unsafe {
                        libc::kill(self.0, libc::SIGKILL);
                    }
                }
            }
        }
        REAP_HOLD_PID.store(pid, std::sync::atomic::Ordering::Release);
        let release = Release(pid);
        REAP_WAIT_STARTED.store(false, std::sync::atomic::Ordering::Release);
        let fork = match ForkChild::start(pid) {
            Ok(fork) => fork,
            Err(error) => {
                REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut status = 0;
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("the child could not be owned: {error}");
            }
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let mut created = create_storage_root(&root).unwrap();
        created.armed = true;
        let bridge = ProviderBridge::from_io(
            tokio::io::BufReader::new(tokio::io::empty()),
            tokio::io::sink(),
        );
        *bridge.fork.lock().await = Some(fork);
        let start = ConfinedStart {
            bridge: Some(bridge),
            root: created,
        };
        let root_path = root.clone();
        let watcher = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            while !REAP_WAIT_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                if began.elapsed() > std::time::Duration::from_secs(5) {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let stayed = root_path.exists();
            REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
            stayed
        });
        drop(start);
        let stayed = watcher.join().expect("the watcher finishes");
        REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
        drop(release);
        assert!(stayed, "the root stays until the child is reaped");
        assert!(!root.exists(), "the root goes after the child is reaped");
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn a_disarmed_root_stays() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("wrote"), b"x").unwrap();
        let mut guard = create_storage_root(&root).unwrap();
        guard.armed = true;
        guard.disarm();
        drop(guard);
        assert!(root.join("wrote").is_file());
    }

    #[tokio::test]
    async fn a_second_shutdown_wait_reaps_before_it_returns() {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                loop {
                    libc::sleep(30);
                }
            }
        }
        assert!(pid > 0, "fork");
        struct Release(libc::pid_t);
        impl Drop for Release {
            fn drop(&mut self) {
                if REAP_HOLD_PID.load(std::sync::atomic::Ordering::Acquire) == self.0 {
                    REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
                }
            }
        }
        REAP_HOLD_PID.store(pid, std::sync::atomic::Ordering::Release);
        let _release = Release(pid);
        let fork = match ForkChild::start(pid) {
            Ok(fork) => fork,
            Err(error) => {
                REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut status = 0;
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("the child could not be owned: {error}");
            }
        };
        let mut bridge = ProviderBridge::from_io(
            tokio::io::BufReader::new(tokio::io::empty()),
            tokio::io::sink(),
        );
        bridge.shutdown_timeout = std::time::Duration::from_millis(40);
        *bridge.fork.lock().await = Some(fork);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if REAP_HOLD_PID.load(std::sync::atomic::Ordering::Acquire) == pid {
                REAP_HOLD_PID.store(0, std::sync::atomic::Ordering::Release);
            }
        });
        let _ = bridge.shutdown().await;
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        let reaped =
            waited == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
        let _ = releaser.join();
        assert!(reaped, "shutdown returns only after the child is reaped");
    }

    #[test]
    fn a_start_without_a_process_handle_reaps_the_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid > 0, "fork");
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let error = refuse_child_without_process_handle(pid);
        assert_eq!(
            error.to_string(),
            "provider start is refused: the process handle could not be opened"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[tokio::test]
    async fn unknown_component_key_is_refused_before_the_gate() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let error = ProviderBridge::spawn_confined(
            "ipfs-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&temp.path().join("never-runs")),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider start is refused: component key \"ipfs-provider\" is not one of did-provider, wallet-provider, model-provider"
        );
        assert!(!root.exists(), "the refused key creates no root");
    }

    #[test]
    fn only_the_confined_entry_makes_a_confined() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root];
        let mut other = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                if path.ends_with("provider/bridge.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("fn from_confined") || text.contains("Confined {") {
                    other.push(path);
                }
            }
        }
        assert!(
            other.is_empty(),
            "only bridge.rs constructs Confined: {other:?}"
        );
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider/bridge.rs"),
        )
        .unwrap();
        let from_needle = concat!("pub ", "fn from_confined(confined: Confined, scheme");
        assert_eq!(source.matches(from_needle).count(), 1);
        let struct_needle = concat!(
            "pub struct Confined {\n    br",
            "idge: Arc<ProviderBridge>,"
        );
        assert_eq!(source.matches(struct_needle).count(), 1);
        assert!(!source.contains(concat!("impl From<ProviderBridge> ", "for Confined")));
        let start = source.find("pub async fn spawn_confined(").unwrap();
        let end = source[start..]
            .find("/// Admit only Runtime-selected private engine sockets")
            .map(|at| at + start)
            .expect("the confined start ends before the model path");
        let body = &source[start..end];
        assert!(
            !body.contains("ProviderBridge::spawn") && !body.contains("Self::spawn("),
            "the confined start has no unconfined fallback"
        );
        assert!(body.contains("super::os_entry::start_provider("));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_confined_start_refuses_and_starts_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("ran");
        let program = temp.path().join("mark.sh");
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("root");
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&program),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider start on macos is refused: the Seatbelt profile has no spawn path yet"
        );
        assert!(!marker.exists(), "the provider binary never runs");
        assert!(!root.exists(), "a refused start leaves no root");
    }

    #[cfg(elastos_unsupported_os_check)]
    #[tokio::test]
    async fn unsupported_os_confined_start_refuses_and_starts_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("ran");
        let program = temp.path().join("mark.sh");
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("root");
        let error = ProviderBridge::spawn_confined(
            "did-provider",
            &committed_authority("did"),
            &CheckedExecutable::for_test(&program),
            &root,
            ProviderConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider start is refused: this operating system has no confinement, so the provider binary does not start"
        );
        assert!(!marker.exists(), "the provider binary never runs");
        assert!(!root.exists(), "a refused start leaves no root");
    }
}
