//! Agents that belong to one person.
//!
//! An owner turns agents on for their Home, then creates, lists, renames and
//! retires them, and turns one agent on or off. Nothing in this module runs
//! an agent.
//!
//! Agent records are kept in their own file,
//! `ElastOS/System/Auth/agent-records.json`. The owner's sign-in file never
//! holds one.
//!
//! Known gap. Nothing yet detects an agent file that someone with write
//! access to the data folder replaces, rolls back or deletes. The feature is
//! off in every default build. A separate change adds that protection before
//! agents can be on by default.
//!
//! `model_tokens_spent` stays on the agent record. An older build of this fork
//! refuses that file by name (`NOT_OUR_FORM`). Home still loads, and agents
//! stay unavailable until a build that knows the field returns.
//!
//! The rules this module keeps:
//!
//! - `build_allows` is the only place the cargo feature is read. With the
//!   feature off, create, list, rename, retire, launch and stop refuse by
//!   name. A root-key change reads the agent file as plain JSON, with the
//!   same mode checks and a bounded read, and refuses when any unretired
//!   record names this owner. That decision opens no key. An unreadable
//!   file refuses with its own reason. That includes a schema other than
//!   this one, an entry without a record or an owner string, and a
//!   `retired_at` that is not absent, null, or an unsigned integer. A file
//!   that names only other owners,
//!   or only retired records of this owner, leaves this owner free to
//!   change the root key.
//! - A load takes no lock and writes nothing. A missing file means no agents.
//!   A file that fails any rule makes agents unavailable, with a named
//!   reason; it is never rewritten or deleted, and the owner's own sign-in
//!   file is read exactly as before.
//! - A write holds the agent lock and raises `sequence` by exactly one. It
//!   stores the file at mode 0600 with the confirmation clear, appends one
//!   audit event of that write, then stores the same sequence again with the
//!   confirmation set. The second store does not raise the sequence. A charge
//!   appends its signed spend event before the file, and names the spent
//!   total. A heal of the signed spend floor does not append: that total is
//!   already a signed spend event.
//! - A root-key change takes the writer before it loads the stored
//!   protection, decides under that writer, and holds it until the key is
//!   stored. An agent created in between waits, and then wraps under the
//!   key the store left. When the agents file is absent, the in-process
//!   mutex does not stop another process from creating the first agent, so
//!   the change also holds the file lock a create takes and removes that
//!   lock file afterwards while the agents file is still absent. After the
//!   lock is taken, the open file is still the one at that path. A missing
//!   or different file is opened and locked again, and a write that cannot
//!   settle on that file is refused by name.
//! - Every write is one of a closed list of operations, and each operation
//!   may change only what `permits` lists for it.
//! - This module never holds the owner's data key. It asks `auth` for a key
//!   derived from it and wraps the agent's own data key under that.

use std::cell::Cell;
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(all(test, unix))]
use std::sync::Condvar;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Context;
use elastos_runtime::auth::{
    validate_principal_root_protection, PrincipalRootCryptoProfileV1, PrincipalRootProtectionV1,
    PrincipalRootProtectorEnvelopeV1, PrincipalRootProtectorKind, PrincipalRootProtectorV1,
    ProofBinding, ProofBindingKind, RuntimeAuditEventV1, DEFAULT_PRINCIPAL_ROOT_CIPHER,
    PRINCIPAL_ROOT_PROTECTION_SCHEMA,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_admission::VerifiedAgentHost;
use crate::auth::{
    AgentHostPackage, PrincipalKind, PrincipalRecord, RuntimePrincipalRole,
    PRINCIPAL_RECORD_VERSION,
};
use crate::host_lock::FileLock;

#[cfg(all(test, unix))]
pub(crate) mod tests;

pub(crate) const AGENT_RECORDS_SCHEMA: &str = "elastos.agent.records/v1";
const AGENT_RECORDS_FILE: &str = "agent-records.json";

/// The refusal every operation gives in a build without the feature.
pub(crate) const FEATURE_OFF: &str = "agents are not built into this Runtime";
/// A root-key change in a build that cannot read the agent file it found.
pub(crate) const AGENTS_FILE_UNREADABLE: &str =
    "This Home has an agents file this build cannot read, so a root-key change is refused.";
/// The open lock file was not the file at the path when the lock was taken.
#[cfg(unix)]
pub(crate) const AGENTS_LOCK_CHANGED: &str =
    "The agents lock changed while this Home was taking it, so the write is refused.";
/// The most bytes a root-key change reads from the agent file.
pub(crate) const MAX_AGENT_FILE_BYTES: u64 = 256 * 1024;

/// How the agent's data key is wrapped: under a key derived with HKDF-SHA256.
const OWNER_ROOT_KDF: &str = "hkdf-sha256";
/// The derivation uses no salt: its input is already a uniformly random
/// 256-bit key. The envelope's salt field may not be empty, so it holds this
/// fixed word, and a file with any other value there is refused.
const OWNER_ROOT_ENVELOPE_SALT: &str = "unsalted";

const NOT_REGULAR: &str = "agent file path is not a regular file";
#[cfg(unix)]
const MODE_TOO_WIDE: &str = "agent file mode is wider than 0600";
pub(crate) const CANNOT_READ: &str = "agent file cannot be read";
pub(crate) const DOES_NOT_PARSE: &str = "agent file does not parse";
pub(crate) const CANNOT_WRITE: &str = "agent file cannot be written";
pub(crate) const SIGN_IN_CANNOT_READ: &str = "sign-in file cannot be read";
const LOCK_NOT_FREE: &str = "agent file lock is not free";
#[cfg(unix)]
pub(crate) const HEAL_LOCK_WAIT: Duration = Duration::from_millis(200);
/// Charge, spend, and standing checks wait this long for the agent file lock.
pub(crate) const CHARGE_LOCK_WAIT: Duration = Duration::from_secs(2);
pub(crate) const NO_OWNER: &str = "agent record names no owner";
const NOT_OUR_FORM: &str = "agent file holds a field or value this Runtime does not write";
const UNKNOWN_SCHEMA: &str = "agent file schema is unknown";
const BAD_SEQUENCE: &str = "agent file sequence is invalid";
const UNKNOWN_VERSION: &str = "agent record version is unknown";
const NOT_AN_AGENT: &str = "agent file holds a record that is not an agent";
const AGENT_IS_ADMIN: &str = "agent record carries a role an agent never has";
const REPEATED_ID: &str = "agent id is repeated";
const REPEATED_ROOT: &str = "agent root is repeated";
const HELD_BY_OWNER_FILE: &str =
    "agent id, root or binding is held by a record in the sign-in file";
const BAD_PROTECTION: &str = "agent storage protection is invalid";

/// Whether this build carries agents at all. The only place the cargo
/// feature is read.
pub(crate) fn build_allows() -> bool {
    cfg!(feature = "prototype-agents")
}

/// Whether the owner has allowed agents on this Home. A missing or unreadable
/// file is off. This reads the record; it does not start the agent Runtime.
pub(crate) fn home_enabled(data_dir: &Path) -> bool {
    open(data_dir, false)
        .map(|opened| opened.file.enabled.is_some())
        .unwrap_or(false)
}

fn build_allows_for_home(data_dir: &Path) -> bool {
    build_allows() || {
        #[cfg(all(test, unix))]
        {
            tests::dispatch_fixture_enabled(data_dir)
        }
        #[cfg(not(all(test, unix)))]
        {
            let _ = data_dir;
            false
        }
    }
}

/// A named refusal. The text is the whole reason, and nothing was written.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// A refusal the Home page can match by `code`. The sentence stays in `reason`.
#[derive(Debug)]
pub(crate) struct CodedRefusal {
    pub(crate) code: &'static str,
    pub(crate) reason: &'static str,
}

impl std::fmt::Display for CodedRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for CodedRefusal {}

fn refused<T>(reason: impl Into<String>) -> anyhow::Result<T> {
    Err(anyhow::Error::new(Refused(reason.into())))
}

#[derive(Debug)]
struct Named(&'static str);

impl std::fmt::Display for Named {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "agents are unavailable: {}", self.0)
    }
}

impl std::error::Error for Named {}

/// Text of a named refusal, for the 409 answer. A file the loader refuses is
/// included, so that answer stays 409.
pub(crate) fn refusal_text(error: &anyhow::Error) -> Option<String> {
    if error.downcast_ref::<Refused>().is_some() || error.downcast_ref::<Named>().is_some() {
        Some(error.to_string())
    } else {
        None
    }
}

/// The agent file. Field order here is the order written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AgentRecordsFile {
    schema: String,
    /// Rises by exactly one on every write. The first write stores 1.
    sequence: u64,
    /// Who turned agents on for this Home, and when. Null while they are off.
    enabled: Option<Enabled>,
    agents: Vec<StoredAgent>,
    /// The operation this sequence wrote, and whether its audit row landed.
    /// Absent on a file written before this field. A lost append repairs this
    /// operation once; it does not pick another agent.
    /// This field is one-way: an older build refuses a file that carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_audit: Option<LastAudit>,
}

/// The audit row a sequence promised. `confirmed` stays false until that row
/// is in the chain, including after the chain has dropped older rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LastAudit {
    pub(crate) sequence: u64,
    pub(crate) operation: String,
    pub(crate) subject: String,
    pub(crate) proof_binding_id: String,
    pub(crate) session_id: String,
    pub(crate) at: u64,
    pub(crate) confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Enabled {
    by: String,
    at: u64,
}

/// One agent: its record and the protection of its storage key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredAgent {
    pub(crate) record: PrincipalRecord,
    pub(crate) protection: PrincipalRootProtectionV1,
    // Absent means on: a record stored before this field still launches.
    #[serde(default = "active_when_absent", skip_serializing_if = "is_active")]
    pub(crate) active: bool,
    /// Model tokens already charged. Absent means zero, and zero is not written.
    /// An older build refuses a file that carries this field by name
    /// (`NOT_OUR_FORM`). Home still loads. Agents stay unavailable until a
    /// build that knows the field returns.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) model_tokens_spent: u64,
}

fn active_when_absent() -> bool {
    true
}
fn is_active(active: &bool) -> bool {
    *active
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl AgentRecordsFile {
    /// What a Home with no agent file starts from. Never written as it is:
    /// the first write raises the sequence to 1.
    fn unwritten() -> Self {
        Self {
            schema: AGENT_RECORDS_SCHEMA.to_string(),
            sequence: 0,
            enabled: None,
            agents: Vec::new(),
            last_audit: None,
        }
    }
}

pub(crate) fn agent_file_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
    Ok(crate::auth::auth_state_path(data_dir)?.with_file_name(AGENT_RECORDS_FILE))
}

/// What a load found.
#[derive(Debug)]
enum AgentFile {
    Missing,
    Loaded(AgentRecordsFile),
    Unavailable(&'static str),
}

/// Reads the agent file. Takes no lock and writes nothing. `owner_file` is
/// every record of the owner's sign-in file, as its own load returned it.
fn load(data_dir: &Path, owner_file: &[PrincipalRecord]) -> anyhow::Result<AgentFile> {
    let bytes = match read_agent_file(data_dir, &agent_file_path(data_dir)?) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(AgentFile::Missing),
        Err(reason) => return Ok(AgentFile::Unavailable(reason)),
    };
    Ok(
        match parse_strict(&bytes).and_then(|file| check(&file, owner_file).map(|()| file)) {
            Ok(file) => AgentFile::Loaded(file),
            Err(reason) => AgentFile::Unavailable(reason),
        },
    )
}

fn windows_agent_file_refused() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(all(test, unix))]
    {
        tests::windows_custody_is_planted()
    }
    #[cfg(not(any(windows, all(test, unix))))]
    {
        false
    }
}

/// The file's bytes, read through one handle, or `None` when there is no
/// file. Refuses a path that is not a regular file under regular
/// directories, and a file anyone but its owner can read or write.
fn read_agent_file(data_dir: &Path, path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    read_agent_file_capped(data_dir, path, None)
}

fn read_agent_file_capped(
    data_dir: &Path,
    path: &Path,
    cap: Option<u64>,
) -> Result<Option<Vec<u8>>, &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(NOT_REGULAR),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CANNOT_READ),
    }
    // A missing file is none. Windows refuses custody only once a file is there.
    if windows_agent_file_refused() {
        return Err(WINDOWS_AGENT_FILE);
    }
    // The file exists, so each parent exists: this only checks them.
    let parents_regular = path.parent().is_some_and(|parent| {
        crate::auth_state_files::ensure_regular_auth_parent(data_dir, parent).is_ok()
    });
    if !parents_regular {
        return Err(NOT_REGULAR);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| NOT_REGULAR)?;
    let metadata = file.metadata().map_err(|_| CANNOT_READ)?;
    if !metadata.is_file() {
        return Err(NOT_REGULAR);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 & !0o600 != 0 {
            return Err(MODE_TOO_WIDE);
        }
    }
    let mut bytes = Vec::new();
    if let Some(limit) = cap {
        (&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| CANNOT_READ)?;
        if bytes.len() as u64 > limit {
            return Err(CANNOT_READ);
        }
    } else {
        file.read_to_end(&mut bytes).map_err(|_| CANNOT_READ)?;
    }
    Ok(Some(bytes))
}

const WINDOWS_AGENT_FILE: &str = "agent file custody is unsupported on Windows";

/// Parses the file and refuses anything this Runtime would not have written:
/// the parsed file, written back, must hold the same fields and values as
/// the bytes read. That one comparison refuses an unknown field at any depth.
pub(crate) fn parse_strict(bytes: &[u8]) -> Result<AgentRecordsFile, &'static str> {
    let file: AgentRecordsFile = serde_json::from_slice(bytes).map_err(|_| DOES_NOT_PARSE)?;
    let found: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| DOES_NOT_PARSE)?;
    let written = serde_json::to_value(&file).map_err(|_| DOES_NOT_PARSE)?;
    if written != found {
        return Err(NOT_OUR_FORM);
    }
    Ok(file)
}

fn is_person(record: &PrincipalRecord) -> bool {
    record.kind == PrincipalKind::Human
        && record.proof_binding.kind != ProofBindingKind::AgentAdmission
}

/// The rules a whole file keeps. A load refuses a file that fails one, and a
/// write refuses to produce one.
fn check(file: &AgentRecordsFile, owner_file: &[PrincipalRecord]) -> Result<(), &'static str> {
    if file.schema != AGENT_RECORDS_SCHEMA {
        return Err(UNKNOWN_SCHEMA);
    }
    if file.sequence == 0 {
        return Err(BAD_SEQUENCE);
    }
    if let Some(reason) = repeated_id_or_root(&file.agents) {
        return Err(reason);
    }
    for agent in &file.agents {
        let record = &agent.record;
        if record.version != PRINCIPAL_RECORD_VERSION {
            return Err(UNKNOWN_VERSION);
        }
        if record.kind != PrincipalKind::Agent {
            return Err(NOT_AN_AGENT);
        }
        if record.role != RuntimePrincipalRole::Guest {
            return Err(AGENT_IS_ADMIN);
        }
        if held_in_owner_file(owner_file, record) {
            return Err(HELD_BY_OWNER_FILE);
        }
        if !protection_is_sound(agent) {
            return Err(BAD_PROTECTION);
        }
    }
    // The existing agent record rule, over the stored persons and the agents.
    let mut records: Vec<PrincipalRecord> = owner_file
        .iter()
        .filter(|record| is_person(record))
        .cloned()
        .collect();
    records.extend(file.agents.iter().map(|agent| agent.record.clone()));
    match crate::auth::agent_admission_state_violation(&records) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// Two agents with one id, or with one root. A root is derived from its id,
/// so the agent record rule also refuses a repeated root; this check names
/// it first.
fn repeated_id_or_root(agents: &[StoredAgent]) -> Option<&'static str> {
    for (index, agent) in agents.iter().enumerate() {
        let (record, earlier) = (&agent.record, &agents[..index]);
        if earlier
            .iter()
            .any(|other| other.record.principal_id == record.principal_id)
        {
            return Some(REPEATED_ID);
        }
        if earlier
            .iter()
            .any(|other| other.record.localhost_root == record.localhost_root)
        {
            return Some(REPEATED_ROOT);
        }
    }
    None
}

/// Whether any record of the owner's sign-in file holds this id, root or
/// binding id. Create never reuses one, whatever kind of record holds it.
fn held_in_owner_file(owner_file: &[PrincipalRecord], record: &PrincipalRecord) -> bool {
    owner_file.iter().any(|stored| {
        stored.principal_id == record.principal_id
            || stored.localhost_root == record.localhost_root
            || stored.proof_binding_id == record.proof_binding_id
    })
}

/// An agent's protection names the agent and its root, and has exactly one
/// protector: the agent's data key wrapped under its owner's root.
fn protection_is_sound(agent: &StoredAgent) -> bool {
    let (record, protection) = (&agent.record, &agent.protection);
    let [protector] = protection.protectors.as_slice() else {
        return false;
    };
    let Some(envelope) = protector.envelope.as_ref() else {
        return false;
    };
    validate_principal_root_protection(protection).is_ok()
        && protection.principal_id == record.principal_id
        && protection.localhost_root == record.localhost_root
        && protection.crypto.cipher == DEFAULT_PRINCIPAL_ROOT_CIPHER
        && protector.kind == PrincipalRootProtectorKind::OwnerRoot
        && record.owner.is_some()
        && protector.subject == record.owner
        && protector.archive.is_none()
        && protector.profile_coverage.is_none()
        && envelope.cipher == DEFAULT_PRINCIPAL_ROOT_CIPHER
        && envelope.kdf == OWNER_ROOT_KDF
        && envelope.salt == OWNER_ROOT_ENVELOPE_SALT
}

static AGENT_WRITE: Mutex<()> = Mutex::new(());

thread_local! {
    static AGENT_FILE_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
    static CHARGE_LOCK_WAITED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn agent_file_lock_held() -> bool {
    AGENT_FILE_LOCK_HELD.with(Cell::get)
}

struct AgentFileLockFlag {
    armed: bool,
}

impl AgentFileLockFlag {
    fn take() -> Self {
        AGENT_FILE_LOCK_HELD.with(|held| held.set(true));
        Self { armed: true }
    }

    #[cfg(not(unix))]
    fn idle() -> Self {
        Self { armed: false }
    }
}

impl Drop for AgentFileLockFlag {
    fn drop(&mut self) {
        if self.armed {
            AGENT_FILE_LOCK_HELD.with(|held| held.set(false));
        }
    }
}

/// The agent file lock is already held on this thread.
pub(crate) const LOCK_ORDER: &str = "agent file lock before the budget mutex";

/// The agent lock: one writer in this process, and on Unix one across
/// processes.
///
/// The in-process mutex is not enough when `agent-records.json` is absent.
/// Another process can create that file and the first agent while this
/// process holds only its own mutex, and a root-key change would then store
/// a different key over the new agent. A root-key change therefore takes the
/// same file lock a create takes. It removes that lock file on the way out
/// when the agents file is still absent, so a finished change leaves no new
/// file. After the lock is taken, the open file must still be the one at
/// that path: the same device and inode. A missing or different file is
/// opened and locked again. A bounded run of those tries ends in a named
/// refusal, so a waiter does not keep a file the other process removed.
/// When the wait itself is bounded, a removed file is opened again inside
/// that same bound. A crash while the lock is held can leave the lock file;
/// the next writer reuses it. A build without agents cannot create an agent
/// itself, and it takes this same file lock because another process built
/// with agents can create the first one. A platform without that file lock
/// holds only the in-process mutex, and a second process is not excluded
/// there. The flock wait finishes before this process's agent mutex. The
/// owner's sign-in lock is only taken inside this lock, and the budget mutex
/// is taken before this lock. The reverse is [`LOCK_ORDER`].
struct WriteLock {
    _file: Option<FileLock>,
    _process: MutexGuard<'static, ()>,
    _order: AgentFileLockFlag,
    /// Removed on drop when the agents file is still absent.
    temporary_lock: Option<PathBuf>,
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let Some(path) = self.temporary_lock.take() else {
            return;
        };
        let agents = path.with_file_name(AGENT_RECORDS_FILE);
        let absent = std::fs::symlink_metadata(&agents)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if absent {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn charge_lock_already_waited() -> bool {
    CHARGE_LOCK_WAITED.with(Cell::get)
}

/// After the outside lock wait, a later take on this thread retries briefly.
#[must_use]
pub(crate) struct ChargeLockWaited;

impl ChargeLockWaited {
    fn idle() -> Self {
        Self
    }

    #[cfg(unix)]
    fn arm() -> Self {
        CHARGE_LOCK_WAITED.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for ChargeLockWaited {
    fn drop(&mut self) {
        CHARGE_LOCK_WAITED.with(|flag| flag.set(false));
    }
}

/// Takes the agent lock for a writer of the agents file. The flock wait
/// finishes before this process's agent mutex.
fn lock_for_write(data_dir: &Path, wait: Option<Duration>) -> anyhow::Result<WriteLock> {
    #[cfg(not(unix))]
    {
        let _ = (data_dir, wait);
        return Err(Named(WINDOWS_AGENT_FILE).into());
    }
    #[cfg(unix)]
    {
        acquire_agent_lock_for(data_dir, true, wait)
    }
}

/// `create_when_absent` keeps the lock file when the agents file is missing,
/// which is what a writer of that file does. A root-key change passes false:
/// on Unix it still takes the file lock, then `WriteLock` removes that file
/// if the agents file is still absent. Create and import both check that the
/// locked file is still the one at the path.
fn acquire_agent_lock(data_dir: &Path, create_when_absent: bool) -> anyhow::Result<WriteLock> {
    acquire_agent_lock_for(data_dir, create_when_absent, None)
}

/// Opens the lock file. A path that cannot be opened is [`LOCK_NOT_FREE`],
/// before any wait.
fn open_agent_lock_file(path: &Path) -> anyhow::Result<std::fs::File> {
    match crate::auth_state_files::open_regular_lock_file(path, "agent records") {
        Ok(file) => Ok(file),
        Err(_) => Err(Named(LOCK_NOT_FREE).into()),
    }
}

/// How many times a writer opens and locks the agents file before refusing.
#[cfg(unix)]
const AGENT_LOCK_IDENTITY_TRIES: u32 = 8;

/// Locks `path` and keeps the lock only when that open file is still the
/// file at the path. A removed or replaced file is opened and locked again.
/// A bounded `wait` covers every try; a later try uses the time still left.
#[cfg(unix)]
fn lock_the_agents_file(path: &Path, wait: Option<Duration>) -> anyhow::Result<FileLock> {
    use std::os::unix::fs::MetadataExt;
    use std::time::Instant;
    let deadline = wait.map(|wait| Instant::now() + wait);
    for _ in 0..AGENT_LOCK_IDENTITY_TRIES {
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(Named(LOCK_NOT_FREE).into());
        }
        let file = open_agent_lock_file(path)?;
        #[cfg(test)]
        note_agent_lock_opened(&file);
        let held = file
            .metadata()
            .context("failed to inspect the agents lock")?;
        let lock = match deadline {
            Some(end) => {
                let remaining = end.saturating_duration_since(Instant::now());
                #[cfg(all(test, unix))]
                let started = Instant::now();
                let waited = FileLock::exclusive_within(file, remaining);
                #[cfg(all(test, unix))]
                tests::note_agent_lock_wait(started.elapsed());
                waited.map_err(|_| Named(LOCK_NOT_FREE))?
            }
            None => FileLock::exclusive(file).context("failed to lock agent records")?,
        };
        #[cfg(test)]
        displace_agent_lock_for_test(path);
        let same = std::fs::symlink_metadata(path).is_ok_and(|current| {
            current.is_file() && current.dev() == held.dev() && current.ino() == held.ino()
        });
        if same {
            return Ok(lock);
        }
        drop(lock);
    }
    refused(AGENTS_LOCK_CHANGED)
}

#[cfg(not(unix))]
fn lock_the_agents_file(path: &Path, wait: Option<Duration>) -> anyhow::Result<FileLock> {
    let file = open_agent_lock_file(path)?;
    match wait {
        Some(wait) => {
            FileLock::exclusive_within(file, wait).map_err(|_| Named(LOCK_NOT_FREE).into())
        }
        None => Ok(FileLock::exclusive(file).context("failed to lock agent records")?),
    }
}

fn agent_process_mutex() -> MutexGuard<'static, ()> {
    AGENT_WRITE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn acquire_agent_lock_for(
    data_dir: &Path,
    create_when_absent: bool,
    wait: Option<Duration>,
) -> anyhow::Result<WriteLock> {
    if agent_file_lock_held() {
        return Err(Named(LOCK_ORDER).into());
    }
    let records = agent_file_path(data_dir)?;
    let absent = std::fs::symlink_metadata(&records)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    #[cfg(not(unix))]
    if absent && !create_when_absent {
        return Ok(WriteLock {
            _file: None,
            _process: agent_process_mutex(),
            _order: AgentFileLockFlag::idle(),
            temporary_lock: None,
        });
    }
    let path = records.with_file_name(format!("{AGENT_RECORDS_FILE}.lock"));
    if let Some(parent) = path.parent() {
        crate::auth_state_files::ensure_regular_auth_parent(data_dir, parent)?;
    }
    // The 2s wait ran outside the mutex. Retry briefly so another caller can leave the lock.
    let wait = match (charge_lock_already_waited(), wait) {
        (true, Some(_)) => Some(Duration::from_millis(500)),
        (_, kept) => kept,
    };
    let file = lock_the_agents_file(&path, wait)?;
    let temporary_lock = if absent && !create_when_absent {
        Some(path)
    } else {
        None
    };
    Ok(WriteLock {
        _file: Some(file),
        _process: agent_process_mutex(),
        _order: AgentFileLockFlag::take(),
        temporary_lock,
    })
}

#[cfg(all(test, unix))]
thread_local! {
    static AGENT_LOCK_OPENED_TRACE: std::cell::Cell<Option<fn(&std::fs::File)>> =
        const { std::cell::Cell::new(None) };
    static DISPLACE_AGENT_LOCK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, unix))]
fn note_agent_lock_opened(file: &std::fs::File) {
    AGENT_LOCK_OPENED_TRACE.with(|hook| {
        if let Some(hook) = hook.get() {
            hook(file);
        }
    });
}

/// The next opens of the agents lock call `hook` before they wait.
#[cfg(all(test, unix))]
pub(crate) fn set_agent_lock_opened_trace(hook: Option<fn(&std::fs::File)>) {
    AGENT_LOCK_OPENED_TRACE.with(|slot| slot.set(hook));
}

/// The next `count` locks remove the path after the lock is taken, so the
/// identity check has to open it again.
#[cfg(all(test, unix))]
pub(crate) fn displace_agent_lock_on_the_next_tries(count: u32) {
    DISPLACE_AGENT_LOCK.with(|left| left.set(count));
}

#[cfg(all(test, unix))]
fn displace_agent_lock_for_test(path: &Path) {
    DISPLACE_AGENT_LOCK.with(|left| {
        let count = left.get();
        if count == 0 {
            return;
        }
        left.set(count - 1);
        let _ = std::fs::remove_file(path);
    });
}

#[cfg(all(test, unix))]
fn agent_lock_identity(lock: &WriteLock) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let metadata = lock
        ._file
        .as_ref()
        .expect("the agents lock holds a file")
        .metadata()
        .expect("the agents lock can be inspected");
    (metadata.dev(), metadata.ino())
}
/// Every change to the agent file is one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Enable,
    Disable,
    Create,
    Rename,
    Retire,
    SetActive,
    Charge,
    /// Raise stored spend to the signed floor. Appends no audit event.
    Heal,
}

impl Operation {
    fn event_type(self) -> &'static str {
        match self {
            Self::Enable => "agent.records.enable",
            Self::Disable => "agent.records.disable",
            Self::Create => "agent.record.create",
            Self::Rename => "agent.record.rename",
            Self::Retire => "agent.record.retire",
            Self::SetActive => "agent.record.active",
            Self::Charge => "agent.record.spend",
            Self::Heal => "agent.record.heal",
        }
    }
}

/// What each operation may change. Every write raises the sequence by
/// exactly one and keeps the schema. Beyond that:
///
/// - enable: `enabled`, from off to on;
/// - disable: `enabled`, from on to off;
/// - create: one agent added at the end, not retired;
/// - rename: one agent's `display_name`, and its `updated_at`;
/// - retire: one agent's `retired_at`, set once, and its `updated_at`;
/// - set active: one agent's `active`, and its `updated_at`;
/// - charge: one active agent's `model_tokens_spent`, raised by one block;
/// - heal: any non-retired agent's `model_tokens_spent`, raised, nothing else.
fn permits(operation: Operation, before: &AgentRecordsFile, after: &AgentRecordsFile) -> bool {
    if after.schema != before.schema || before.sequence.checked_add(1) != Some(after.sequence) {
        return false;
    }
    let same_agents = after.agents == before.agents;
    let same_enabled = after.enabled == before.enabled;
    match operation {
        Operation::Enable => same_agents && before.enabled.is_none() && after.enabled.is_some(),
        Operation::Disable => same_agents && before.enabled.is_some() && after.enabled.is_none(),
        Operation::Create => {
            same_enabled
                && after.agents.split_last().is_some_and(|(added, kept)| {
                    kept == before.agents.as_slice() && added.record.retired_at.is_none()
                })
        }
        Operation::Rename => one_agent(before, after, same_enabled, renames),
        Operation::Retire => one_agent(before, after, same_enabled, retires),
        Operation::SetActive => one_agent(before, after, same_enabled, sets_active),
        Operation::Charge => one_agent(before, after, same_enabled, spends),
        Operation::Heal => {
            same_enabled
                && after.agents.len() == before.agents.len()
                && before
                    .agents
                    .iter()
                    .zip(&after.agents)
                    .all(|(old, new)| spend_floor_keeps(old, new))
                && before.agents.iter().zip(&after.agents).any(|(old, new)| {
                    old.record.retired_at.is_none()
                        && new.model_tokens_spent > old.model_tokens_spent
                })
        }
    }
}

/// A non-retired agent may keep a higher `model_tokens_spent`. A retired
/// agent stays as it was. Nothing else moves.
fn spend_floor_keeps(old: &StoredAgent, new: &StoredAgent) -> bool {
    if old.record.retired_at.is_some() {
        return old == new;
    }
    let mut expected = old.clone();
    expected.model_tokens_spent = new.model_tokens_spent;
    expected == *new && new.model_tokens_spent >= old.model_tokens_spent
}

fn one_agent(
    before: &AgentRecordsFile,
    after: &AgentRecordsFile,
    same_enabled: bool,
    allows: fn(&StoredAgent, &StoredAgent) -> bool,
) -> bool {
    let changed: Vec<_> = before
        .agents
        .iter()
        .zip(&after.agents)
        .filter(|(old, new)| old != new)
        .collect();
    same_enabled
        && after.agents.len() == before.agents.len()
        && matches!(changed.as_slice(), [(old, new)] if allows(old, new))
}

/// `new` is `old` with a different `display_name` and `updated_at` moved,
/// and nothing else changed.
fn renames(old: &StoredAgent, new: &StoredAgent) -> bool {
    let mut expected = old.clone();
    expected.record.display_name = new.record.display_name.clone();
    expected.record.updated_at = new.record.updated_at;
    old.record.retired_at.is_none()
        && old.record.display_name != new.record.display_name
        && expected == *new
}

/// `new` is `old` with `retired_at` set for the first time and `updated_at`
/// moved, and nothing else changed.
fn retires(old: &StoredAgent, new: &StoredAgent) -> bool {
    let mut expected = old.clone();
    expected.record.retired_at = new.record.retired_at;
    expected.record.updated_at = new.record.updated_at;
    old.record.retired_at.is_none() && new.record.retired_at.is_some() && expected == *new
}

fn spends(old: &StoredAgent, new: &StoredAgent) -> bool {
    let mut expected = old.clone();
    expected.model_tokens_spent = new.model_tokens_spent;
    old.active
        && old.record.retired_at.is_none()
        && new.model_tokens_spent > old.model_tokens_spent
        && expected == *new
}

fn sets_active(old: &StoredAgent, new: &StoredAgent) -> bool {
    let mut expected = old.clone();
    expected.active = new.active;
    expected.record.updated_at = new.record.updated_at;
    old.active != new.active && expected == *new
}

/// Who asked for a write: a stored person, on their proof-bound session.
pub(crate) struct Caller<'a> {
    pub(crate) principal_id: &'a str,
    pub(crate) proof_binding_id: &'a str,
    pub(crate) session_id: &'a str,
}

/// The Home's records as one operation sees them.
struct Opened {
    /// Held for a write. `None` for a read.
    lock: Option<WriteLock>,
    /// Every record of the owner's sign-in file.
    owner_file: Vec<PrincipalRecord>,
    /// The agent file, or the unwritten start when there is none.
    file: AgentRecordsFile,
}

/// Loads both files, under the agent lock when the operation will write.
/// Refuses when the agent file fails a rule.
/// Test seam: the next write of this Home stores the bytes and returns before
/// the audit row. The following open under the agent lock appends that row.
fn open(data_dir: &Path, for_write: bool) -> anyhow::Result<Opened> {
    open_for(data_dir, for_write, None)
}

fn open_for(data_dir: &Path, for_write: bool, wait: Option<Duration>) -> anyhow::Result<Opened> {
    let lock = match for_write {
        true => Some(lock_for_write(data_dir, wait)?),
        false => None,
    };
    // The sign-in loader hands agents through too. The sign-in file itself
    // holds none, and every rule below compares this file with the records
    // that file holds, so agent records are left out here.
    let owner_file: Vec<PrincipalRecord> = crate::auth::load_owner_principals(data_dir)
        .map_err(|_| Named(SIGN_IN_CANNOT_READ))?
        .into_iter()
        .filter(|record| {
            record.kind != PrincipalKind::Agent
                && record.proof_binding.kind != ProofBindingKind::AgentAdmission
        })
        .collect();
    let mut file = match load(data_dir, &owner_file)? {
        AgentFile::Missing => AgentRecordsFile::unwritten(),
        AgentFile::Loaded(file) => file,
        AgentFile::Unavailable(reason) => return Err(Named(reason).into()),
    };
    if for_write {
        if let Some(pending) = file.last_audit.clone().filter(|audit| {
            !audit.confirmed && audit.sequence == file.sequence && audit.sequence != 0
        }) {
            let held = owner_file
                .iter()
                .any(|record| record.proof_binding_id == pending.proof_binding_id);
            if !held {
                anyhow::bail!("retired agent's owner is not in the sign-in file");
            }
            let bytes = std::fs::read(agent_file_path(data_dir)?)?;
            crate::agent_record_audit::repair_recorded_audit(data_dir, &pending, &bytes)?;
            if let Some(audit) = file.last_audit.as_mut() {
                audit.confirmed = true;
            }
            let updated = serde_json::to_vec_pretty(&file)?;
            crate::auth::atomic_write(&agent_file_path(data_dir)?, &updated)?;
        }
    }
    Ok(Opened {
        lock,
        owner_file,
        file,
    })
}

#[derive(Debug)]
pub(crate) enum SpendRefusal {
    /// `asked`, the drawn total excluding it, the charged block, the ceiling.
    Over(u64, u64, u64, u64),
    Name(&'static str),
    /// The hosted owner approval was not current. The file was not written.
    HostedRun,
}

fn reason_of(err: &anyhow::Error) -> &'static str {
    if let Some(named) = err.downcast_ref::<Named>() {
        return named.0;
    }
    #[cfg(unix)]
    if err
        .downcast_ref::<Refused>()
        .is_some_and(|refused| refused.0 == AGENTS_LOCK_CHANGED)
    {
        return AGENTS_LOCK_CHANGED;
    }
    CANNOT_READ
}

fn agent_of<'a>(
    file: &'a AgentRecordsFile,
    id: &str,
    owner: Option<&str>,
) -> Result<&'a StoredAgent, &'static str> {
    file.enabled.as_ref().ok_or(NOT_ENABLED)?;
    let same_id = |agent: &&StoredAgent| agent.record.principal_id == id;
    let agent = file.agents.iter().find(same_id).ok_or(NO_SUCH_AGENT)?;
    let same_owner = |o: &str| agent.record.owner.as_deref() == Some(o);
    let owned = owner.is_none_or(same_owner);
    owned.then_some(()).ok_or(NO_SUCH_AGENT)?;
    let live = agent.record.retired_at.is_none();
    live.then_some(()).ok_or(ALREADY_RETIRED)?;
    agent.active.then_some(()).ok_or(NOT_ACTIVE)?;
    let named = agent.record.owner.as_deref().filter(|id| !id.is_empty());
    named.ok_or(NO_OWNER)?;
    Ok(agent)
}

/// Takes the agent file lock for at most [`CHARGE_LOCK_WAIT`] and releases it.
/// This does not take the process mutex, so the wait cannot pin the file lock
/// while another caller holds that mutex. The budget mutex is still free.
pub(crate) fn wait_agent_file_lock(data_dir: &Path) -> Result<ChargeLockWaited, &'static str> {
    if !build_allows_for_home(data_dir) {
        return Ok(ChargeLockWaited::idle());
    }
    #[cfg(not(unix))]
    {
        return Err(WINDOWS_AGENT_FILE);
    }
    #[cfg(unix)]
    {
        let records = agent_file_path(data_dir).map_err(|err| reason_of(&err))?;
        let path = records.with_file_name(format!("{AGENT_RECORDS_FILE}.lock"));
        if let Some(parent) = path.parent() {
            crate::auth_state_files::ensure_regular_auth_parent(data_dir, parent)
                .map_err(|err| reason_of(&err))?;
        }
        let lock =
            lock_the_agents_file(&path, Some(CHARGE_LOCK_WAIT)).map_err(|err| reason_of(&err))?;
        release_probe_lock(&records, &path, lock);
        Ok(ChargeLockWaited::arm())
    }
}

/// A probe that settles on a Home with no agents file removes that lock file
/// before it releases the lock.
#[cfg(unix)]
fn release_probe_lock(records: &Path, lock_path: &Path, lock: FileLock) {
    let absent = std::fs::symlink_metadata(records)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    if absent {
        let _ = std::fs::remove_file(lock_path);
    }
    drop(lock);
}

pub(crate) fn model_spend(data_dir: &Path, agent_id: &str) -> Result<(String, u64), &'static str> {
    if !build_allows_for_home(data_dir) {
        return Err(FEATURE_OFF);
    }
    let opened = open_for(data_dir, true, Some(CHARGE_LOCK_WAIT)).map_err(|err| reason_of(&err))?;
    let agent = agent_of(&opened.file, agent_id, None)?;
    let owner = agent.record.owner.clone().ok_or(NO_OWNER)?;
    let floor =
        crate::model_budget::signed_spend_floor(data_dir, agent_id, agent.model_tokens_spent)?;
    Ok((owner, agent.model_tokens_spent.max(floor)))
}

fn hosted_owner_still_approved(data_dir: &Path, agent_id: &str, offer_id: Option<&str>) -> bool {
    match offer_id {
        Some(offer_id) => {
            crate::api::gateway::hosted_charge_still_approved(data_dir, agent_id, offer_id)
        }
        None => true,
    }
}

/// The agent is still active for this owner, and a hosted offer is still approved.
/// The agent lock is held for both reads.
pub(crate) fn hosted_charge_still_standing(
    data_dir: &Path,
    owner: &str,
    agent_id: &str,
    offer_id: &str,
) -> Result<(), SpendRefusal> {
    let opened = open_for(data_dir, true, Some(CHARGE_LOCK_WAIT))
        .map_err(|err| SpendRefusal::Name(reason_of(&err)))?;
    agent_of(&opened.file, agent_id, Some(owner)).map_err(SpendRefusal::Name)?;
    if !hosted_owner_still_approved(data_dir, agent_id, Some(offer_id)) {
        return Err(SpendRefusal::HostedRun);
    }
    Ok(())
}

/// Writes every non-retired agent's stored total up to its signed spend
/// floor. The caller already holds the host lock, or this is a charge, or
/// turning an agent off or on. See [`crate::host_lock::start_host_for_agents`].
/// An unreadable agents file, including a damaged file, a newer file, and
/// Windows, is left as it is and this returns `Ok`. A full disk, a read-only
/// folder, an unreadable sign-in file, a lock that is not free, or a failed
/// raised copy returns that cause. The managed runtime returns `Ok` and
/// writes nothing.
pub fn raise_spend_file_to_signed_floor(data_dir: &Path) -> Result<(), &'static str> {
    if !build_allows_for_home(data_dir) || crate::host_lock::is_subordinate_managed_runtime() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let audit = crate::model_budget::load_spend_audit(data_dir)?;
        let preview = match open(data_dir, false) {
            Ok(opened) => opened,
            Err(err) => return quiet_when_agents_are_unavailable(err),
        };
        if raised_copy(data_dir, &audit, &preview.file)?.is_none() {
            return Ok(());
        }
        let opened = match open_for(data_dir, true, Some(HEAL_LOCK_WAIT)) {
            Ok(opened) => opened,
            Err(err) => return quiet_when_agents_are_unavailable(err),
        };
        let Some(after) = raised_copy(data_dir, &audit, &opened.file)? else {
            return Ok(());
        };
        let caller = Caller {
            principal_id: "",
            proof_binding_id: "",
            session_id: "",
        };
        write(data_dir, &opened, Operation::Heal, &after, &caller, "", 0).map_err(|_| CANNOT_WRITE)
    }
}

#[cfg(unix)]
fn quiet_when_agents_are_unavailable(err: anyhow::Error) -> Result<(), &'static str> {
    let named = err.downcast_ref::<Named>().map(|named| named.0);
    match named {
        Some(LOCK_ORDER) => Err(LOCK_ORDER),
        Some(LOCK_NOT_FREE) => Err(LOCK_NOT_FREE),
        Some(SIGN_IN_CANNOT_READ) => Err(SIGN_IN_CANNOT_READ),
        Some(_) => Ok(()),
        None => Err(reason_of(&err)),
    }
}

/// One file with every non-retired total raised to its signed floor.
/// Retired agents stay as they were. `None` when nothing is behind.
#[cfg(unix)]
fn raised_copy(
    data_dir: &Path,
    audit: &crate::model_budget::SpendAudit,
    file: &AgentRecordsFile,
) -> Result<Option<AgentRecordsFile>, &'static str> {
    let mut after = file.clone();
    let mut raised = false;
    for agent in &mut after.agents {
        if agent.record.retired_at.is_some() {
            continue;
        }
        let floor = audit.floor(
            data_dir,
            &agent.record.principal_id,
            agent.model_tokens_spent,
        );
        if floor > agent.model_tokens_spent {
            agent.model_tokens_spent = floor;
            raised = true;
        }
    }
    if !raised {
        return Ok(None);
    }
    after.sequence = after.sequence.checked_add(1).ok_or(BAD_SEQUENCE)?;
    Ok(Some(after))
}

pub(crate) fn charge_model_spend(
    data_dir: &Path,
    owner: &str,
    agent_id: &str,
    memory: (u64, u64),
    add: u64,
    ceiling: u64,
    offer_id: Option<&str>,
) -> Result<(u64, u64), SpendRefusal> {
    if !build_allows_for_home(data_dir) {
        return Err(SpendRefusal::Name(FEATURE_OFF));
    }
    raise_spend_file_to_signed_floor(data_dir).map_err(SpendRefusal::Name)?;
    let opened = open_for(data_dir, true, Some(CHARGE_LOCK_WAIT))
        .map_err(|err| SpendRefusal::Name(reason_of(&err)))?;
    let agent = agent_of(&opened.file, agent_id, Some(owner)).map_err(SpendRefusal::Name)?;
    let floor =
        crate::model_budget::signed_spend_floor(data_dir, agent_id, agent.model_tokens_spent)
            .map_err(SpendRefusal::Name)?;
    let stored = agent.model_tokens_spent.max(floor);
    let is_owner = |record: &&PrincipalRecord| record.principal_id == owner;
    let person = opened.owner_file.iter().find(is_owner);
    let person = person.ok_or(SpendRefusal::Name(NOT_A_PERSON))?;
    let decided = crate::model_budget::block_charge(memory, stored, add, ceiling);
    let err = |held, charged| SpendRefusal::Over(add, held, charged, ceiling);
    let (next, charged, raised) = decided.map_err(|(held, charged)| err(held, charged))?;
    // The agent lock is held. A hosted offer is read again here, before the
    // file write and before this charge returns to the send.
    if !hosted_owner_still_approved(data_dir, agent_id, offer_id) {
        return Err(SpendRefusal::HostedRun);
    }
    let Some(total) = raised else {
        return Ok((next, charged));
    };
    let mut after = opened.file.clone();
    let seq = after.sequence.checked_add(1);
    after.sequence = seq.ok_or(SpendRefusal::Name(BAD_SEQUENCE))?;
    let same = |agent: &&mut StoredAgent| agent.record.principal_id == agent_id;
    let slot = after.agents.iter_mut().find(same);
    let slot = slot.ok_or(SpendRefusal::Name(NO_SUCH_AGENT))?;
    slot.model_tokens_spent = total;
    let proof = &person.proof_binding_id;
    let caller = Caller {
        principal_id: owner,
        proof_binding_id: proof,
        session_id: "",
    };
    let now = crate::auth::now_ts();
    let saved = write(
        data_dir,
        &opened,
        Operation::Charge,
        &after,
        &caller,
        agent_id,
        now,
    );
    saved.map_err(|_| SpendRefusal::Name(CANNOT_WRITE))?;
    Ok((next, charged))
}

/// Writes `after` over the opened file. `subject` is the agent the event is
/// about, or the owner for enable and disable.
fn write(
    data_dir: &Path,
    opened: &Opened,
    operation: Operation,
    after: &AgentRecordsFile,
    caller: &Caller<'_>,
    subject: &str,
    now: u64,
) -> anyhow::Result<()> {
    if opened.lock.is_none() {
        anyhow::bail!("agent file write needs the agent lock");
    }
    if !permits(operation, &opened.file, after) {
        anyhow::bail!("agent file change is not one {operation:?} permits");
    }
    if let Err(reason) = check(after, &opened.owner_file) {
        anyhow::bail!("agent file change refused: {reason}");
    }
    if operation == Operation::Heal {
        #[cfg(all(test, unix))]
        if tests::spend_file_write_fails() {
            return Err(Named(CANNOT_WRITE).into());
        }
        let bytes = serde_json::to_vec_pretty(after)?;
        crate::auth::atomic_write(&agent_file_path(data_dir)?, &bytes)?;
        return Ok(());
    }
    if operation == Operation::Charge {
        let bytes = serde_json::to_vec_pretty(after)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let total = after
            .agents
            .iter()
            .find(|agent| agent.record.principal_id == subject)
            .map(|agent| agent.model_tokens_spent)
            .unwrap_or(0);
        let event = RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:agent-records:{}:{}", after.sequence, &digest[..16]),
            event_type: operation.event_type().to_string(),
            principal_id: Some(subject.to_string()),
            proof_binding_id: None,
            session_id: None,
            challenge_id: None,
            capsule_id: None,
            result: "ok".to_string(),
            reason: format!(
                "owner={} seq={} spent={total} sha256={digest}",
                caller.principal_id, after.sequence
            ),
            occurred_at: now,
            signer_did: None,
            signature: None,
        };
        #[cfg(all(test, unix))]
        if tests::spend_append_fails() {
            anyhow::bail!("spend event was not appended");
        }
        crate::auth::append_audit_event(data_dir, event)?;
        #[cfg(all(test, unix))]
        if tests::spend_file_write_fails() {
            return Err(Named(CANNOT_WRITE).into());
        }
        #[cfg(all(test, unix))]
        if tests::spend_stops_before_file() {
            return Ok(());
        }
        crate::auth::atomic_write(&agent_file_path(data_dir)?, &bytes)?;
        return Ok(());
    }
    let mut recorded = after.clone();
    recorded.last_audit = Some(LastAudit {
        sequence: after.sequence,
        operation: operation.event_type().to_string(),
        subject: subject.to_string(),
        proof_binding_id: caller.proof_binding_id.to_string(),
        session_id: caller.session_id.to_string(),
        at: now,
        confirmed: false,
    });
    let bytes = serde_json::to_vec_pretty(&recorded)?;
    crate::auth::atomic_write(&agent_file_path(data_dir)?, &bytes)?;
    #[cfg(test)]
    if crate::api::gateway::seams::take_record_audit(data_dir) {
        anyhow::bail!("injected agent record audit failure");
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:agent-records:{}:{}", after.sequence, &digest[..16]),
            event_type: operation.event_type().to_string(),
            principal_id: Some(subject.to_string()),
            proof_binding_id: Some(caller.proof_binding_id.to_string()),
            session_id: Some(caller.session_id.to_string()),
            challenge_id: None,
            capsule_id: None,
            result: "ok".to_string(),
            reason: format!("seq={} sha256={digest}", after.sequence),
            occurred_at: now,
            signer_did: None,
            signature: None,
        },
    )?;
    if let Some(audit) = recorded.last_audit.as_mut() {
        audit.confirmed = true;
    }
    // Same sequence as the audited write. The hash in the row is the first file.
    let confirmed = serde_json::to_vec_pretty(&recorded)?;
    crate::auth::atomic_write(&agent_file_path(data_dir)?, &confirmed)?;
    Ok(())
}

/// An agent that is off, retired, or on a Home with agents off cannot ask,
/// be granted, or use its storage. A principal that is not an agent is left
/// alone, so a person's capsule is unchanged. A data directory with no agent
/// file is that case: opening it would refuse the ask when the Home's sign-in
/// file is absent, and a person's capsule would change.
pub(crate) fn refuse_inactive_agent(data_dir: &Path, principal_id: &str) -> anyhow::Result<()> {
    if principal_id.is_empty()
        || !build_allows_for_home(data_dir)
        || crate::auth::validate_agent_id(principal_id).is_err()
    {
        return Ok(());
    }
    let path = match agent_file_path(data_dir) {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };
    match read_agent_file(data_dir, &path) {
        Ok(None) => return Ok(()),
        Ok(Some(_)) => {}
        Err(reason) => return refused(format!("agents are unavailable: {reason}")),
    }
    let opened = open(data_dir, false)?;
    let Some(agent) = opened
        .file
        .agents
        .iter()
        .find(|agent| agent.record.principal_id == principal_id)
    else {
        return Ok(());
    };
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    if agent.record.retired_at.is_some() {
        return refused(ALREADY_RETIRED);
    }
    if !agent.active {
        return refused(NOT_ACTIVE);
    }
    Ok(())
}

/// Wraps an agent's data key under the key `auth` derived for it. The nonce
/// is fresh and random each time, so two wraps of one key never match.
fn wrap_data_key(
    wrap_key: &[u8; 32],
    data_key: &[u8; 32],
) -> anyhow::Result<PrincipalRootProtectorEnvelopeV1> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    Ok(PrincipalRootProtectorEnvelopeV1 {
        cipher: DEFAULT_PRINCIPAL_ROOT_CIPHER.to_string(),
        kdf: OWNER_ROOT_KDF.to_string(),
        salt: OWNER_ROOT_ENVELOPE_SALT.to_string(),
        nonce: crate::auth::b64_url(&nonce),
        wrapped_data_key: crate::auth::encrypt_aes256_gcm_bytes(wrap_key, &nonce, data_key)?,
    })
}

/// A new data key for an agent's root, wrapped under its owner's root. The
/// key itself is erased when this returns; only the wrap is kept. This
/// module never sees the owner's protection: `auth` loads it and hands back
/// only the derived wrap key. `None`: the owner has no storage protection.
fn protect_agent_root(
    data_dir: &Path,
    owner: &PrincipalRecord,
    agent_id: &str,
    localhost_root: &str,
    now: u64,
) -> anyhow::Result<Option<PrincipalRootProtectionV1>> {
    let mut data_key = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(data_key.as_mut_slice());
    let mut protection = PrincipalRootProtectionV1 {
        schema: PRINCIPAL_ROOT_PROTECTION_SCHEMA.to_string(),
        principal_id: agent_id.to_string(),
        localhost_root: localhost_root.to_string(),
        data_key_id: crate::auth::principal_data_key_id(data_key.as_slice()),
        crypto: PrincipalRootCryptoProfileV1 {
            recovery_kdf: OWNER_ROOT_KDF.to_string(),
            ..PrincipalRootCryptoProfileV1::default()
        },
        protectors: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    let Some(wrap_key) = crate::auth::owner_root_wrap_key(
        data_dir,
        &owner.principal_id,
        &owner.localhost_root,
        &protection,
    )?
    else {
        return Ok(None);
    };
    protection.protectors.push(PrincipalRootProtectorV1 {
        protector_id: format!(
            "protector:owner-root:{}",
            agent_id.trim_start_matches("agent:v2:")
        ),
        kind: PrincipalRootProtectorKind::OwnerRoot,
        label: "Owner root".to_string(),
        subject: Some(owner.principal_id.clone()),
        created_at: now,
        verified_at: None,
        envelope: Some(wrap_data_key(&wrap_key, &data_key)?),
        archive: None,
        profile_coverage: None,
    });
    Ok(Some(protection))
}

/// The refusal for create, list, rename and retire while agents are off for a Home.
pub(crate) const NOT_ENABLED: &str = "agents are not turned on for this Home";
/// The refusal for a caller who is not a stored person on a proved binding.
pub(crate) const NOT_A_PERSON: &str = "only a stored person may use agents";
/// The refusal for a person who may not turn agents on or off.
pub(crate) const NOT_AN_ADMIN: &str = "only an admin of this Home turns agents on or off";
/// The refusal when the agent's owner is a Guest, or their last passkey is revoked.
pub(crate) const OWNER_NOT_ADMIN: &str = "the agent's owner is not an admin";

/// Refuses by name in a build without the feature. Every operation below
/// starts here.
pub(crate) fn require_build() -> anyhow::Result<()> {
    match build_allows() {
        true => Ok(()),
        false => refused(FEATURE_OFF),
    }
}

/// The caller's stored record: a person, never an agent, on the proof
/// binding their session proved.
fn caller_person<'a>(
    owner_file: &'a [PrincipalRecord],
    caller: &Caller<'_>,
) -> anyhow::Result<&'a PrincipalRecord> {
    let person = owner_file.iter().find(|record| {
        record.principal_id == caller.principal_id
            && record.proof_binding_id == caller.proof_binding_id
            && is_person(record)
    });
    match person {
        Some(person) => Ok(person),
        None => refused(NOT_A_PERSON),
    }
}

/// Turns agents on or off for this Home. Returns the state it leaves.
/// Turning them off keeps every record; create, list, rename and retire then refuse.
pub(crate) fn set_enabled(
    data_dir: &Path,
    caller: &Caller<'_>,
    enabled: bool,
    now: u64,
) -> anyhow::Result<bool> {
    require_build()?;
    set_enabled_in_any_build(data_dir, caller, enabled, now)
}

fn set_enabled_in_any_build(
    data_dir: &Path,
    caller: &Caller<'_>,
    enabled: bool,
    now: u64,
) -> anyhow::Result<bool> {
    let opened = open(data_dir, true)?;
    if !crate::auth::is_admin(caller_person(&opened.owner_file, caller)?) {
        return refused(NOT_AN_ADMIN);
    }
    if opened.file.enabled.is_some() == enabled {
        return Ok(enabled);
    }
    let mut after = opened.file.clone();
    after.sequence += 1;
    after.enabled = enabled.then(|| Enabled {
        by: caller.principal_id.to_string(),
        at: now,
    });
    let operation = match enabled {
        true => Operation::Enable,
        false => Operation::Disable,
    };
    let subject = caller.principal_id;
    write(data_dir, &opened, operation, &after, caller, subject, now)?;
    Ok(enabled)
}

/// The most agents one owner may have that are not retired.
pub(crate) const MAX_LIVE_AGENTS_PER_OWNER: usize = 8;

const BAD_REQUEST: &str = "agent request is invalid: a field is empty, too long or malformed";
const REQUEST_ID_REUSED: &str = "request id was already used for a different agent";
const AT_THE_LIMIT: &str = "owner already has the most agents a Home allows";
const OWNER_UNPROTECTED: &str = "owner has no current storage protection";
const ID_HELD: &str = "agent id or root is already held";

/// The whole create request. An unknown or missing field is refused. The
/// owner of the new agent is always the caller; no field can name another.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateRequest {
    pub(crate) display_name: String,
    pub(crate) agent_host: String,
    pub(crate) request_id: String,
}

/// What an owner is shown of one of their agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AgentView {
    pub(crate) agent_id: String,
    pub(crate) display_name: String,
    pub(crate) agent_host: Option<AgentHostPackage>,
    pub(crate) created_at: u64,
    pub(crate) retired_at: Option<u64>,
    // Read-only. The activate route is what changes it.
    pub(crate) active: bool,
}

fn view(agent: &StoredAgent) -> AgentView {
    AgentView {
        agent_id: agent.record.principal_id.clone(),
        display_name: agent.record.display_name.clone(),
        agent_host: agent.record.agent_host_package.clone(),
        created_at: agent.record.created_at,
        retired_at: agent.record.retired_at,
        active: agent.active,
    }
}

fn owned_by(agent: &StoredAgent, owner: &PrincipalRecord) -> bool {
    agent.record.owner.as_deref() == Some(owner.principal_id.as_str())
}

/// A name of 1 to 128 letters, digits, `-`, `_`, `.` or `:`.
fn is_token(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

/// One line of 1 to 64 bytes with no control character and no outer space.
fn is_display_name(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text == text.trim() && !text.chars().any(char::is_control)
}

/// Whether any record, in either file, holds this id or root. A retired
/// agent still holds both, so neither is ever used again.
fn id_or_root_held(opened: &Opened, record: &PrincipalRecord) -> bool {
    held_in_owner_file(&opened.owner_file, record)
        || opened.file.agents.iter().any(|agent| {
            agent.record.principal_id == record.principal_id
                || agent.record.localhost_root == record.localhost_root
        })
}

/// Creates an agent owned by the caller. `admit` checks the named Agent Host
/// and is asked only once every other refusal has passed. The same owner,
/// `request_id` and body returns the same agent and writes nothing.
pub(crate) fn create(
    data_dir: &Path,
    caller: &Caller<'_>,
    request: &CreateRequest,
    admit: impl FnOnce(&str) -> anyhow::Result<VerifiedAgentHost>,
    now: u64,
) -> anyhow::Result<AgentView> {
    require_build()?;
    create_in_any_build(data_dir, caller, request, admit, now)
}

fn create_in_any_build(
    data_dir: &Path,
    caller: &Caller<'_>,
    request: &CreateRequest,
    admit: impl FnOnce(&str) -> anyhow::Result<VerifiedAgentHost>,
    now: u64,
) -> anyhow::Result<AgentView> {
    let opened = open(data_dir, true)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let owner = caller_person(&opened.owner_file, caller)?;
    if !is_display_name(&request.display_name)
        || !is_token(&request.agent_host)
        || !is_token(&request.request_id)
    {
        return refused(BAD_REQUEST);
    }
    let mut theirs = opened
        .file
        .agents
        .iter()
        .filter(|agent| owned_by(agent, owner));
    if let Some(existing) =
        theirs.find(|agent| agent.record.request_id.as_deref() == Some(&request.request_id))
    {
        let host = existing.record.agent_host_package.as_ref();
        let same_body = existing.record.display_name == request.display_name
            && host.is_some_and(|host| host.name == request.agent_host);
        return match same_body {
            true => Ok(view(existing)),
            false => refused(REQUEST_ID_REUSED),
        };
    }
    let live = opened
        .file
        .agents
        .iter()
        .filter(|agent| owned_by(agent, owner) && agent.record.retired_at.is_none())
        .count();
    if live >= MAX_LIVE_AGENTS_PER_OWNER {
        return refused(AT_THE_LIMIT);
    }
    // The wrap reads the owner's key. A root-key change holds this same lock
    // until its store returns, so the key read here is the key that store left.
    #[cfg(all(test, unix))]
    pause_agent_writer(data_dir, PAUSE_BEFORE_WRAP);
    let id = crate::auth::fresh_agent_id();
    let root = crate::auth::principal_kind_localhost_root(&id, PrincipalKind::Agent);
    let Some(protection) = protect_agent_root(data_dir, owner, &id, &root, now)? else {
        return refused(OWNER_UNPROTECTED);
    };
    let host = admit(&request.agent_host)?;
    let binding = ProofBinding::agent_admission(&id, now);
    let agent = StoredAgent {
        protection,
        record: PrincipalRecord {
            principal_id: id,
            proof_binding_id: binding.id(),
            proof_binding: binding,
            display_name: request.display_name.clone(),
            initial_profile_display_name: None,
            role: RuntimePrincipalRole::Guest,
            localhost_root: root,
            kind: PrincipalKind::Agent,
            created_at: now,
            updated_at: now,
            owner: Some(owner.principal_id.clone()),
            request_id: Some(request.request_id.clone()),
            agent_host_package: Some(host.package().clone()),
            retired_at: None,
            version: PRINCIPAL_RECORD_VERSION,
        },
        active: false,
        model_tokens_spent: 0,
    };
    if id_or_root_held(&opened, &agent.record) {
        return refused(ID_HELD);
    }
    let mut after = opened.file.clone();
    after.sequence += 1;
    after.agents.push(agent.clone());
    let subject = agent.record.principal_id.as_str();
    write(
        data_dir,
        &opened,
        Operation::Create,
        &after,
        caller,
        subject,
        now,
    )?;
    Ok(view(&agent))
}

/// The caller's own agents, retired ones included.
pub(crate) fn list(data_dir: &Path, caller: &Caller<'_>) -> anyhow::Result<Vec<AgentView>> {
    require_build()?;
    list_in_any_build(data_dir, caller)
}

fn list_in_any_build(data_dir: &Path, caller: &Caller<'_>) -> anyhow::Result<Vec<AgentView>> {
    let opened = open(data_dir, false)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let owner = caller_person(&opened.owner_file, caller)?;
    let theirs = opened
        .file
        .agents
        .iter()
        .filter(|agent| owned_by(agent, owner));
    Ok(theirs.map(view).collect())
}

pub(crate) fn opening_agent_count(data_dir: &Path, owner_id: &str) -> anyhow::Result<usize> {
    if !build_allows() {
        return named_in_plain_file(data_dir, owner_id, true);
    }
    let Some(opened) = open_for_root_change(data_dir)? else {
        return Ok(0);
    };
    let Some(owner) = opened
        .owner_file
        .iter()
        .find(|record| record.principal_id == owner_id && is_person(record))
    else {
        return Ok(0);
    };
    let mut count = 0usize;
    for agent in &opened.file.agents {
        if owned_by(agent, owner)
            && agent.record.retired_at.is_none()
            && data_key_opens(data_dir, &owner.principal_id, &agent.protection)?
        {
            count += 1;
        }
    }
    Ok(count)
}

/// The agent file for a root-key decision in a build that has agents.
/// `None` is a Home with no file.
fn open_for_root_change(data_dir: &Path) -> anyhow::Result<Option<Opened>> {
    let path = agent_file_path(data_dir)?;
    if std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    Ok(Some(open(data_dir, false)?))
}

/// Owner ids in the agent file, read as plain JSON. `None` is no file.
/// The read uses the same mode checks as a load, and stops at
/// `MAX_AGENT_FILE_BYTES`. An unreadable file refuses with its own reason.
/// This path opens no key, so a build without agents can decide.
fn plain_owner_names(data_dir: &Path) -> anyhow::Result<Option<Vec<(String, bool)>>> {
    let path = agent_file_path(data_dir)?;
    let bytes = match read_agent_file_capped(data_dir, &path, Some(MAX_AGENT_FILE_BYTES)) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(None),
        Err(_) => return Err(Refused(AGENTS_FILE_UNREADABLE.to_string()).into()),
    };
    match owners_in_plain_json(&bytes) {
        Ok(owners) => Ok(Some(owners)),
        Err(_) => Err(Refused(AGENTS_FILE_UNREADABLE.to_string()).into()),
    }
}

/// One record's owner id, and whether that record is retired.
fn owners_in_plain_json(bytes: &[u8]) -> Result<Vec<(String, bool)>, &'static str> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| DOES_NOT_PARSE)?;
    if value.get("schema").and_then(|item| item.as_str()) != Some(AGENT_RECORDS_SCHEMA) {
        return Err(DOES_NOT_PARSE);
    }
    let Some(agents) = value.get("agents").and_then(|item| item.as_array()) else {
        return Err(DOES_NOT_PARSE);
    };
    let mut owners = Vec::new();
    for agent in agents {
        let Some(record) = agent.get("record") else {
            return Err(DOES_NOT_PARSE);
        };
        let Some(owner) = record.get("owner").and_then(|owner| owner.as_str()) else {
            return Err(DOES_NOT_PARSE);
        };
        let retired = match record.get("retired_at") {
            None => false,
            Some(retired_at) if retired_at.is_null() => false,
            Some(retired_at) if retired_at.as_u64().is_some() => true,
            Some(_) => return Err(DOES_NOT_PARSE),
        };
        owners.push((owner.to_string(), retired));
    }
    Ok(owners)
}

/// `unretired_only` is the root-key decision: a retired record does not stop
/// opening. A reassignment passes false, because a retired record still
/// names its owner.
fn named_in_plain_file(
    data_dir: &Path,
    owner_id: &str,
    unretired_only: bool,
) -> anyhow::Result<usize> {
    let Some(owners) = plain_owner_names(data_dir)? else {
        return Ok(0);
    };
    Ok(owners
        .iter()
        .filter(|(owner, retired)| owner == owner_id && (!unretired_only || !retired))
        .count())
}

fn data_key_opens(
    data_dir: &Path,
    owner_id: &str,
    protection: &PrincipalRootProtectionV1,
) -> anyhow::Result<bool> {
    crate::api::auth_gateway::agent_key_open(data_dir, owner_id, protection)
        .ok_or_else(|| Refused(CANNOT_OPEN_THE_WRAP.to_string()).into())
}

pub(crate) const CANNOT_OPEN_THE_WRAP: &str =
    "This Home cannot open the key that wraps an agent's data, so a root-key change is refused.";

pub(crate) const PASSKEY_NO_LONGER_NAMES: &str = "This passkey no longer names the account this recovery started with, so the recovery is refused.";

pub(crate) fn agents_would_stop_opening(count: usize) -> String {
    let word = if count == 1 { "agent" } else { "agents" };
    format!(
        "{count} {word} on this Home would stop opening, so nothing was changed. Use this Recovery Kit on another Home instead."
    )
}

/// Create Recovery Kit. The same words in a build with agents and without.
pub(crate) fn agents_use_a_key_not_in_a_kit(count: usize) -> String {
    let (word, verb) = if count == 1 {
        ("agent", "uses")
    } else {
        ("agents", "use")
    };
    format!(
        "{count} {word} on this Home {verb} a key this Home can't put in a Recovery Kit yet, so nothing was changed."
    )
}

pub(crate) fn agents_would_belong_to_nobody(count: usize) -> String {
    let (word, names) = if count == 1 {
        ("agent", "its record names")
    } else {
        ("agents", "their records name")
    };
    format!(
        "{count} {word} on this Home would belong to nobody. This recovery changes the owner id {names}."
    )
}

/// Held from the opening count until the caller finishes storing the key.
pub(crate) struct AgentWriterGuard {
    _lock: WriteLock,
}

/// The count and the key store are one decision. The caller stores the key
/// before dropping the guard. The guard is taken after any provider wait,
/// and before `key_changes` loads the stored protection.
///
/// A reassignment that changes the owner id a record names refuses: that
/// agent would belong to nobody. A retired record still names its owner, so
/// it counts. The same owner id is refused only when the key changes and an
/// agent's data would stop opening. A build without agents counts unretired
/// records that name the owner and opens no key.
pub(crate) fn hold_agent_writer_for_root_change(
    data_dir: &Path,
    current_owner_id: &str,
    next_owner_id: &str,
    key_changes: impl FnOnce() -> anyhow::Result<bool>,
) -> anyhow::Result<AgentWriterGuard> {
    let lock = acquire_agent_lock(data_dir, false)?;
    #[cfg(all(test, unix))]
    pause_agent_writer(data_dir, PAUSE_BEFORE_STORE);
    if current_owner_id != next_owner_id {
        let named = agents_naming_owner(data_dir, current_owner_id, false)?;
        if named > 0 {
            return Err(Refused(agents_would_belong_to_nobody(named)).into());
        }
    } else if key_changes()? {
        let count = opening_agent_count(data_dir, current_owner_id)?;
        if count > 0 {
            return Err(Refused(agents_would_stop_opening(count)).into());
        }
    }
    Ok(AgentWriterGuard { _lock: lock })
}

pub(crate) fn hold_unarchived(data_dir: &Path, owner_id: &str) -> anyhow::Result<AgentWriterGuard> {
    let guard = hold_agent_writer_for_root_change(data_dir, owner_id, owner_id, || Ok(false))?;
    let named = agents_naming_owner(data_dir, owner_id, true)?;
    if named > 0 {
        return Err(Refused(agents_use_a_key_not_in_a_kit(named)).into());
    }
    Ok(guard)
}

fn agents_naming_owner(
    data_dir: &Path,
    owner_id: &str,
    unretired_only: bool,
) -> anyhow::Result<usize> {
    if !build_allows() {
        return named_in_plain_file(data_dir, owner_id, unretired_only);
    }
    let Some(opened) = open_for_root_change(data_dir)? else {
        return Ok(0);
    };
    Ok(opened
        .file
        .agents
        .iter()
        .filter(|agent| {
            agent.record.owner.as_deref() == Some(owner_id)
                && (!unretired_only || agent.record.retired_at.is_none())
        })
        .count())
}

#[cfg(all(test, unix))]
pub(crate) const PAUSE_BEFORE_STORE: &str = "before-store";
#[cfg(all(test, unix))]
pub(crate) const PAUSE_BEFORE_WRAP: &str = "before-wrap";

#[cfg(all(test, unix))]
struct WriterPause {
    data_dir: PathBuf,
    point: &'static str,
    arrived: bool,
    release: bool,
}

/// One pause per Home. Two tests can arm two Homes at once; a single slot
/// would let one Home release the other.
#[cfg(all(test, unix))]
static WRITER_PAUSES: Mutex<Vec<WriterPause>> = Mutex::new(Vec::new());
#[cfg(all(test, unix))]
static WRITER_PAUSE_CV: Condvar = Condvar::new();

#[cfg(all(test, unix))]
pub(crate) struct AgentWriterPauseGuard {
    data_dir: PathBuf,
}

#[cfg(all(test, unix))]
impl Drop for AgentWriterPauseGuard {
    fn drop(&mut self) {
        release_agent_writer_pause(&self.data_dir);
    }
}

#[cfg(all(test, unix))]
fn writer_pause_lock() -> MutexGuard<'static, Vec<WriterPause>> {
    WRITER_PAUSES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Arms the pause for this Home. Dropping the guard lets that Home's waiter
/// continue. Another Home keeps its own pause.
#[cfg(all(test, unix))]
pub(crate) fn arm_agent_writer_pause(
    data_dir: &Path,
    point: &'static str,
) -> AgentWriterPauseGuard {
    let mut pauses = writer_pause_lock();
    pauses.retain(|pause| pause.data_dir != data_dir);
    pauses.push(WriterPause {
        data_dir: data_dir.to_path_buf(),
        point,
        arrived: false,
        release: false,
    });
    AgentWriterPauseGuard {
        data_dir: data_dir.to_path_buf(),
    }
}

#[cfg(all(test, unix))]
pub(crate) fn agent_writer_pause_arrived(data_dir: &Path) -> bool {
    writer_pause_lock()
        .iter()
        .any(|pause| pause.data_dir == data_dir && pause.arrived)
}

#[cfg(all(test, unix))]
fn release_agent_writer_pause(data_dir: &Path) {
    if let Some(pause) = writer_pause_lock()
        .iter_mut()
        .find(|pause| pause.data_dir == data_dir)
    {
        pause.release = true;
    }
    WRITER_PAUSE_CV.notify_all();
}

#[cfg(all(test, unix))]
fn pause_agent_writer(data_dir: &Path, point: &str) {
    let mut guard = writer_pause_lock();
    while let Some(index) = guard
        .iter()
        .position(|pause| pause.data_dir == data_dir && pause.point == point && !pause.release)
    {
        guard[index].arrived = true;
        WRITER_PAUSE_CV.notify_all();
        guard = WRITER_PAUSE_CV
            .wait(guard)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

const NO_SUCH_AGENT: &str = "the caller owns no agent with that id";
pub(crate) const ALREADY_RETIRED: &str = "agent is already retired";
pub(crate) const NOT_ACTIVE: &str = "agent is off until its owner turns it on";

/// Renames one of the caller's agents. The display name and `updated_at`
/// are the only fields that change. The same name writes nothing. A retired
/// agent is refused. Another person's agent gives the same refusal as an
/// unknown id.
pub(crate) fn rename(
    data_dir: &Path,
    caller: &Caller<'_>,
    agent_id: &str,
    display_name: &str,
    now: u64,
) -> anyhow::Result<AgentView> {
    require_build()?;
    rename_in_any_build(data_dir, caller, agent_id, display_name, now)
}

fn rename_in_any_build(
    data_dir: &Path,
    caller: &Caller<'_>,
    agent_id: &str,
    display_name: &str,
    now: u64,
) -> anyhow::Result<AgentView> {
    let opened = open(data_dir, true)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let owner = caller_person(&opened.owner_file, caller)?;
    let mut after = opened.file.clone();
    let Some(agent) = after
        .agents
        .iter_mut()
        .find(|agent| agent.record.principal_id == agent_id && owned_by(agent, owner))
    else {
        return refused(NO_SUCH_AGENT);
    };
    if agent.record.retired_at.is_some() {
        return refused(ALREADY_RETIRED);
    }
    if !is_display_name(display_name) {
        return refused(BAD_REQUEST);
    }
    if agent.record.display_name == display_name {
        return Ok(view(agent));
    }
    agent.record.display_name = display_name.to_string();
    agent.record.updated_at = now;
    let renamed = view(agent);
    after.sequence += 1;
    write(
        data_dir,
        &opened,
        Operation::Rename,
        &after,
        caller,
        agent_id,
        now,
    )?;
    Ok(renamed)
}

/// Retires one of the caller's agents, once. The record stays as a
/// tombstone, so its id and root are never used again, and its storage is
/// kept. Another person's agent gives the same refusal as an unknown id.
pub(crate) fn retire(
    data_dir: &Path,
    caller: &Caller<'_>,
    agent_id: &str,
    now: u64,
) -> anyhow::Result<AgentView> {
    require_build()?;
    retire_in_any_build(data_dir, caller, agent_id, now)
}

fn retire_in_any_build(
    data_dir: &Path,
    caller: &Caller<'_>,
    agent_id: &str,
    now: u64,
) -> anyhow::Result<AgentView> {
    let opened = open(data_dir, true)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let owner = caller_person(&opened.owner_file, caller)?;
    let mut after = opened.file.clone();
    after.sequence += 1;
    let Some(agent) = after
        .agents
        .iter_mut()
        .find(|agent| agent.record.principal_id == agent_id && owned_by(agent, owner))
    else {
        return refused(NO_SUCH_AGENT);
    };
    if agent.record.retired_at.is_some() {
        return refused(ALREADY_RETIRED);
    }
    agent.record.retired_at = Some(now);
    agent.record.updated_at = now;
    let retired = view(agent);
    write(
        data_dir,
        &opened,
        Operation::Retire,
        &after,
        caller,
        agent_id,
        now,
    )?;
    Ok(retired)
}

pub(crate) fn set_active(
    data_dir: &Path,
    caller: &Caller<'_>,
    agent_id: &str,
    active: bool,
    now: u64,
) -> anyhow::Result<AgentView> {
    if !build_allows_for_home(data_dir) {
        return refused(FEATURE_OFF);
    }
    raise_spend_file_to_signed_floor(data_dir).map_err(Named)?;
    let opened = open(data_dir, true)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let owner = caller_person(&opened.owner_file, caller)?;
    let mut after = opened.file.clone();
    let Some(agent) = after
        .agents
        .iter_mut()
        .find(|agent| agent.record.principal_id == agent_id && owned_by(agent, owner))
    else {
        return refused(NO_SUCH_AGENT);
    };
    if agent.record.retired_at.is_some() {
        return refused(ALREADY_RETIRED);
    }
    if agent.active == active {
        return Ok(view(agent));
    }
    agent.active = active;
    agent.record.updated_at = now;
    let shown = view(agent);
    after.sequence += 1;
    write(
        data_dir,
        &opened,
        Operation::SetActive,
        &after,
        caller,
        agent_id,
        now,
    )?;
    Ok(shown)
}

/// One stored agent of `owner_id`, for a launch. Every gate applies before a
/// record leaves this module: the build, the Home's stored choice, a stored
/// person as the owner, that the owner is an admin with a live passkey now,
/// the agent's own owner, its retirement, and whether its owner has turned
/// this agent on.
pub(crate) fn stored_agent(
    data_dir: &Path,
    owner_id: &str,
    agent_id: &str,
) -> anyhow::Result<StoredAgent> {
    if !build_allows_for_home(data_dir) {
        return refused(FEATURE_OFF);
    }
    let opened = open(data_dir, false)?;
    if opened.file.enabled.is_none() {
        return refused(NOT_ENABLED);
    }
    let Some(owner) = opened
        .owner_file
        .iter()
        .find(|record| record.principal_id == owner_id && is_person(record))
    else {
        return refused(NOT_A_PERSON);
    };
    let Some(agent) = opened
        .file
        .agents
        .iter()
        .find(|agent| agent.record.principal_id == agent_id && owned_by(agent, owner))
    else {
        return refused(NO_SUCH_AGENT);
    };
    if !owner_is_admin_now(data_dir, owner_id)? {
        return refused(OWNER_NOT_ADMIN);
    }
    if agent.record.retired_at.is_some() {
        return refused(NO_SUCH_AGENT);
    }
    if !agent.active {
        return refused(NOT_ACTIVE);
    }
    Ok(agent.clone())
}

/// One Home whose next owner-role read fails. A failed read is not "not an admin".
#[cfg(test)]
static OWNER_ADMIN_READ_FAILS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// The next `owner_is_admin_now` for this Home fails closed.
#[cfg(all(test, unix))]
pub(crate) fn fail_owner_admin_read(data_dir: &Path) {
    OWNER_ADMIN_READ_FAILS
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .insert(data_dir.to_path_buf());
}

/// The owner is an admin now: Admin role, and a live passkey when they have one.
/// A Guest, and an admin whose every passkey is revoked, is not. A failed read
/// is an error. It is not a Guest.
pub(crate) fn owner_is_admin_now(data_dir: &Path, owner_id: &str) -> anyhow::Result<bool> {
    #[cfg(test)]
    if OWNER_ADMIN_READ_FAILS
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .remove(data_dir)
    {
        anyhow::bail!("the owner's role could not be read");
    }
    let records = match crate::auth::load_owner_principals(data_dir) {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!("owner admin check was not read: {error:#}");
            anyhow::bail!("the owner's role could not be read");
        }
    };
    let mut admin = false;
    let mut passkey = false;
    let mut live_passkey = false;
    for record in &records {
        if record.principal_id != owner_id || !is_person(record) {
            continue;
        }
        admin |= crate::auth::is_admin(record);
        if let Some(key) = record.proof_binding.passkey.as_ref() {
            passkey = true;
            live_passkey |= key.revoked_at.is_none();
        }
    }
    Ok(admin && (!passkey || live_passkey))
}

/// The route that demotes an owner stops that owner's agents itself.
/// A demote that does not come through the route is not claimed, and the
/// registered stop runs for that owner.
static DEMOTE_STOP_CLAIMS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
type OwnerDemotedHook = fn(&Path, &str);
static OWNER_DEMOTED_HOOK: std::sync::LazyLock<std::sync::Mutex<Option<OwnerDemotedHook>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

fn demote_stop_key(data_dir: &Path, owner_id: &str) -> String {
    format!("{}\n{owner_id}", data_dir.display())
}

fn demote_claims() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    DEMOTE_STOP_CLAIMS
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

/// The demote route calls this before it changes the role, then stops the
/// agents itself and releases the claim.
pub(crate) fn claim_demoted_stop(data_dir: &Path, owner_id: &str) {
    demote_claims().insert(demote_stop_key(data_dir, owner_id));
}

pub(crate) fn release_demoted_stop(data_dir: &Path, owner_id: &str) {
    demote_claims().remove(&demote_stop_key(data_dir, owner_id));
}

/// The gateway registers the stop that a direct demote runs.
pub(crate) fn set_owner_demoted_hook(hook: fn(&Path, &str)) {
    *OWNER_DEMOTED_HOOK
        .lock()
        .unwrap_or_else(|err| err.into_inner()) = Some(hook);
}

/// A role change to Guest. The route's own stop is claimed and skips this.
/// With no agents there is nothing to stop.
pub(crate) fn owner_demoted(data_dir: &Path, owner_id: &str) {
    if demote_claims().contains(&demote_stop_key(data_dir, owner_id)) {
        return;
    }
    if ids_owned_by(data_dir, owner_id).is_empty() {
        return;
    }
    let hook = OWNER_DEMOTED_HOOK
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .copied();
    if let Some(hook) = hook {
        hook(data_dir, owner_id);
    }
}

/// Agent ids this person owns, retired records included, so their open plans close.
pub(crate) fn ids_owned_by(data_dir: &Path, owner_id: &str) -> Vec<String> {
    let Ok(opened) = open(data_dir, false) else {
        return Vec::new();
    };
    opened
        .file
        .agents
        .into_iter()
        .filter(|agent| agent.record.owner.as_deref() == Some(owner_id))
        .map(|agent| agent.record.principal_id)
        .collect()
}

/// The stored owner of one agent, when the file holds that id.
pub(crate) fn owner_of(data_dir: &Path, agent_id: &str) -> Option<String> {
    let opened = open(data_dir, false).ok()?;
    opened
        .file
        .agents
        .into_iter()
        .find(|agent| agent.record.principal_id == agent_id)
        .and_then(|agent| agent.record.owner)
}

/// The stored agent, without the owner check. Stop uses this after it has
/// already allowed another admin to end an agent whose owner is not an admin.
pub(crate) fn agent_record(data_dir: &Path, agent_id: &str) -> anyhow::Result<StoredAgent> {
    if !build_allows_for_home(data_dir) {
        return refused(FEATURE_OFF);
    }
    let opened = open(data_dir, false)?;
    match opened
        .file
        .agents
        .into_iter()
        .find(|agent| agent.record.principal_id == agent_id)
    {
        Some(agent) => Ok(agent),
        None => refused(NO_SUCH_AGENT),
    }
}

/// One stored agent of `owner_id`, for a Stop. The owner must own the record.
/// The agent may be off or retired, and the Home may have turned agents off:
/// a running guest stays stoppable by that owner. Another owner's agent is
/// refused, the same way a launch lookup refuses it.
pub(crate) fn stored_agent_for_stop(
    data_dir: &Path,
    owner_id: &str,
    agent_id: &str,
) -> anyhow::Result<StoredAgent> {
    if !build_allows_for_home(data_dir) {
        return refused(FEATURE_OFF);
    }
    let opened = open(data_dir, false)?;
    let Some(owner) = opened
        .owner_file
        .iter()
        .find(|record| record.principal_id == owner_id && is_person(record))
    else {
        return refused(NOT_A_PERSON);
    };
    let Some(agent) = opened
        .file
        .agents
        .iter()
        .find(|agent| agent.record.principal_id == agent_id && owned_by(agent, owner))
    else {
        return refused(NO_SUCH_AGENT);
    };
    Ok(agent.clone())
}

/// The agent file's record for one principal and root, while agents are on for
/// this Home. `None` in a build without the feature, while they are off, and
/// for any id or root the file does not hold. Production asks go through
/// `stored_agent_for_protection` and `refuse_inactive_agent`. This lookup is
/// what the tests hold the filtered rule against.
#[cfg(test)]
pub(crate) fn stored_agent_for_root(
    data_dir: &Path,
    principal_id: &str,
    localhost_root: &str,
) -> anyhow::Result<Option<StoredAgent>> {
    if !build_allows_for_home(data_dir) {
        return Ok(None);
    }
    let opened = open(data_dir, false)?;
    if opened.file.enabled.is_none() {
        return Ok(None);
    }
    Ok(opened
        .file
        .agents
        .iter()
        .find(|agent| {
            agent.record.principal_id == principal_id
                && agent.record.localhost_root == localhost_root
                && agent.active
                && agent.record.retired_at.is_none()
        })
        .cloned())
}

/// The agent file's record for one principal and root, including an agent
/// that is off or retired and a Home that has turned agents off. The key
/// stays with the record, so a write does not fall through to plaintext.
/// A grant still uses [`stored_agent_for_root`], which returns none unless
/// the agent is on.
fn stored_agent_for_protection(
    data_dir: &Path,
    principal_id: &str,
    localhost_root: &str,
) -> anyhow::Result<Option<StoredAgent>> {
    if !build_allows_for_home(data_dir) {
        return Ok(None);
    }
    let opened = open(data_dir, false)?;
    Ok(opened.file.agents.into_iter().find(|agent| {
        agent.record.principal_id == principal_id && agent.record.localhost_root == localhost_root
    }))
}

/// The agent file's stored protection for one principal and root, or `None`.
/// The sign-in file holds none for an agent, so this is where the bridge's
/// protection reader finds one. An agent that is off still has its key: the
/// bytes stay sealed, and the ask is refused separately.
pub(crate) fn stored_protection(
    data_dir: &Path,
    principal_id: &str,
    localhost_root: &str,
) -> anyhow::Result<Option<PrincipalRootProtectionV1>> {
    Ok(
        stored_agent_for_protection(data_dir, principal_id, localhost_root)?
            .map(|agent| agent.protection),
    )
}

/// The owner and the raw wrap of one stored protection, for `auth` to open.
/// The stored protection must equal the one passed in, byte for byte, so a
/// protection that merely looks like an agent's yields nothing. This module
/// never holds a key: `auth` derives the wrap key and opens the wrap.
///
/// A build that does not serve agents does not open a wrap. Its root-key
/// decision reads the agent file and does not call this.
pub(crate) fn stored_wrap(
    data_dir: &Path,
    protection: &PrincipalRootProtectionV1,
) -> anyhow::Result<(String, [u8; 12], Vec<u8>)> {
    if !build_allows_for_home(data_dir) {
        return refused(FEATURE_OFF);
    }
    wrap_parts(data_dir, protection)
}

/// The owner and the raw wrap. `stored_wrap` is the only caller, and it
/// applies the feature gate before this runs.
fn wrap_parts(
    data_dir: &Path,
    protection: &PrincipalRootProtectionV1,
) -> anyhow::Result<(String, [u8; 12], Vec<u8>)> {
    let opened = open(data_dir, false)?;
    let Some(agent) = opened.file.agents.iter().find(|agent| {
        agent.record.principal_id == protection.principal_id
            && agent.record.localhost_root == protection.localhost_root
    }) else {
        anyhow::bail!("agent file holds no record for this principal root");
    };
    if agent.protection != *protection {
        anyhow::bail!("principal-root protection is not the agent file's stored one");
    }
    let Some(owner_id) = agent.record.owner.clone() else {
        anyhow::bail!("agent record names no owner");
    };
    let [protector] = agent.protection.protectors.as_slice() else {
        anyhow::bail!("principal-root protection must hold one protector");
    };
    let Some(envelope) = protector.envelope.as_ref() else {
        anyhow::bail!("owner-root protector holds no envelope");
    };
    let nonce: [u8; 12] = crate::auth::b64_url_decode(&envelope.nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner-root nonce has the wrong length"))?;
    Ok((
        owner_id,
        nonce,
        crate::auth::b64_url_decode(&envelope.wrapped_data_key)?,
    ))
}

/// Adds the agent file's records to what the sign-in file's loader returns,
/// while agents are on for this Home. It never fails: an agent fault leaves the
/// owner's own load exactly as it was. A record already present stays one.
pub(crate) fn merge_into(data_dir: &Path, state: &mut crate::auth::AuthState) {
    if !build_allows_for_home(data_dir) {
        return;
    }
    let Ok(AgentFile::Loaded(file)) = load(data_dir, &state.principals) else {
        return;
    };
    if file.enabled.is_none() {
        return;
    }
    for agent in file.agents {
        if !state
            .principals
            .iter()
            .any(|record| record.principal_id == agent.record.principal_id)
        {
            state.principals.push(agent.record);
        }
    }
}

/// The sign-in file's own records: `state` without the agent records the
/// agent file holds unchanged. A caller that adds or changes an agent record
/// keeps it here, and the save guard refuses it. `None` when nothing is
/// dropped, which is every build without the feature.
pub(crate) fn without_agent_roots(
    data_dir: &Path,
    state: &crate::auth::AuthState,
) -> Option<crate::auth::AuthState> {
    if !build_allows_for_home(data_dir) {
        return None;
    }
    // The file's records are read here, never through the sign-in loader: a
    // save holds the sign-in lock while it asks, and the loader needs it.
    let mut stored = Vec::new();
    if let Ok(path) = agent_file_path(data_dir) {
        if let Ok(Some(bytes)) = read_agent_file(data_dir, &path) {
            if let Ok(file) = parse_strict(&bytes) {
                stored = file.agents;
            }
        }
    }
    let is_agent = |record: &PrincipalRecord| stored.iter().any(|agent| agent.record == *record);
    if !state.principals.iter().any(is_agent) {
        return None;
    }
    let mut stripped = state.clone();
    stripped.principals.retain(|record| !is_agent(record));
    Some(stripped)
}
