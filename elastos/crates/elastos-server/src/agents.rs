//! Agents that belong to one person.
//!
//! An owner turns agents on for their Home, then creates, lists and retires
//! them. Nothing in this module runs an agent.
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
//! The rules this module keeps:
//!
//! - `build_allows` is the only place the cargo feature is read. With the
//!   feature off every operation refuses by name, whatever is on disk.
//! - A load takes no lock and writes nothing. A missing file means no agents.
//!   A file that fails any rule makes agents unavailable, with a named
//!   reason; it is never rewritten or deleted, and the owner's own sign-in
//!   file is read exactly as before.
//! - A write holds the agent lock, raises `sequence` by exactly one, replaces
//!   the file in one step at mode 0600, and then appends one audit event to
//!   the owner's audit chain.
//! - Every write is one of a closed list of operations, and each operation
//!   may change only what `permits` lists for it.
//! - This module never holds the owner's data key. It asks `auth` for a key
//!   derived from it and wraps the agent's own data key under that.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

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

#[cfg(test)]
pub(crate) mod tests;

pub(crate) const AGENT_RECORDS_SCHEMA: &str = "elastos.agent.records/v1";
const AGENT_RECORDS_FILE: &str = "agent-records.json";

/// The refusal every operation gives in a build without the feature.
pub(crate) const FEATURE_OFF: &str = "agents are not built into this Runtime";

/// How the agent's data key is wrapped: under a key derived with HKDF-SHA256.
const OWNER_ROOT_KDF: &str = "hkdf-sha256";
/// The derivation uses no salt: its input is already a uniformly random
/// 256-bit key. The envelope's salt field may not be empty, so it holds this
/// fixed word, and a file with any other value there is refused.
const OWNER_ROOT_ENVELOPE_SALT: &str = "unsalted";

const NOT_REGULAR: &str = "agent file path is not a regular file";
const MODE_TOO_WIDE: &str = "agent file mode is wider than 0600";
const CANNOT_READ: &str = "agent file cannot be read";
const DOES_NOT_PARSE: &str = "agent file does not parse";
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

/// A named refusal. The text is the whole reason, and nothing was written.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

fn refused<T>(reason: impl Into<String>) -> anyhow::Result<T> {
    Err(anyhow::Error::new(Refused(reason.into())))
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Enabled {
    by: String,
    at: u64,
}

/// One agent: its record and the protection of its storage key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredAgent {
    record: PrincipalRecord,
    protection: PrincipalRootProtectionV1,
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
        }
    }
}

fn agent_file_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
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

/// The file's bytes, read through one handle, or `None` when there is no
/// file. Refuses a path that is not a regular file under regular
/// directories, and a file anyone but its owner can read or write.
fn read_agent_file(data_dir: &Path, path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(NOT_REGULAR),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CANNOT_READ),
    }
    // The file exists, so each parent exists: this only checks them.
    let parents_regular = path
        .parent()
        .is_some_and(|parent| crate::auth::ensure_regular_auth_parent(data_dir, parent).is_ok());
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
    file.read_to_end(&mut bytes).map_err(|_| CANNOT_READ)?;
    Ok(Some(bytes))
}

/// Parses the file and refuses anything this Runtime would not have written:
/// the parsed file, written back, must hold the same fields and values as
/// the bytes read. That one comparison refuses an unknown field at any depth.
fn parse_strict(bytes: &[u8]) -> Result<AgentRecordsFile, &'static str> {
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
    for (index, agent) in file.agents.iter().enumerate() {
        let record = &agent.record;
        let earlier = &file.agents[..index];
        if record.version != PRINCIPAL_RECORD_VERSION {
            return Err(UNKNOWN_VERSION);
        }
        if record.kind != PrincipalKind::Agent {
            return Err(NOT_AN_AGENT);
        }
        if record.role != RuntimePrincipalRole::Guest {
            return Err(AGENT_IS_ADMIN);
        }
        if earlier
            .iter()
            .any(|other| other.record.principal_id == record.principal_id)
        {
            return Err(REPEATED_ID);
        }
        if earlier
            .iter()
            .any(|other| other.record.localhost_root == record.localhost_root)
        {
            return Err(REPEATED_ROOT);
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

/// The agent lock: one writer in this process, and one across processes.
struct WriteLock {
    _file: FileLock,
    _process: MutexGuard<'static, ()>,
}

/// Takes the agent lock. The owner's sign-in lock is only ever taken inside
/// it, by the audit append, and nothing that holds the sign-in lock takes
/// this one.
fn lock_for_write(data_dir: &Path) -> anyhow::Result<WriteLock> {
    let process = AGENT_WRITE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = agent_file_path(data_dir)?.with_file_name(format!("{AGENT_RECORDS_FILE}.lock"));
    if let Some(parent) = path.parent() {
        crate::auth::ensure_regular_auth_parent(data_dir, parent)?;
    }
    let file = crate::auth::open_regular_lock_file(&path, "agent records")?;
    Ok(WriteLock {
        _file: FileLock::exclusive(file).context("failed to lock agent records")?,
        _process: process,
    })
}

/// Every change to the agent file is one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Enable,
    Disable,
    Create,
    Retire,
}

impl Operation {
    fn event_type(self) -> &'static str {
        match self {
            Self::Enable => "agent.records.enable",
            Self::Disable => "agent.records.disable",
            Self::Create => "agent.record.create",
            Self::Retire => "agent.record.retire",
        }
    }
}

/// What each operation may change. Every write raises the sequence by
/// exactly one and keeps the schema. Beyond that:
///
/// - enable: `enabled`, from off to on;
/// - disable: `enabled`, from on to off;
/// - create: one agent added at the end, not retired;
/// - retire: one agent's `retired_at`, set once, and its `updated_at`.
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
        Operation::Retire => {
            let changed: Vec<_> = before
                .agents
                .iter()
                .zip(&after.agents)
                .filter(|(old, new)| old != new)
                .collect();
            same_enabled
                && after.agents.len() == before.agents.len()
                && matches!(changed.as_slice(), [(old, new)] if retires(old, new))
        }
    }
}

/// `new` is `old` with `retired_at` set for the first time and `updated_at`
/// moved, and nothing else changed.
fn retires(old: &StoredAgent, new: &StoredAgent) -> bool {
    let mut expected = old.clone();
    expected.record.retired_at = new.record.retired_at;
    expected.record.updated_at = new.record.updated_at;
    old.record.retired_at.is_none() && new.record.retired_at.is_some() && expected == *new
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
fn open(data_dir: &Path, for_write: bool) -> anyhow::Result<Opened> {
    let lock = match for_write {
        true => Some(lock_for_write(data_dir)?),
        false => None,
    };
    let owner_file = crate::auth::load_auth_state(data_dir)?.principals;
    let file = match load(data_dir, &owner_file)? {
        AgentFile::Missing => AgentRecordsFile::unwritten(),
        AgentFile::Loaded(file) => file,
        AgentFile::Unavailable(reason) => {
            return refused(format!("agents are unavailable: {reason}"))
        }
    };
    Ok(Opened {
        lock,
        owner_file,
        file,
    })
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
    let bytes = serde_json::to_vec_pretty(after)?;
    crate::auth::atomic_write(&agent_file_path(data_dir)?, &bytes)?;
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
    )
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
/// key itself is erased when this returns; only the wrap is kept.
fn protect_agent_root(
    data_dir: &Path,
    owner: &PrincipalRootProtectionV1,
    agent_id: &str,
    localhost_root: &str,
    now: u64,
) -> anyhow::Result<PrincipalRootProtectionV1> {
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
    let wrap_key = crate::auth::owner_root_wrap_key(data_dir, owner, &protection)?;
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
    Ok(protection)
}

/// The refusal for create, list and retire while agents are off for a Home.
pub(crate) const NOT_ENABLED: &str = "agents are not turned on for this Home";
/// The refusal for a caller who is not a stored person on a proved binding.
pub(crate) const NOT_A_PERSON: &str = "only a stored person may use agents";
/// The refusal for a person who may not turn agents on or off.
pub(crate) const NOT_AN_ADMIN: &str = "only an admin of this Home turns agents on or off";

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
/// Turning them off keeps every record; create, list and retire then refuse.
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
const MAX_LIVE_AGENTS_PER_OWNER: usize = 8;

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
}

fn view(agent: &StoredAgent) -> AgentView {
    AgentView {
        agent_id: agent.record.principal_id.clone(),
        display_name: agent.record.display_name.clone(),
        agent_host: agent.record.agent_host_package.clone(),
        created_at: agent.record.created_at,
        retired_at: agent.record.retired_at,
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
    let Some(owner_protection) = crate::auth::load_principal_root_protection(
        data_dir,
        &owner.principal_id,
        &owner.localhost_root,
    )?
    else {
        return refused(OWNER_UNPROTECTED);
    };
    let host = admit(&request.agent_host)?;

    let id = crate::auth::fresh_agent_id();
    let root = crate::auth::principal_kind_localhost_root(&id, PrincipalKind::Agent);
    let binding = ProofBinding::agent_admission(&id, now);
    let agent = StoredAgent {
        protection: protect_agent_root(data_dir, &owner_protection, &id, &root, now)?,
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

const NO_SUCH_AGENT: &str = "the caller owns no agent with that id";
const ALREADY_RETIRED: &str = "agent is already retired";

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
