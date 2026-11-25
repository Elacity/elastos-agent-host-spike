//! Core runtime implementation

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use tokio::sync::RwLock;

use crate::bundle_admission::{self, AcceptedSignature, BundleKind, BundleRefusal};
use crate::model_budget::{AgentKey, ModelBudget};
use crate::resource_bridge::{BridgePrincipal, LaunchContent};
use elastos_bundle_identity::{checked_bundle_within, Budget, CheckedBundle, LabCid};
use elastos_common::{AuthorityBound, CapsuleManifest, CapsuleType, ElastosError, Result};
use elastos_compute::providers::{
    component_bridge_leg, BridgeHostcall, BridgeHostcallAsync, ComponentBridgeLeg,
    ComponentProvider, STOPPED_BEFORE_RUN,
};
use elastos_compute::{CapsuleHandle, ComputeProvider};
use elastos_storage::StorageProvider;

use elastos_runtime::capsule::check_entrypoint_file;
use elastos_runtime::primitives::audit::AuditEvent;
use elastos_runtime::primitives::SecureTimestamp;
use elastos_runtime::provider::ProviderRegistry;
use elastos_runtime::signature::{hash_content, SignatureVerifier};

/// The status of an activation that answered `starting` and whose worker has
/// not yet reported that the guest entered `run`.
pub const CAPSULE_STARTING: &str = "starting";
/// The status of an activation whose guest entered `run`.
pub const CAPSULE_RUNNING: &str = "running";
/// The status of an activation that ended.
pub const CAPSULE_STOPPED: &str = "stopped";
/// The status of an activation that trapped.
pub const CAPSULE_FAILED: &str = "failed";
/// The cause of an activation whose guest's `run` returned success.
pub const CAUSE_COMPLETED: &str = "completed";

/// How long an ended activation stays listed, so its session, status and cause
/// can still be read after the response that started it has long gone. The end
/// hands the entry's removal at this instant to the [`RETENTION_SWEEPER`]; a
/// listing also prunes an entry this old.
pub const ENDED_CAPSULE_RETENTION: std::time::Duration = std::time::Duration::from_secs(60);

/// The registry map the Runtime and every activation's end share.
type CapsuleRegistry = RwLock<HashMap<String, RunningCapsuleInfo>>;

/// One ended entry the sweeper removes at its deadline, if the entry still
/// records this end. The registry is held weakly: a Runtime that has gone
/// takes its registry with it, and its removals are then nothing.
struct DueRemoval {
    registry: std::sync::Weak<CapsuleRegistry>,
    id: String,
    ended_at: std::time::Instant,
}

/// The sweeper's deadline queue, ordered by deadline and then by arrival.
struct RetentionQueue {
    due: std::collections::BTreeMap<(std::time::Instant, u64), DueRemoval>,
    arrivals: u64,
    /// Whether the sweeper thread runs. It is started by the first end that
    /// schedules a removal, and by a later one if that start failed.
    sweeping: bool,
}

/// The one retention sweeper of the process: a plain thread, outside every
/// tokio runtime, so no runtime's shutdown can cancel a removal. It waits on
/// [`RetentionSweeper::wake`] until the earliest deadline, with the queue's
/// lock released while it waits, and takes the registry lock only after the
/// deadline has come.
struct RetentionSweeper {
    queue: StdMutex<RetentionQueue>,
    wake: std::sync::Condvar,
}

static RETENTION_SWEEPER: RetentionSweeper = RetentionSweeper {
    queue: StdMutex::new(RetentionQueue {
        due: std::collections::BTreeMap::new(),
        arrivals: 0,
        sweeping: false,
    }),
    wake: std::sync::Condvar::new(),
};

impl RetentionSweeper {
    /// Removes `id` from `registry` at `deadline` if the entry still records
    /// the end at `ended_at`. A thread that cannot be started is logged; a
    /// listing still prunes the entry, and the next end tries the start again.
    fn schedule(
        &'static self,
        registry: &Arc<CapsuleRegistry>,
        id: &str,
        ended_at: std::time::Instant,
        deadline: std::time::Instant,
    ) {
        let mut queue = self.queue.lock().unwrap_or_else(|err| err.into_inner());
        let arrival = queue.arrivals;
        queue.arrivals += 1;
        queue.due.insert(
            (deadline, arrival),
            DueRemoval {
                registry: Arc::downgrade(registry),
                id: id.to_string(),
                ended_at,
            },
        );
        if !queue.sweeping {
            let started = std::thread::Builder::new()
                .name("ended-capsule-retention".into())
                .spawn(move || self.sweep());
            match started {
                Ok(_) => queue.sweeping = true,
                Err(error) => {
                    tracing::error!(%error, "activation {id}: no thread for its retention")
                }
            }
        }
        drop(queue);
        self.wake.notify_one();
    }

    /// The sweeper thread: one removal at a time, each at its deadline.
    fn sweep(&'static self) {
        loop {
            let due = self.next_due();
            if let Some(registry) = due.registry.upgrade() {
                let mut capsules = registry.blocking_write();
                remove_ended_entry(&mut capsules, &due.id, due.ended_at);
            }
        }
    }

    /// Waits until the earliest deadline has come and takes that removal.
    fn next_due(&self) -> DueRemoval {
        let mut queue = self.queue.lock().unwrap_or_else(|err| err.into_inner());
        loop {
            let now = std::time::Instant::now();
            let wait = match queue.due.first_entry() {
                Some(first) if first.key().0 <= now => return first.remove(),
                Some(first) => Some(first.key().0.saturating_duration_since(now)),
                None => None,
            };
            queue = match wait {
                Some(wait) => {
                    self.wake
                        .wait_timeout(queue, wait)
                        .unwrap_or_else(|err| err.into_inner())
                        .0
                }
                None => self.wake.wait(queue).unwrap_or_else(|err| err.into_inner()),
            };
        }
    }
}

/// Information about a running capsule (for API responses and lifecycle management)
#[derive(Debug, Clone)]
pub struct RunningCapsuleInfo {
    /// Unique capsule instance ID
    pub id: String,
    /// Capsule name from manifest
    pub name: String,
    /// Current status (`starting`, `running`, `stopped` or `failed`)
    pub status: String,
    /// Capsule type (WASM, MicroVM)
    pub capsule_type: CapsuleType,
    /// Handle for stopping the capsule (optional, not all capsules have handles)
    pub handle: Option<CapsuleHandle>,
    /// The session this instance runs in: the capsule id the bridge and the
    /// pending store use for it, which is also the instance id.
    pub session_id: String,
    /// The principal admission bound the instance to, for an agent launch or
    /// a launch grant.
    pub principal: Option<String>,
    /// Why the activation ended, once it has: `completed` for a natural
    /// return, or the trap's message.
    pub cause: Option<String>,
    /// When the activation ended; `None` while it is starting or running.
    pub ended_at: Option<std::time::Instant>,
}

/// Which unsigned local capsules the Runtime admits.
enum UnsignedCapsules {
    /// A source or CI Home with `dev_mode = true`.
    Allowed,
    /// Only capsules setup installed from the signed release of the Home at this data dir.
    InstalledRelease(PathBuf),
    /// Unsigned capsules are refused. The Home's data dir is known once
    /// admission is configured; a Runtime that was never configured has none.
    Refused(Option<PathBuf>),
}

/// A component folder start outside dev mode, as the folder gate's one walk
/// read it: the manifest that walk read from `capsule.json`, the CID that
/// names the bytes, the entrypoint bytes from that same walk, and the data dir
/// whose by-CID store may accept the CID. `None` for the data dir is a Runtime
/// with no configured Home store.
struct FolderStart {
    manifest: CapsuleManifest,
    cid: LabCid,
    entrypoint: Vec<u8>,
    data_dir: Option<PathBuf>,
}

/// The signer that admitted a capsule: the trusted key that verified it, the
/// installed signed release, or dev_mode's unsigned admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Signer {
    /// A trusted capsule-signing key, named by its `did:key`.
    Key { did: String },
    /// Admitted as a capsule of the installed signed release.
    InstalledRelease,
    /// Admitted unsigned because `dev_mode = true`.
    UnsignedDev,
}

/// Whether a start waits for the activation to end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    /// Wait for the guest's `run` to end: a CLI run, a bundle start, a test.
    Bounded,
    /// A component returns once its guest entered `run`, and stays in the
    /// registry until it ends. Other capsule types stay bounded.
    Detached,
}

/// One admitted agent's model identity and ceiling for one activation.
#[derive(Clone)]
struct AgentModelCeiling {
    ceiling: u64,
    key: AgentKey,
}

/// The main ElastOS runtime
pub struct Runtime {
    // Keep the storage provider alive for runtime/lifecycle ownership even
    // before direct storage API calls are exposed from this layer.
    _storage: Arc<dyn StorageProvider>,
    /// Compute providers (WASM, crosvm, etc.)
    compute_providers: Vec<Arc<dyn ComputeProvider>>,
    /// Signature verifier for capsule integrity
    signature_verifier: RwLock<SignatureVerifier>,
    /// Unsigned capsule admission; signed capsules always use the verifier.
    unsigned_capsules: RwLock<UnsignedCapsules>,
    /// Provider registry (optional, set when server mode is active)
    provider_registry: RwLock<Option<Arc<ProviderRegistry>>>,
    /// Registry of running capsules (for API queries). Shared with each
    /// activation's ending watcher so the entry it wrote at admission can be
    /// ended without the Runtime handle.
    running_capsules: Arc<RwLock<HashMap<String, RunningCapsuleInfo>>>,
    /// Agent starts share this gate so a replay cannot pass between grant
    /// consumption and registration of its running session. The activation's
    /// end holds the same mutex: it puts the start tuple on the one stop
    /// audit, then drops the record.
    agent_launches: Arc<tokio::sync::Mutex<AgentLaunchState>>,
    /// Live Stop tokens. A non-empty set is that agent's stopping mark.
    /// Lock order: `agent_launches`, then this mutex. It is held for a few
    /// instructions and never across an await. Drop takes only this mutex.
    stop_marks: Arc<StdMutex<AgentStopMarks>>,
    /// One live run per agent. Set when the run is admitted. Cleared when
    /// that run's ending releases it, and also when the start is dropped
    /// before the ending owns it. The token travels with the start that
    /// admitted it. `agent_launches` covers the grant check and the session
    /// record, not the load. `launch_turns` is one turn per agent, held from
    /// that check until the session record is stored, and by the end until
    /// it has read the record. Different agents do not share a turn.
    live_runs: Arc<StdMutex<AgentLiveRuns>>,
    launch_turns: Arc<StdMutex<HashMap<String, LaunchTurn>>>,
    /// Reference to the component provider for ABI-specific launch.
    component_provider: Option<Arc<ComponentProvider>>,
    /// Per-launch manifest capability ceilings for capsule bridge requests.
    bridge_manifest_capabilities: Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>>,
    /// Model-token ceiling for an admitted agent, by capsule id. A missing
    /// entry is not an admitted agent. Present, including 0, is the ceiling
    /// admission recorded and passed into the start. The manifest is not
    /// read again for this number.
    bridge_model_token_ceilings: Arc<StdRwLock<HashMap<String, AgentModelCeiling>>>,
    model_budget: Arc<ModelBudget>,
    model_offer_bounds: Arc<StdRwLock<HashMap<String, crate::resource_bridge::ModelOfferBound>>>,
    /// The capability store and manager a detached activation's end settles
    /// through, set with the provider registry. `None` is a Runtime with no
    /// capability plane (the CLI): an ending there has nothing to settle.
    instance_authority: StdRwLock<Option<InstanceAuthority>>,
    /// A detached activation's stop request, by its capsule id: the flag the
    /// bridge's wait loop reads and the cause its end records. It goes when
    /// the activation ends.
    activation_stops: Arc<StdRwLock<HashMap<String, Arc<ActivationStop>>>>,
    /// For each program a content launch is running, by its capsule id: the
    /// content it was launched with. Kept like the ceilings, beside them.
    launch_contents: Arc<StdRwLock<HashMap<String, Arc<LaunchContent>>>>,
    /// Launches kept for their page after the program's start is over, by a
    /// launch id of their own (`page_launch.rs`). The bridge never reads them.
    pub(crate) page_launches: crate::page_launch::PageLaunches,
    /// Test only: which stop-wait bound applies. The key is this token, not
    /// the heap address of `activation_stops`. Zero is the 40s default.
    #[cfg(test)]
    stop_wait_token: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct AgentLaunchState {
    used: HashMap<String, u64>,
    /// The start record for an agent session, keyed by session id. The
    /// session's one end removes it, whether the owner stopped the guest or
    /// the guest ended on its own.
    sessions: HashMap<String, AgentSessionRecord>,
    /// Set once Stop has asked a live row to end. Dropping Stop does not
    /// clear it. Start stays refused while a live row remains, and clears
    /// it once no live row remains.
    stop_requested: HashSet<String>,
}

/// One Stop's tokens. The mark is a non-empty set for that agent.
#[derive(Default)]
struct AgentStopMarks {
    tokens: HashMap<String, HashSet<u64>>,
    next: u64,
}

impl AgentStopMarks {
    fn holds(&self, agent_id: &str) -> bool {
        self.tokens.get(agent_id).is_some_and(|set| !set.is_empty())
    }
}

/// The facts a Start keeps so the owner's Stop can write the same tuple.
pub(crate) struct AgentStartFacts<'a> {
    pub(crate) agent_id: &'a str,
    pub(crate) owner: &'a str,
    pub(crate) host_cid: &'a str,
    pub(crate) launch_id: &'a str,
    pub(crate) expires_at: u64,
}

/// One agent session's audit tuple, stored at Start and taken at Stop.
#[derive(Clone)]
pub(crate) struct AgentSessionRecord {
    pub(crate) agent_id: String,
    pub(crate) owner: String,
    pub(crate) host_cid: String,
    pub(crate) launch_id: String,
    pub(crate) session_id: String,
}

/// One launch's content in the Runtime's table, for as long as this value
/// lives. It is put there when the value is made and taken away when the
/// value is dropped, however that happens: at the end of the start, or when
/// the start is cancelled and its future dropped.
struct LaunchHeld {
    table: Arc<StdRwLock<HashMap<String, Arc<LaunchContent>>>>,
    id: String,
}

impl LaunchHeld {
    fn new(
        table: &Arc<StdRwLock<HashMap<String, Arc<LaunchContent>>>>,
        id: &str,
        launch: Arc<LaunchContent>,
    ) -> Self {
        // A poisoned lock still holds the map: the entry goes in all the same,
        // as it goes out in `drop`.
        let mut launches = table.write().unwrap_or_else(|it| it.into_inner());
        launches.insert(id.to_string(), launch);
        drop(launches);
        Self {
            table: table.clone(),
            id: id.to_string(),
        }
    }
}

impl Drop for LaunchHeld {
    fn drop(&mut self) {
        // A poisoned lock still holds the map: the entry goes all the same.
        let mut launches = match self.table.write() {
            Ok(launches) => launches,
            Err(poisoned) => poisoned.into_inner(),
        };
        launches.remove(&self.id);
    }
}

/// The capability store and manager a detached activation's end settles and
/// revokes through: the same pair the bridge asked a grant from. A revoke
/// that store cannot save is kept in the pending revocation list of the Home
/// at `data_dir`.
#[derive(Clone)]
struct InstanceAuthority {
    pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
    data_dir: std::path::PathBuf,
}

/// The cause an activation records when the task watching it went away before
/// the guest's outcome was known.
const CAUSE_TASK_LOST: &str = "activation task ended before its outcome";

/// One detached activation's stop request (M1-R A10-R). `requested` is the
/// flag the bridge's wait loop reads, so a guest held inside a call leaves it
/// within one poll; `cause` is the reason the activation's one end records.
/// The cause is written before the flag is raised, so an end that sees the
/// flag always sees its reason.
struct ActivationStop {
    flag: Arc<crate::resource_bridge::ActivationStopFlag>,
    cause: StdMutex<Option<String>>,
}

impl ActivationStop {
    /// Records this stop's reason (`stopped: <reason>`) and raises the flag.
    /// The first reason recorded is the one the end records: a later stop
    /// keeps it.
    fn request(&self, reason: &str) {
        self.cause
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get_or_insert_with(|| format!("{CAPSULE_STOPPED}: {reason}"));
        self.flag.requested.store(true, Ordering::Release);
    }

    /// The reason this stop was requested with, if any.
    fn cause(&self) -> Option<String> {
        self.cause
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    /// Whether the bridge's wait loop left the guest's call because of this
    /// stop: then the stop, not the call, is what ended the guest.
    fn cancelled(&self) -> bool {
        self.flag.cancelled.load(Ordering::Acquire)
    }
}

/// Stop-wait bounds for tests. The key is a token stored on the Runtime,
/// not the heap address of `activation_stops`.
#[cfg(test)]
static TEST_STOP_WAITS: StdMutex<Vec<(u64, std::time::Duration)>> = StdMutex::new(Vec::new());

#[cfg(test)]
static NEXT_STOP_WAIT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// First observation of whether Stop had marked this agent before its rows
/// were read. Keyed by the launch gate so parallel tests stay apart.
#[cfg(test)]
static STOP_MARK_BEFORE_ROWS: StdMutex<Vec<(usize, String, Option<bool>)>> =
    StdMutex::new(Vec::new());

/// Pauses Stop after its token is set and before the registry is read.
#[cfg(test)]
struct StopRowsGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

/// Pauses or panics one admitted Start at a named await, after its live run
/// is set. Keyed by the live-run map so parallel tests stay apart.
#[cfg(test)]
struct LiveRunGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    panic: bool,
}

#[cfg(test)]
static LIVE_RUN_GATES: StdMutex<Vec<(usize, &'static str, LiveRunGate)>> =
    StdMutex::new(Vec::new());

/// Waits when a test armed `point` for this live-run map. An unarmed point
/// returns at once. The end uses the same gate as a Start.
#[cfg(test)]
async fn await_live_run_gate(key: usize, point: &'static str) {
    let gate = {
        let mut gates = LIVE_RUN_GATES.lock().unwrap_or_else(|err| err.into_inner());
        let Some(pos) = gates
            .iter()
            .rposition(|(stored, name, _)| *stored == key && *name == point)
        else {
            return;
        };
        gates.swap_remove(pos).2
    };
    if gate.panic {
        panic!("live run panic at {point}");
    }
    gate.entered.notify_one();
    gate.release.notified().await;
}

#[cfg(test)]
static REFUSE_AFTER_ADMIT: StdMutex<Vec<usize>> = StdMutex::new(Vec::new());

#[cfg(test)]
static STOP_ROWS_GATES: StdMutex<Vec<(usize, String, StopRowsGate)>> = StdMutex::new(Vec::new());

#[cfg(test)]
static STOP_PANIC_AFTER_MARK: StdMutex<Vec<(usize, String)>> = StdMutex::new(Vec::new());

#[cfg(test)]
pub(crate) struct StopRowsPause {
    pub(crate) entered: Arc<tokio::sync::Notify>,
    pub(crate) release: Arc<tokio::sync::Notify>,
}

/// Holds one armed live-run await. Drop removes it if the start never reached it.
#[cfg(test)]
pub(crate) struct LiveRunPause {
    pub(crate) entered: Arc<tokio::sync::Notify>,
    pub(crate) release: Arc<tokio::sync::Notify>,
    key: usize,
    point: &'static str,
}

#[cfg(test)]
impl Drop for LiveRunPause {
    fn drop(&mut self) {
        let mut gates = LIVE_RUN_GATES.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(pos) = gates
            .iter()
            .rposition(|(stored, name, _)| *stored == self.key && *name == self.point)
        {
            gates.swap_remove(pos);
        }
    }
}

/// Holds one armed refusal after admission. Drop removes it if the start never took it.
#[cfg(test)]
pub(crate) struct RefuseAfterAdmit {
    key: usize,
}

#[cfg(test)]
impl Drop for RefuseAfterAdmit {
    fn drop(&mut self) {
        let mut armed = REFUSE_AFTER_ADMIT
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(pos) = armed.iter().rposition(|stored| *stored == self.key) {
            armed.swap_remove(pos);
        }
    }
}

#[cfg(test)]
pub(crate) struct StopWaitLimit {
    token: u64,
}

#[cfg(test)]
impl Drop for StopWaitLimit {
    fn drop(&mut self) {
        let mut waits = TEST_STOP_WAITS
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        waits.retain(|(token, _)| *token != self.token);
    }
}

/// Clears this Stop's token when Stop returns or is dropped. It does not
/// clear another Stop's token, and it does not clear `stop_requested`.
pub(crate) struct AgentStopGuard {
    marks: Arc<StdMutex<AgentStopMarks>>,
    agent_id: String,
    token: u64,
}

impl Drop for AgentStopGuard {
    fn drop(&mut self) {
        let mut marks = self.marks.lock().unwrap_or_else(|err| err.into_inner());
        let Some(set) = marks.tokens.get_mut(&self.agent_id) else {
            return;
        };
        set.remove(&self.token);
        if set.is_empty() {
            marks.tokens.remove(&self.agent_id);
        }
    }
}

/// Admitted runs, one set per agent. A non-empty set is that agent's live run.
/// The mutex is held for a few instructions and never across an await.
#[derive(Default)]
struct AgentLiveRuns {
    tokens: HashMap<String, HashSet<u64>>,
    next: u64,
    /// A planted registry row's token, so ending that row removes the same one.
    #[cfg(test)]
    planted: HashMap<String, (String, u64)>,
}

impl AgentLiveRuns {
    fn holds(&self, agent_id: &str) -> bool {
        self.tokens.get(agent_id).is_some_and(|set| !set.is_empty())
    }

    fn admit(&mut self, agent_id: &str) -> u64 {
        let token = self.next;
        self.next = self.next.wrapping_add(1);
        self.tokens
            .entry(agent_id.to_string())
            .or_default()
            .insert(token);
        token
    }

    fn clear(&mut self, agent_id: &str, token: u64) {
        let Some(set) = self.tokens.get_mut(agent_id) else {
            return;
        };
        set.remove(&token);
        if set.is_empty() {
            self.tokens.remove(agent_id);
        }
    }
}

/// One agent's start and its end share this turn. Different agents do not.
type LaunchTurn = Arc<tokio::sync::Mutex<()>>;

/// Owns one admitted run. Dropping it, by the ending, a cancel, a panic, or a
/// refusal after admission, removes only this token.
struct AgentLiveRun {
    runs: Arc<StdMutex<AgentLiveRuns>>,
    agent_id: String,
    token: u64,
}

impl Drop for AgentLiveRun {
    fn drop(&mut self) {
        let mut runs = self.runs.lock().unwrap_or_else(|err| err.into_inner());
        runs.clear(&self.agent_id, self.token);
    }
}

/// Where an end that is still owed runs when its guard is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwedEnd {
    /// In a task of the current runtime.
    Task,
    /// On a thread of its own: the task was dropped before the end finished,
    /// as a runtime shutting down drops the tasks it has not run.
    Thread,
    /// Nowhere: the thread could not finish it either.
    Lost,
}

/// Owns a detached component's admission context until its watcher has
/// ended it. One ending, however the activation ends: the worker is stopped,
/// the session's pending requests are denied and its grants revoked, the
/// ceiling and principal go away, one `capsule_stop` is audited with the
/// cause, and the registry entry records the status, cause and end. Nothing
/// here starts the activation again.
struct ActivationContextHeld {
    id: elastos_common::CapsuleId,
    handle: CapsuleHandle,
    component: Arc<ComponentProvider>,
    registry: Arc<RwLock<HashMap<String, RunningCapsuleInfo>>>,
    manifest_capabilities: Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>>,
    model_token_ceilings: Arc<StdRwLock<HashMap<String, AgentModelCeiling>>>,
    activation_stops: Arc<StdRwLock<HashMap<String, Arc<ActivationStop>>>>,
    /// The launch contents, by capsule id: a content launch's program reads
    /// its content from here until its end, and no other activation does.
    launch_contents: Arc<StdRwLock<HashMap<String, Arc<LaunchContent>>>>,
    /// This activation's stop request, the same value the bridge and the stop
    /// route hold.
    stop: Arc<ActivationStop>,
    authority: Option<InstanceAuthority>,
    /// Start records for agent sessions. The one end reads the tuple onto
    /// its stop audit, then removes the record once `ended_at` is visible.
    agent_sessions: Arc<tokio::sync::Mutex<AgentLaunchState>>,
    /// This activation's live-run token. The ending drops it after the row
    /// records `ended_at`, or when this value is dropped without that ending.
    live_run: Option<AgentLiveRun>,
    /// The same turns the start holds until the session record is stored.
    launch_turns: Arc<StdMutex<HashMap<String, LaunchTurn>>>,
    /// How long the ended entry stays before the sweeper removes it:
    /// [`ENDED_CAPSULE_RETENTION`], which only a unit row shortens.
    retention: std::time::Duration,
    /// The end is owed until the registry entry records it.
    armed: bool,
    owed: OwedEnd,
    /// The status and cause the session was settled with, so an end run
    /// again after a lost task records and audits the same ones.
    settled: Option<(String, String)>,
    audited: bool,
}

impl ActivationContextHeld {
    fn new(
        runtime: &Runtime,
        handle: &CapsuleHandle,
        component: Arc<ComponentProvider>,
        live_run: Option<AgentLiveRun>,
    ) -> Self {
        let authority = runtime
            .instance_authority
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        // The stop request lives as long as the activation: the bridge looks
        // it up by capsule id on every call, and the stop route by instance id.
        let stop = Arc::new(ActivationStop {
            flag: Arc::new(crate::resource_bridge::ActivationStopFlag::default()),
            cause: StdMutex::new(None),
        });
        runtime
            .activation_stops
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .insert(handle.id.0.clone(), stop.clone());
        Self {
            id: handle.id.clone(),
            handle: handle.clone(),
            component,
            registry: runtime.running_capsules.clone(),
            retention: ENDED_CAPSULE_RETENTION,
            manifest_capabilities: runtime.bridge_manifest_capabilities.clone(),
            model_token_ceilings: runtime.bridge_model_token_ceilings.clone(),
            activation_stops: runtime.activation_stops.clone(),
            launch_contents: runtime.launch_contents.clone(),
            stop,
            authority,
            agent_sessions: runtime.agent_launches.clone(),
            live_run,
            launch_turns: Arc::clone(&runtime.launch_turns),
            armed: true,
            owed: OwedEnd::Task,
            settled: None,
            audited: false,
        }
    }

    /// The reason a stop was requested with, if it was.
    fn requested_stop(&self) -> Option<String> {
        self.stop.cause()
    }

    /// Whether the bridge left the guest's call because of its stop.
    fn stop_cancelled_guest(&self) -> bool {
        self.stop.cancelled()
    }

    /// The turn this agent's start holds until the session record is stored.
    /// The end takes it before reading that record, so the read cannot pass
    /// the insert.
    async fn hold_launch_turn(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let agent_id = self.live_run.as_ref()?.agent_id.clone();
        let turn = self
            .launch_turns
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(&agent_id)?
            .clone();
        Some(turn.lock_owned().await)
    }

    /// Takes away what the start put in place: the provider's activation
    /// entry and the principal the guest ran for, the manifest ceiling, the
    /// model-token ceiling and the launch content. It is called at the one
    /// end of every detached activation, before the entry records the end,
    /// so nothing of the instance is left for a reader or a late bridge call.
    /// The stop request is not this method's: the entry's end takes it away
    /// after the write, so a racing stop still finds it.
    async fn release(&mut self) {
        crate::resource_bridge::forget_agent_plan_dispatch_authority(&self.id.0);
        self.component.forget_instance(&self.id).await;
        if let Ok(mut bounds) = self.manifest_capabilities.write() {
            bounds.remove(&self.id.0);
        }
        self.model_token_ceilings
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id.0);
        self.launch_contents
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id.0);
    }

    /// The one ending of a detached activation (M1-R A11-R). `status` is
    /// `failed` with this `cause`, or `stopped` with its own. The session's
    /// pending requests are denied by the Runtime and its grants revoked
    /// before the context goes; the stop is audited once; and the entry is
    /// written last, so a reader that sees `ended_at` also sees that nothing
    /// of the activation is left. A revoke the store could not save ends the
    /// entry `failed`, with a cause that names it. The stop request is taken
    /// away only after the entry records the end, so a stop that finds the
    /// entry not ended also finds its request. Its retention is timed from
    /// that write: the entry's removal goes to the [`RETENTION_SWEEPER`]
    /// here, so it happens at its 60 s even if nothing lists or registers
    /// again and every tokio runtime has shut down.
    async fn end_instance(mut self, status: &str, cause: &str) {
        let (status, cause) = match self.settled.clone() {
            Some(settled) => settled,
            None => {
                // An activation that already ended has no entry to stop; an
                // ending one keeps it until its worker sees the stop flag.
                let _ = self.component.stop(&self.handle).await;
                let settled = match &self.authority {
                    Some(authority) => {
                        crate::api::handlers::settle::settle_and_revoke_guests(
                            &authority.pending_store,
                            &authority.capability_manager,
                            &authority.data_dir,
                            &self.id.0,
                            cause,
                            Some(self.component.as_ref()),
                        )
                        .await
                    }
                    None => Ok(()),
                };
                let ended = match settled {
                    Ok(()) => (status.to_string(), cause.to_string()),
                    Err(error) => (
                        CAPSULE_FAILED.to_string(),
                        format!("{cause}; revocation not saved: {error}"),
                    ),
                };
                self.settled = Some(ended.clone());
                ended
            }
        };
        self.release().await;
        #[cfg(test)]
        let ended_key = self
            .live_run
            .as_ref()
            .map(|run| std::sync::Arc::as_ptr(&run.runs) as usize);
        let _turn = self.hold_launch_turn().await;
        if let (Some(authority), false) = (&self.authority, self.audited) {
            let record = self
                .agent_sessions
                .lock()
                .await
                .sessions
                .get(&self.id.0)
                .cloned();
            let reason = stop_reason(&status, &cause);
            let log = authority.capability_manager.audit_log();
            match record {
                Some(record) => log.emit(AuditEvent::CapsuleStop {
                    timestamp: SecureTimestamp::now(),
                    capsule_id: self.id.0.clone(),
                    reason,
                    agent_id: Some(record.agent_id),
                    owner: Some(record.owner),
                    cid: Some(record.host_cid),
                    launch_id: Some(record.launch_id),
                    session_id: Some(record.session_id),
                }),
                None => log.capsule_stop(&self.id.0, reason),
            }
            self.audited = true;
        }
        let ended_at = std::time::Instant::now();
        let mut capsules = self.registry.write().await;
        let recorded = if let Some(info) = capsules.get_mut(&self.id.0) {
            if info.ended_at.is_none() {
                info.status = status.to_string();
                info.cause = Some(cause.to_string());
                info.ended_at = Some(ended_at);
                true
            } else {
                false
            }
        } else {
            false
        };
        drop(capsules);

        // The live run stays until this end is visible. Clearing it inside
        // `release`, before this write, would admit a second run while this
        // row is still live. A start that never records a row, such as a
        // launch cancelled before registration, still drops the token here.
        #[cfg(test)]
        if let Some(key) = ended_key {
            await_live_run_gate(key, "ended").await;
        }
        drop(self.live_run.take());

        // The start record goes after `ended_at` is visible. A reader that
        // finds no record also finds the session ended, so a second stop does
        // not treat a live guest as a missing record.
        self.agent_sessions.lock().await.sessions.remove(&self.id.0);

        // The stop request is taken away only after the entry records the
        // end, so a stop that finds the entry not ended also finds its
        // request.
        self.activation_stops
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id.0);
        self.armed = false;

        // The sweeper removes the entry at its retention, whichever runtime
        // ran the end and whether or not the start runtime still lives. A
        // reader that pruned it first, or an entry a later start replaced,
        // leaves the removal a no-op: only this end's own `ended_at` goes.
        if recorded {
            RETENTION_SWEEPER.schedule(
                &self.registry,
                &self.id.0,
                ended_at,
                ended_at + self.retention,
            );
        }
    }

    /// This guard's owed end, moved into a new guard; this one is left
    /// disarmed.
    fn take_owed(&mut self) -> Self {
        self.armed = false;
        ActivationContextHeld {
            id: self.id.clone(),
            handle: self.handle.clone(),
            component: self.component.clone(),
            registry: self.registry.clone(),
            retention: self.retention,
            manifest_capabilities: self.manifest_capabilities.clone(),
            model_token_ceilings: self.model_token_ceilings.clone(),
            activation_stops: self.activation_stops.clone(),
            launch_contents: self.launch_contents.clone(),
            stop: self.stop.clone(),
            authority: self.authority.clone(),
            agent_sessions: self.agent_sessions.clone(),
            live_run: self.live_run.take(),
            launch_turns: Arc::clone(&self.launch_turns),
            armed: true,
            owed: self.owed,
            settled: self.settled.take(),
            audited: self.audited,
        }
    }

    /// Test only: a retention short enough for a row to wait out in real
    /// time, since the sweeper runs on the real clock.
    #[cfg(test)]
    fn retained_for(mut self, retention: std::time::Duration) -> Self {
        self.retention = retention;
        self
    }
}

/// The audit reason one ending carries. A trap is the activation's error; a
/// natural return completed; anything else was stopped.
fn stop_reason(status: &str, cause: &str) -> elastos_runtime::primitives::audit::StopReason {
    use elastos_runtime::primitives::audit::StopReason;
    match status {
        CAPSULE_STOPPED if cause == CAUSE_COMPLETED => StopReason::Completed,
        CAPSULE_STOPPED => StopReason::Requested,
        _ => StopReason::Error(cause.to_string()),
    }
}

/// Whether a start that failed is the stop's doing: the stop took the loading
/// component away, or the epoch callback interrupted its start function. Any
/// other failed start is the guest's own.
fn start_ended_by_stop(err: &ElastosError) -> bool {
    match err {
        ElastosError::CapsuleNotFound(_) => true,
        ElastosError::Compute(message) => message == STOPPED_BEFORE_RUN,
        _ => false,
    }
}

impl Drop for ActivationContextHeld {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.owed == OwedEnd::Lost {
            self.armed = false;
            tracing::error!("activation {}: its end could not run", self.id.0);
            return;
        }
        // The watcher, or the task running the end, went away before the end
        // was recorded. The end still runs, once, from where it got to: in a
        // task first, and on a thread of its own if that task is dropped too.
        // The new guard stays armed until its end is recorded.
        let mut end = self.take_owed();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) if end.owed == OwedEnd::Task => {
                end.owed = OwedEnd::Thread;
                runtime.spawn(end.end_instance(CAPSULE_FAILED, CAUSE_TASK_LOST));
            }
            _ => {
                end.owed = OwedEnd::Lost;
                let thread = std::thread::Builder::new().name("activation-end".into());
                let spawned = thread.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(runtime) = runtime {
                        runtime.block_on(end.end_instance(CAPSULE_FAILED, CAUSE_TASK_LOST));
                    }
                });
                if let Err(error) = spawned {
                    tracing::error!(%error, "activation {}: no thread for its end", self.id.0);
                }
            }
        }
    }
}

/// The only place a by-CID start can build a [`VerifiedBundle`].
///
/// The struct's fields are private to this module. A struct literal written
/// outside it, including one shaped `Ok(VerifiedBundle { ... })`, does not
/// compile. [`VerifiedBundle::check`] is the function here that builds one.
mod verified_bundle {
    use std::path::Path;

    use elastos_bundle_identity::{CheckedBundle, LabCid};
    use elastos_common::CapsuleManifest;
    use elastos_runtime::signature::SignatureVerifier;

    use crate::bundle_admission::{
        self, AcceptedSignature, AdmittedBundle, BundleKind, BundleRefusal,
    };

    /// A bundle the by-CID start has checked. The walked CID is the one asked
    /// for, a publisher this Home trusts signed it, and the manifest was
    /// admitted. A program loads from [`VerifiedBundle::into_component`].
    /// The signature this start reports is the [`AcceptedSignature`] returned
    /// beside the bundle, not a field of the bundle.
    pub(crate) struct VerifiedBundle {
        cid: LabCid,
        admitted: AdmittedBundle,
    }

    impl VerifiedBundle {
        /// Builds the bundle the start keeps. The walked CID equals `asked`,
        /// the signature verifies under `trust`, the manifest is admitted,
        /// and a program's imports pass.
        pub(crate) fn check(
            bundle: &CheckedBundle,
            asked: &LabCid,
            signature: &Path,
            trust: &SignatureVerifier,
        ) -> std::result::Result<(Self, AcceptedSignature), BundleRefusal> {
            if bundle.cid() != *asked {
                return Err(BundleRefusal::CidMismatch {
                    asked: asked.to_string(),
                    computed: bundle.cid().to_string(),
                });
            }
            let accepted = bundle_admission::check_bundle_signature(signature, asked, trust)?;
            let admitted = bundle_admission::admit_bundle_manifest(bundle)?;
            if admitted.kind == BundleKind::Program {
                crate::component::validate_component_imports_for_manifest(
                    &admitted.component,
                    &admitted.manifest,
                )
                .map_err(BundleRefusal::NotAComponent)?;
            }
            Ok((
                VerifiedBundle {
                    cid: *asked,
                    admitted,
                },
                accepted,
            ))
        }

        pub(crate) fn cid(&self) -> &LabCid {
            &self.cid
        }

        pub(crate) fn kind(&self) -> BundleKind {
            self.admitted.kind
        }

        pub(crate) fn manifest(&self) -> &CapsuleManifest {
            &self.admitted.manifest
        }

        pub(crate) fn pins(&self) -> &[(String, String)] {
            &self.admitted.pins
        }

        pub(crate) fn take_pins(&mut self) -> Vec<(String, String)> {
            std::mem::take(&mut self.admitted.pins)
        }

        pub(crate) fn take_files(&mut self) -> std::collections::BTreeMap<String, Vec<u8>> {
            std::mem::take(&mut self.admitted.files)
        }

        /// The manifest and the entrypoint bytes the loader compiles.
        pub(crate) fn into_component(self) -> (CapsuleManifest, Vec<u8>) {
            (self.admitted.manifest, self.admitted.component)
        }
    }
}

use verified_bundle::VerifiedBundle;

/// Test only: the four tables the installed bridge host call reads for one
/// capsule id, so a row can make a late call under exactly what an end left.
#[cfg(test)]
pub(crate) struct BridgeTables {
    pub manifest_capabilities: Vec<AuthorityBound>,
    pub launch: Option<Arc<LaunchContent>>,
    pub model_token_ceiling: Option<u64>,
    pub stop: Option<Arc<crate::resource_bridge::ActivationStopFlag>>,
}

impl Runtime {
    /// The v2 guests this runtime hosts. The owner's revoke routes tell them.
    pub(crate) fn component_guests(&self) -> Option<Arc<ComponentProvider>> {
        self.component_provider.clone()
    }

    /// Create a new runtime with a single compute provider (backward compatible)
    pub fn new(storage: Arc<dyn StorageProvider>, compute: Arc<dyn ComputeProvider>) -> Self {
        Self {
            _storage: storage,
            compute_providers: vec![compute],
            signature_verifier: RwLock::new(SignatureVerifier::new()),
            unsigned_capsules: RwLock::new(UnsignedCapsules::Refused(None)),
            provider_registry: RwLock::new(None),
            running_capsules: Arc::new(RwLock::new(HashMap::new())),
            agent_launches: Arc::new(tokio::sync::Mutex::new(AgentLaunchState::default())),
            stop_marks: Arc::new(StdMutex::new(AgentStopMarks::default())),
            live_runs: Arc::new(StdMutex::new(AgentLiveRuns::default())),
            launch_turns: Arc::new(StdMutex::new(HashMap::new())),
            component_provider: None,
            bridge_manifest_capabilities: Arc::new(StdRwLock::new(HashMap::new())),
            bridge_model_token_ceilings: Arc::new(StdRwLock::new(HashMap::new())),
            model_budget: Arc::new(ModelBudget::new()),
            model_offer_bounds: Arc::new(StdRwLock::new(HashMap::new())),
            instance_authority: StdRwLock::new(None),
            activation_stops: Arc::default(),
            launch_contents: Arc::default(),
            page_launches: Default::default(),
            #[cfg(test)]
            stop_wait_token: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_providers_and_component(
        storage: Arc<dyn StorageProvider>,
        compute_providers: Vec<Arc<dyn ComputeProvider>>,
        component_provider: Option<Arc<ComponentProvider>>,
    ) -> Self {
        Self {
            _storage: storage,
            compute_providers,
            signature_verifier: RwLock::new(SignatureVerifier::new()),
            unsigned_capsules: RwLock::new(UnsignedCapsules::Refused(None)),
            provider_registry: RwLock::new(None),
            running_capsules: Arc::new(RwLock::new(HashMap::new())),
            agent_launches: Arc::new(tokio::sync::Mutex::new(AgentLaunchState::default())),
            stop_marks: Arc::new(StdMutex::new(AgentStopMarks::default())),
            live_runs: Arc::new(StdMutex::new(AgentLiveRuns::default())),
            launch_turns: Arc::new(StdMutex::new(HashMap::new())),
            component_provider,
            bridge_manifest_capabilities: Arc::new(StdRwLock::new(HashMap::new())),
            bridge_model_token_ceilings: Arc::new(StdRwLock::new(HashMap::new())),
            model_budget: Arc::new(ModelBudget::new()),
            model_offer_bounds: Arc::new(StdRwLock::new(HashMap::new())),
            instance_authority: StdRwLock::new(None),
            activation_stops: Arc::default(),
            launch_contents: Arc::default(),
            page_launches: Default::default(),
            #[cfg(test)]
            stop_wait_token: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Runs one bridge future on `handle`, on this thread. A `spawn_blocking`
    /// worker whose runtime handle is entered stays on that thread too.
    pub(crate) fn block_on_component_bridge<T>(
        handle: &tokio::runtime::Handle,
        leg: ComponentBridgeLeg,
        fut: impl std::future::Future<Output = T> + Send,
    ) -> T
    where
        T: Send,
    {
        let ComponentBridgeLeg::Caller = leg;
        handle.block_on(fut)
    }

    /// The model account a capsule's bridge calls spend. The key is the agent
    /// admission stored for that capsule, so every session of the agent shares
    /// one ceiling. A missing entry is not an admitted agent.
    fn model_dispatch_budget(
        capsule_id: &str,
        ceilings: &StdRwLock<HashMap<String, AgentModelCeiling>>,
        account: &Arc<ModelBudget>,
        offers: &Arc<StdRwLock<HashMap<String, crate::resource_bridge::ModelOfferBound>>>,
    ) -> (
        Option<u64>,
        Option<crate::resource_bridge::ModelDispatchBudget>,
    ) {
        let held = ceilings
            .read()
            .unwrap_or_else(|it| it.into_inner())
            .get(capsule_id)
            .cloned();
        let ceiling = held.as_ref().map(|held| held.ceiling);
        let budget = held.map(|held| crate::resource_bridge::ModelDispatchBudget {
            agent: held.key,
            account: account.clone(),
            offers: offers.clone(),
        });
        (ceiling, budget)
    }

    /// Set the provider registry and capability manager for provider dispatch
    /// and real token minting.
    ///
    /// Also configures the component hostcall so component capsules can
    /// communicate with providers through Runtime-controlled authority.
    pub async fn set_provider_registry(
        &self,
        registry: Arc<ProviderRegistry>,
        capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        data_dir: std::path::PathBuf,
    ) {
        // A detached activation's end settles through this pair, so it is held
        // from here rather than read again at the end.
        *self
            .instance_authority
            .write()
            .unwrap_or_else(|err| err.into_inner()) = Some(InstanceAuthority {
            pending_store: pending_store.clone(),
            capability_manager: capability_manager.clone(),
            data_dir: data_dir.clone(),
        });
        if let Some(ref component) = self.component_provider {
            let host_reg = registry.clone();
            let host_cap_mgr = capability_manager.clone();
            let host_pending = pending_store.clone();
            let host_data_dir = data_dir.clone();
            let host_manifest_capabilities = self.bridge_manifest_capabilities.clone();
            let host_model_token_ceilings = self.bridge_model_token_ceilings.clone();
            let host_model_budget = self.model_budget.clone();
            let host_model_offer_bounds = self.model_offer_bounds.clone();
            let host_activation_stops = self.activation_stops.clone();
            let host_launch_contents = self.launch_contents.clone();
            let host_handle = tokio::runtime::Handle::current();
            let bridge_call: BridgeHostcallAsync =
                Arc::new(move |line, capsule_id, principal_id| {
                    let manifest_capabilities = host_manifest_capabilities
                        .read()
                        .ok()
                        .and_then(|guard| guard.get(capsule_id).cloned())
                        .unwrap_or_default();
                    // The content this caller was launched with, if it is the
                    // program of a content launch: looked up by its own id, as
                    // its ceiling is, and nobody else's. A poisoned lock still
                    // holds the table, as for the guard. The read guard ends with
                    // this statement: it is not held across the call below, so an
                    // activation's end can take the content away while another
                    // guest is inside the bridge.
                    let launch = host_launch_contents
                        .read()
                        .unwrap_or_else(|it| it.into_inner())
                        .get(capsule_id)
                        .cloned();
                    let (model_token_ceiling, model_budget) = Self::model_dispatch_budget(
                        capsule_id,
                        &host_model_token_ceilings,
                        &host_model_budget,
                        &host_model_offer_bounds,
                    );
                    // The stop this activation was asked for, if any: the bridge's
                    // wait loop leaves a long capability wait through it.
                    let stop = host_activation_stops
                        .read()
                        .unwrap_or_else(|it| it.into_inner())
                        .get(capsule_id)
                        .map(|stop| stop.flag.clone());
                    let ctx = crate::resource_bridge::BridgeContext {
                        provider_registry: host_reg.clone(),
                        capability_manager: host_cap_mgr.clone(),
                        pending_store: host_pending.clone(),
                        capsule_id: capsule_id.to_string(),
                        // The provider minted this id for the one activation, so
                        // the Runtime session is the activation, taken here from
                        // the Runtime's own hostcall and never from the Bus
                        // identity field the guest reads.
                        session_id: capsule_id.to_string(),
                        principal_id: principal_id.map(ToOwned::to_owned),
                        manifest_capabilities,
                        data_dir: Some(host_data_dir.clone()),
                        launch,
                        model_token_ceiling,
                        model_budget,
                        stop,
                    };
                    let line = line.to_string();
                    Box::pin(async move {
                        let response =
                            crate::resource_bridge::handle_component_resource_request(&line, ctx)
                                .await
                                .map_err(|err| err.to_string())?;
                        serde_json::to_string(&response).map_err(|err| err.to_string())
                    })
                        as std::pin::Pin<
                            Box<
                                dyn std::future::Future<
                                        Output = std::result::Result<String, String>,
                                    > + Send,
                            >,
                        >
                });
            let bridge_for_v1 = bridge_call.clone();
            component.set_bus_hostcall_async(bridge_call);
            // v1 stays on the caller thread. The leg is Caller, so this does
            // not start a thread. v2 awaits `bridge_call` and never comes here.
            component.set_bus_hostcall(Arc::new(move |line, capsule_id, principal_id| {
                Self::block_on_component_bridge(
                    &host_handle,
                    component_bridge_leg(),
                    bridge_for_v1(line, capsule_id, principal_id),
                )
            }));
            tracing::info!("Component resource bridge configured");
        }

        let mut guard = self.provider_registry.write().await;
        *guard = Some(registry);
    }

    /// Override the default local capsule carrier host-call handler.
    ///
    /// Used by attached-runtime execution to route guest calls
    /// through the already-running local runtime API.
    pub fn set_bridge_hostcall(&self, hostcall: BridgeHostcall) {
        if let Some(ref component) = self.component_provider {
            component.set_bus_hostcall(hostcall);
        }
    }

    /// The admitted ceiling held for a running capsule. An attached bridge
    /// uses this value so a folder selector cannot supply a different manifest.
    pub fn bridge_bounds_for_capsule(&self, id: &str) -> Option<Vec<AuthorityBound>> {
        self.bridge_manifest_capabilities
            .read()
            .ok()
            .and_then(|bounds| bounds.get(id).cloned())
    }

    /// Find a compute provider that supports the given capsule type
    fn get_provider(&self, capsule_type: &CapsuleType) -> Option<Arc<dyn ComputeProvider>> {
        self.compute_providers
            .iter()
            .find(|p| p.supports(capsule_type))
            .cloned()
    }

    fn get_provider_for_manifest(
        &self,
        manifest: &CapsuleManifest,
    ) -> Option<Arc<dyn ComputeProvider>> {
        if manifest.is_component_capsule() {
            return self
                .component_provider
                .as_ref()
                .map(|provider| provider.clone() as Arc<dyn ComputeProvider>);
        }
        if matches!(
            manifest.execution_type(),
            CapsuleType::Wasm
                | CapsuleType::WebProjection
                | CapsuleType::NativeProvider
                | elastos_common::CapsuleType::NativeHost
        ) {
            return None;
        }
        self.get_provider(&manifest.capsule_type)
    }

    /// Configure capsule admission for the Home at `data_dir`.
    ///
    /// An installed signed release always enforces signatures: its publisher
    /// keys and `trusted_keys` verify signed capsules, and an unsigned capsule
    /// is admitted only when setup installed it from that release by CID. Other
    /// Homes admit unsigned capsules only with `dev_mode = true`, which source
    /// and CI Homes set explicitly.
    pub async fn configure_capsule_admission(
        &self,
        data_dir: &Path,
        trusted_keys: &[String],
        dev_mode: bool,
    ) -> Result<()> {
        let installed = crate::setup::installed_release_source(data_dir)
            .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;
        let mut verifier = SignatureVerifier::new();
        for key in trusted_keys {
            verifier.add_trusted_key_hex(key)?;
        }
        for did in installed.iter().flat_map(|source| &source.publisher_dids) {
            let key = crate::crypto::decode_did_key(did)
                .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;
            verifier.add_trusted_key(key)?;
        }
        let trusted_key_count = verifier.trusted_key_count();
        let unsigned = match (installed, dev_mode) {
            (Some(_), _) => UnsignedCapsules::InstalledRelease(data_dir.to_path_buf()),
            (None, true) => UnsignedCapsules::Allowed,
            (None, false) => UnsignedCapsules::Refused(Some(data_dir.to_path_buf())),
        };
        match &unsigned {
            UnsignedCapsules::Allowed => tracing::warn!(
                "Capsule signature verification running in dev_mode=true; unsigned local capsules are allowed"
            ),
            UnsignedCapsules::InstalledRelease(_) => tracing::info!(
                "Capsule signatures enforced for the installed release with {} trusted key(s); unsigned capsules only from the signed release{}",
                trusted_key_count,
                if dev_mode { " (config.toml dev_mode does not apply)" } else { "" }
            ),
            UnsignedCapsules::Refused(_) => tracing::info!(
                "Capsule signatures enforced with {} trusted key(s)",
                trusted_key_count
            ),
        }
        *self.signature_verifier.write().await = verifier;
        *self.unsigned_capsules.write().await = unsigned;
        Ok(())
    }

    /// Check a bundle's signature file against the keys this Home trusts:
    /// the same verifier, with the same keys, as every other admission here.
    pub async fn check_bundle_signature(
        &self,
        file: &Path,
        cid: &LabCid,
    ) -> std::result::Result<AcceptedSignature, BundleRefusal> {
        let verifier = self.signature_verifier.read().await;
        bundle_admission::check_bundle_signature(file, cid, &verifier)
    }

    /// Load and run a capsule from a local directory
    pub async fn run_local(&self, path: &Path, args: Vec<String>) -> Result<CapsuleHandle> {
        self.run_local_with_principal(path, args, None).await
    }

    /// Explicit unsigned Component start for a source or CI Home. An installed
    /// signed release never enters this mode, even if config.toml enables it.
    pub async fn run_unsigned_development_component(
        &self,
        path: &Path,
        args: Vec<String>,
    ) -> Result<CapsuleHandle> {
        if !matches!(
            *self.unsigned_capsules.read().await,
            UnsignedCapsules::Allowed
        ) {
            return Err(ElastosError::InvalidManifest(
                "--dev-unsigned-component requires a source Home with dev_mode = true; installed releases refuse it".into(),
            ));
        }
        let manifest_bytes = tokio::fs::read(path.join("capsule.json"))
            .await
            .map_err(|error| ElastosError::InvalidManifest(error.to_string()))?;
        let manifest: CapsuleManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| ElastosError::InvalidManifest(error.to_string()))?;
        manifest.validate().map_err(ElastosError::InvalidManifest)?;
        if !manifest.is_component_capsule() {
            return Err(ElastosError::InvalidManifest(
                "--dev-unsigned-component requires a Component manifest".into(),
            ));
        }
        if manifest.signature.is_some() {
            return Err(ElastosError::InvalidManifest(
                "--dev-unsigned-component accepts only unsigned Components; stage a signed bundle"
                    .into(),
            ));
        }
        self.run_local(path, args).await
    }

    /// Load and run a capsule from a local directory with an optional runtime
    /// principal for current-user storage alias resolution.
    pub async fn run_local_with_principal(
        &self,
        path: &Path,
        args: Vec<String>,
        principal_id: Option<crate::resource_bridge::BridgePrincipal>,
    ) -> Result<CapsuleHandle> {
        self.run_local_with_signer(path, args, principal_id)
            .await
            .map(|(handle, _signer)| handle)
    }

    /// Load and run a capsule, also returning the signer admission verified.
    /// An agent's own principal reaches no launch here: only an admitted
    /// launch may hand the bridge a stored agent's id.
    pub(crate) async fn run_local_with_signer(
        &self,
        path: &Path,
        args: Vec<String>,
        principal_id: Option<crate::resource_bridge::BridgePrincipal>,
    ) -> Result<(CapsuleHandle, Signer)> {
        self.run_signer(
            path,
            args,
            (principal_id, None),
            None,
            LaunchMode::Bounded,
            (|_| {}, |_| {}),
        )
        .await
    }

    /// [`Self::run_local_with_signer`] with the moments around the folder
    /// gate's one walk. Tests change the folder before the walk, as another
    /// process could, to show that the manifest the gate checks and the bytes
    /// that load are the ones that one walk read; and after the walk to show
    /// that nothing reads the folder again.
    #[cfg(test)]
    pub(crate) async fn run_local_with_signer_observed(
        &self,
        path: &Path,
        args: Vec<String>,
        before_folder_walk: impl FnOnce(&Path) + Send,
        after_folder_walk: impl FnOnce(&CheckedBundle) + Send,
    ) -> Result<(CapsuleHandle, Signer)> {
        self.run_signer(
            path,
            args,
            (None, None),
            None,
            LaunchMode::Bounded,
            (before_folder_walk, after_folder_walk),
        )
        .await
    }

    /// Start a capsule and return after admission, while its component worker
    /// starts. A component activation stays in the registry (session, status,
    /// cause) until it ends; a non-component start is still bounded and has
    /// nothing to register. This is the launch route's entry.
    pub(crate) async fn start_local_with_signer(
        &self,
        path: &Path,
        args: Vec<String>,
        principal_id: Option<crate::resource_bridge::BridgePrincipal>,
        grant_name: Option<&str>,
    ) -> Result<(CapsuleHandle, Signer)> {
        self.run_signer(
            path,
            args,
            (principal_id, grant_name),
            None,
            LaunchMode::Detached,
            (|_| {}, |_| {}),
        )
        .await
    }

    /// The same start for a launch that admitted its principal. `actor` is the
    /// admission context's stored agent id, and it is the only way an agent's
    /// id reaches a bridge principal. The manifest and the entrypoint are the
    /// exact bytes admission walked; this reads neither back from `path`.
    /// The bounded admitted start: waits for the guest's `run` to end. Kept
    /// beside [`Self::start_local_admitted`] because it is the call the launch
    /// route's F-sync falsifier restores, and the agent rows that assert a
    /// whole run use it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn run_local_admitted(
        &self,
        path: &Path,
        args: Vec<String>,
        admission: crate::agent_admission::AdmissionContext,
    ) -> Result<(CapsuleHandle, Signer)> {
        self.run_local_admitted_mode(path, args, admission, LaunchMode::Bounded, None)
            .await
    }

    /// The launch route's admitted start: see [`Self::start_local_with_signer`].
    /// `live_run` is the token this start admitted. It moves into the activation.
    async fn start_local_admitted(
        &self,
        path: &Path,
        args: Vec<String>,
        admission: crate::agent_admission::AdmissionContext,
        live_run: Option<AgentLiveRun>,
    ) -> Result<(CapsuleHandle, Signer)> {
        self.run_local_admitted_mode(path, args, admission, LaunchMode::Detached, live_run)
            .await
    }

    /// Consume the short grant once. One live run for this agent refuses
    /// another start. The run is admitted under `live_runs` before any await
    /// that follows, and that admission does not read the registry, so a
    /// registry writer cannot delay the model ceiling. The token travels with
    /// this call into the activation. This agent's turn is held until the
    /// session record is stored, so a Stop that sees the row can take the tuple.
    pub(crate) async fn start_agent_once(
        &self,
        path: &Path,
        admission: crate::agent_admission::AdmissionContext,
        facts: AgentStartFacts<'_>,
    ) -> Result<(CapsuleHandle, Signer)> {
        let capsules = &self.running_capsules;
        let turn = self.launch_turn(facts.agent_id);
        let _turn = turn.lock().await;
        let live_run = {
            let mut state = self.agent_launches.lock().await;
            if Self::refuse_start_for_stop(&self.stop_marks, capsules, &mut state, facts.agent_id) {
                return Err(ElastosError::InvalidManifest(Self::AGENT_STOPPING.into()));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.used.retain(|_, expiry| *expiry > now);
            if facts.expires_at <= now {
                return Err(ElastosError::InvalidManifest(
                    "agent launch grant expired".into(),
                ));
            }
            // A live agent answers "already running" before the used-grant
            // check, including when the second Start presents the same grant.
            // A refused second grant is not marked used.
            if self.live_run_held(facts.agent_id) {
                return Err(ElastosError::InvalidManifest(
                    Self::AGENT_ALREADY_RUNNING.into(),
                ));
            }
            if state.used.contains_key(facts.launch_id) {
                return Err(ElastosError::InvalidManifest(
                    "agent launch grant was already used".into(),
                ));
            }
            let Some(live_run) = self.admit_live_run(facts.agent_id) else {
                return Err(ElastosError::InvalidManifest(
                    Self::AGENT_ALREADY_RUNNING.into(),
                ));
            };
            state
                .used
                .insert(facts.launch_id.to_string(), facts.expires_at);
            #[cfg(test)]
            if self.take_refuse_after_live_admit() {
                return Err(ElastosError::InvalidManifest(
                    "refused after the live run was admitted".into(),
                ));
            }
            live_run
        };
        let started = self
            .start_local_admitted(path, vec![], admission, Some(live_run))
            .await?;
        let session_id = started.0.id.0.clone();
        self.agent_launches.lock().await.sessions.insert(
            session_id.clone(),
            AgentSessionRecord {
                agent_id: facts.agent_id.to_string(),
                owner: facts.owner.to_string(),
                host_cid: facts.host_cid.to_string(),
                launch_id: facts.launch_id.to_string(),
                session_id,
            },
        );
        Ok(started)
    }

    fn launch_turn(&self, agent_id: &str) -> LaunchTurn {
        let mut turns = self
            .launch_turns
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let runs = self.live_runs.lock().unwrap_or_else(|err| err.into_inner());
        turns.retain(|id, turn| id == agent_id || Arc::strong_count(turn) > 1 || runs.holds(id));
        drop(runs);
        turns
            .entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn live_run_held(&self, agent_id: &str) -> bool {
        self.live_runs
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .holds(agent_id)
    }

    /// `Some` is this start's token. `None` means this agent already has one.
    fn admit_live_run(&self, agent_id: &str) -> Option<AgentLiveRun> {
        let mut runs = self.live_runs.lock().unwrap_or_else(|err| err.into_inner());
        if runs.holds(agent_id) {
            return None;
        }
        let token = runs.admit(agent_id);
        Some(AgentLiveRun {
            runs: Arc::clone(&self.live_runs),
            agent_id: agent_id.to_string(),
            token,
        })
    }

    /// Live session ids whose principal is `agent_id`. The capsule name is
    /// not read: two rows that share a host name stay distinct, and a row
    /// with no principal is not this agent.
    pub(crate) async fn live_sessions_for_agent(&self, agent_id: &str) -> Vec<String> {
        #[cfg(test)]
        self.note_stop_mark_before_rows(agent_id);
        let capsules = self.running_capsules.read().await;
        let mut ids: Vec<String> = capsules
            .values()
            .filter(|info| info.ended_at.is_none() && info.principal.as_deref() == Some(agent_id))
            .map(|info| info.id.clone())
            .collect();
        ids.sort();
        ids
    }

    pub(crate) const AGENT_STOPPING: &'static str = "this agent is stopping";

    pub(crate) const AGENT_ALREADY_RUNNING: &'static str = "this agent is already running";

    /// Marks the agent with this Stop's token. The guard clears that token
    /// when Stop returns or the future is dropped, including a panic.
    pub(crate) async fn begin_agent_stop(self: &Arc<Self>, agent_id: &str) -> AgentStopGuard {
        let turn = self.launch_turn(agent_id);
        let _turn = turn.lock().await;
        let token = {
            // A Start that already passed its check holds this agent's turn
            // until its session is registered.
            let _gate = self.agent_launches.lock().await;
            let mut marks = self
                .stop_marks
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let token = marks.next;
            marks.next = marks.next.wrapping_add(1);
            let _ = marks
                .tokens
                .entry(agent_id.to_string())
                .or_default()
                .insert(token);
            token
        };
        AgentStopGuard {
            marks: Arc::clone(&self.stop_marks),
            agent_id: agent_id.to_string(),
            token,
        }
    }

    /// Records that Stop has asked this agent's live rows to end. The drop
    /// guard does not clear this.
    pub(crate) async fn note_agent_stop_requested(&self, agent_id: &str) {
        self.agent_launches
            .lock()
            .await
            .stop_requested
            .insert(agent_id.to_string());
    }

    /// `Some` when the registry could be read: true when a row for this agent
    /// has not ended. `None` when the registry is busy. This does not wait.
    fn live_row_in(
        capsules: &RwLock<HashMap<String, RunningCapsuleInfo>>,
        agent_id: &str,
    ) -> Option<bool> {
        let capsules = capsules.try_read().ok()?;
        Some(
            capsules
                .values()
                .any(|info| info.ended_at.is_none() && info.principal.as_deref() == Some(agent_id)),
        )
    }

    fn stop_mark_held(marks: &StdMutex<AgentStopMarks>, agent_id: &str) -> bool {
        marks
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .holds(agent_id)
    }

    /// While any Stop token is set, Start is refused and the registry is not
    /// read. The row test applies only to `stop_requested`. No signal does
    /// not read the registry. No live row clears `stop_requested`. Each Stop
    /// clears only its own token, in [`AgentStopGuard`].
    fn refuse_start_for_stop(
        marks: &StdMutex<AgentStopMarks>,
        capsules: &RwLock<HashMap<String, RunningCapsuleInfo>>,
        state: &mut AgentLaunchState,
        agent_id: &str,
    ) -> bool {
        if Self::stop_mark_held(marks, agent_id) {
            return true;
        }
        if !state.stop_requested.contains(agent_id) {
            return false;
        }
        match Self::live_row_in(capsules, agent_id) {
            Some(false) => {
                state.stop_requested.remove(agent_id);
                false
            }
            Some(true) | None => true,
        }
    }

    pub(crate) async fn agent_is_stopping(&self, agent_id: &str) -> bool {
        let capsules = &self.running_capsules;
        let mut state = self.agent_launches.lock().await;
        Self::refuse_start_for_stop(&self.stop_marks, capsules, &mut state, agent_id)
    }

    /// The start record for this session, if Start stored one and the
    /// session has not ended. Looking does not take the record: the session's
    /// one end removes it after `ended_at` is visible.
    pub(crate) async fn agent_session(&self, session_id: &str) -> Option<AgentSessionRecord> {
        self.agent_launches
            .lock()
            .await
            .sessions
            .get(session_id)
            .cloned()
    }

    /// Test only: plant a start record the launch route did not write.
    ///
    /// The caller lives in the agents build's launch tests. This allow keeps
    /// the helper when that build is off, where those tests are not compiled.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn insert_agent_session_for_test(&self, record: AgentSessionRecord) {
        let session_id = record.session_id.clone();
        self.agent_launches
            .lock()
            .await
            .sessions
            .insert(session_id, record);
    }

    #[cfg(test)]
    fn note_stop_mark_before_rows(&self, agent_id: &str) {
        let key = Arc::as_ptr(&self.agent_launches) as usize;
        let marked = Self::stop_mark_held(&self.stop_marks, agent_id);
        let mut probes = STOP_MARK_BEFORE_ROWS
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(slot) = probes
            .iter_mut()
            .rev()
            .find(|(stored, id, seen)| *stored == key && id == agent_id && seen.is_none())
        {
            slot.2 = Some(marked);
        }
    }

    #[cfg(test)]
    pub(crate) async fn agent_stop_flag_is_set(&self, agent_id: &str) -> bool {
        Self::stop_mark_held(&self.stop_marks, agent_id)
    }

    #[cfg(test)]
    pub(crate) fn arm_stop_mark_probe(&self, agent_id: &str) {
        STOP_MARK_BEFORE_ROWS
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((
                Arc::as_ptr(&self.agent_launches) as usize,
                agent_id.to_string(),
                None,
            ));
    }

    #[cfg(test)]
    pub(crate) fn stop_mark_seen_before_rows(&self, agent_id: &str) -> Option<bool> {
        let key = Arc::as_ptr(&self.agent_launches) as usize;
        STOP_MARK_BEFORE_ROWS
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .iter()
            .rev()
            .find(|(stored, id, _)| *stored == key && id == agent_id)
            .and_then(|(_, _, seen)| *seen)
    }

    #[cfg(test)]
    fn stop_rows_key(&self) -> usize {
        Arc::as_ptr(&self.agent_launches) as usize
    }

    #[cfg(test)]
    pub(crate) fn arm_stop_before_rows(&self, agent_id: &str) -> StopRowsPause {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        STOP_ROWS_GATES
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((
                self.stop_rows_key(),
                agent_id.to_string(),
                StopRowsGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                },
            ));
        StopRowsPause { entered, release }
    }

    #[cfg(test)]
    pub(crate) async fn pause_before_stop_rows(&self, agent_id: &str) {
        let gate = {
            let key = self.stop_rows_key();
            let mut gates = STOP_ROWS_GATES
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let pos = gates
                .iter()
                .rposition(|(stored, id, _)| *stored == key && id == agent_id);
            pos.map(|pos| gates.swap_remove(pos).2)
        };
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn arm_stop_panic_after_mark(&self, agent_id: &str) {
        STOP_PANIC_AFTER_MARK
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((self.stop_rows_key(), agent_id.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn take_stop_panic_after_mark(&self, agent_id: &str) -> bool {
        let key = self.stop_rows_key();
        let mut armed = STOP_PANIC_AFTER_MARK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let Some(pos) = armed
            .iter()
            .rposition(|(stored, id)| *stored == key && id == agent_id)
        else {
            return false;
        };
        armed.swap_remove(pos);
        true
    }

    /// Await points on an admitted Start, after the live run is set and before
    /// the guest is running. A test cancels at each one.
    #[cfg(test)]
    pub(crate) const LIVE_RUN_AWAIT_POINTS: &[&str] = &[
        "entrypoint",
        "providers",
        "signature",
        "load",
        "principal",
        "register",
    ];

    #[cfg(test)]
    fn live_run_key(&self) -> usize {
        Arc::as_ptr(&self.live_runs) as usize
    }

    #[cfg(test)]
    pub(crate) fn agent_live_run_held(&self, agent_id: &str) -> bool {
        self.live_run_held(agent_id)
    }

    #[cfg(test)]
    pub(crate) fn arm_live_run_await(&self, point: &'static str) -> LiveRunPause {
        self.arm_live_run_gate(point, false)
    }

    #[cfg(test)]
    pub(crate) fn arm_live_run_panic(&self, point: &'static str) -> LiveRunPause {
        self.arm_live_run_gate(point, true)
    }

    #[cfg(test)]
    fn arm_live_run_gate(&self, point: &'static str, panic: bool) -> LiveRunPause {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        LIVE_RUN_GATES
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((
                self.live_run_key(),
                point,
                LiveRunGate {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                    panic,
                },
            ));
        LiveRunPause {
            entered,
            release,
            key: self.live_run_key(),
            point,
        }
    }

    /// Waits when a test armed this point. An unarmed point returns at once.
    #[cfg(test)]
    async fn live_run_await(&self, point: &'static str) {
        await_live_run_gate(self.live_run_key(), point).await;
    }

    #[cfg(test)]
    pub(crate) fn arm_refuse_after_live_admit(&self) -> RefuseAfterAdmit {
        let key = self.live_run_key();
        REFUSE_AFTER_ADMIT
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(key);
        RefuseAfterAdmit { key }
    }

    #[cfg(test)]
    fn take_refuse_after_live_admit(&self) -> bool {
        let key = self.live_run_key();
        let mut armed = REFUSE_AFTER_ADMIT
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let Some(pos) = armed.iter().rposition(|stored| *stored == key) else {
            return false;
        };
        armed.swap_remove(pos);
        true
    }

    #[cfg(test)]
    pub(crate) async fn plant_open_agent_stop_for_test(&self, agent_id: &str, session_id: &str) {
        self.register_capsule(RunningCapsuleInfo {
            id: session_id.to_string(),
            name: "planted".to_string(),
            status: CAPSULE_RUNNING.to_string(),
            capsule_type: CapsuleType::Wasm,
            handle: None,
            session_id: session_id.to_string(),
            principal: Some(agent_id.to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
        self.insert_agent_session_for_test(AgentSessionRecord {
            agent_id: agent_id.to_string(),
            owner: "person:owner".to_string(),
            host_cid: "cid".to_string(),
            launch_id: format!("launch:{session_id}"),
            session_id: session_id.to_string(),
        })
        .await;
        self.activation_stops
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                session_id.to_string(),
                Arc::new(ActivationStop {
                    flag: Arc::new(crate::resource_bridge::ActivationStopFlag::default()),
                    cause: StdMutex::new(None),
                }),
            );
        self.note_planted_live_run(agent_id, session_id);
    }

    /// The planted row and the live-run token are one fact. Ending the row
    /// removes the token this plant added, and no other.
    #[cfg(test)]
    fn note_planted_live_run(&self, agent_id: &str, session_id: &str) {
        let mut runs = self.live_runs.lock().unwrap_or_else(|err| err.into_inner());
        if let Some((old_agent, old_token)) = runs.planted.remove(session_id) {
            runs.clear(&old_agent, old_token);
        }
        let token = runs.admit(agent_id);
        runs.planted
            .insert(session_id.to_string(), (agent_id.to_string(), token));
    }

    #[cfg(test)]
    fn clear_planted_live_run(&self, session_id: &str) {
        let mut runs = self.live_runs.lock().unwrap_or_else(|err| err.into_inner());
        if let Some((agent_id, token)) = runs.planted.remove(session_id) {
            runs.clear(&agent_id, token);
        }
    }

    /// Ends a planted row so it is no longer live. The stopping mark is left
    /// as it is: a test can see whether Start still treats that mark as a refusal.
    #[cfg(test)]
    pub(crate) async fn end_planted_session_for_test(&self, session_id: &str) {
        let mut capsules = self.running_capsules.write().await;
        if let Some(info) = capsules.get_mut(session_id) {
            info.ended_at = Some(std::time::Instant::now());
            info.status = CAPSULE_STOPPED.to_string();
        }
        drop(capsules);
        self.clear_planted_live_run(session_id);
    }

    #[cfg(test)]
    pub(crate) fn limit_stop_wait_for_test(&self, bound: std::time::Duration) -> StopWaitLimit {
        let token = NEXT_STOP_WAIT_TOKEN.fetch_add(1, Ordering::Relaxed);
        TEST_STOP_WAITS
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((token, bound));
        self.stop_wait_token.store(token, Ordering::Release);
        StopWaitLimit { token }
    }

    #[cfg(test)]
    fn test_stop_wait_bound(&self) -> std::time::Duration {
        let token = self.stop_wait_token.load(Ordering::Acquire);
        if token == 0 {
            return std::time::Duration::from_secs(40);
        }
        TEST_STOP_WAITS
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .iter()
            .rev()
            .find(|(stored, _)| *stored == token)
            .map(|(_, bound)| *bound)
            .unwrap_or(std::time::Duration::from_secs(40))
    }

    /// Both admitted entries derive the same actor and ceiling from the
    /// stored admission context before it is consumed.
    async fn run_local_admitted_mode(
        &self,
        path: &Path,
        args: Vec<String>,
        admission: crate::agent_admission::AdmissionContext,
        mode: LaunchMode,
        live_run: Option<AgentLiveRun>,
    ) -> Result<(CapsuleHandle, Signer)> {
        let actor = crate::resource_bridge::BridgePrincipal::from_admission(&admission);
        let ceiling = admission.model_token_ceiling();
        let model_admission = AgentModelCeiling {
            ceiling,
            key: AgentKey::from_admission(&admission),
        };
        if ceiling > 0 {
            self.model_budget
                .open(&model_admission.key, ceiling)
                .map_err(|refusal| {
                    ElastosError::InvalidManifest(format!(
                        "model budget admission refused: {refusal:?}"
                    ))
                })?;
        }
        let (manifest, entrypoint) = admission.into_parts();
        self.run_signer(
            path,
            args,
            (Some(actor), None),
            Some((manifest, entrypoint, model_admission, live_run)),
            mode,
            (|_| {}, |_| {}),
        )
        .await
    }

    /// Load one local start. `admitted` is the walked manifest and entrypoint
    /// when this start may hand the bridge a stored agent's id; nothing is read
    /// again for them. A start with no record reads the folder and refuses an
    /// agent's id.
    async fn run_signer(
        &self,
        path: &Path,
        args: Vec<String>,
        launch: (Option<BridgePrincipal>, Option<&str>),
        admitted: Option<(
            CapsuleManifest,
            Vec<u8>,
            AgentModelCeiling,
            Option<AgentLiveRun>,
        )>,
        mode: LaunchMode,
        walk_hooks: (
            impl FnOnce(&Path) + Send,
            impl FnOnce(&CheckedBundle) + Send,
        ),
    ) -> Result<(CapsuleHandle, Signer)> {
        let (principal_id, grant_name) = launch;
        let (before_folder_walk, after_folder_walk) = walk_hooks;
        let admitted_launch = admitted.is_some();
        if !admitted_launch {
            crate::agent_admission::refuse_unadmitted_agent_principal(
                principal_id
                    .as_ref()
                    .map(crate::resource_bridge::BridgePrincipal::principal_str),
            )
            .map_err(|err| ElastosError::InvalidManifest(err.to_string()))?;
        }
        let (manifest, walked, admitted_model, live_run) = match admitted {
            Some((manifest, entrypoint, model_admission, live_run)) => (
                Some(manifest),
                Some(entrypoint),
                Some(model_admission),
                live_run,
            ),
            None => (None, None, None, None),
        };
        let mut manifest: CapsuleManifest = match manifest {
            Some(manifest) => {
                manifest.validate().map_err(ElastosError::InvalidManifest)?;
                manifest
            }
            None => {
                let manifest_path = path.join("capsule.json");
                let manifest_data = tokio::task::spawn_blocking(move || {
                    elastos_common::capsule_manifest_file::read(&manifest_path)
                })
                .await
                .map_err(|err| ElastosError::Io(std::io::Error::other(err)))?
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ElastosError::InvalidManifest(format!(
                            "capsule.json not found in {}",
                            path.display()
                        ))
                    } else {
                        ElastosError::Io(e)
                    }
                })?;
                let manifest: CapsuleManifest =
                    serde_json::from_slice(&manifest_data).map_err(|e| {
                        ElastosError::InvalidManifest(format!(
                            "Failed to parse capsule.json: {}",
                            e
                        ))
                    })?;
                manifest.validate().map_err(ElastosError::InvalidManifest)?;
                manifest
            }
        };

        // A component folder start outside dev mode makes one walk of the
        // folder here. The manifest the checks below, the gate and the load
        // use is the `capsule.json` that walk read, never a second read of
        // the file. Dev mode walks nothing and keeps the manifest read above.
        let folder_start = if manifest.is_component_capsule() && !admitted_launch {
            self.walk_folder_start(path, before_folder_walk, after_folder_walk)
                .await?
        } else {
            None
        };
        if let Some(start) = &folder_start {
            manifest = start.manifest.clone();
        }
        if grant_name.is_some_and(|name| manifest.name != name) {
            return Err(ElastosError::InvalidManifest(
                "launch grant mismatch".into(),
            ));
        }

        if let Some(model_admission) = &admitted_model {
            if manifest.resources.model_token_ceiling() != model_admission.ceiling {
                return Err(ElastosError::InvalidManifest(
                    "the model-token ceiling is the one admission recorded".into(),
                ));
            }
        }

        // Reject entrypoints that escape the capsule directory
        if manifest.entrypoint.contains("..")
            || std::path::Path::new(&manifest.entrypoint).is_absolute()
        {
            return Err(ElastosError::InvalidManifest(
                "Entrypoint must be a relative path within the capsule directory".into(),
            ));
        }
        // The same rule for what is on disk, before anything opens it.
        #[cfg(test)]
        self.live_run_await("entrypoint").await;
        check_entrypoint_file(path, &manifest.entrypoint).await?;

        tracing::info!(
            "Loading capsule '{}' ({:?})",
            manifest.name,
            manifest.capsule_type
        );

        // Check provider dependencies
        #[cfg(test)]
        self.live_run_await("providers").await;
        self.check_provider_dependencies(&manifest).await?;

        // A component's entrypoint is one buffer. The signature check, the
        // import check and the compiler below all use these same bytes: the
        // walked ones for an admitted launch, and the ones the folder gate's
        // one walk read otherwise outside dev mode.
        let (folder_cid, folder_data_dir) = match &folder_start {
            Some(start) => (Some(start.cid), start.data_dir.clone()),
            None => (None, None),
        };
        // `dev_unsigned` marks the one case with no walk: a dev mode folder
        // start. Its load is the dev-only one, not the checked one.
        let (admitted_bytes, dev_unsigned) = if manifest.is_component_capsule() {
            match (walked, folder_start) {
                (Some(bytes), _) => (Some(bytes), false),
                (None, Some(start)) => (Some(start.entrypoint), false),
                (None, None) => (
                    Some(crate::component::read_admitted_entrypoint(path, &manifest).await?),
                    true,
                ),
            }
        } else {
            if walked.is_some() {
                return Err(ElastosError::InvalidManifest(
                    crate::agent_admission::NOT_A_COMPONENT.to_string(),
                ));
            }
            (None, false)
        };

        // Verify signature if verifier is configured
        let signer = self
            .verify_capsule_signature(&manifest, path, admitted_bytes.as_deref())
            .await?;
        // A folder manifest has no dependency CID field. Only the by-CID
        // entry can verify a signed dependency closure; refuse loose members
        // before the component provider receives any bytes.
        if let Some(requirement) = manifest
            .requires
            .first()
            .filter(|_| manifest.is_component_capsule())
        {
            return Err(ElastosError::InvalidManifest(format!(
                "bundle_requirement_unpinned: {}",
                requirement.name
            )));
        }
        if let Some(bytes) = &admitted_bytes {
            crate::component::validate_component_imports_for_manifest(bytes, &manifest)
                .map_err(ElastosError::InvalidManifest)?;
        }

        // A folder start outside dev mode starts only a component whose walk
        // CID is one this Home already admitted: a by-CID slot staged from a
        // signed bundle, or the CID the Home's own install record holds for
        // this folder. The signature check above names the signer; this names
        // the bytes.
        if let Some(cid) = folder_cid {
            self.accept_folder_start(path, &manifest, &cid, folder_data_dir.as_deref())
                .await?;
        }

        // A manifest that declares an agent runs only through a launch that
        // admitted it. A start with no admission context has no launcher,
        // whichever entrance it came from: the attach route and a launch
        // without an agent both stop here.
        if !admitted_launch && manifest.agent.is_some() {
            return Err(ElastosError::InvalidManifest(
                crate::agent_admission::NO_LAUNCHER.to_string(),
            ));
        }

        // Find a compute provider that supports this capsule type
        let provider = self.get_provider_for_manifest(&manifest).ok_or_else(|| {
            if manifest.is_component_capsule() {
                ElastosError::Compute("No component compute provider is configured".to_string())
            } else {
                ElastosError::Compute(format!(
                    "No compute provider supports capsule type: {:?}",
                    manifest.capsule_type
                ))
            }
        })?;

        // Load capsule
        // A component is always compiled from the bytes checked above. The
        // provider's own `load(path)` reads the file itself and checks nothing,
        // so it is for capsules that are not components.
        let mut handle = match (admitted_bytes, &self.component_provider) {
            (Some(bytes), Some(component)) if dev_unsigned => {
                self.load_dev_unsigned_component(component, bytes, manifest)
                    .await?
            }
            (Some(bytes), Some(component)) => {
                #[cfg(test)]
                self.live_run_await("load").await;
                component.load_admitted(bytes, manifest).await?
            }
            (Some(_), None) => {
                return Err(ElastosError::Compute(
                    "No component compute provider is configured".to_string(),
                ))
            }
            (None, _) => provider.load(path, manifest).await?,
        };
        self.start_loaded(
            provider,
            &mut handle,
            args,
            principal_id.map(crate::resource_bridge::BridgePrincipal::into_bridge_principal_string),
            admitted_model.map(|ceiling| (ceiling, live_run)),
            mode,
        )
        .await?;

        Ok((handle, signer))
    }

    /// The dev-only component load: no CID, no closure, maybe no signature.
    /// It runs only while this Home admits unsigned capsules, which takes the
    /// owner's `dev_mode = true` on a Home with no installed signed release.
    async fn load_dev_unsigned_component(
        &self,
        component: &ComponentProvider,
        bytes: Vec<u8>,
        manifest: CapsuleManifest,
    ) -> Result<CapsuleHandle> {
        if !matches!(
            *self.unsigned_capsules.read().await,
            UnsignedCapsules::Allowed
        ) {
            return Err(ElastosError::InvalidManifest(format!(
                "dev_unsigned_component_refused: '{}' starts unchecked only with dev_mode = true",
                manifest.name
            )));
        }
        component.load_admitted(bytes, manifest).await
    }

    /// The one walk a component folder start outside dev mode makes. In dev
    /// mode it returns `None`, and the caller reads the entrypoint as before.
    /// The walk is the staging walk under the staging budget; the manifest it
    /// read from `capsule.json` and the entrypoint bytes it read are what the
    /// caller checks and loads, so nothing reads the folder again.
    async fn walk_folder_start(
        &self,
        path: &Path,
        before_walk: impl FnOnce(&Path),
        after_walk: impl FnOnce(&CheckedBundle),
    ) -> Result<Option<FolderStart>> {
        let data_dir = {
            let admission = self.unsigned_capsules.read().await;
            match &*admission {
                UnsignedCapsules::Allowed => return Ok(None),
                UnsignedCapsules::InstalledRelease(dir) => Some(dir.clone()),
                UnsignedCapsules::Refused(dir) => dir.clone(),
            }
        };
        before_walk(path);
        let bundle = checked_bundle_within(path, bundle_admission::BUNDLE_WALK_BUDGET).map_err(
            |refusal| {
                ElastosError::InvalidManifest(format!(
                    "Folder {} is not a bundle a folder start accepts: {}",
                    path.display(),
                    bundle_admission::walk_refusal(refusal)
                ))
            },
        )?;
        after_walk(&bundle);
        let manifest_bytes = bundle.entry("capsule.json").ok_or_else(|| {
            ElastosError::InvalidManifest(format!("capsule.json not found in {}", path.display()))
        })?;
        let manifest: CapsuleManifest = serde_json::from_slice(manifest_bytes).map_err(|e| {
            ElastosError::InvalidManifest(format!("Failed to parse capsule.json: {}", e))
        })?;
        manifest.validate().map_err(ElastosError::InvalidManifest)?;
        if !manifest.is_component_capsule() {
            return Err(ElastosError::InvalidManifest(format!(
                "Capsule '{}' changed while its folder was walked: its manifest is no longer a component manifest",
                manifest.name
            )));
        }
        let entrypoint = bundle.entry(&manifest.entrypoint).ok_or_else(|| {
            ElastosError::InvalidManifest(format!(
                "Capsule '{}' entrypoint '{}' is not a file of its bundle",
                manifest.name, manifest.entrypoint
            ))
        })?;
        Ok(Some(FolderStart {
            manifest,
            cid: bundle.cid(),
            entrypoint: entrypoint.to_vec(),
            data_dir,
        }))
    }

    /// Whether this Home already admitted the walk CID of a component folder
    /// start: the CID its own install record holds for the folder's canonical
    /// path and this walk, or a by-CID slot staged from a bundle that passes
    /// the one bundle signature check.
    async fn accept_folder_start(
        &self,
        path: &Path,
        manifest: &CapsuleManifest,
        cid: &LabCid,
        data_dir: Option<&Path>,
    ) -> Result<()> {
        let recorded = data_dir
            .and_then(|data_dir| crate::setup::recorded_install_cid(data_dir, path))
            .is_some_and(|recorded| recorded == cid.to_string());
        if !recorded {
            match data_dir {
                Some(data_dir) if self.by_cid_slot_accepts(data_dir, cid).await => {}
                _ => {
                    return Err(ElastosError::InvalidManifest(format!(
                        "Capsule '{}' is not installed: its folder walk CID {} is not a by-CID bundle this Home accepted and no install recorded it",
                        manifest.name, cid
                    )))
                }
            }
        }
        Ok(())
    }

    /// Whether the Home at `data_dir` holds a by-CID slot for `cid` whose
    /// bytes recompute to it and whose signature passes this Home's check.
    async fn by_cid_slot_accepts(&self, data_dir: &Path, cid: &LabCid) -> bool {
        let slot = bundle_admission::bundle_slot(data_dir, cid);
        let Ok(bundle) = checked_bundle_within(&slot, bundle_admission::BUNDLE_WALK_BUDGET) else {
            return false;
        };
        if bundle.cid() != *cid {
            return false;
        }
        let verifier = self.signature_verifier.read().await;
        bundle_admission::check_bundle_signature(
            &bundle_admission::bundle_signature_path(data_dir, cid),
            cid,
            &verifier,
        )
        .is_ok()
    }

    /// Start the bundle that the Home at `data_dir` holds under the name
    /// `cid`, and return who signed it.
    ///
    /// The bundle is a program, and it is what starts; or it is content, and
    /// then what starts is the one program of the page that content pins:
    /// content pins exactly its viewer, a page, and a page pins exactly its
    /// program, the core. While the core runs, the content's files, as this
    /// start's walk read them, are its to read under the launch name
    /// (`elastos://launch/content/`), if its manifest asks for that name;
    /// the bridge answers those reads itself and the store is not read
    /// again. What it writes for the launch, under `elastos://launch/output/`,
    /// is kept in the launch's memory and goes with it. The content and the
    /// page get no instance, and the
    /// handle returned is the core's. A page is not started by its own CID.
    /// Under a program only programs may be pinned.
    ///
    /// Nothing in the store is trusted. The slot is walked again under the
    /// staging limits and must recompute to `cid`; the signature file that is
    /// beside it now must pass the one signature check again, and its signer
    /// is the one returned; the manifest must be one a start by CID takes;
    /// and the component that is compiled is the bytes the walk of its
    /// bundle read, never a second read of the file. A missing slot is a
    /// refusal: nothing is fetched.
    ///
    /// What starts may ask for no more than its own signed manifest asks
    /// for. Its ceiling is filled like every capsule's, from the one bounds
    /// function, and for a manifest this start admits that is its `asks`
    /// and nothing else. A manifest without asks gives an empty ceiling,
    /// and that capsule is also loaded sealed: the component provider
    /// refuses its every call to the bridge before any handler sees it. A
    /// manifest with asks is loaded unsealed, so that it can ask; the asks
    /// grant nothing, and the bridge refuses whatever is beyond them.
    ///
    /// A manifest's requirements must each pin a bundle by CID, and every
    /// pinned bundle, and every bundle those pin, must be in the store and
    /// pass the same checks, under its own signature and inside the one
    /// walk budget they all share, before anything starts. A pinned bundle
    /// is checked and nothing more, the core under content aside: it is not
    /// started, and the capsule that starts gets no way to reach it or its
    /// bytes. A bundle that two pins
    /// reach is checked and counted once. Who is trusted is read once for
    /// the whole start.
    pub async fn run_by_bundle(
        &self,
        data_dir: &Path,
        cid: &str,
        args: Vec<String>,
        principal_id: Option<String>,
    ) -> std::result::Result<(CapsuleHandle, AcceptedSignature), BundleRefusal> {
        let budget = bundle_admission::BUNDLE_WALK_BUDGET;
        self.run_by_bundle_observed(data_dir, cid, args, principal_id, budget, |_| {})
            .await
    }

    /// [`Runtime::run_by_bundle`] under `budget`, telling `after_walk` each
    /// time the one walk of a bundle's slot is done, with that bundle's CID.
    /// Tests change the slot at that moment, as another process could, and
    /// give a budget small enough to reach.
    pub(crate) async fn run_by_bundle_observed(
        &self,
        data_dir: &Path,
        cid: &str,
        args: Vec<String>,
        principal_id: Option<String>,
        budget: Budget,
        after_walk: impl FnMut(&LabCid),
    ) -> std::result::Result<(CapsuleHandle, AcceptedSignature), BundleRefusal> {
        let started = self.start_by_bundle(data_dir, cid, args, principal_id, budget, after_walk);
        started
            .await
            .map(|started| (started.handle, started.accepted))
    }

    /// The start by CID itself. Besides what [`Runtime::run_by_bundle_observed`]
    /// returns, a start of content gives back its launch (the content's files,
    /// their listing and what the program wrote) and the name of the page the
    /// content pins, for a caller that keeps the launch for that page.
    pub(crate) async fn start_by_bundle(
        &self,
        data_dir: &Path,
        cid: &str,
        args: Vec<String>,
        principal_id: Option<String>,
        budget: Budget,
        mut after_walk: impl FnMut(&LabCid),
    ) -> std::result::Result<crate::page_launch::Started, BundleRefusal> {
        // A start by CID names no stored agent, so an agent's own principal
        // is refused here before the walk begins.
        crate::agent_admission::refuse_unadmitted_agent_principal(principal_id.as_deref())
            .map_err(|err| BundleRefusal::StartFailed(err.to_string()))?;
        let asked: LabCid = cid
            .parse()
            .map_err(|_| BundleRefusal::CidFormInvalid(cid.to_string()))?;
        // One budget for the bundle asked for and every bundle pinned below
        // it: the files and bytes each walk takes in come off what the next
        // may take.
        let mut left = budget;
        // Who is trusted is read once, here. That one reading judges the
        // bundle asked for and every bundle pinned below it, and it is held
        // until the last of them is judged: trust cannot change between two
        // bundles of one start. It is let go before anything is loaded.
        let trust = self.signature_verifier.read().await;
        let (mut admitted, accepted): (VerifiedBundle, AcceptedSignature) = self
            .admit_closure_member(data_dir, &asked, &trust, &mut left, &mut after_walk)
            .await?;
        // What may sit below the bundle asked for follows from what it is. A
        // program pins programs. Content pins exactly one bundle, its
        // viewer, which must be a page. A page is reached through the
        // content that pins it and is not started by its own CID.
        let below_root = match (admitted.kind(), admitted.pins().len()) {
            (BundleKind::Program, _) => BundleKind::Program,
            (BundleKind::Content, 1) => BundleKind::Page,
            (BundleKind::Content, pins) => return Err(BundleRefusal::ContentRequiresInvalid(pins)),
            (BundleKind::Page, _) => {
                return Err(bundle_admission::misplaced(BundleKind::Page, None))
            }
        };
        // The bundles it pins, and the ones those pin, in the manifests'
        // order and depth first: each is held to the checks just made, then
        // to its requirement's name and to the kind its place allows. The
        // flag marks the one program a content's page pins: its core.
        let below = |depth: usize, kind: BundleKind, core: bool, pins: Vec<(String, String)>| {
            let pins = pins.into_iter().rev();
            pins.map(move |(name, pin)| (depth + 1, kind, core, name, pin))
        };
        // For content, what its program may read while it runs: the files
        // this walk has just read, held for the launch. A content whose
        // listing would be too long to serve is refused here, before
        // anything it pins is read.
        let launch = match admitted.kind() {
            BundleKind::Content => {
                let content = LaunchContent::new(admitted.take_files());
                Some(Arc::new(
                    content.map_err(BundleRefusal::ContentListingTooLong)?,
                ))
            }
            BundleKind::Program | BundleKind::Page => None,
        };
        let content_name = launch.as_ref().map(|_| admitted.manifest().name.clone());
        let pins = admitted.take_pins();
        // Every bundle admitted so far, by its CID: the name it carries, the
        // deepest place a pin has reached it at, and its own pins. The
        // bundle asked for is kept with its pins like any other: a cycle of
        // pins back to it cannot be built, and if one were, the measuring
        // would go round until the depth limit refused it.
        let root = (admitted.manifest().name.clone(), 1, pins.clone());
        let mut seen = HashMap::from([(admitted.cid().to_string(), root)]);
        let mut pending: Vec<_> = below(1, below_root, false, pins).collect();
        let mut members = 1;
        // The page a content pins, by its name: the one the launch is for.
        let mut kept_page = None;
        // What starts: the program asked for or, under content, the core.
        let mut starts = (admitted.kind() == BundleKind::Program).then_some(admitted);
        while let Some((depth, expected, core, name, pin)) = pending.pop() {
            let refused = |refusal| BundleRefusal::Requirement {
                name: name.clone(),
                refusal: Box::new(refusal),
            };
            // No pin sits below the depth limit, whatever it pins: also a
            // pin on a bundle this start has already admitted higher up.
            if depth > bundle_admission::CLOSURE_MAX_DEPTH {
                return Err(refused(BundleRefusal::ClosureTooDeep));
            }
            let Ok(pinned) = pin.parse::<LabCid>() else {
                return Err(refused(BundleRefusal::CidFormInvalid(pin)));
            };
            // A bundle reached a second time, through another pin, was
            // admitted on its first reach. Its name must be this
            // requirement's too. It is not walked or counted again. Reached
            // deeper than before, its own pins sit deeper too: they are
            // measured again from here, out of memory, so that the depth
            // limit does not turn on which pin the walk met first. Its kind
            // needs no second look: content and its page could be reached
            // again only by a cycle of pins, which then starts nothing, so
            // what is reached twice is a program under a program, and what
            // it pins are programs.
            if let Some((carried, deepest, pins)) = seen.get_mut(&pinned.to_string()) {
                if *carried != name {
                    return Err(refused(BundleRefusal::RequirementMismatch(carried.clone())));
                }
                if depth > *deepest {
                    *deepest = depth;
                    pending.extend(below(depth, BundleKind::Program, false, pins.clone()));
                }
                continue;
            }
            members += 1;
            if members > bundle_admission::CLOSURE_MAX_MEMBERS {
                return Err(refused(BundleRefusal::ClosureTooMany));
            }
            let (mut member, _) = self
                .admit_closure_member(data_dir, &pinned, &trust, &mut left, &mut after_walk)
                .await
                .map_err(refused)?;
            if member.manifest().name != name {
                return Err(refused(BundleRefusal::RequirementMismatch(
                    member.manifest().name.clone(),
                )));
            }
            if member.kind() != expected {
                let found = member.kind();
                return Err(refused(match core {
                    true => BundleRefusal::ViewerCoreInvalid(format!(
                        "the viewer pins {}, not a program",
                        bundle_admission::kind_word(found)
                    )),
                    false => bundle_admission::misplaced(found, Some(expected)),
                }));
            }
            // A page pins exactly one bundle, its program. Whatever a
            // program pins is a program.
            let pins = member.take_pins();
            let page = member.kind() == BundleKind::Page;
            if page {
                kept_page = Some(crate::page_launch::Page {
                    name: member.manifest().name.clone(),
                    entrypoint: member.manifest().entrypoint.clone(),
                    files: member.take_files(),
                });
            }
            if page && pins.len() != 1 {
                return Err(refused(BundleRefusal::ViewerCoreInvalid(format!(
                    "the viewer pins {} bundles, not its one program",
                    pins.len()
                ))));
            }
            let known = (member.manifest().name.clone(), depth, pins.clone());
            seen.insert(pinned.to_string(), known);
            pending.extend(below(depth, BundleKind::Program, page, pins));
            if core {
                starts = Some(member);
            }
        }
        drop(trust);

        let failed = |error: ElastosError| BundleRefusal::StartFailed(error.to_string());
        let Some(component) = self.component_provider.clone() else {
            return Err(BundleRefusal::StartFailed(
                "No component compute provider is configured".to_string(),
            ));
        };
        // The seal follows the asks. A capsule whose manifest asks for
        // nothing is loaded sealed: the provider refuses its calls to the
        // bridge itself, so no handler sees one, whoever installed it. One
        // with asks is loaded unsealed, because it must be able to ask. Its
        // ceiling is filled where every capsule's is, by the shared end
        // below from the one bounds function; for a manifest this start
        // admits that is the asks and nothing else, because `asks` is the
        // one field on the key list that function reads.
        let Some(starts) = starts else {
            return Err(BundleRefusal::ViewerCoreInvalid(
                "no program was found under the viewer".to_string(),
            ));
        };
        let (manifest, bytes) = starts.into_component();
        let loaded = match manifest.asks.is_empty() {
            true => component.load_admitted_sealed(bytes, manifest).await,
            false => component.load_admitted(bytes, manifest).await,
        };
        let mut handle = loaded.map_err(failed)?;
        // The launch's content is the program's to read from before it
        // starts until the start is over, kept under the program's own
        // capsule id. "Over" is when the start returns, and also when it is
        // cancelled: the program may run on in its own thread after that,
        // and from then on it reads nothing of the content.
        let held = launch
            .clone()
            .map(|launch| LaunchHeld::new(&self.launch_contents, &handle.id.0, launch));
        let started = self.start_loaded(
            component,
            &mut handle,
            args,
            principal_id,
            None,
            LaunchMode::Bounded,
        );
        let started = started.await;
        drop(held);
        started.map_err(failed)?;
        Ok(crate::page_launch::Started {
            handle,
            accepted,
            launch,
            page: kept_page,
            content_name,
        })
    }

    /// The checks every bundle of a start by CID passes, the one asked for
    /// and each pinned one alike, in this order: the store has a slot for
    /// `cid`; one walk of it, inside what is `left` of the closure's budget;
    /// and then [`VerifiedBundle::check`], which builds the value this start
    /// keeps. That function requires the files to recompute to `cid`, accepts
    /// the signature beside the slot under `trust` (the start's one reading
    /// of who is trusted), and only then judges the manifest and a program's
    /// imports. Its fields are private to the module that defines the struct.
    /// What the walk took in comes off `left`.
    ///
    /// The walk is not blind to the manifest: to name a bundle it parses
    /// and validates `capsule.json` with the Runtime's reader, before the
    /// CID and the signature are known to be right, and refuses what that
    /// reader refuses. It keeps the name, the role and the type from it and
    /// decides nothing else by it. The manifest that can start, and the
    /// pins that are followed, come from the judgement after the signature.
    async fn admit_closure_member(
        &self,
        data_dir: &Path,
        asked: &LabCid,
        trust: &SignatureVerifier,
        left: &mut Budget,
        after_walk: &mut impl FnMut(&LabCid),
    ) -> std::result::Result<(VerifiedBundle, AcceptedSignature), BundleRefusal> {
        // Windows only: Unix already reports ENOTDIR (store IO) for a file where a
        // store directory must be, so its "missing" answer must not change.
        #[cfg(windows)]
        fn bundle_store_ancestor_blocks_lookup(data_dir: &Path, slot: &Path) -> Option<String> {
            let mut cursor = slot.parent();
            while let Some(path) = cursor {
                if !path.starts_with(data_dir) {
                    break;
                }
                match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_dir() => {}
                    Ok(_) => {
                        return Some(format!(
                            "could not look into the bundle store at {}: not a directory",
                            path.display()
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Some(format!(
                            "could not look into the bundle store at {}: {error}",
                            path.display()
                        ));
                    }
                }
                if path == data_dir {
                    break;
                }
                cursor = path.parent();
            }
            None
        }

        let slot = bundle_admission::bundle_slot(data_dir, asked);
        match std::fs::symlink_metadata(&slot) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A missing slot is "no such bundle" only when the store can be
                // looked into. On Windows, a file where a store directory must
                // be reports NotFound for the child path. That is still store IO.
                #[cfg(windows)]
                if let Some(why) = bundle_store_ancestor_blocks_lookup(data_dir, &slot) {
                    return Err(BundleRefusal::Store(why));
                }
                return Err(BundleRefusal::Missing(asked.to_string()));
            }
            Err(error) => {
                return Err(BundleRefusal::Store(format!(
                    "could not look at the slot for {asked}: {error}"
                )));
            }
        }
        // The one walk of the slot. The manifest and the component below
        // come from this value; the slot is not read again.
        let bundle = checked_bundle_within(&slot, *left).map_err(bundle_admission::walk_refusal)?;
        after_walk(asked);
        let files = bundle.entries();
        let bytes: u64 = files.iter().map(|file| file.content.len() as u64).sum();
        left.max_entries = left.max_entries.saturating_sub(files.len());
        left.max_total_bytes = left.max_total_bytes.saturating_sub(bytes);
        let signature = bundle_admission::bundle_signature_path(data_dir, asked);
        VerifiedBundle::check(&bundle, asked, &signature, trust)
    }

    /// Test only: whether who is trusted could be replaced at this moment.
    /// It cannot while a start by CID holds its one reading.
    #[cfg(test)]
    pub(crate) fn trust_can_change_now(&self) -> bool {
        self.signature_verifier.try_write().is_ok()
    }

    /// Test only: the paths of the content the capsule `id` may read right
    /// now as the program of a content launch.
    #[cfg(test)]
    pub(crate) fn launch_paths_of(&self, id: &str) -> Option<Vec<String>> {
        let launches = self.launch_contents.read().unwrap();
        launches.get(id).map(|launch| launch.paths())
    }

    /// Test only: the model-token ceilings the bridge holds right now, one
    /// entry per admitted instance. A missing id is not an admitted agent.
    #[cfg(test)]
    pub(crate) fn model_token_ceilings_held(&self) -> Vec<(String, u64)> {
        let ceilings = self
            .bridge_model_token_ceilings
            .read()
            .unwrap_or_else(|err| err.into_inner());
        let mut held: Vec<_> = ceilings
            .iter()
            .map(|(id, admission)| (id.clone(), admission.ceiling))
            .collect();
        held.sort();
        held
    }

    /// Test only: the ceiling the bridge holds the capsule `id` to right now,
    /// each entry as it prints.
    #[cfg(test)]
    pub(crate) fn ceiling_of(&self, id: &str) -> Option<Vec<String>> {
        let ceilings = self.bridge_manifest_capabilities.read().unwrap();
        let ceiling = ceilings.get(id);
        ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect())
    }

    /// Test only: what an end left in this Runtime's own tables, by the name
    /// of each that still holds the instance's id. Empty is A12-R's "nothing
    /// remains": no manifest ceiling, model-token ceiling, launch content or
    /// stop request. The compute provider's activation entry and principal
    /// are its tables: `provider_entry_for_test` reads the entry, and the
    /// provider's own row proves `forget_instance` takes the principal away.
    #[cfg(test)]
    pub(crate) async fn context_left_for_test(&self, id: &str) -> Vec<&'static str> {
        let mut left = Vec::new();
        if table_holds(&self.bridge_manifest_capabilities, id) {
            left.push("manifest ceiling");
        }
        if table_holds(&self.bridge_model_token_ceilings, id) {
            left.push("model-token ceiling");
        }
        if table_holds(&self.launch_contents, id) {
            left.push("launch content");
        }
        if table_holds(&self.activation_stops, id) {
            left.push("stop request");
        }
        left
    }

    /// Test only: whether the compute provider still holds an activation
    /// entry for this handle. `status` is the provider's own answer: an entry
    /// is a status, a forgotten one is not found.
    #[cfg(test)]
    pub(crate) async fn provider_entry_for_test(&self, handle: &CapsuleHandle) -> bool {
        match &self.component_provider {
            Some(component) => component.status(handle).await.is_ok(),
            None => false,
        }
    }

    /// Test only: the principal the compute provider holds for this handle's
    /// activation; `Some(None)` for an activation bound to no principal, `None`
    /// when it holds no binding.
    #[cfg(test)]
    pub(crate) async fn provider_principal_for_test(
        &self,
        handle: &CapsuleHandle,
    ) -> Option<Option<String>> {
        match &self.component_provider {
            Some(component) => component.bridge_principal(&handle.id).await,
            None => None,
        }
    }

    /// Test only: the manifest ceilings, so a planted session can copy the
    /// live run's ceiling. The copy itself lives with the storage rows.
    #[cfg(test)]
    pub(crate) fn manifest_ceilings_for_test(
        &self,
    ) -> Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>> {
        Arc::clone(&self.bridge_manifest_capabilities)
    }

    /// Test only: the tables the installed bridge host call reads for a call
    /// from `id`, as it reads them: the manifest ceiling, the launch content,
    /// the model-token ceiling and the stop request. A row builds the context
    /// from these, so a late call is judged by exactly what the end left.
    #[cfg(test)]
    pub(crate) fn bridge_tables_for_test(&self, id: &str) -> BridgeTables {
        let manifest_capabilities = self
            .manifest_ceilings_for_test()
            .read()
            .ok()
            .and_then(|guard| guard.get(id).cloned())
            .unwrap_or_default();
        let launch = self
            .launch_contents
            .read()
            .unwrap_or_else(|it| it.into_inner())
            .get(id)
            .cloned();
        let model_token_ceiling = self
            .bridge_model_token_ceilings
            .read()
            .unwrap_or_else(|it| it.into_inner())
            .get(id)
            .map(|admission| admission.ceiling);
        let stop = self
            .activation_stops
            .read()
            .unwrap_or_else(|it| it.into_inner())
            .get(id)
            .map(|stop| stop.flag.clone());
        BridgeTables {
            manifest_capabilities,
            launch,
            model_token_ceiling,
            stop,
        }
    }

    /// The end of every start, and the one place in this file that fills a
    /// capsule's ceiling: from the one bounds function, for a start from a
    /// folder and for a start by CID alike. While the activation runs, that
    /// ceiling is what the bridge holds it to and, for a component,
    /// `principal_id` is who it runs for; `args` go on its handle first.
    ///
    /// Bounded: this returns when the start has ended, well or badly, and the
    /// ceiling and principal go with it. Detached: a component returns after
    /// admission with `starting`; the worker's `started` changes the entry to
    /// `running`, and the ending watcher takes the ceiling
    /// and principal away and records the status and cause when the guest
    /// ends. The entry stays listed for [`ENDED_CAPSULE_RETENTION`].
    async fn start_loaded(
        &self,
        provider: Arc<dyn ComputeProvider>,
        handle: &mut CapsuleHandle,
        args: Vec<String>,
        principal_id: Option<String>,
        model_admission: Option<(AgentModelCeiling, Option<AgentLiveRun>)>,
        mode: LaunchMode,
    ) -> Result<()> {
        let (model_admission, mut live_run) = match model_admission {
            Some((ceiling, live_run)) => (Some(ceiling), live_run),
            None => (None, None),
        };
        if live_run.is_some() && !handle.manifest.is_component_capsule() {
            return Err(ElastosError::InvalidManifest(
                crate::agent_admission::NOT_A_COMPONENT.to_string(),
            ));
        }
        // A v2 component stays up. A folder start uses this detached path,
        // with the same admission, grants, and limits as a v1 start.
        let v2_resident = handle.manifest.bus_contract.as_deref()
            == Some(elastos_common::ELASTOS_BUS_V2_CONTRACT);
        let detached_component = if (mode == LaunchMode::Detached || v2_resident)
            && handle.manifest.is_component_capsule()
        {
            Some(self.component_provider.clone().ok_or_else(|| {
                ElastosError::Compute("No component compute provider is configured".to_string())
            })?)
        } else {
            None
        };
        let mut carried = if model_admission.is_some() {
            live_run.take()
        } else {
            None
        };
        let held = detached_component.as_ref().map(|component| {
            ActivationContextHeld::new(self, handle, component.clone(), carried.take())
        });
        drop(live_run);
        drop(carried);
        self.hold_launch_context(handle, principal_id.clone(), model_admission)
            .await;

        // Set args on handle before starting
        handle.args = args;

        if let Some(component) = detached_component {
            let id = handle.id.clone();
            self.register_capsule(RunningCapsuleInfo {
                id: id.0.clone(),
                name: handle.manifest.name.clone(),
                status: CAPSULE_STARTING.to_string(),
                capsule_type: handle.manifest.capsule_type.clone(),
                handle: Some(handle.clone()),
                session_id: id.0.clone(),
                principal: principal_id,
                cause: None,
                ended_at: None,
            })
            .await;
            self.watch_activation(
                id,
                handle.clone(),
                component,
                held.expect("detached context"),
            );
            return Ok(());
        }

        // Start capsule
        let start = provider.start(handle).await;
        self.release_launch_context(&handle.id).await;
        start
    }

    /// The ceiling and, for a component, the principal the bridge holds this
    /// activation to while it runs. `Some` is the ceiling admission recorded;
    /// a start that was not admitted gets no token entry.
    async fn hold_launch_context(
        &self,
        handle: &CapsuleHandle,
        principal_id: Option<String>,
        model_admission: Option<AgentModelCeiling>,
    ) {
        if let Ok(mut bounds) = self.bridge_manifest_capabilities.write() {
            bounds.insert(
                handle.id.0.clone(),
                handle.manifest.resource_authority_bounds(),
            );
        }
        if let Some(admission) = model_admission {
            self.bridge_model_token_ceilings
                .write()
                .unwrap_or_else(|err| err.into_inner())
                .insert(handle.id.0.clone(), admission);
        }
        if handle.manifest.is_component_capsule() {
            if let Some(component) = &self.component_provider {
                #[cfg(test)]
                self.live_run_await("principal").await;
                component
                    .set_bridge_principal(&handle.id, principal_id)
                    .await;
            }
        }
    }

    /// Takes away what [`Self::hold_launch_context`] put in place, at the end
    /// of the activation however it ended.
    async fn release_launch_context(&self, id: &elastos_common::CapsuleId) {
        if let Some(component) = &self.component_provider {
            component.clear_bridge_principal(id).await;
        }
        if let Ok(mut bounds) = self.bridge_manifest_capabilities.write() {
            bounds.remove(&id.0);
        }
        self.bridge_model_token_ceilings
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&id.0);
    }

    /// Remove a loaded component before the watcher can start its guest. This
    /// exercises the real provider's pre-start error through the registry.
    #[cfg(test)]
    pub(crate) async fn remove_loaded_component_for_test(&self, id: &str) {
        let handle = self
            .get_capsule(id)
            .await
            .and_then(|entry| entry.handle)
            .expect("the admitted component has a handle");
        let component = self
            .component_provider
            .as_ref()
            .expect("component provider");
        component
            .stop(&handle)
            .await
            .expect("remove the loaded component");
    }

    /// Hold registration so a route can be cancelled after it has installed
    /// its admission context and before its watcher owns that context.
    #[cfg(test)]
    pub(crate) async fn hold_capsule_registry_for_test(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<String, RunningCapsuleInfo>> {
        self.running_capsules.write().await
    }

    /// The compute provider's own status of a registered component: it is
    /// `Running` from the moment its start runs guest code.
    #[cfg(test)]
    pub(crate) async fn component_status_for_test(
        &self,
        id: &str,
    ) -> Option<elastos_common::CapsuleStatus> {
        let handle = self.get_capsule(id).await?.handle?;
        let component = self.component_provider.as_ref()?;
        component.status(&handle).await.ok()
    }

    /// The cause a stop of `id` has recorded so far, read from its stop
    /// request.
    #[cfg(test)]
    pub(crate) fn requested_stop_for_test(&self, id: &str) -> Option<String> {
        let stops = self
            .activation_stops
            .read()
            .unwrap_or_else(|err| err.into_inner());
        stops.get(id)?.cause()
    }

    /// Starts this activation and waits for its worker to publish its outcome, then ends it
    /// through [`ActivationContextHeld::end_instance`]: the entry is `stopped`
    /// with cause `completed` on a natural return, or `failed` with the
    /// trap's cause, and it keeps its `ended_at` for
    /// [`ENDED_CAPSULE_RETENTION`]. A stop requested before the outcome ends
    /// the activation as `stopped` with the reason it was requested with when
    /// the worker's ending is that stop's doing: a return or a `stopped`
    /// after the request, a trap after the bridge left the guest's call for
    /// it, or a start the stop took away or interrupted.
    fn watch_activation(
        &self,
        id: elastos_common::CapsuleId,
        handle: CapsuleHandle,
        component: Arc<ComponentProvider>,
        held: ActivationContextHeld,
    ) {
        use elastos_compute::providers::ActivationOutcome;

        let registry = self.running_capsules.clone();
        tokio::spawn(async move {
            // A stop that arrived while the activation was still starting: the
            // guest is not run at all, and the stop is its whole end.
            if let Some(cause) = held.requested_stop() {
                held.end_instance(CAPSULE_STOPPED, &cause).await;
                return;
            }
            let (status, cause) = match component.start_resident(&handle).await {
                Ok(mut activation) => {
                    // Only the compute worker's `started` moves the entry from
                    // admission's `starting` to `running`.
                    if let Some(info) = registry.write().await.get_mut(&id.0) {
                        info.status = CAPSULE_RUNNING.to_string();
                    }
                    match activation.ended().await {
                        ActivationOutcome::Returned => match held.requested_stop() {
                            Some(cause) => (CAPSULE_STOPPED, cause),
                            None => (CAPSULE_STOPPED, CAUSE_COMPLETED.to_string()),
                        },
                        // A trap is the guest's own ending unless the stop is
                        // what ended it: the worker's epoch interrupt, or the
                        // bridge leaving the guest's call for the stop.
                        ActivationOutcome::Trapped(message) => match held.requested_stop() {
                            Some(cause) if held.stop_cancelled_guest() => (CAPSULE_STOPPED, cause),
                            _ => (CAPSULE_FAILED, message),
                        },
                        ActivationOutcome::Stopped => (
                            CAPSULE_STOPPED,
                            held.requested_stop()
                                .unwrap_or_else(|| "stopped by request".to_string()),
                        ),
                    }
                }
                Err(err) => match held.requested_stop() {
                    Some(cause) if start_ended_by_stop(&err) => (CAPSULE_STOPPED, cause),
                    _ => (CAPSULE_FAILED, err.to_string()),
                },
            };
            held.end_instance(status, &cause).await;
        });
    }

    /// Check that all providers required by a capsule are registered
    async fn check_provider_dependencies(&self, manifest: &CapsuleManifest) -> Result<()> {
        if let Some(ref providers) = manifest.providers {
            let registry = self.provider_registry.read().await;
            if let Some(ref registry) = *registry {
                for scheme in providers.keys() {
                    if !registry.has_provider(scheme).await {
                        return Err(ElastosError::Compute(format!(
                            "Capsule '{}' requires provider for scheme '{}' which is not registered",
                            manifest.name, scheme
                        )));
                    }
                }
            }
            // If no registry is set, skip check (CLI mode without server)
        }
        Ok(())
    }

    /// Verify capsule signature if verification is enabled
    async fn verify_capsule_signature(
        &self,
        manifest: &CapsuleManifest,
        path: &Path,
        admitted: Option<&[u8]>,
    ) -> Result<Signer> {
        if manifest.signature.is_none() {
            return match &*self.unsigned_capsules.read().await {
                UnsignedCapsules::Allowed => {
                    tracing::warn!(
                        "Unsigned capsule '{}' allowed because dev_mode=true",
                        manifest.name
                    );
                    Ok(Signer::UnsignedDev)
                }
                // An agent is named by the key that signed it. The installed
                // release has no signer DID yet (rong-ruling-a5-measure-1945 Q3,
                // gated), so an agent declared there is refused, failing closed.
                UnsignedCapsules::InstalledRelease(_) if manifest.agent.is_some() => {
                    Err(ElastosError::InvalidManifest(format!(
                        "Capsule '{}' declares an agent but no trusted key signed it",
                        manifest.name
                    )))
                }
                UnsignedCapsules::InstalledRelease(data_dir) => {
                    crate::setup::verify_installed_release_capsule(data_dir, &manifest.name, path)
                        .map_err(|e| {
                            ElastosError::InvalidManifest(format!(
                                "Capsule '{}' is unsigned and not from the installed signed release: {e:#}",
                                manifest.name
                            ))
                        })
                        .map(|()| Signer::InstalledRelease)
                }
                UnsignedCapsules::Refused(_) => Err(ElastosError::InvalidManifest(format!(
                    "Capsule '{}' is unsigned; only a source or development Home with dev_mode = true runs unsigned capsules",
                    manifest.name
                ))),
            };
        }

        #[cfg(test)]
        self.live_run_await("signature").await;
        let verifier = self.signature_verifier.read().await;

        if verifier.trusted_key_count() == 0 {
            return Err(ElastosError::InvalidManifest(
                "Capsule signature verification has no trusted keys configured".into(),
            ));
        }

        // Hash the entrypoint: the bytes already read for a component, the file otherwise.
        let content_hash = match admitted {
            Some(bytes) => hash_content(bytes),
            None => {
                let entrypoint_path = path.join(&manifest.entrypoint);
                hash_content(&tokio::fs::read(&entrypoint_path).await.map_err(|e| {
                    ElastosError::InvalidManifest(format!(
                        "Failed to read entrypoint {}: {}",
                        manifest.entrypoint, e
                    ))
                })?)
            }
        };

        // Verify signature; the matched trusted key names the signer.
        let Some(key) = verifier.verify_capsule(manifest, &content_hash)? else {
            return Err(ElastosError::InvalidManifest(
                "Capsule signature verification failed".into(),
            ));
        };
        let did = crate::crypto::encode_did_key(&key)
            .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;

        tracing::info!("Capsule signature verified successfully by {}", did);
        Ok(Signer::Key { did })
    }

    /// Stop a running capsule
    pub async fn stop(&self, handle: &CapsuleHandle) -> Result<()> {
        // Find the provider that supports this capsule type
        let provider = self
            .get_provider_for_manifest(&handle.manifest)
            .ok_or_else(|| {
                ElastosError::Compute(format!(
                    "No compute provider supports capsule type: {:?}",
                    handle.manifest.capsule_type
                ))
            })?;

        provider.stop(handle).await
    }

    /// Check if a capsule type is supported by any provider
    pub fn supports_capsule_type(&self, capsule_type: &CapsuleType) -> bool {
        self.get_provider(capsule_type).is_some()
    }

    /// Register a running capsule with the runtime
    ///
    /// This is used by external code (like main.rs for MicroVM capsules) to
    /// register capsules that weren't started through Runtime's run_* methods.
    pub async fn register_capsule(&self, info: RunningCapsuleInfo) {
        #[cfg(test)]
        self.live_run_await("register").await;
        let mut capsules = self.running_capsules.write().await;
        prune_ended(&mut capsules, std::time::Instant::now());
        tracing::info!("Registered capsule '{}' with ID: {}", info.name, info.id);
        capsules.insert(info.id.clone(), info);
    }

    /// Unregister a capsule from the runtime
    pub async fn unregister_capsule(&self, id: &str) {
        let mut capsules = self.running_capsules.write().await;
        if capsules.remove(id).is_some() {
            tracing::info!("Unregistered capsule: {}", id);
        }
    }

    /// List all registered capsules, sorted by id. An entry that ended more
    /// than [`ENDED_CAPSULE_RETENTION`] ago leaves the listing here.
    pub async fn list_capsules(&self) -> Vec<RunningCapsuleInfo> {
        if let Some(component) = &self.component_provider {
            component.reap_joined_residents().await;
        }
        self.list_capsules_pruning_at(std::time::Instant::now())
            .await
    }

    /// Test the retention boundary without waiting for the clock.
    #[cfg(test)]
    pub(crate) async fn list_capsules_at(
        &self,
        now: std::time::Instant,
    ) -> Vec<RunningCapsuleInfo> {
        self.list_capsules_pruning_at(now).await
    }

    async fn list_capsules_pruning_at(&self, now: std::time::Instant) -> Vec<RunningCapsuleInfo> {
        let mut capsules = self.running_capsules.write().await;
        prune_ended(&mut capsules, now);
        let mut listed: Vec<RunningCapsuleInfo> = capsules.values().cloned().collect();
        listed.sort_by(|left, right| left.id.cmp(&right.id));
        listed
    }

    /// Get a specific capsule by ID
    pub async fn get_capsule(&self, id: &str) -> Option<RunningCapsuleInfo> {
        let mut capsules = self.running_capsules.write().await;
        prune_ended(&mut capsules, std::time::Instant::now());
        capsules.get(id).cloned()
    }

    /// Update a capsule's status
    pub async fn update_capsule_status(&self, id: &str, status: &str) {
        let mut capsules = self.running_capsules.write().await;
        if let Some(info) = capsules.get_mut(id) {
            info.status = status.to_string();
            tracing::debug!("Updated capsule {} status to: {}", id, status);
        }
    }

    /// Stop a capsule by its ID, with the reason `user`: the route without a
    /// body. See [`Self::stop_capsule_with_reason`].
    pub async fn stop_capsule_by_id(&self, id: &str) -> Result<Option<RunningCapsuleInfo>> {
        self.stop_capsule_with_reason(id, "user").await
    }

    /// Stop a capsule by its ID with this reason (M1-R A10-R). A detached
    /// activation is ended by its own watcher, the one place an activation
    /// ends: this records the reason, raises the flag the bridge's wait loop
    /// reads, gives the compute provider the stop its epoch callback reads,
    /// and waits for that end. The entry is then `stopped` with cause
    /// `stopped: <reason>` and is kept for [`ENDED_CAPSULE_RETENTION`], unless
    /// the guest ended for its own reason first, or an earlier stop's reason
    /// was recorded first: then the entry says so.
    ///
    /// Returns the entry as the stop leaves it, or `None` if the id is not
    /// registered. A stop of an ending or ended activation changes nothing
    /// and returns the outcome its one end recorded. An activation with no
    /// stop request (a capsule registered with a handle by its launcher) is
    /// stopped and unregistered as before.
    pub async fn stop_capsule_with_reason(
        &self,
        id: &str,
        reason: &str,
    ) -> Result<Option<RunningCapsuleInfo>> {
        // The entry and its stop request are read under one lock: the end
        // takes the request away only after the entry records `ended_at`, so
        // an entry not ended here still has its request if a watcher ends it.
        let (info, stop) = {
            let capsules = self.running_capsules.read().await;
            let Some(info) = capsules.get(id).cloned() else {
                return Ok(None);
            };
            let stops = self
                .activation_stops
                .read()
                .unwrap_or_else(|err| err.into_inner());
            (info, stops.get(id).cloned())
        };
        if info.ended_at.is_some() {
            return Ok(Some(info));
        }

        // A guest in guest code, its start function included, is trapped by
        // its epoch callback, which reads this provider's stop flag; a
        // component not yet started is taken away, so its start ends as
        // stopped before it runs. A guest inside a bridge call leaves that
        // call through the stop's own flag, which the bridge checks.
        let provider = info
            .handle
            .as_ref()
            .and_then(|handle| Some((handle, self.get_provider_for_manifest(&handle.manifest)?)));

        let Some(stop) = stop else {
            // No watcher holds this activation: stop it through its provider
            // and take its entry away, as before.
            if let Some((handle, provider)) = provider {
                tracing::info!("Stopping capsule '{}' ({})", info.name, id);
                provider.stop(handle).await?;
            }
            self.unregister_capsule(id).await;
            return Ok(Some(RunningCapsuleInfo {
                status: CAPSULE_STOPPED.to_string(),
                ended_at: Some(std::time::Instant::now()),
                ..info
            }));
        };

        // The reason is recorded before the flag is raised, so the end that
        // sees the flag records this cause.
        stop.request(reason);
        if let Some((handle, provider)) = provider {
            tracing::info!("Stopping capsule '{}' ({})", info.name, id);
            provider.stop(handle).await?;
        }

        self.wait_ended(id).await;
        // The end happened, whatever its recorded status and cause: the
        // entry the list serves says which, and a stop whose guest ran to its
        // own ending is still a stop that left nothing running.
        Ok(self.get_capsule(id).await)
    }

    /// Waits until the registry records this activation's end, or until the
    /// wait bound passes. The worker's own deadline is 10 s; the bridge's
    /// longest wait is 30 s.
    async fn wait_ended(&self, id: &str) {
        #[cfg(test)]
        let bound = self.test_stop_wait_bound();
        #[cfg(not(test))]
        let bound = std::time::Duration::from_secs(40);
        let deadline = std::time::Instant::now() + bound;
        loop {
            let ended = self
                .get_capsule(id)
                .await
                .map(|info| info.ended_at.is_some())
                .unwrap_or(true);
            if ended || std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

/// Takes an ended entry away only if it is still this end's: a reader may have
/// pruned it first, or a later start may have replaced it, and neither is this
/// end's to remove.
fn remove_ended_entry(
    capsules: &mut HashMap<String, RunningCapsuleInfo>,
    id: &str,
    ended_at: std::time::Instant,
) {
    if capsules
        .get(id)
        .is_some_and(|info| info.ended_at == Some(ended_at))
    {
        capsules.remove(id);
    }
}

/// Removes the entries whose activation ended at least
/// [`ENDED_CAPSULE_RETENTION`] before `now`. The end schedules its own
/// removal with the [`RETENTION_SWEEPER`]; a reader still
/// prunes, so the boundary can be read at an injected instant and an entry
/// registered already ended cannot outlive its retention either.
fn prune_ended(capsules: &mut HashMap<String, RunningCapsuleInfo>, now: std::time::Instant) {
    capsules.retain(|_, info| match info.ended_at {
        Some(ended_at) => now.duration_since(ended_at) < ENDED_CAPSULE_RETENTION,
        None => true,
    });
}

/// Whether a table still holds this id. A poisoned lock still holds its map,
/// as every reader here assumes.
#[cfg(test)]
fn table_holds<T>(table: &StdRwLock<HashMap<String, T>>, id: &str) -> bool {
    table
        .read()
        .unwrap_or_else(|err| err.into_inner())
        .contains_key(id)
}

#[cfg(all(test, target_os = "macos"))]
fn live_thread_count() -> u32 {
    extern "C" {
        fn mach_task_self() -> libc::mach_port_t;
    }
    // SAFETY: `mach_task_self` is this process. `task_threads` writes a kernel
    // array that this function releases with `vm_deallocate` before it returns.
    unsafe {
        let mut list: libc::thread_act_array_t = std::ptr::null_mut();
        let mut count: libc::mach_msg_type_number_t = 0;
        let task = mach_task_self();
        let kr = libc::task_threads(task, &mut list, &mut count);
        if kr == 0 && !list.is_null() {
            let bytes = (count as usize).saturating_mul(std::mem::size_of::<libc::thread_act_t>());
            libc::vm_deallocate(task, list as libc::vm_address_t, bytes as libc::vm_size_t);
        }
        count
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_trait::async_trait;
    use elastos_common::{
        elastos_bus_v1_wit_sha256, elastos_bus_v2_wit_sha256, CapsuleId, CapsuleManifest,
        CapsuleRole, CapsuleStatus, CapsuleType, Permissions, ResourceLimits,
        ELASTOS_BUS_V1_CONTRACT, ELASTOS_BUS_V2_CONTRACT, SCHEMA_V1,
    };
    use elastos_compute::{CapsuleInfo, ComputeProvider};
    use elastos_runtime::capability::pending::GrantDuration;
    #[cfg(unix)]
    use elastos_runtime::capability::Settler;
    use elastos_runtime::capability::{CapabilityManager, CapabilityStore, TokenConstraints};
    use elastos_runtime::primitives::audit::{AuditEvent, AuditLog};
    use elastos_runtime::primitives::metrics::MetricsManager;
    use elastos_runtime::provider::{
        Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
    };
    use elastos_storage::providers::LocalFSProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use wasm_encoder::{
        Component, ComponentImportSection, ComponentTypeRef as EncodedComponentTypeRef,
        ComponentTypeSection, InstanceType,
    };

    impl Runtime {
        /// How many per-agent turns this runtime still holds.
        pub(crate) fn launch_turn_count_for_test(&self) -> usize {
            self.launch_turns
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .len()
        }

        /// Gives `planted_id` the model account and manifest ceiling `live_id`
        /// already holds. This does not Start the planted session and does not
        /// admit a live run.
        pub(crate) fn share_agent_model_account_for_test(&self, live_id: &str, planted_id: &str) {
            let held = self
                .bridge_model_token_ceilings
                .read()
                .unwrap_or_else(|err| err.into_inner())
                .get(live_id)
                .cloned()
                .expect("the live run holds this agent's model account");
            self.bridge_model_token_ceilings
                .write()
                .unwrap_or_else(|err| err.into_inner())
                .insert(planted_id.to_string(), held);
            let bounds = self
                .bridge_manifest_capabilities
                .read()
                .ok()
                .and_then(|guard| guard.get(live_id).cloned())
                .unwrap_or_default();
            if let Ok(mut guard) = self.bridge_manifest_capabilities.write() {
                guard.insert(planted_id.to_string(), bounds);
            }
        }

        /// The account [`Self::model_dispatch_budget`] would hand this capsule.
        pub(crate) fn model_dispatch_for_test(
            &self,
            capsule_id: &str,
        ) -> (
            Option<u64>,
            Option<crate::resource_bridge::ModelDispatchBudget>,
        ) {
            Self::model_dispatch_budget(
                capsule_id,
                &self.bridge_model_token_ceilings,
                &self.model_budget,
                &self.model_offer_bounds,
            )
        }

        /// The bridge context the hostcall builds for `capsule_id`, including the
        /// model account from [`Self::model_dispatch_budget`].
        pub(crate) async fn bridge_context_for_test(
            &self,
            capsule_id: &str,
            principal_id: Option<String>,
        ) -> crate::resource_bridge::BridgeContext {
            let registry = self
                .provider_registry
                .read()
                .await
                .clone()
                .expect("the runtime has a provider registry");
            let authority = self
                .instance_authority
                .read()
                .unwrap_or_else(|err| err.into_inner())
                .clone()
                .expect("the runtime has its capability plane");
            let tables = self.bridge_tables_for_test(capsule_id);
            let (model_token_ceiling, model_budget) = self.model_dispatch_for_test(capsule_id);
            crate::resource_bridge::BridgeContext {
                provider_registry: registry,
                capability_manager: authority.capability_manager,
                pending_store: authority.pending_store,
                capsule_id: capsule_id.to_string(),
                session_id: capsule_id.to_string(),
                principal_id,
                manifest_capabilities: tables.manifest_capabilities,
                data_dir: Some(authority.data_dir),
                launch: tables.launch,
                model_token_ceiling,
                model_budget,
                stop: tables.stop,
            }
        }
    }

    pub(crate) struct NoopComputeProvider;

    #[async_trait]
    impl ComputeProvider for NoopComputeProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("test-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    struct CountingComputeProvider {
        loads: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    pub(crate) struct BusConformanceProvider {
        pub(crate) requests: Mutex<Vec<serde_json::Value>>,
    }

    #[async_trait]
    impl Provider for BusConformanceProvider {
        async fn handle(
            &self,
            _request: ResourceRequest,
        ) -> std::result::Result<ResourceResponse, ProviderError> {
            Err(ProviderError::Provider(
                "the Bus conformance provider accepts JSON dispatch only".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            vec!["test"]
        }

        fn name(&self) -> &'static str {
            "bus-v1-conformance"
        }

        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> std::result::Result<serde_json::Value, ProviderError> {
            self.requests.lock().await.push(request.clone());
            Ok(serde_json::json!({"status": "ok"}))
        }
    }

    #[async_trait]
    impl ComputeProvider for CountingComputeProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(CapsuleHandle {
                id: CapsuleId::new("counting-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    /// The map the launch entry fills: capsule id to ceiling.
    type Ceilings = Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>>;

    /// Records, when a capsule starts, the ceiling the launch entry filled for it.
    #[derive(Default)]
    struct CeilingReadingProvider {
        ceilings: std::sync::OnceLock<Ceilings>,
        seen: std::sync::Mutex<Vec<Option<Vec<String>>>>,
    }

    #[async_trait]
    impl ComputeProvider for CeilingReadingProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("ceiling-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
            let ceilings = self.ceilings.get().unwrap().read().unwrap();
            let ceiling = ceilings.get(&handle.id.0);
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            self.seen.lock().unwrap().push(ceiling);
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    /// The launch entry fills a capsule's ceiling from the bounds function: a
    /// capability is its ceiling, for any action (the control), and a
    /// manifest whose only authority field is asks is started under those
    /// asks, each with its actions.
    #[tokio::test]
    async fn the_launch_entry_starts_a_manifest_with_asks_under_its_asks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let provider = Arc::new(CeilingReadingProvider::default());
        let runtime = Runtime::new(storage, provider.clone());
        assert!(provider
            .ceilings
            .set(runtime.bridge_manifest_capabilities.clone())
            .is_ok());
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = temp_dir.path().join("asks-launch");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        let mut with_capability = unsigned_manifest();
        with_capability.capsule_type = CapsuleType::MicroVM;
        with_capability.entrypoint = "rootfs.ext4".to_string();
        let mut with_asks = with_capability.clone();
        with_capability.capabilities = vec!["elastos://did/*".to_string()];
        with_asks.asks = vec![elastos_common::ManifestAsk {
            resource: "elastos://did/*".to_string(),
            actions: vec![elastos_common::AskAction::Read],
        }];
        for manifest in [with_capability, with_asks] {
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            runtime.run_local(&dir, Vec::new()).await.unwrap();
        }
        assert_eq!(
            *provider.seen.lock().unwrap(),
            vec![
                Some(vec!["elastos://did/*".to_string()]),
                Some(vec!["elastos://did/* [read]".to_string()])
            ]
        );
    }

    /// A manifest whose requirement carries a `cid`: a pin. Only
    /// `PinnedManifest` reads one; every start from a folder parses the
    /// ordinary manifest type, which refuses the key.
    pub(crate) const PINNED_MANIFEST: &str = r#"{"schema":"elastos.capsule/v1","name":"pinned-fixture","version":"0.1.0","role":"app","type":"microvm","entrypoint":"rootfs.ext4","requires":[{"name":"viewer","kind":"capsule","cid":"bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy"}]}"#;

    /// The same manifest with the pin taken out: the control of each row.
    pub(crate) fn unpinned_manifest() -> String {
        let pin = r#","cid":"bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy""#;
        assert_eq!(PINNED_MANIFEST.matches(pin).count(), 1);
        PINNED_MANIFEST.replace(pin, "")
    }

    /// Writes a capsule folder holding `manifest` and its entrypoint file.
    pub(crate) fn write_fixture_capsule(parent: &Path, manifest: &str) -> PathBuf {
        let dir = parent.join("pinned-fixture");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        std::fs::write(dir.join("capsule.json"), manifest).unwrap();
        dir
    }

    /// The launch entry stops at its own manifest parse for a pinned
    /// manifest, before a compute provider loads anything. The same manifest
    /// without the pin is loaded, so the pin is what stops it.
    #[tokio::test]
    async fn the_launch_entry_stops_at_its_manifest_parse_for_a_pinned_requirement() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = write_fixture_capsule(temp_dir.path(), PINNED_MANIFEST);
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        let expected = "Invalid manifest: Failed to parse capsule.json: unknown field `cid`";
        assert!(error.to_string().starts_with(expected), "{error}");
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        write_fixture_capsule(temp_dir.path(), &unpinned_manifest());
        runtime.run_local(&dir, Vec::new()).await.unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    /// What a provider saw when it was asked to start a capsule: the ceiling
    /// recorded for it, and the arguments on its handle.
    type SeenAtStart = (Option<Vec<String>>, Vec<String>);

    /// Records, at each start, the ceiling the launch entry filled for the
    /// capsule and the arguments on its handle; refuses the start when told to.
    #[derive(Default)]
    struct TailRecordingProvider {
        ceilings: std::sync::OnceLock<Ceilings>,
        starts: std::sync::Mutex<Vec<SeenAtStart>>,
        refuse: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl ComputeProvider for TailRecordingProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("tail-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
            let ceilings = self.ceilings.get().unwrap().read().unwrap();
            let ceiling = ceilings.get(&handle.id.0);
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            self.starts
                .lock()
                .unwrap()
                .push((ceiling, handle.args.clone()));
            if self.refuse.load(Ordering::SeqCst) {
                return Err(ElastosError::Compute("refused by the test".to_string()));
            }
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    /// The end of the folder start, asserted where it is called: while the
    /// provider starts the capsule, the ceiling recorded for it is its
    /// manifest's, and its handle carries the caller's arguments; when the
    /// start has ended, well or badly, no ceiling is left for it. Written
    /// before that end is shared with the start by CID, so that the move
    /// keeps each of these.
    #[tokio::test]
    async fn the_folder_start_records_the_ceiling_hands_over_the_args_and_clears_the_ceiling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let provider = Arc::new(TailRecordingProvider::default());
        let runtime = Runtime::new(storage, provider.clone());
        assert!(provider
            .ceilings
            .set(runtime.bridge_manifest_capabilities.clone())
            .is_ok());
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = temp_dir.path().join("tail");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        let mut manifest = unsigned_manifest();
        manifest.capsule_type = CapsuleType::MicroVM;
        manifest.entrypoint = "rootfs.ext4".to_string();
        manifest.capabilities = vec!["elastos://did/*".to_string()];
        manifest.permissions.storage = vec!["localhost://Users/self/Documents/*".to_string()];
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let ceiling = vec![
            "elastos://did/*".to_string(),
            "localhost://Users/self/Documents/*".to_string(),
        ];
        let args = vec!["one".to_string(), "two".to_string()];
        let none_left = || {
            runtime
                .bridge_manifest_capabilities
                .read()
                .unwrap()
                .is_empty()
        };

        let handle = runtime.run_local(&dir, args.clone()).await.unwrap();
        assert_eq!(handle.args, args);
        assert_eq!(handle.id.0, "tail-capsule");
        assert_eq!(
            *provider.starts.lock().unwrap(),
            vec![(Some(ceiling.clone()), args.clone())]
        );
        assert!(
            none_left(),
            "no ceiling is left after a start that ended well"
        );

        provider.refuse.store(true, Ordering::SeqCst);
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        assert_eq!(error.to_string(), "Compute error: refused by the test");
        assert_eq!(
            *provider.starts.lock().unwrap(),
            vec![(Some(ceiling.clone()), args), (Some(ceiling), Vec::new())]
        );
        assert!(none_left(), "no ceiling is left after a start that failed");
    }

    /// The same for a component, through the real component provider. The
    /// fixture component asks the Runtime who it runs for and goes on only
    /// for its own person; then it calls the bridge. So: with that person
    /// given, its call reaches the bridge with that principal and under the
    /// ceiling of its manifest; with no person given, it ends before any
    /// call. No ceiling is left either time. The bridge here answers with a
    /// refusal, so nothing is granted and no provider is asked.
    #[tokio::test]
    async fn the_folder_start_of_a_component_gives_the_bridge_its_principal_and_ceiling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        type Call = (String, Option<String>, Option<Vec<String>>);
        let calls: Arc<std::sync::Mutex<Vec<Call>>> = Arc::default();
        let seen = calls.clone();
        let ceilings = runtime.bridge_manifest_capabilities.clone();
        runtime.set_bridge_hostcall(Arc::new(move |_line, capsule_id, principal_id| {
            let ceiling = ceilings.read().unwrap().get(capsule_id).cloned();
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            seen.lock().unwrap().push((
                capsule_id.to_string(),
                principal_id.map(ToOwned::to_owned),
                ceiling,
            ));
            Err("refused by the test".to_string())
        }));
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let person = "person:local:bus-conformance";

        let ended = runtime
            .run_local_with_principal(
                &fixture,
                Vec::new(),
                Some(crate::resource_bridge::BridgePrincipal::for_test(person)),
            )
            .await;

        let none_left = || {
            runtime
                .bridge_manifest_capabilities
                .read()
                .unwrap()
                .is_empty()
        };
        let made = calls.lock().unwrap().clone();
        assert_eq!(made.len(), 1, "one call, refused: {made:?}");
        for (capsule_id, principal_id, ceiling) in made.iter() {
            assert!(capsule_id.starts_with("component-"), "{capsule_id}");
            assert_eq!(principal_id.as_deref(), Some(person));
            assert_eq!(
                ceiling.as_deref(),
                Some(&["elastos://test/bus/probe".to_string()][..])
            );
        }
        assert!(none_left(), "no ceiling is left after the component ended");
        let error = ended.expect_err("the fixture ends in an error when its call is refused");
        assert_eq!(
            error.to_string(),
            "Compute error: Component capsule denied: BusError::Internal(\"refused by the test\")"
        );

        let error = runtime
            .run_local_with_principal(&fixture, Vec::new(), None)
            .await
            .expect_err("the fixture does not go on without its person");
        assert_eq!(
            error.to_string(),
            "Compute error: Component capsule denied: BusError::Denied(\"Runtime did not bind the conformance principal\")"
        );
        assert_eq!(calls.lock().unwrap().len(), 1, "no call without the person");
        assert!(none_left(), "no ceiling is left after that start either");
    }

    /// A12-R at the one end, in this Runtime's tables: the manifest ceiling,
    /// the model-token ceiling, the launch content and the stop request all
    /// go. No agent launch holds content; a content start does, under its
    /// program's own id, and the end takes it away, so nothing a later bridge
    /// call could be held to or read survives.
    #[tokio::test]
    async fn the_one_end_leaves_nothing_in_the_tables_the_start_filled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let component = Arc::new(ComponentProvider::new());
        let runtime =
            Runtime::with_providers_and_component(storage, Vec::new(), Some(component.clone()));
        let manifest: CapsuleManifest = serde_json::from_str(&component_manifest_json("ended"))
            .expect("the component manifest");
        let handle = CapsuleHandle {
            id: CapsuleId::new("component-ended"),
            manifest,
            args: Vec::new(),
        };
        let id = handle.id.0.clone();
        runtime.launch_contents.write().unwrap().insert(
            id.clone(),
            Arc::new(
                crate::resource_bridge::LaunchContent::new(std::collections::BTreeMap::new())
                    .expect("an empty content"),
            ),
        );
        runtime
            .bridge_manifest_capabilities
            .write()
            .unwrap()
            .insert(id.clone(), handle.manifest.resource_authority_bounds());
        runtime.bridge_model_token_ceilings.write().unwrap().insert(
            id.clone(),
            AgentModelCeiling {
                ceiling: 7,
                key: AgentKey::for_test("agent:v2:ended"),
            },
        );

        assert_eq!(
            runtime.bridge_bounds_for_capsule(&id),
            Some(handle.manifest.resource_authority_bounds()),
            "the attached bridge reads the active manifest ceiling"
        );

        let held = ActivationContextHeld::new(&runtime, &handle, component, None);
        let mut filled = runtime.context_left_for_test(&id).await;
        filled.sort_unstable();
        assert_eq!(
            filled,
            [
                "launch content",
                "manifest ceiling",
                "model-token ceiling",
                "stop request",
            ],
            "the start filled the tables"
        );

        held.end_instance(CAPSULE_FAILED, "test end").await;
        assert_eq!(
            runtime.context_left_for_test(&id).await,
            Vec::<&str>::new(),
            "the one end leaves nothing"
        );
        assert_eq!(runtime.bridge_bounds_for_capsule(&id), None);
    }

    /// The retention the sweeper rows give their activation. The sweeper runs
    /// on the real clock, so each row waits this out in real time.
    const ROW_RETENTION: std::time::Duration = std::time::Duration::from_secs(1);

    /// A Runtime with a component provider and no compute providers, for the
    /// sweeper rows.
    async fn retention_runtime(temp_dir: &tempfile::TempDir) -> (Runtime, Arc<ComponentProvider>) {
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let component = Arc::new(ComponentProvider::new());
        let runtime =
            Runtime::with_providers_and_component(storage, Vec::new(), Some(component.clone()));
        (runtime, component)
    }

    /// Registers an entry as a start does and makes its context, with
    /// [`ROW_RETENTION`], on the runtime this is awaited on: the activation's
    /// start runtime.
    async fn retained_activation(
        runtime: &Runtime,
        component: Arc<ComponentProvider>,
        name: &str,
    ) -> (ActivationContextHeld, String) {
        let manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json(name)).expect("the component manifest");
        let handle = CapsuleHandle {
            id: CapsuleId::new(format!("component-{name}")),
            manifest,
            args: Vec::new(),
        };
        let id = handle.id.0.clone();
        runtime
            .register_capsule(RunningCapsuleInfo {
                id: id.clone(),
                name: name.to_string(),
                status: CAPSULE_STARTING.to_string(),
                capsule_type: handle.manifest.capsule_type.clone(),
                handle: Some(handle.clone()),
                session_id: id.clone(),
                principal: None,
                cause: None,
                ended_at: None,
            })
            .await;
        let held = ActivationContextHeld::new(runtime, &handle, component, None)
            .retained_for(ROW_RETENTION);
        (held, id)
    }

    /// The instant the end recorded, read from the registry map itself: a
    /// listing would prune.
    async fn recorded_end(runtime: &Runtime, id: &str) -> std::time::Instant {
        runtime
            .running_capsules
            .read()
            .await
            .get(id)
            .and_then(|info| info.ended_at)
            .expect("the ended entry is kept at its end")
    }

    /// Reads the registry map itself, never a listing that would prune, until
    /// the entry is gone, and answers the instant it saw that; `None` if the
    /// entry is still there well after its retention. It polls with
    /// `tokio::time::sleep`, so the runtime it is awaited on stays free.
    async fn swept_at(runtime: &Runtime, id: &str) -> Option<std::time::Instant> {
        let cap = std::time::Instant::now() + ROW_RETENTION + std::time::Duration::from_secs(5);
        loop {
            if !runtime.running_capsules.read().await.contains_key(id) {
                return Some(std::time::Instant::now());
            }
            if std::time::Instant::now() >= cap {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// The entry went at its retention and not before it.
    fn assert_swept(swept: Option<std::time::Instant>, ended_at: std::time::Instant, row: &str) {
        let swept = swept.unwrap_or_else(|| {
            panic!("{row}: the ended entry is gone at its retention, with nothing reading it")
        });
        assert!(
            swept >= ended_at + ROW_RETENTION,
            "{row}: the ended entry is kept until its retention"
        );
    }

    /// A3-R S6 fix 4, row (a): the start runtime lives throughout. The end
    /// runs on it and the row waits on it, so a removal that needed that
    /// runtime could run; the sweeper takes the entry at its retention with
    /// nothing listing or registering again. F-nosweep (the sweeper skips the
    /// removal) leaves the entry there and reddens the row.
    #[tokio::test]
    async fn an_ended_entry_is_removed_at_its_retention_without_a_reader() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (runtime, component) = retention_runtime(&temp_dir).await;
        let (held, id) = retained_activation(&runtime, component, "retained").await;
        held.end_instance(CAPSULE_FAILED, "test end").await;
        let ended_at = recorded_end(&runtime, &id).await;
        assert_swept(
            swept_at(&runtime, &id).await,
            ended_at,
            "live start runtime",
        );
    }

    /// A3-R S6 fix 4, row (a) through the fallback: the start runtime lives,
    /// and the end runs on a throwaway current-thread runtime, the way `Drop`
    /// hands a lost end to a thread, which closes when the end returns. The
    /// sweeper belongs to neither runtime. F-nosweep reddens the row.
    #[tokio::test]
    async fn a_fallback_end_removes_its_entry_at_retention_without_a_registry_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (runtime, component) = retention_runtime(&temp_dir).await;
        let (held, id) = retained_activation(&runtime, component, "fallback-retained").await;
        std::thread::spawn(move || {
            let end_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the fallback end");
            end_runtime.block_on(held.end_instance(CAPSULE_FAILED, CAUSE_TASK_LOST));
        })
        .join()
        .expect("the fallback end runs");
        let ended_at = recorded_end(&runtime, &id).await;
        assert_swept(swept_at(&runtime, &id).await, ended_at, "fallback end");
    }

    /// A3-R S6 fix 4, row (b): the start runtime is dropped before the end.
    /// The S3 lost-task shape: the runtime the activation started on goes
    /// away, and the end then runs from a thread on a runtime of its own,
    /// which closes when the end returns. The row waits on a third runtime.
    /// F-nosweep reddens the row.
    #[test]
    fn a_lost_end_removes_its_entry_at_retention_without_a_registry_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let start = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the runtime the activation starts on");
        let (runtime, held, id) = start.block_on(async {
            let (runtime, component) = retention_runtime(&temp_dir).await;
            let (held, id) = retained_activation(&runtime, component, "lost-retained").await;
            (runtime, held, id)
        });
        drop(start);
        std::thread::spawn(move || {
            let end_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the lost end");
            end_runtime.block_on(held.end_instance(CAPSULE_FAILED, CAUSE_TASK_LOST));
        })
        .join()
        .expect("the lost end runs");

        let after = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the runtime the row reads on");
        after.block_on(async {
            let ended_at = recorded_end(&runtime, &id).await;
            assert_swept(swept_at(&runtime, &id).await, ended_at, "lost end");
        });
    }

    /// A3-R S6 fix 4, row (c), the round-4 sequence: the end runs on the
    /// start runtime while it lives, and that runtime is dropped after the
    /// end but before the entry's deadline. A removal that runtime ran would
    /// be cancelled with it; the sweeper's is not. The row waits on another
    /// runtime. F-nosweep reddens the row.
    #[test]
    fn an_end_whose_start_runtime_shuts_down_before_the_deadline_removes_its_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let start = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the runtime the activation starts and ends on");
        let (runtime, id, ended_at) = start.block_on(async {
            let (runtime, component) = retention_runtime(&temp_dir).await;
            let (held, id) = retained_activation(&runtime, component, "shutdown-retained").await;
            held.end_instance(CAPSULE_FAILED, "test end").await;
            let ended_at = recorded_end(&runtime, &id).await;
            (runtime, id, ended_at)
        });
        drop(start);
        assert!(
            std::time::Instant::now() < ended_at + ROW_RETENTION,
            "the start runtime is gone before the entry's deadline"
        );

        let after = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the runtime the row reads on");
        after.block_on(async {
            assert_swept(
                swept_at(&runtime, &id).await,
                ended_at,
                "start runtime shut down after the end",
            );
        });
    }

    pub(crate) async fn test_runtime() -> (Runtime, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let compute = Arc::new(NoopComputeProvider);
        (Runtime::new(storage, compute), temp_dir)
    }

    #[tokio::test]
    async fn an_unused_turn_is_removed_and_a_live_agents_turn_stays() {
        let (runtime, _dir) = test_runtime().await;
        let runtime = Arc::new(runtime);
        let live = "agent:v2:0123456789abcdef0123456789abcdef";
        let idle = "not-an-agent";
        let other = "also-not";
        runtime
            .plant_open_agent_stop_for_test(live, "session-held")
            .await;
        drop(runtime.begin_agent_stop(live).await);
        drop(runtime.begin_agent_stop(idle).await);
        assert_eq!(runtime.launch_turn_count_for_test(), 2);
        drop(runtime.begin_agent_stop(other).await);
        assert_eq!(
            runtime.launch_turn_count_for_test(),
            2,
            "the live turn was dropped or the idle turn stayed"
        );
    }

    #[tokio::test]
    async fn start_loaded_refuses_a_non_component_on_the_token_path() {
        let (runtime, _dir) = test_runtime().await;
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let token = runtime
            .admit_live_run(agent)
            .expect("the token path has a token");
        let mut manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json("plain-wasm")).unwrap();
        manifest.runtime_abi = None;
        manifest.bus_contract = None;
        manifest.execution = None;
        assert!(
            !manifest.is_component_capsule(),
            "the fixture is still a component"
        );
        let mut handle = CapsuleHandle {
            id: CapsuleId::new("plain-wasm"),
            manifest,
            args: Vec::new(),
        };
        let err = runtime
            .start_loaded(
                Arc::new(NoopComputeProvider),
                &mut handle,
                Vec::new(),
                Some(agent.to_string()),
                Some((
                    AgentModelCeiling {
                        ceiling: 0,
                        key: AgentKey::for_test(agent),
                    },
                    Some(token),
                )),
                LaunchMode::Detached,
            )
            .await
            .expect_err("a non-component on the token path was started");
        assert!(
            err.to_string()
                .contains(crate::agent_admission::NOT_A_COMPONENT),
            "{err}"
        );
        assert!(
            !runtime.agent_live_run_held(agent),
            "the refused start left the token held"
        );
    }

    #[tokio::test]
    async fn a_stop_wait_limit_stays_on_the_runtime_that_set_it() {
        let (first, _first_dir) = test_runtime().await;
        let (second, _second_dir) = test_runtime().await;
        let limit = first.limit_stop_wait_for_test(std::time::Duration::from_millis(20));
        assert_eq!(
            first.test_stop_wait_bound(),
            std::time::Duration::from_millis(20)
        );
        assert_eq!(
            second.test_stop_wait_bound(),
            std::time::Duration::from_secs(40)
        );
        drop(limit);
        assert_eq!(
            first.test_stop_wait_bound(),
            std::time::Duration::from_secs(40)
        );
    }

    /// Row 5d at the folder entrance: an agent's own principal is refused by
    /// name before any manifest is read, and the same call with a person's
    /// principal or none still reaches the manifest.
    #[tokio::test]
    async fn an_agents_principal_reaches_no_folder_launch_that_did_not_admit_it() {
        if !crate::agents::build_allows() {
            return;
        }
        let (runtime, temp) = test_runtime().await;
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let error = runtime
            .run_local_with_signer(
                temp.path(),
                Vec::new(),
                Some(crate::resource_bridge::BridgePrincipal::for_test(agent)),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: a stored agent's principal reaches only a launch that admitted \
             it: agent:v2:0123456789abcdef0123456789abcdef"
        );
        let absent = runtime
            .run_local_with_signer(&temp.path().join("none"), Vec::new(), None)
            .await
            .unwrap_err();
        assert!(
            absent
                .to_string()
                .starts_with("Invalid manifest: capsule.json not found in "),
            "{absent}"
        );
    }

    /// Row 5d at the start by CID: the same refusal, before the CID is read.
    #[tokio::test]
    async fn an_agents_principal_reaches_no_start_by_cid() {
        if !crate::agents::build_allows() {
            return;
        }
        let (runtime, temp) = test_runtime().await;
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let refusal = runtime
            .run_by_bundle(
                temp.path(),
                "not-a-cid",
                Vec::new(),
                Some(agent.to_string()),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refusal,
            BundleRefusal::StartFailed(
                "a stored agent's principal reaches only a launch that admitted it: \
                 agent:v2:0123456789abcdef0123456789abcdef"
                    .to_string()
            )
        );
    }

    fn unsigned_manifest() -> CapsuleManifest {
        CapsuleManifest {
            schema: SCHEMA_V1.to_string(),
            version: "0.1.0".to_string(),
            name: "unsigned-test".to_string(),
            description: None,
            author: None,
            role: CapsuleRole::App,
            capsule_type: CapsuleType::Wasm,
            runtime_abi: None,
            bus_contract: None,
            wit_world_sha256: None,
            execution: None,
            projections: Vec::new(),
            entrypoint: "app.wasm".to_string(),
            requires: Vec::new(),
            provides: None,
            authority: None,
            capabilities: Vec::new(),
            interfaces: Vec::new(),
            resources: ResourceLimits::default(),
            permissions: Permissions::default(),
            microvm: None,
            providers: None,
            icon: None,
            viewer: None,
            window_policy: None,
            model_content: None,
            agent: None,
            asks: Vec::new(),
            signature: None,
        }
    }

    pub(crate) fn component_with_extra_import() -> Vec<u8> {
        let mut types = ComponentTypeSection::new();
        types.instance(&InstanceType::new());

        let mut imports = ComponentImportSection::new();
        imports.import(
            "wasi:filesystem/types@0.2.0",
            EncodedComponentTypeRef::Instance(0),
        );

        let mut component = Component::new();
        component.section(&types);
        component.section(&imports);
        component.finish()
    }

    #[tokio::test]
    async fn home_without_installed_release_runs_unsigned_capsules_only_in_dev_mode() {
        let (runtime, temp_dir) = test_runtime().await;
        for dev_mode in [false, true] {
            runtime
                .configure_capsule_admission(temp_dir.path(), &[], dev_mode)
                .await
                .unwrap();
            let result = runtime
                .verify_capsule_signature(&unsigned_manifest(), temp_dir.path(), None)
                .await;
            assert_eq!(result.is_ok(), dev_mode, "{result:?}");
        }
    }

    #[tokio::test]
    async fn explicit_unsigned_development_component_runs_only_in_source_home() {
        let (runtime, temp_dir) = component_runtime().await;
        let folder = temp_dir.path().join("development-component");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join("capsule.json"),
            component_manifest_json("development-component"),
        )
        .unwrap();
        std::fs::write(folder.join("app.component.wasm"), quiet_component()).unwrap();
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], false)
            .await
            .unwrap();
        let error = runtime
            .run_unsigned_development_component(&folder, Vec::new())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("requires a source Home"),
            "{error}"
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let handle = runtime
            .run_unsigned_development_component(&folder, Vec::new())
            .await
            .unwrap();
        assert_eq!(handle.manifest.name, "development-component");
    }

    /// An installed Home whose config.toml still says `dev_mode = true` (the
    /// earlier default) admits only its signed release's capsules and capsules
    /// signed by the release publisher.
    #[cfg(unix)]
    #[tokio::test]
    async fn installed_release_refuses_unsigned_and_foreign_signed_local_capsules() {
        let mut home = crate::installed_release::tests::Fixture::new();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let manifest_json = std::fs::read(fixture.join("capsule.json")).unwrap();
        let manifest: CapsuleManifest = serde_json::from_slice(&manifest_json).unwrap();
        let name = manifest.name.clone();
        let entrypoint = b"component bytes";
        let install = |dir: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("capsule.json"), &manifest_json).unwrap();
            std::fs::write(dir.join(&manifest.entrypoint), entrypoint).unwrap();
        };
        let (cid, sha256) = ("bafkreirelease", "ab".repeat(32));
        std::fs::write(
            home.data.join("components.json"),
            serde_json::to_vec(&serde_json::json!({
                "external": {(&name): {
                    "install_path": format!("capsules/{name}"),
                    "platforms": {(crate::setup::detect_platform()): {
                        "cid": cid, "checksum": format!("sha256:{sha256}"),
                        "extract_path": format!("capsules/{name}")
                    }}
                }},
                "capsules": {(&name): {"cid": cid, "sha256": sha256}},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
        home.bind_components();
        let release_dir = home.data.join("capsules").join(&name);
        install(&release_dir);
        std::fs::write(release_dir.join(".elastos-cid"), cid).unwrap();
        std::fs::write(release_dir.join(".elastos-artifact-sha256"), &sha256).unwrap();
        let local_dir = home.data.join("local").join(&name);
        install(&local_dir);

        let (runtime, _storage) = test_runtime().await;
        runtime
            .configure_capsule_admission(&home.data, &[], true)
            .await
            .unwrap();
        let error = runtime
            .run_unsigned_development_component(&local_dir, Vec::new())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("installed releases refuse it"),
            "{error}"
        );
        // The installed signed release is named as such, not as a key or dev.
        assert_eq!(
            runtime
                .verify_capsule_signature(&manifest, &release_dir, None)
                .await
                .unwrap(),
            Signer::InstalledRelease
        );
        let error = runtime
            .verify_capsule_signature(&manifest, &local_dir, None)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not from the installed signed release"),
            "{error}"
        );
        // A5-S2b: an agent declared on the installed release is refused.
        let mut declared = manifest.clone();
        declared.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        let error = runtime
            .verify_capsule_signature(&declared, &release_dir, None)
            .await
            .unwrap_err();
        let expected = format!(
            "Capsule '{}' declares an agent but no trusted key signed it",
            declared.name
        );
        assert!(error.to_string().contains(&expected), "{error}");

        let signed_by = |key: u8| {
            let mut signed = manifest.clone();
            elastos_runtime::signature::sign_capsule(
                &elastos_runtime::signature::SigningKey::from_bytes(&[key; 32]),
                &mut signed,
                &hash_content(entrypoint),
            )
            .unwrap();
            signed
        };
        // The fixture release is signed by key 71.
        runtime
            .verify_capsule_signature(&signed_by(71), &local_dir, None)
            .await
            .unwrap();
        let error = runtime
            .verify_capsule_signature(&signed_by(9), &local_dir, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");

        // A release capsule whose CID receipt no longer matches is refused too.
        std::fs::write(release_dir.join(".elastos-cid"), "bafkreiother").unwrap();
        assert!(runtime
            .verify_capsule_signature(&manifest, &release_dir, None)
            .await
            .is_err());
    }

    /// A signed capsule names its signer by the matched key's DID; dev_mode's
    /// unsigned admission is named as such.
    #[tokio::test]
    async fn verify_capsule_signature_names_the_matched_signer() {
        let (runtime, temp_dir) = test_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[71; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let dir = temp_dir.path().join("signed-capsule");
        std::fs::create_dir_all(&dir).unwrap();
        let entrypoint = b"entrypoint bytes";
        std::fs::write(dir.join("main.wasm"), entrypoint).unwrap();
        let mut manifest = unsigned_manifest();
        manifest.entrypoint = "main.wasm".to_string();
        manifest.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(entrypoint))
            .unwrap();

        let expected_did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        let signer = runtime
            .verify_capsule_signature(&manifest, &dir, None)
            .await
            .unwrap();
        assert_eq!(signer, Signer::Key { did: expected_did });

        // The unsigned capsule is named unsigned by dev_mode's admission, and
        // dev_mode admits a declared agent unsigned.
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        manifest.signature = None;
        for capsule in [unsigned_manifest(), manifest] {
            assert_eq!(
                runtime
                    .verify_capsule_signature(&capsule, &dir, None)
                    .await
                    .unwrap(),
                Signer::UnsignedDev
            );
        }
    }

    /// For a component the signature is checked over the bytes the Runtime
    /// already read, whatever the file holds by then.
    #[tokio::test]
    async fn a_signature_is_checked_over_the_admitted_bytes_not_the_file() {
        let (runtime, temp_dir) = test_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[71; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let dir = temp_dir.path().join("signed-capsule");
        std::fs::create_dir_all(&dir).unwrap();
        let (signed, other): (&[u8], &[u8]) = (b"the signed bytes", b"replaced after the read");
        let mut manifest = unsigned_manifest();
        manifest.entrypoint = "main.wasm".to_string();
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(signed))
            .unwrap();

        // The file was replaced after the read: the signed bytes in hand still pass.
        std::fs::write(dir.join("main.wasm"), other).unwrap();
        runtime
            .verify_capsule_signature(&manifest, &dir, Some(signed))
            .await
            .expect("the signed bytes that were read pass");
        // The file still holds the signed bytes, but other bytes were read: refused.
        std::fs::write(dir.join("main.wasm"), signed).unwrap();
        let error = runtime
            .verify_capsule_signature(&manifest, &dir, Some(other))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("signature verification failed"),
            "{error}"
        );
    }

    /// A component with one empty `run`, as bytes.
    pub(crate) fn quiet_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
              (import "elastos:bus/types@1.0.0" (instance $types
                (type $error (variant
                  (case "denied" string) (case "not-found" string) (case "invalid" string)
                  (case "unavailable" string) (case "timeout" string) (case "internal" string)))
                (export "bus-error" (type (eq $error)))))
              (alias export $types "bus-error" (type $bus-error))
              (core module $m
                (memory (export "memory") 1)
                (func (export "run") (result i32) (i32.const 0)))
              (core instance $i (instantiate $m))
              (func $run (result (result (error $bus-error)))
                (canon lift (core func $i "run") (memory $i "memory")))
              (instance $lifecycle (export "run" (func $run)))
              (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#,
        )
        .expect("component text")
    }

    pub(crate) fn component_manifest_json(name: &str) -> String {
        format!(
            r#"{{
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": "{name}",
                "role": "app",
                "type": "wasm",
                "runtime_abi": "elastos.component/v1",
                "bus_contract": "{}",
                "wit_world_sha256": "{}",
                "execution": "component",
                "projections": ["cli"],
                "entrypoint": "app.component.wasm"
            }}"#,
            ELASTOS_BUS_V1_CONTRACT,
            elastos_bus_v1_wit_sha256()
        )
    }

    /// A Runtime with a component provider, for the folder gate's rows.
    async fn component_runtime() -> (Runtime, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        (runtime, temp_dir)
    }

    /// Write one signed component folder at `dir`: the manifest, the
    /// entrypoint named by it, and the signature over both.
    fn signed_component_folder(
        dir: &Path,
        name: &str,
        key: &elastos_runtime::signature::SigningKey,
    ) -> Vec<u8> {
        std::fs::create_dir_all(dir).unwrap();
        let component = quiet_component();
        let mut manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json(name)).unwrap();
        elastos_runtime::signature::sign_capsule(key, &mut manifest, &hash_content(&component))
            .unwrap();
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("app.component.wasm"), &component).unwrap();
        component
    }

    /// A folder start has no pin field, so its closure is the root alone:
    /// a component that names a requirement is refused before any load, on
    /// a non-dev Home whose install record holds the folder's CID and in dev
    /// mode alike.
    #[tokio::test]
    async fn local_component_refuses_unpinned_requirement_before_load() {
        for dev_mode in [false, true] {
            local_requirement_refused(dev_mode).await;
        }
    }

    async fn local_requirement_refused(dev_mode: bool) {
        let (runtime, temp) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[92; 32]);
        runtime
            .configure_capsule_admission(
                temp.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                dev_mode,
            )
            .await
            .unwrap();
        let folder = temp.path().join("local-requires");
        let bytes = signed_component_folder(&folder, "local-requires", &key);
        let mut manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(folder.join("capsule.json")).unwrap()).unwrap();
        manifest.requires.push(elastos_common::CapsuleRequirement {
            name: "needed".to_string(),
            kind: elastos_common::RequirementKind::Capsule,
        });
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(&bytes))
            .unwrap();
        std::fs::write(
            folder.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        crate::setup::record_install_cid(temp.path(), &folder, &folder);
        let error = runtime.run_local(&folder, Vec::new()).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bundle_requirement_unpinned: needed"),
            "dev_mode {dev_mode}: {error}"
        );
        assert!(runtime.list_capsules().await.is_empty());
    }

    /// The dev-only component load refuses unless the owner turned dev mode
    /// on: a Runtime never configured and a Home with `dev_mode = false`
    /// both refuse it, so a normal start cannot reach unchecked bytes.
    #[tokio::test]
    async fn the_dev_component_load_needs_dev_mode() {
        for dev_mode in [None, Some(false), Some(true)] {
            let (runtime, temp) = component_runtime().await;
            let key = elastos_runtime::signature::SigningKey::from_bytes(&[93; 32]);
            if let Some(dev_mode) = dev_mode {
                runtime
                    .configure_capsule_admission(temp.path(), &[], dev_mode)
                    .await
                    .unwrap();
            }
            let folder = temp.path().join("dev-only");
            let bytes = signed_component_folder(&folder, "dev-only", &key);
            let manifest: CapsuleManifest =
                serde_json::from_slice(&std::fs::read(folder.join("capsule.json")).unwrap())
                    .unwrap();
            let component = runtime.component_provider.clone().unwrap();
            let loaded = runtime
                .load_dev_unsigned_component(&component, bytes, manifest)
                .await;
            match dev_mode {
                Some(true) => assert!(loaded.is_ok(), "{:?}", loaded.err()),
                _ => assert!(
                    loaded
                        .unwrap_err()
                        .to_string()
                        .contains("dev_unsigned_component_refused"),
                    "dev_mode {dev_mode:?}"
                ),
            }
        }
    }

    #[cfg(unix)]
    /// A component folder outside dev mode is walked once by the folder gate,
    /// and the bytes that walk read are the bytes that run. The test changes
    /// the entrypoint right after the walk: a second read would meet the new
    /// bytes, and the entrypoint-read hook would record that read.
    #[tokio::test]
    async fn a_component_folder_start_loads_the_bytes_its_gate_walk_read() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[71; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("capsule");
        signed_component_folder(&capsule_dir, "walked-bytes", &key);
        crate::setup::record_install_cid(temp_dir.path(), &capsule_dir, &capsule_dir);

        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        crate::component::AFTER_ENTRYPOINT_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_path| {
                counted.fetch_add(1, Ordering::SeqCst);
            }));
        });
        // The hook is taken away again however this test ends.
        struct ResetHook;
        impl Drop for ResetHook {
            fn drop(&mut self) {
                crate::component::AFTER_ENTRYPOINT_READ.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _reset = ResetHook;

        let entrypoint = capsule_dir.join("app.component.wasm");
        let walked = Arc::new(AtomicUsize::new(0));
        let seen = walked.clone();
        let launched = runtime
            .run_local_with_signer_observed(
                &capsule_dir,
                Vec::new(),
                |_| {},
                move |_bundle| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    std::fs::write(&entrypoint, b"changed after the gate walk").unwrap();
                },
            )
            .await;

        assert_eq!(walked.load(Ordering::SeqCst), 1, "one gate walk");
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "the gate walk is the only read of the entrypoint"
        );
        assert_eq!(
            std::fs::read(capsule_dir.join("app.component.wasm")).unwrap(),
            b"changed after the gate walk"
        );
        let (_, signer) = launched.expect("the walked bytes are the bytes that run");
        let did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        assert_eq!(signer, Signer::Key { did });
    }

    /// The manifest the gate judges is the one the gate's walk read, not the
    /// one the caller read before the walk. The test replaces `capsule.json`
    /// right before the walk, as another process could, with a manifest of the
    /// same key and entrypoint under another name: the refusal names the name
    /// that walk read.
    #[tokio::test]
    async fn the_manifest_the_gate_checks_is_the_walked_one() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[78; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("two-manifests");
        let component = signed_component_folder(&capsule_dir, "probe-manifest", &key);
        let mut walked_manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json("walked-manifest")).unwrap();
        elastos_runtime::signature::sign_capsule(
            &key,
            &mut walked_manifest,
            &elastos_runtime::signature::hash_content(&component),
        )
        .unwrap();
        let walked_json = serde_json::to_vec(&walked_manifest).unwrap();
        let manifest_path = capsule_dir.join("capsule.json");

        let launched = runtime
            .run_local_with_signer_observed(
                &capsule_dir,
                Vec::new(),
                move |_path| {
                    std::fs::write(&manifest_path, &walked_json).unwrap();
                },
                |_| {},
            )
            .await;
        let error = launched
            .expect_err("a folder no install recorded is refused")
            .to_string();
        assert!(error.contains("is not installed"), "{error}");
        assert!(error.contains("'walked-manifest'"), "{error}");
        assert!(!error.contains("'probe-manifest'"), "{error}");
        assert!(runtime.list_capsules().await.is_empty(), "nothing started");
    }
    #[cfg(unix)]
    /// An installed folder starts from both entrances: the CLI's bounded
    /// start and the launch route's detached start.
    #[tokio::test]
    async fn an_installed_folder_starts_from_the_cli_and_the_route() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[72; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("installed");
        signed_component_folder(&capsule_dir, "installed-folder", &key);
        crate::setup::record_install_cid(temp_dir.path(), &capsule_dir, &capsule_dir);
        let did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();

        let (handle, signer) = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .expect("the CLI starts an installed folder");
        assert_eq!(signer, Signer::Key { did: did.clone() });
        assert_eq!(handle.manifest.name, "installed-folder");

        let (_handle, signer) = runtime
            .start_local_with_signer(&capsule_dir, Vec::new(), None, None)
            .await
            .expect("the route starts an installed folder");
        assert_eq!(signer, Signer::Key { did });
        assert!(runtime
            .start_local_with_signer(&capsule_dir, Vec::new(), None, Some("another-capsule"))
            .await
            .is_err());
    }

    /// A folder signed by a trusted key that no install recorded and no
    /// by-CID slot accepted is refused on a Home outside dev mode, with the
    /// reason that names its walk CID.
    #[tokio::test]
    async fn a_signed_folder_with_no_record_is_refused_on_a_non_dev_home() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[73; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("unrecorded");
        signed_component_folder(&capsule_dir, "unrecorded-folder", &key);
        let cid = crate::stage_cmd::bundle_cid(&capsule_dir).unwrap();

        let error = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .expect_err("a folder no install recorded is refused");
        let text = error.to_string();
        assert!(text.contains("is not installed"), "{text}");
        assert!(text.contains(&cid), "{text}");
        assert!(runtime.list_capsules().await.is_empty(), "nothing started");
    }

    /// The same signed folder with no record starts in dev mode.
    #[tokio::test]
    async fn a_signed_folder_with_no_record_starts_in_dev_mode() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[74; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                true,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("dev-folder");
        signed_component_folder(&capsule_dir, "dev-folder", &key);

        let (_, signer) = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .expect("dev mode starts a signed folder with no record");
        let did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        assert_eq!(signer, Signer::Key { did });
    }

    /// A folder whose bytes changed after its install does not recompute to
    /// the recorded CID, so the gate refuses it.
    #[tokio::test]
    async fn a_folder_changed_after_its_install_is_refused() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[75; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("changed");
        signed_component_folder(&capsule_dir, "changed-folder", &key);
        crate::setup::record_install_cid(temp_dir.path(), &capsule_dir, &capsule_dir);
        // A file the manifest does not name and the signature does not cover:
        // the walk names different bytes, and the signature still passes.
        std::fs::write(capsule_dir.join("added-after-install.txt"), b"later").unwrap();

        let error = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .expect_err("a folder changed after its install is refused");
        assert!(error.to_string().contains("is not installed"), "{error}");
        assert!(runtime.list_capsules().await.is_empty(), "nothing started");
    }

    /// A folder with a file beside it that holds its own walk CID is still not
    /// installed: the gate reads this Home's install record, which no install
    /// wrote here, so both entries refuse it.
    #[tokio::test]
    async fn a_sidecar_beside_the_folder_does_not_record_an_install() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[79; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("sidecar-only");
        signed_component_folder(&capsule_dir, "sidecar-only", &key);
        let cid = crate::stage_cmd::bundle_cid(&capsule_dir).unwrap();
        // The file slice 4's install also writes, filled in here without one.
        std::fs::write(
            crate::setup::install_cid_record(&capsule_dir).unwrap(),
            format!("{cid}\n"),
        )
        .unwrap();

        let cli = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .map(|_| ())
            .expect_err("the CLI refuses a folder no install recorded")
            .to_string();
        let route = runtime
            .start_local_with_signer(&capsule_dir, Vec::new(), None, None)
            .await
            .map(|_| ())
            .expect_err("the route refuses a folder no install recorded")
            .to_string();
        assert!(cli.contains("is not installed"), "{cli}");
        assert!(cli.contains(&cid), "{cli}");
        assert_eq!(cli, route);
        assert!(runtime.list_capsules().await.is_empty(), "nothing started");
    }

    /// A by-CID slot staged from a signed bundle accepts the folder it was
    /// staged from, without an install record.
    #[tokio::test]
    async fn a_staged_folder_start_is_accepted_by_its_by_cid_slot() {
        let (runtime, temp_dir) = component_runtime().await;
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[76; 32]);
        runtime
            .configure_capsule_admission(
                &data_dir,
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("staged");
        signed_component_folder(&capsule_dir, "staged-folder", &key);
        let cid = crate::stage_cmd::bundle_cid(&capsule_dir).unwrap();
        let signature = temp_dir.path().join("staged.sig.json");
        std::fs::write(
            &signature,
            crate::bundle_admission::tests::signed(&cid, &key),
        )
        .unwrap();
        crate::stage_cmd::stage_bundle(&runtime, &data_dir, &capsule_dir, &signature)
            .await
            .expect("the signed bundle stages");

        let (_, signer) = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .expect("the staged CID accepts the folder it came from");
        let did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        assert_eq!(signer, Signer::Key { did });
    }

    /// The CLI's bounded start and the route's detached start give the same
    /// answer for a folder the gate does not accept.
    #[tokio::test]
    async fn the_cli_and_the_route_refuse_an_unrecorded_folder_alike() {
        let (runtime, temp_dir) = component_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[77; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("same-answer");
        signed_component_folder(&capsule_dir, "same-answer", &key);

        let cli = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await
            .map(|_| ())
            .expect_err("the CLI refuses it")
            .to_string();
        let route = runtime
            .start_local_with_signer(&capsule_dir, Vec::new(), None, None)
            .await
            .map(|_| ())
            .expect_err("the route refuses it")
            .to_string();
        assert_eq!(cli, route);
        assert!(cli.contains("is not installed"), "{cli}");
    }

    /// A component file one byte over the cap is refused at launch, before the
    /// signature check, the import check or the compiler see it.
    #[tokio::test]
    async fn a_component_file_over_the_size_cap_is_refused_at_launch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            component_manifest_json("oversized-component"),
        )
        .unwrap();
        let file = std::fs::File::create(capsule_dir.join("app.component.wasm")).unwrap();
        file.set_len(8 * 1024 * 1024 + 1).unwrap();

        let error = runtime
            .run_local_with_principal(&capsule_dir, Vec::new(), None)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: failed to read component entrypoint app.component.wasm: \
             component file is larger than the 8388608 byte limit"
        );
    }

    /// A Runtime whose one compute provider counts its loads, a capsule folder
    /// holding a signed microVM manifest whose entrypoint is `rootfs.ext4`, and
    /// the Home's admission set as asked.
    async fn entrypoint_fixture(
        dev_mode: bool,
    ) -> (Runtime, tempfile::TempDir, PathBuf, Arc<AtomicUsize>) {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[42; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                dev_mode,
            )
            .await
            .unwrap();
        let mut manifest = unsigned_manifest();
        manifest.name = "entrypoint-kind".to_string();
        manifest.capsule_type = CapsuleType::MicroVM;
        manifest.entrypoint = "rootfs.ext4".to_string();
        if !dev_mode {
            elastos_runtime::signature::sign_capsule(
                &key,
                &mut manifest,
                &hash_content(b"vm image bytes"),
            )
            .unwrap();
        }
        let dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        (runtime, temp_dir, dir, loads)
    }

    #[tokio::test]
    async fn a_regular_entrypoint_and_a_link_inside_the_capsule_folder_are_launched() {
        let (runtime, _temp, dir, loads) = entrypoint_fixture(true).await;
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        runtime.run_local(&dir, Vec::new()).await.unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);

        #[cfg(unix)]
        {
            std::fs::rename(dir.join("rootfs.ext4"), dir.join("image.bin")).unwrap();
            std::os::unix::fs::symlink("image.bin", dir.join("rootfs.ext4")).unwrap();
            runtime.run_local(&dir, Vec::new()).await.unwrap();
            assert_eq!(loads.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn a_folder_as_an_entrypoint_is_refused_before_the_provider_loads() {
        let (runtime, _temp, dir, loads) = entrypoint_fixture(true).await;
        std::fs::create_dir(dir.join("rootfs.ext4")).unwrap();
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: Entrypoint rootfs.ext4 is not a regular file"
        );
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_entrypoint_link_that_leads_out_of_the_capsule_folder_is_refused() {
        let (runtime, temp, dir, loads) = entrypoint_fixture(true).await;
        // A real file outside the capsule folder, where the link points.
        let outside = temp.path().join("outside.img");
        std::fs::write(&outside, b"vm image bytes").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("rootfs.ext4")).unwrap();
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: Entrypoint rootfs.ext4 leads out of the capsule directory"
        );
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    /// Makes a pipe at `path`. If a launch is still blocked reading it after
    /// `launch` has been given ten seconds, opens it for writing once so the
    /// blocked reader ends, and reports the block.
    #[cfg(unix)]
    async fn launch_with_a_pipe_entrypoint(runtime: &Runtime, dir: &Path) -> Result<CapsuleHandle> {
        use std::os::unix::fs::OpenOptionsExt;
        let pipe = dir.join("rootfs.ext4");
        let made = std::process::Command::new("mkfifo").arg(&pipe).status();
        assert!(made.unwrap().success(), "mkfifo");
        let launch = runtime.run_local(dir, Vec::new());
        match tokio::time::timeout(std::time::Duration::from_secs(10), launch).await {
            Ok(result) => result,
            Err(_) => {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&pipe);
                panic!("the launch blocked on a pipe that nobody writes to");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_pipe_as_an_entrypoint_is_refused_and_never_opened() {
        // A Home that enforces signatures reads the entrypoint to hash it, so
        // an opened pipe would block here; a dev Home would hand it to the provider.
        for dev_mode in [false, true] {
            let (runtime, _temp, dir, loads) = entrypoint_fixture(dev_mode).await;
            let error = launch_with_a_pipe_entrypoint(&runtime, &dir)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Invalid manifest: Entrypoint rootfs.ext4 is not a regular file",
                "dev_mode {dev_mode}"
            );
            assert_eq!(loads.load(Ordering::SeqCst), 0, "dev_mode {dev_mode}");
        }
    }

    /// A Home with no signed release, dev_mode off and one trusted key refuses
    /// an unsigned capsule, a capsule signed by another key, and a signed
    /// capsule whose entrypoint changed. The refusal happens at launch, before
    /// a compute provider loads it. The trusted key's capsule is loaded.
    #[tokio::test]
    async fn launch_refuses_untrusted_signers_before_the_provider_loads() {
        async fn launch(
            runtime: &Runtime,
            dir: &Path,
            manifest: &CapsuleManifest,
            entrypoint: &[u8],
        ) -> Result<CapsuleHandle> {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
            std::fs::write(dir.join(&manifest.entrypoint), entrypoint).unwrap();
            runtime.run_local(dir, Vec::new()).await
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        let trusted = elastos_runtime::signature::SigningKey::from_bytes(&[42; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(trusted.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();

        let entrypoint = b"vm image bytes";
        let mut manifest = unsigned_manifest();
        manifest.name = "foreign-vm".to_string();
        manifest.capsule_type = CapsuleType::MicroVM;
        manifest.entrypoint = "rootfs.ext4".to_string();
        let signed_by = |key: &elastos_runtime::signature::SigningKey| {
            let mut signed = manifest.clone();
            elastos_runtime::signature::sign_capsule(key, &mut signed, &hash_content(entrypoint))
                .unwrap();
            signed
        };
        let dir = temp_dir.path().join("foreign-vm");

        let error = launch(&runtime, &dir, &manifest, entrypoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("is unsigned"), "{error}");
        let foreign = elastos_runtime::signature::SigningKey::from_bytes(&[9; 32]);
        let error = launch(&runtime, &dir, &signed_by(&foreign), entrypoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");
        let error = launch(&runtime, &dir, &signed_by(&trusted), b"changed image")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        launch(&runtime, &dir, &signed_by(&trusted), entrypoint)
            .await
            .unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn descriptive_execution_types_refuse_generic_compute() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        for source in [
            include_str!("../../../../templates/capsules/web-app/capsule.json"),
            include_str!("../../../../templates/capsules/provider-contract/capsule.json"),
            include_str!("../../../../capsules/model-provider/capsule.json"),
            include_str!("../../../../capsules/home/capsule.json"),
            include_str!("../../../capsules/shell/capsule.json"),
        ] {
            let manifest: CapsuleManifest = serde_json::from_str(source).unwrap();
            manifest.validate().unwrap();
            let capsule_dir = temp_dir.path().join(&manifest.name);
            std::fs::create_dir_all(
                capsule_dir.join(std::path::Path::new(&manifest.entrypoint).parent().unwrap()),
            )
            .unwrap();
            std::fs::write(
                capsule_dir.join(&manifest.entrypoint),
                b"untrusted artifact",
            )
            .unwrap();
            std::fs::write(capsule_dir.join("capsule.json"), source).unwrap();
            assert!(runtime.get_provider_for_manifest(&manifest).is_none());
            let error = runtime
                .run_local(&capsule_dir, Vec::new())
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("No compute provider supports"),
                "{error}"
            );
        }
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn component_import_validation_fails_before_provider_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let compute = Arc::new(CountingComputeProvider {
            loads: loads.clone(),
        });
        let runtime = Runtime::new(storage, compute);
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();

        let capsule_dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("app.component.wasm"),
            component_with_extra_import(),
        )
        .unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            format!(
                r#"{{
                    "schema": "elastos.capsule/v1",
                    "version": "0.1.0",
                    "name": "bad-component",
                    "role": "app",
                    "type": "wasm",
                    "runtime_abi": "elastos.component/v1",
                    "bus_contract": "{}",
                    "wit_world_sha256": "{}",
                    "execution": "component",
                    "projections": ["cli"],
                    "entrypoint": "app.component.wasm"
                }}"#,
                ELASTOS_BUS_V1_CONTRACT,
                elastos_bus_v1_wit_sha256()
            ),
        )
        .unwrap();

        let err = runtime
            .run_local_with_principal(&capsule_dir, Vec::new(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("component import"));
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    /// A Runtime with the component provider, the real resource bridge, and a
    /// stored Agent whose root has principal-root protection, as on a Home.
    #[cfg(unix)]
    struct AgentHostRuntime {
        runtime: Arc<Runtime>,
        capability_manager: Arc<CapabilityManager>,
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        audit_log: Arc<AuditLog>,
        data_dir: std::path::PathBuf,
        agent_id: String,
        folder: std::path::PathBuf,
        _home: crate::agents::tests::Home,
        _temp: tempfile::TempDir,
    }

    #[cfg(unix)]
    async fn agent_host_runtime() -> AgentHostRuntime {
        use crate::bundle_admission::tests::key;
        use crate::stage_cmd::bundle_cid;
        let temp = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/agent-host");
        let folder = temp.path().join("agent-host");
        std::fs::create_dir_all(&folder).unwrap();
        let component = std::fs::read(source.join("agent-host.component.wasm")).unwrap();
        let mut manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(source.join("capsule.json")).unwrap()).unwrap();
        assert_eq!(
            manifest.agent.as_ref().map(|agent| agent.kind),
            Some(elastos_common::AgentKind::Agent),
        );
        let publisher = key(108);
        elastos_runtime::signature::sign_capsule(
            &publisher,
            &mut manifest,
            &hash_content(&component),
        )
        .unwrap();
        std::fs::write(
            folder.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(folder.join("agent-host.component.wasm"), component).unwrap();
        let cid = bundle_cid(&folder).unwrap();
        let (home, agents) = crate::agents::tests::home_with_agents_if_built(1, &cid)
            .expect("Agent Host guest rows need agents built");
        let agent_id = agents.into_iter().next().unwrap();
        let data_dir = home.path().to_path_buf();
        let storage = Arc::new(
            LocalFSProvider::new(temp.path().join("storage"))
                .await
                .unwrap(),
        );
        let component_provider = Arc::new(ComponentProvider::new());
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(component_provider),
        ));
        runtime
            .configure_capsule_admission(
                &data_dir,
                &[hex::encode(publisher.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store = Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
        );
        runtime
            .set_provider_registry(
                Arc::new(ProviderRegistry::new()),
                capability_manager.clone(),
                pending_store.clone(),
                data_dir.clone(),
            )
            .await;
        AgentHostRuntime {
            runtime,
            capability_manager,
            pending_store,
            audit_log,
            data_dir,
            agent_id,
            folder,
            _home: home,
            _temp: temp,
        }
    }

    #[cfg(unix)]
    fn agent_host_journal(fx: &AgentHostRuntime) -> (String, String) {
        let root =
            crate::auth::principal_stored_localhost_root(Some(&fx.data_dir), &fx.agent_id).unwrap();
        let journal = format!("{root}/.AppData/Agents/agent-host/tasks/demo/journal");
        (root, journal)
    }

    #[cfg(unix)]
    fn launch_agent_host(
        fx: &AgentHostRuntime,
    ) -> tokio::task::JoinHandle<elastos_common::Result<elastos_compute::CapsuleHandle>> {
        let runtime = fx.runtime.clone();
        let agent_id = fx.agent_id.clone();
        let folder = fx.folder.clone();
        let data_dir = fx.data_dir.clone();
        tokio::spawn(async move {
            let admission = crate::agent_admission::admit_launch(
                &data_dir,
                &data_dir,
                Some(crate::agents::tests::OWNER_ID),
                Some(&agent_id),
                crate::agent_admission::walk_launch(&folder).unwrap(),
            )
            .unwrap()
            .unwrap();
            runtime
                .run_local_admitted(&folder, Vec::new(), admission)
                .await
                .map(|(handle, _)| handle)
        })
    }

    async fn next_pending(
        store: &elastos_runtime::capability::pending::PendingRequestStore,
        launch: &mut tokio::task::JoinHandle<
            elastos_common::Result<elastos_compute::CapsuleHandle>,
        >,
    ) -> elastos_runtime::capability::pending::PendingCapabilityRequest {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(request) = store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::select! {
                    result = &mut *launch => match result {
                        Ok(Ok(_)) => panic!("the agent host finished before its grant ask"),
                        Ok(Err(error)) => panic!("the agent host stopped before its grant ask: {error:#}"),
                        Err(error) => panic!("the agent host launch task failed: {error}"),
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        })
        .await
        .expect("the agent host must ask for a grant")
    }

    fn component_invoke_outcomes(audit_log: &AuditLog) -> Vec<(String, String)> {
        audit_log
            .recent_events(100)
            .iter()
            .filter_map(|event| match event {
                AuditEvent::Custom {
                    event_type,
                    details,
                } if event_type == "component.invoke.completed" => Some((
                    details["operation"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    details["outcome"].as_str().unwrap_or_default().to_string(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The guest journals its activation before asking to submit a plan.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_writes_and_reads_its_journal_through_the_real_bridge() {
        let fx = agent_host_runtime().await;
        let (root, journal) = agent_host_journal(&fx);
        let mut launch = launch_agent_host(&fx);
        let mut asked = Vec::new();
        for _ in 0..3 {
            let pending = next_pending(&fx.pending_store, &mut launch).await;
            asked.push((pending.resource.as_str().to_string(), pending.action));
            let token = fx.capability_manager.grant(
                pending.session_id.as_str(),
                pending.resource.clone(),
                pending.action,
                TokenConstraints::default(),
                None,
            );
            fx.pending_store
                .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish after its grants")
            .expect("the launch task must not panic")
            .expect("the agent host must write and read back its journal");
        assert_eq!(
            asked,
            vec![
                (journal.clone(), elastos_runtime::capability::Action::Write),
                (journal.clone(), elastos_runtime::capability::Action::Read),
                (
                    "elastos://inspect/submit_agent_plan".to_string(),
                    elastos_runtime::capability::Action::Write,
                ),
            ]
        );
        assert!(fx.pending_store.list_pending().await.is_empty());

        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(4).any(|window| window == b"EAHJ"),
            "stored encrypted"
        );
        let plain = crate::auth::read_principal_root_object(
            &fx.data_dir,
            &fx.agent_id,
            &root,
            &journal,
            &path,
        )
        .unwrap();
        assert_eq!(&plain[..4], b"EAHJ");
        assert_eq!(plain[4..6], 2u16.to_le_bytes());
        let outcomes = component_invoke_outcomes(&fx.audit_log);
        assert!(
            outcomes.contains(&("write".to_string(), "ok".to_string())),
            "{outcomes:?}"
        );
        assert!(
            outcomes.contains(&("read".to_string(), "ok".to_string())),
            "{outcomes:?}"
        );
    }

    /// A journal written by the agent host's format 1 encoder (examples/
    /// agent-host at f873957): two turns, a person's "goal\nship it", a goal
    /// record and a read.
    const AGENT_HOST_FORMAT_1_JOURNAL: &[&str] = &[
        "4541484a010001000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000008000000012500000001011f000000596f752061726520",
        "74686520456c6173744f53206167656e7420686f73742ea02b08ad6c00bb31f647037293207751f5",
        "3c2263c8327d802d0366362842eae0010b00000002030500000068656c6c6fe95bec7ef4c055b5ac",
        "9bd4132a121f4b80fee6f9e9ab1840c2b9987db191557d012300000001021d0000005265706c7920",
        "696e206f6e652073686f7274207061726167726170682ee0d8f303b4006e394934144da53d29f29f",
        "d5b7af273f5049ee9adfb35ee3e16a011100000002030b0000007365636f6e64207475726e3c58cd",
        "0c1acd922f79f72b8863e82f6e5b17bc062114e1c3424e3361521380e7012b000000010225000000",
        "4b656570207468652066697273742073797374656d206c696e6520756e6368616e6765642e1f2116",
        "24b9d75a3b0e9be6368b55c6910e9e32513e8604c8ebb90c2df05e969d011200000002030c000000",
        "676f616c0a73686970206974989306519e8b7d7906f58012c704d5e9235617efa2bf2a905644396e",
        "a975da40011a000000020314000000676f616c0a66696e69736820746865206e6f7465afa8d8a679",
        "d52cb425643fc8d448d7edea3d8eb3ec9ab24c3b77063190a654b1017a0000000209740000003120",
        "62366139386439636539613264393134393238386661336466343264333737633365343237333761",
        "666463646166373134653333633061313030623531303630206c6f63616c686f73743a2f2f557365",
        "72732f73656c662f446f63756d656e74732f6e6f7465732e7478740a616c7068610a488b95a013ae",
        "a1d802a5c30e7d04ecfa818ba6e06b0c028fa53f8383a013674a488b95a013aea1d802a5c30e7d04",
        "ecfa818ba6e06b0c028fa53f8383a013674a",
    ];

    /// A task whose stored journal is format 1: the guest's run fails with
    /// exactly the text the person sees, and the stored object is not touched.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_refuses_a_format_1_journal_with_its_reason() {
        let fx = agent_host_runtime().await;
        let (root, journal) = agent_host_journal(&fx);
        let hex: String = AGENT_HOST_FORMAT_1_JOURNAL.concat();
        let old: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        assert_eq!(old[4..6], 1u16.to_le_bytes());
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::auth::write_principal_root_object(
            &fx.data_dir,
            &fx.agent_id,
            &root,
            &journal,
            &path,
            &old,
        )
        .unwrap();
        let mut launch = launch_agent_host(&fx);
        let mut asked = Vec::new();
        for _ in 0..2 {
            let pending = next_pending(&fx.pending_store, &mut launch).await;
            asked.push((pending.resource.as_str().to_string(), pending.action));
            let token = fx.capability_manager.grant(
                pending.session_id.as_str(),
                pending.resource.clone(),
                pending.action,
                TokenConstraints::default(),
                None,
            );
            fx.pending_store
                .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                .await
                .unwrap();
        }
        assert_eq!(
            asked,
            vec![
                (journal.clone(), elastos_runtime::capability::Action::Write),
                (journal.clone(), elastos_runtime::capability::Action::Read),
            ],
            "a format 1 journal stops before the submit ask"
        );
        let error = tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish")
            .expect("the launch task must not panic")
            .expect_err("a format 1 journal must stop the task");
        assert!(
            error
                .to_string()
                .contains("journal format 1 not supported; start a new task"),
            "{error}"
        );
        let stored = crate::auth::read_principal_root_object(
            &fx.data_dir,
            &fx.agent_id,
            &root,
            &journal,
            &path,
        )
        .unwrap();
        assert_eq!(stored, old, "the old object is not touched");
    }

    /// The shell denies both journal requests: the guest finishes before a
    /// submit ask, sends no resource call, and stores nothing.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_stores_nothing_when_its_journal_grants_are_denied() {
        let fx = agent_host_runtime().await;
        let (_root, journal) = agent_host_journal(&fx);
        let mut launch = launch_agent_host(&fx);
        for _ in 0..2 {
            let pending = next_pending(&fx.pending_store, &mut launch).await;
            assert_eq!(pending.resource.as_str(), journal);
            fx.pending_store
                .deny_request_by(pending.id.as_str(), "not now", Settler::Shell)
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish after the denials")
            .expect("the launch task must not panic")
            .expect("a denied agent host still finishes cleanly");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        assert!(!path.exists());
        assert!(fx.pending_store.list_pending().await.is_empty());
        assert!(component_invoke_outcomes(&fx.audit_log).is_empty());
    }

    /// A capsule started by its CID is held to its asks by the real bridge.
    /// The bus fixture component asks the Runtime for a read grant on its
    /// probe resource, then reads it. Staged with a manifest that asks for
    /// exactly that, its request reaches the shell as a pending request: the
    /// ask itself granted nothing. Granted there, the read reaches the
    /// provider and the run ends well, and no ceiling is left behind. Staged
    /// with an ask on the same resource that lists only `write`, the bridge
    /// refuses the request for the read, in the sentence that names the
    /// action; no prompt is made and the provider sees nothing more.
    #[tokio::test]
    async fn a_capsule_started_by_cid_is_held_to_its_asks_by_the_real_bridge() {
        use crate::bundle_admission::tests::{key, signed};
        use crate::stage_cmd::{bundle_cid, stage_bundle};
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let publisher = key(71);
        let trusted = [hex::encode(publisher.verifying_key().to_bytes())];
        runtime
            .configure_capsule_admission(temp_dir.path(), &trusted, false)
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store = Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
        );
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(BusConformanceProvider::default());
        registry.register(provider.clone()).await;
        runtime
            .set_provider_registry(
                registry,
                capability_manager.clone(),
                pending_store.clone(),
                temp_dir.path().join("runtime-data"),
            )
            .await;

        let component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"),
        )
        .unwrap();
        let probe = "elastos://test/bus/probe";
        // Stage a bundle named `name` whose manifest asks for `actions` on the probe.
        let staged = |name: &'static str, actions: &'static [&'static str]| {
            let (runtime, data_dir, component) = (runtime.clone(), data_dir.clone(), &component);
            let folder = temp_dir.path().join("source").join(name);
            let signature = temp_dir.path().join(format!("{name}.sig.json"));
            let publisher = &publisher;
            async move {
                let mut manifest: serde_json::Value =
                    serde_json::from_str(&component_manifest_json(name)).unwrap();
                manifest["asks"] = serde_json::json!([{"resource": probe, "actions": actions}]);
                std::fs::create_dir_all(&folder).unwrap();
                std::fs::write(folder.join("capsule.json"), manifest.to_string()).unwrap();
                std::fs::write(folder.join("app.component.wasm"), component).unwrap();
                let cid = bundle_cid(&folder).unwrap();
                std::fs::write(&signature, signed(&cid, publisher)).unwrap();
                stage_bundle(&runtime, &data_dir, &folder, &signature)
                    .await
                    .unwrap();
                cid
            }
        };
        let start = |cid: String| {
            let (runtime, data_dir) = (runtime.clone(), data_dir.clone());
            tokio::spawn(async move {
                let person = Some("person:local:bus-conformance".to_string());
                let ran = runtime.run_by_bundle(&data_dir, &cid, Vec::new(), person);
                ran.await.map(|(handle, _)| handle.manifest.name)
            })
        };

        // Inside the asks.
        let launch = start(staged("asks-read", &["read"]).await);
        let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a request inside the asks reaches the shell");
        assert_eq!(pending.resource.as_str(), probe);
        assert_eq!(pending.action, elastos_runtime::capability::Action::Read);
        assert!(provider.requests.lock().await.is_empty(), "no grant yet");
        let capsule_id = pending.session_id.as_str().to_string();
        assert_eq!(
            runtime.ceiling_of(&capsule_id),
            Some(vec![format!("{probe} [read]")]),
            "while it runs, its ceiling is its asks"
        );
        let token = capability_manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(pending.id.as_str(), token, GrantDuration::Session)
            .await
            .unwrap();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), launch)
            .await
            .expect("the run ends after the grant")
            .expect("the launch task does not panic");
        assert_eq!(ended.unwrap(), "asks-read");
        assert_eq!(provider.requests.lock().await.len(), 1);
        assert_eq!(runtime.ceiling_of(&capsule_id), None, "none left after");

        // Beyond the asks: the same resource, but the action is not listed.
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            start(staged("asks-write", &["write"]).await),
        )
        .await
        .expect("a refused run ends at once")
        .expect("the launch task does not panic")
        .expect_err("the request for the read is refused");
        assert_eq!(refused.code(), "bundle_start_failed");
        let sentence = format!("capsule manifest does not declare authority to read {probe}");
        assert!(refused.to_string().contains(&sentence), "{refused}");
        assert!(
            pending_store.list_pending().await.is_empty(),
            "no prompt was made"
        );
        assert_eq!(provider.requests.lock().await.len(), 1, "nothing more");
    }

    /// A6-R. Two admitted agents run two component instances with distinct
    /// principals and sessions. A's token is minted for A's session and filed
    /// for A; B's own pending request is settled with a leaked copy. B's guest
    /// presents it and the real
    /// bridge refuses it at `validate`'s caller step with `capability_denied`
    /// before the provider is reached; the audit names B as the caller of the
    /// failed use and `wrong_capsule` as the reason. A's own invoke is the
    /// control: the provider is called exactly once, for A.
    #[cfg(unix)]
    #[tokio::test]
    async fn sibling_token_refused() {
        if !crate::agents::build_allows() {
            return;
        }
        use crate::bundle_admission::tests::key;
        use crate::stage_cmd::bundle_cid;
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let publisher = key(107);
        let trusted = [hex::encode(publisher.verifying_key().to_bytes())];
        let component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"),
        )
        .unwrap();
        let probe = "elastos://test/bus/probe";
        let folder = temp_dir.path().join("agent-host");
        std::fs::create_dir_all(&folder).unwrap();
        let mut manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json("agent-host")).unwrap();
        manifest.asks = serde_json::from_value(serde_json::json!([
            {"resource": probe, "actions": ["read"]}
        ]))
        .unwrap();
        manifest.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        elastos_runtime::signature::sign_capsule(
            &publisher,
            &mut manifest,
            &hash_content(&component),
        )
        .unwrap();
        std::fs::write(
            folder.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(folder.join("app.component.wasm"), &component).unwrap();
        let cid = bundle_cid(&folder).unwrap();
        let (home, agents) = crate::agents::tests::home_with_agents_if_built(2, &cid)
            .expect("A6-R agent row requires prototype agents");
        let data_dir = home.path().to_path_buf();
        assert_ne!(agents[0], agents[1], "two distinct A5 agent principals");
        for agent in &agents {
            assert!(
                agent.starts_with("agent:v2:"),
                "A5 agent principal: {agent}"
            );
            let root =
                crate::auth::principal_stored_localhost_root(Some(&data_dir), agent).unwrap();
            assert!(root.starts_with("localhost://UsersAI/"), "{root}");
        }
        runtime
            .configure_capsule_admission(&data_dir, &trusted, false)
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store = Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
        );
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(BusConformanceProvider::default());
        registry.register(provider.clone()).await;
        runtime
            .set_provider_registry(
                registry.clone(),
                capability_manager.clone(),
                pending_store.clone(),
                data_dir.clone(),
            )
            .await;

        let start = |agent: &str| {
            let admission = crate::agent_admission::admit_launch(
                &data_dir,
                &data_dir,
                Some(home.owner.principal_id.as_str()),
                Some(agent),
                crate::agent_admission::walk_launch(&folder).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(admission.actor(), agent);
            let (runtime, folder) = (runtime.clone(), folder.clone());
            tokio::spawn(async move {
                runtime
                    .run_local_admitted(&folder, Vec::new(), admission)
                    .await
                    .map(|(handle, _)| handle)
            })
        };

        let launch_a = start(&agents[0]);
        let a_pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(held) = pending_store.list_pending().await.into_iter().next() {
                    break held;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("A asks for its grant");
        let launch_b = start(&agents[1]);

        // Two instances, two sessions: the one probe is asked for twice.
        let pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let held = pending_store.list_pending().await;
                if held.len() == 2 {
                    break held;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both instances ask the shell for the probe");
        let b_pending = pending
            .into_iter()
            .find(|request| request.id != a_pending.id)
            .expect("B has its own request");
        let a_session = a_pending.session_id.as_str().to_string();
        let b_session = b_pending.session_id.as_str().to_string();
        assert_ne!(a_session, b_session, "two instances are two sessions");

        // A's token, minted for A's session. Filed for A, and also handed to
        // B's own pending request: a leaked sibling token.
        let a_token = capability_manager.grant(
            &a_session,
            a_pending.resource.clone(),
            a_pending.action,
            TokenConstraints::default(),
            None,
        );
        for request in [&a_pending, &b_pending] {
            pending_store
                .grant_request(request.id.as_str(), a_token.clone(), GrantDuration::Session)
                .await
                .unwrap();
        }

        let (left, right) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(launch_a, launch_b)
        })
        .await
        .expect("both activations end");
        let (left, right) = (
            left.expect("the first launch task does not panic"),
            right.expect("the second launch task does not panic"),
        );
        let calls = provider.requests.lock().await.clone();
        assert_eq!(
            calls.len(),
            1,
            "the provider is called once, for A; B's call never reaches it"
        );
        assert_eq!(
            calls[0]["probe"], "bus-v1-conformance",
            "A's probe is the one provider call"
        );
        let (ran, refused) = match (left, right) {
            (Ok(handle), Err(refusal)) | (Err(refusal), Ok(handle)) => (handle, refusal),
            _ => panic!("exactly one instance uses its own grant and completes"),
        };
        assert_eq!(ran.id.0, a_session, "A's own token runs A's own instance");
        assert!(
            refused.to_string().contains("BusError::Denied"),
            "B's component receives the bridge denial: {refused}"
        );
        assert!(
            refused.to_string().contains("Capability validation failed"),
            "B's invoke is refused by the capability check: {refused}"
        );

        // The bridge persists the principal and session of the component
        // invocation, independently of the capability-use audit below.
        let completed: Vec<_> = crate::auth::load_auth_state(&data_dir)
            .unwrap()
            .audit
            .into_iter()
            .filter(|event| event.event_type == "component.invoke.completed")
            .collect();
        assert_eq!(
            completed.len(),
            2,
            "one completed invoke per agent: {completed:?}"
        );
        for (principal, session, result) in [
            (&agents[0], &a_session, "ok"),
            (&agents[1], &b_session, "denied"),
        ] {
            assert!(
                completed.iter().any(|event| {
                    event.principal_id.as_deref() == Some(principal.as_str())
                        && event.session_id.as_deref() == Some(session.as_str())
                        && event.result == result
                }),
                "{principal} must own its {result} persisted invoke event: {completed:?}"
            );
        }

        let events = audit_log.recent_events(2_000);
        let token_id = a_token.id().to_string();
        let uses: Vec<(String, bool)> = events
            .iter()
            .filter_map(|event| match event {
                AuditEvent::CapabilityUse {
                    token_id: used,
                    capsule_id,
                    success,
                    ..
                } if used == &token_id => Some((capsule_id.clone(), *success)),
                _ => None,
            })
            .collect();
        assert!(
            uses.contains(&(a_session.clone(), true)),
            "A's use of its own token is audited with A as the caller: {uses:?}"
        );
        assert!(
            uses.contains(&(b_session.clone(), false)),
            "B's use of A's token is audited with B as the caller: {uses:?}"
        );
        assert_eq!(uses.len(), 2, "one use each: {uses:?}");

        let warnings: Vec<&str> = events
            .iter()
            .filter_map(|event| match event {
                AuditEvent::SecurityWarning {
                    warning_type,
                    details,
                    ..
                } if warning_type == "capability_validation_failed" => Some(details.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            warnings.len(),
            1,
            "exactly one failed validation: {warnings:?}"
        );
        assert!(
            warnings[0].contains("wrong_capsule"),
            "the audit records wrong_capsule as the reason: {}",
            warnings[0]
        );
        assert!(
            warnings[0].contains(&b_session),
            "the same record names B as the caller: {}",
            warnings[0]
        );

        // The guest's BusError maps the wire code to Denied. Inspect the same
        // bridge entry with B's leaked token to pin its exact wire code.
        let context = crate::resource_bridge::BridgeContext {
            provider_registry: registry,
            capability_manager: capability_manager.clone(),
            pending_store: pending_store.clone(),
            capsule_id: b_session.clone(),
            session_id: b_session.clone(),
            principal_id: Some(agents[1].clone()),
            manifest_capabilities: manifest.resource_authority_bounds(),
            data_dir: Some(data_dir.clone()),
            launch: None,
            model_token_ceiling: None,
            model_budget: None,
            stop: None,
        };
        let line = serde_json::json!({
            "id": 99,
            "request": {
                "type": "resource_invoke", "uri": probe, "operation": "read",
                "token": a_token.to_base64().unwrap(),
                "body": {"probe": "bus-v1-conformance"}
            }
        })
        .to_string();
        let denied = crate::resource_bridge::handle_component_resource_request(&line, context)
            .await
            .unwrap();
        assert_eq!(denied["response"]["code"], "capability_denied", "{denied}");
        assert_eq!(
            provider.requests.lock().await.len(),
            1,
            "only A reached the provider"
        );
    }

    /// B2-undeclared. The signed asks are the whole ceiling. A request for a
    /// resource the asks never named is refused by the real bridge in the
    /// sentence that names the action and the resource, though the capsule is
    /// loaded unsealed because it has asks: no prompt is made and the
    /// provider is not reached. The control is the same component under an
    /// ask on the resource it requests: it reaches the shell, and granted
    /// there it reads once and ends well.
    #[tokio::test]
    async fn a_request_for_a_resource_the_signed_manifest_never_asked_for_is_refused() {
        use crate::bundle_admission::tests::{key, signed};
        use crate::stage_cmd::{bundle_cid, stage_bundle};
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let publisher = key(103);
        let trusted = [hex::encode(publisher.verifying_key().to_bytes())];
        runtime
            .configure_capsule_admission(temp_dir.path(), &trusted, false)
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store = Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
        );
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(BusConformanceProvider::default());
        registry.register(provider.clone()).await;
        runtime
            .set_provider_registry(
                registry,
                capability_manager.clone(),
                pending_store.clone(),
                temp_dir.path().join("runtime-data"),
            )
            .await;

        let component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"),
        )
        .unwrap();
        let probe = "elastos://test/bus/probe";
        let elsewhere = "elastos://test/bus/elsewhere";
        // Stage a bundle named `name` whose asks declare `actions` on `resource`.
        let staged = |name: &'static str,
                      resource: &'static str,
                      actions: &'static [&'static str]| {
            let (runtime, data_dir, component) = (runtime.clone(), data_dir.clone(), &component);
            let folder = temp_dir.path().join("source").join(name);
            let signature = temp_dir.path().join(format!("{name}.sig.json"));
            let publisher = &publisher;
            async move {
                let mut manifest: serde_json::Value =
                    serde_json::from_str(&component_manifest_json(name)).unwrap();
                manifest["asks"] = serde_json::json!([{"resource": resource, "actions": actions}]);
                std::fs::create_dir_all(&folder).unwrap();
                std::fs::write(folder.join("capsule.json"), manifest.to_string()).unwrap();
                std::fs::write(folder.join("app.component.wasm"), component).unwrap();
                let cid = bundle_cid(&folder).unwrap();
                std::fs::write(&signature, signed(&cid, publisher)).unwrap();
                stage_bundle(&runtime, &data_dir, &folder, &signature)
                    .await
                    .unwrap();
                cid
            }
        };
        let start = |cid: String| {
            let (runtime, data_dir) = (runtime.clone(), data_dir.clone());
            tokio::spawn(async move {
                let person = Some("person:local:bus-conformance".to_string());
                let ran = runtime.run_by_bundle(&data_dir, &cid, Vec::new(), person);
                ran.await.map(|(handle, _)| handle.manifest.name)
            })
        };

        // The control: the ask names the resource the component requests.
        let launch = start(staged("asks-probe", probe, &["read"]).await);
        let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a request inside the asks reaches the shell");
        assert_eq!(pending.resource.as_str(), probe);
        assert_eq!(pending.action, elastos_runtime::capability::Action::Read);
        let token = capability_manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(pending.id.as_str(), token, GrantDuration::Session)
            .await
            .unwrap();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), launch)
            .await
            .expect("the run ends after the grant")
            .expect("the launch task does not panic");
        assert_eq!(ended.unwrap(), "asks-probe");

        // Beyond the asks: the resource is not one the signed manifest asked
        // for, though the same ask would admit it with one word changed.
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            start(staged("asks-elsewhere", elsewhere, &["read"]).await),
        )
        .await
        .expect("a refused run ends at once")
        .expect("the launch task does not panic")
        .expect_err("the request for the probe is refused");
        assert_eq!(refused.code(), "bundle_start_failed");
        let sentence = format!("capsule manifest does not declare authority to read {probe}");
        assert!(refused.to_string().contains(&sentence), "{refused}");
        assert!(
            pending_store.list_pending().await.is_empty(),
            "no prompt was made"
        );
        assert_eq!(
            provider.requests.lock().await.len(),
            1,
            "the provider saw only the granted read"
        );
    }

    #[tokio::test]
    async fn component_conformance_exercises_bus_authorization_dispatch_and_audit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let component_provider = Arc::new(ComponentProvider::new());
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(component_provider.clone()),
        ));
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();

        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store = Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
        );
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(BusConformanceProvider::default());
        registry.register(provider.clone()).await;
        runtime
            .set_provider_registry(
                registry,
                capability_manager.clone(),
                pending_store.clone(),
                temp_dir.path().join("runtime-data"),
            )
            .await;

        let fixture_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let launch_runtime = runtime.clone();
        let launch_fixture = fixture_dir.clone();
        let launch = tokio::spawn(async move {
            launch_runtime
                .run_local_with_principal(
                    &launch_fixture,
                    Vec::new(),
                    Some(crate::resource_bridge::BridgePrincipal::for_test(
                        "person:local:bus-conformance",
                    )),
                )
                .await
        });

        let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("component must create a pending capability request");

        assert_eq!(pending.resource.as_str(), "elastos://test/bus/probe");
        assert_eq!(pending.action, elastos_runtime::capability::Action::Read);
        assert_eq!(pending.reason, "verify the Component-to-Bus authority path");
        assert!(pending.session_id.as_str().starts_with("component-"));

        let token = capability_manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(pending.id.as_str(), token, GrantDuration::Session)
            .await
            .unwrap();

        let handle = tokio::time::timeout(std::time::Duration::from_secs(5), launch)
            .await
            .expect("component must finish after the grant")
            .expect("component launch task must not panic")
            .expect("component must complete the Bus conformance flow");
        assert_eq!(handle.manifest.name, "bus-v1-conformance");

        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["op"], "read");
        assert_eq!(requests[0]["probe"], "bus-v1-conformance");
        drop(requests);

        let events = audit_log.recent_events(32);
        assert!(events.iter().any(|event| matches!(
            event,
            AuditEvent::CapabilityRequested { resource, .. }
                if resource == "elastos://test/bus/probe"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            AuditEvent::CapabilityUse { capsule_id, success: true, .. }
                if capsule_id == pending.session_id.as_str()
        )));
        let requested_audit = events.iter().find_map(|event| match event {
            AuditEvent::Custom {
                event_type,
                details,
            } if event_type == "component.invoke.requested" => {
                details.get("audit_id").and_then(|value| value.as_str())
            }
            _ => None,
        });
        let completed_audit = events.iter().find_map(|event| match event {
            AuditEvent::Custom {
                event_type,
                details,
            } if event_type == "component.invoke.completed" => {
                details.get("audit_id").and_then(|value| value.as_str())
            }
            _ => None,
        });
        assert!(requested_audit.is_some());
        assert_eq!(requested_audit, completed_audit);

        let denied_runtime = runtime.clone();
        let denied_fixture = fixture_dir.clone();
        let denied_launch = tokio::spawn(async move {
            denied_runtime
                .run_local_with_principal(
                    &denied_fixture,
                    Vec::new(),
                    Some(crate::resource_bridge::BridgePrincipal::for_test(
                        "person:local:bus-conformance",
                    )),
                )
                .await
        });
        let denied_pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second component activation must request a capability");
        let wrong_action_token = capability_manager.grant(
            denied_pending.session_id.as_str(),
            denied_pending.resource.clone(),
            elastos_runtime::capability::Action::Write,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(
                denied_pending.id.as_str(),
                wrong_action_token,
                GrantDuration::Session,
            )
            .await
            .unwrap();

        let denied = tokio::time::timeout(std::time::Duration::from_secs(5), denied_launch)
            .await
            .expect("denied component activation must finish")
            .expect("denied component task must not panic")
            .expect_err("wrong-action grant must not authorize provider dispatch");
        assert!(denied.to_string().contains("Component capsule denied"));
        assert_eq!(provider.requests.lock().await.len(), 1);
        assert!(audit_log.recent_events(64).iter().any(|event| matches!(
            event,
            AuditEvent::Custom { event_type, details }
                if event_type == "component.invoke.completed"
                    && details["capsule_id"] == denied_pending.session_id.as_str()
                    && details["outcome"] == "denied"
        )));
        assert!(matches!(
            component_provider.status(&handle).await,
            Err(ElastosError::CapsuleNotFound(_))
        ));
    }

    /// A3-R S4+S5 fix 4. The first stop's reason is the cause the end
    /// records; a later stop raises the same flag and changes nothing else.
    #[test]
    fn a_later_stop_keeps_the_first_cause() {
        let stop = ActivationStop {
            flag: Arc::new(crate::resource_bridge::ActivationStopFlag::default()),
            cause: StdMutex::new(None),
        };
        assert_eq!(stop.cause(), None);
        stop.request("first");
        assert!(stop.flag.requested.load(Ordering::Acquire));
        stop.request("second");
        assert_eq!(stop.cause().as_deref(), Some("stopped: first"));
        assert!(stop.flag.requested.load(Ordering::Acquire));
    }

    /// A3-R S4+S5 fix 1. A stop given to the provider while the component is
    /// still loading takes it away, and the start that follows fails as the
    /// stop's doing. A start interrupted by the stop is the stop's doing too;
    /// a start that ends on its own fuel is the guest's failure.
    #[tokio::test]
    async fn a_start_the_stop_took_away_is_the_stops_doing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("app.component.wasm"), quiet_component()).unwrap();
        let manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json("taken-away")).unwrap();
        let component = ComponentProvider::new();
        let handle = component.load(temp.path(), manifest).await.unwrap();
        component.stop(&handle).await.unwrap();
        let err = match component.start_resident(&handle).await {
            Ok(_) => panic!("a component the stop took away started"),
            Err(err) => err,
        };
        assert!(start_ended_by_stop(&err), "{err}");
        assert!(start_ended_by_stop(&ElastosError::Compute(
            STOPPED_BEFORE_RUN.to_string()
        )));
        let own = "Failed to instantiate component capsule: all fuel consumed by WebAssembly";
        assert!(!start_ended_by_stop(&ElastosError::Compute(
            own.to_string()
        )));
    }

    fn v2_home_bytes(kind: &str) -> Vec<u8> {
        let source = include_str!("../../../tests/fixtures/components/v2-resident.wat");
        let source = match kind {
            "trap" => source.replacen(
                "call $new global.set $set\n      call $next)",
                "call $new global.set $set\n      unreachable)",
                1,
            ),
            "spin" => source.replacen(
                "call $new global.set $set\n      call $next)",
                "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
                1,
            ),
            _ => source.to_string(),
        };
        wat::parse_str(source).expect("v2 home guest")
    }

    /// Loads a v2 guest, registers it, and lets the watcher start it. `fuel`
    /// replaces the resident fuel before the guest runs.
    async fn start_v2_home(
        bytes: Vec<u8>,
        name: &str,
        fuel: Option<u64>,
    ) -> (
        Runtime,
        Arc<ComponentProvider>,
        CapsuleHandle,
        tempfile::TempDir,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp.path().to_path_buf())
                .await
                .unwrap(),
        );
        let component = Arc::new(ComponentProvider::new());
        let runtime =
            Runtime::with_providers_and_component(storage, Vec::new(), Some(component.clone()));
        let mut manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json(name)).unwrap();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_bus_v2_wit_sha256());
        let handle = component.load_admitted(bytes, manifest).await.unwrap();
        if let Some(fuel) = fuel {
            component.set_v2_fuel(&handle.id, fuel).await.unwrap();
        }
        let id = handle.id.0.clone();
        runtime
            .hold_launch_context(&handle, Some("person:local:resident".into()), None)
            .await;
        runtime
            .register_capsule(RunningCapsuleInfo {
                id: id.clone(),
                name: name.to_string(),
                status: CAPSULE_STARTING.to_string(),
                capsule_type: handle.manifest.capsule_type.clone(),
                handle: Some(handle.clone()),
                session_id: id.clone(),
                principal: Some("person:local:resident".into()),
                cause: None,
                ended_at: None,
            })
            .await;
        let held = ActivationContextHeld::new(&runtime, &handle, component.clone(), None);
        runtime.watch_activation(handle.id.clone(), handle.clone(), component.clone(), held);
        (runtime, component, handle, temp)
    }

    async fn wait_v2_status(runtime: &Runtime, id: &str, running: bool) -> RunningCapsuleInfo {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(entry) = runtime.get_capsule(id).await {
                    if running && entry.status == CAPSULE_RUNNING {
                        return entry;
                    }
                    if entry.ended_at.is_some() {
                        return entry;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("v2 resident did not reach its status: {id}"))
    }

    async fn assert_v2_home_cleared(
        runtime: &Runtime,
        component: &ComponentProvider,
        handle: &CapsuleHandle,
    ) {
        assert!(
            runtime
                .context_left_for_test(handle.id.as_str())
                .await
                .is_empty(),
            "tokens stay after the end"
        );
        assert!(!runtime.provider_entry_for_test(handle).await);
        assert!(runtime.provider_principal_for_test(handle).await.is_none());
        assert!(component
            .read_v2_frame(Some("person:local:resident"), handle.id.as_str())
            .is_none());
    }

    /// A detached v2 guest stays up, answers stop, and the end clears its
    /// tokens, frame, and events. The launch record names that stop.
    #[tokio::test]
    async fn a_v2_home_resident_stays_up_and_stops() {
        let (runtime, component, handle, _temp) =
            start_v2_home(v2_home_bytes("stay"), "stays", None).await;
        let running = wait_v2_status(&runtime, handle.id.as_str(), true).await;
        assert_eq!(running.status, CAPSULE_RUNNING);
        assert_eq!(running.session_id, handle.id.0);
        assert!(running.cause.is_none());
        assert!(running.ended_at.is_none());
        assert_eq!(
            component.status(&handle).await.unwrap(),
            CapsuleStatus::Running
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert_eq!(
            component.status(&handle).await.unwrap(),
            CapsuleStatus::Running,
            "the guest stays up"
        );
        let ended = runtime
            .stop_capsule_by_id(handle.id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended.status, CAPSULE_STOPPED);
        assert_eq!(ended.cause.as_deref(), Some("stopped: user"));
        assert!(ended.ended_at.is_some());
        assert_eq!(ended.session_id, handle.id.0);
        assert_v2_home_cleared(&runtime, &component, &handle).await;
    }

    /// A trap and a fuel end each finish the resident and clear the same state.
    #[tokio::test]
    async fn a_v2_home_resident_trap_and_fuel_end_clear_it() {
        let (runtime, component, handle, _temp) =
            start_v2_home(v2_home_bytes("trap"), "traps", None).await;
        let ended = wait_v2_status(&runtime, handle.id.as_str(), false).await;
        assert_eq!(ended.status, CAPSULE_FAILED);
        let cause = ended.cause.unwrap();
        assert!(cause.contains("unreachable"), "{cause}");
        assert_eq!(ended.session_id, handle.id.0);
        assert_v2_home_cleared(&runtime, &component, &handle).await;

        let (runtime, component, handle, _temp) =
            start_v2_home(v2_home_bytes("spin"), "fuel", Some(1_000)).await;
        let ended = wait_v2_status(&runtime, handle.id.as_str(), false).await;
        assert_eq!(ended.status, CAPSULE_FAILED);
        let cause = ended.cause.unwrap();
        assert!(cause.contains("execution-bound"), "{cause}");
        assert_v2_home_cleared(&runtime, &component, &handle).await;
    }

    /// Dropping the runtime that watches the guest is a server shutdown. The
    /// owed end still runs, and it clears the same state.
    #[test]
    fn a_v2_home_resident_shutdown_ends_and_clears() {
        let local = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (runtime, component, handle, _temp) = local.block_on(async {
            let started = start_v2_home(v2_home_bytes("stay"), "shutdown", None).await;
            let running = wait_v2_status(&started.0, started.2.id.as_str(), true).await;
            assert_eq!(running.status, CAPSULE_RUNNING);
            started
        });
        drop(local);
        let poll = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        poll.block_on(async {
            let ended = wait_v2_status(&runtime, handle.id.as_str(), false).await;
            assert_eq!(ended.status, CAPSULE_FAILED);
            assert_eq!(ended.cause.as_deref(), Some(CAUSE_TASK_LOST));
            assert_v2_home_cleared(&runtime, &component, &handle).await;
        });
    }

    #[cfg(unix)]
    /// A3-R S3 fix 1. A guard dropped with its end owed hands the end to a
    /// task, and the runtime shuts down before it runs that task, as a
    /// runtime does with the tasks it has not run. The end still happens
    /// once: the entry ends `failed` with the lost-task cause, the session's
    /// pending request is denied and its grant revoked, and one
    /// `capsule_stop` is audited.
    #[test]
    fn a_lost_end_task_still_ends_the_activation_once() {
        use elastos_runtime::capability::manager::ValidationError;
        use elastos_runtime::capability::{Action, RequestStatus, ResourceId};
        use elastos_runtime::primitives::audit::StopReason;
        use elastos_runtime::session::SessionId;

        const ID: &str = "lost-end";
        let resource = ResourceId::new("elastos://content/publish");
        let shutting_down = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (runtime, audit_log, pending_store, manager, pending, token, _temp) = shutting_down
            .block_on(async {
                let temp = tempfile::tempdir().unwrap();
                let storage = LocalFSProvider::new(temp.path().join("storage"))
                    .await
                    .unwrap();
                let component = Arc::new(ComponentProvider::new());
                let runtime = Runtime::with_providers_and_component(
                    Arc::new(storage),
                    Vec::new(),
                    Some(component.clone()),
                );
                let audit_log = Arc::new(AuditLog::new());
                let manager = Arc::new(CapabilityManager::new(
                    Arc::new(CapabilityStore::new()),
                    audit_log.clone(),
                    Arc::new(MetricsManager::new()),
                ));
                let pending_store = Arc::new(
                    elastos_runtime::capability::pending::PendingRequestStore::new(
                        audit_log.clone(),
                    ),
                );
                let data_dir = temp.path().join("data");
                std::fs::create_dir_all(&data_dir).unwrap();
                runtime
                    .set_provider_registry(
                        Arc::new(ProviderRegistry::new()),
                        manager.clone(),
                        pending_store.clone(),
                        data_dir,
                    )
                    .await;

                let handle = CapsuleHandle {
                    id: CapsuleId::new(ID),
                    manifest: serde_json::from_str(&component_manifest_json(ID)).unwrap(),
                    args: Vec::new(),
                };
                runtime
                    .register_capsule(RunningCapsuleInfo {
                        id: ID.to_string(),
                        name: ID.to_string(),
                        status: CAPSULE_RUNNING.to_string(),
                        capsule_type: CapsuleType::Wasm,
                        handle: Some(handle.clone()),
                        session_id: ID.to_string(),
                        principal: None,
                        cause: None,
                        ended_at: None,
                    })
                    .await;
                let session = || SessionId::from_string(ID);
                let pending = pending_store
                    .create_request(session(), resource.clone(), Action::Read)
                    .await
                    .id
                    .to_string();
                let granted = pending_store
                    .create_request(session(), resource.clone(), Action::Write)
                    .await
                    .id
                    .to_string();
                let constraints = TokenConstraints::default();
                let token = manager.grant(ID, resource.clone(), Action::Write, constraints, None);
                pending_store
                    .grant_request(&granted, token.clone(), GrantDuration::Session)
                    .await
                    .unwrap();

                drop(ActivationContextHeld::new(
                    &runtime, &handle, component, None,
                ));
                (
                    runtime,
                    audit_log,
                    pending_store,
                    manager,
                    pending,
                    token,
                    temp,
                )
            });
        let entry = runtime.running_capsules.try_read().unwrap()[ID].clone();
        assert!(entry.ended_at.is_none(), "the end's task has not run");
        drop(shutting_down);

        let after = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        after.block_on(async {
            let entry = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(entry) = runtime.get_capsule(ID).await {
                        if entry.ended_at.is_some() {
                            break entry;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the end still runs after its task was dropped");
            assert_eq!(entry.status, CAPSULE_FAILED);
            assert_eq!(entry.cause.as_deref(), Some(CAUSE_TASK_LOST));

            let RequestStatus::Denied { reason, settled_by } =
                pending_store.get_request(&pending).await.unwrap().status
            else {
                panic!("the pending request is not settled");
            };
            assert_eq!(reason, format!("instance ended: {CAUSE_TASK_LOST}"));
            assert_eq!(settled_by, Settler::Runtime);
            assert_eq!(
                manager
                    .validate(&token, ID, Action::Write, &resource, None)
                    .await,
                Err(ValidationError::TokenRevoked)
            );

            // Exactly once, also after the end had time to run again.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let stops: Vec<_> = audit_log
                .recent_events(usize::MAX)
                .into_iter()
                .filter_map(|event| match event {
                    AuditEvent::CapsuleStop {
                        capsule_id, reason, ..
                    } if capsule_id == ID => Some(reason),
                    _ => None,
                })
                .collect();
            assert!(
                matches!(stops.as_slice(), [StopReason::Error(cause)] if cause == CAUSE_TASK_LOST),
                "{stops:?}"
            );
        });
    }

    /// A v1 bridge future runs on the `spawn_blocking` thread that called it.
    /// That thread has a runtime handle entered, so a choice made by
    /// `Handle::try_current` would add a thread for the call.
    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v1_bridge_on_a_blocking_thread_adds_no_thread() {
        let handle = tokio::runtime::Handle::current();
        let joined = tokio::task::spawn_blocking(move || {
            assert!(
                tokio::runtime::Handle::try_current().is_ok(),
                "a spawn_blocking worker has a runtime handle entered"
            );
            let caller = std::thread::current().id();
            let before = super::live_thread_count();
            let (ran_on, during) = Runtime::block_on_component_bridge(
                &handle,
                elastos_compute::providers::ComponentBridgeLeg::Caller,
                async move {
                    tokio::task::yield_now().await;
                    (std::thread::current().id(), super::live_thread_count())
                },
            );
            assert_eq!(
                during, before,
                "a v1 bridge on a blocking thread adds no thread"
            );
            assert_eq!(ran_on, caller, "a v1 bridge future stays on the caller");
        })
        .await;
        assert!(
            joined.is_ok(),
            "the blocking bridge call panicked: {joined:?}"
        );
    }
}
