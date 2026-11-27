//! WASM Component Model provider for the ElastOS component ABI.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, OnceLock,
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use wasmtime::component::{
    bindgen, Component, Destination, HasSelf, Linker, StreamProducer, StreamReader, StreamResult,
};
use wasmtime::{
    Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline,
    WasmFeatures,
};

use elastos_common::{
    CapsuleId, CapsuleManifest, CapsuleRuntimeAbi, CapsuleStatus, CapsuleType, ElastosError,
    Result, ELASTOS_BUS_V2_CONTRACT,
};
use elastos_guest::{
    bus as guest_bus,
    runtime::{ResponseEnvelope, RuntimeRequest, RuntimeResponse},
};

use crate::providers::bus2_ui::{Frame, FrameNode};
use crate::{CapsuleHandle, CapsuleInfo, ComputeProvider};

type HostAnswer = std::result::Result<String, String>;
use super::{BridgeHostcall, BridgeHostcallAsync, BridgeLegGuard, ComponentBridgeLeg};

bindgen!({
    path: "../../wit",
    world: "product-capsule-v1",
});

mod v2 {
    wasmtime::component::bindgen!({ path: "../../wit-bus-v2", world: "product-capsule-v2" });
}

type V2BusError = v2::elastos::bus::types::BusError;
type V2Result<T> = std::result::Result<T, V2BusError>;

const COMPONENT_FUEL: u64 = 100_000_000;
/// Yield the executor this often so one busy guest does not hold the thread.
/// The token bucket, not this slice, is the fuel bound.
const V2_FUEL_SLICE: u64 = 10_000_000;
const COMPONENT_MEMORY_SIZE: usize = 128 * 1024 * 1024;
/// The largest component file the Runtime reads or compiles. The largest
/// component in this repository is under 1 MiB.
pub const COMPONENT_MAX_BYTES: usize = 8 * 1024 * 1024;
/// How long a load waits for the one compile slot before it gives up.
const COMPONENT_COMPILE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
/// One deadline tick. Wasmtime calls this the engine "epoch"; this code says
/// "tick", because "epoch" already names the capability revocation epoch.
const DEADLINE_TICK: Duration = Duration::from_millis(10);
/// Shortest positive sleep. The guest clock is whole milliseconds, so a 1 ms
/// loop parks for at least this long: the thread yields, and the bucket
/// refills for that parked time.
const V2_SLEEP_FLOOR: Duration = Duration::from_millis(1);
/// How long one activation's own code may run. Time inside Bus calls is not
/// counted, so a run that waits on the Runtime is not ended for waiting.
/// Two things this is not: it is not exact (a ticker thread that is starved
/// makes the limit late, never early by more than one tick), and it cannot
/// stop a Bus call that never returns, because host code has no tick checks.
/// Fuel counts instructions, and how long an instruction takes depends on the
/// instruction and the machine; this bounds the time itself.
const COMPONENT_RUN_DEADLINE: Duration = Duration::from_secs(10);
/// Stop first closes events; a guest that keeps running is then aborted.
#[cfg(not(test))]
const V2_STOP_GRACE: Duration = Duration::from_millis(200);
#[cfg(test)]
const V2_STOP_GRACE: Duration = Duration::from_millis(20);
/// Every v2 read and every v2 bridge call that is not a person's approval.
/// The guest waits this long, then the call is a timeout. A stop joins within
/// this too. Host code that blocks cannot be cut, the same limit
/// `COMPONENT_RUN_DEADLINE` carries: the timeout lands on the next yield.
const V2_HOST_DEADLINE: Duration = Duration::from_secs(2);
/// How long the frame route's client waits. A frame read that cannot check
/// the book in this time answers empty, never the stored frame.
pub const V2_FRAME_ROUTE_DEADLINE: Duration = Duration::from_secs(2);
/// A person's approval. The bridge polls the shell for 30 s; this is that
/// same limit, so an answer inside it still reaches the guest.
const V2_APPROVAL_DEADLINE: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const V2_EPOCH_TICKS: u64 = 1_000;
#[cfg(test)]
const V2_TEST_EPOCH_TICKS: u64 = 30;
/// The named ending of a run that the deadline stopped.
const ENDING_EPOCH_DEADLINE: &str = "epoch-deadline";
/// The named ending of a run whose spent fuel added up to the tick budget.
const ENDING_EXECUTION_BOUND: &str = "execution-bound";
/// How many v2 guests may run at once. The refusal names this cap.
#[cfg(test)]
const V2_RESIDENT_CAP: usize = 2;
#[cfg(not(test))]
const V2_RESIDENT_CAP: usize = 8;
/// The named ending of a run that used up its fuel.
const ENDING_FUEL_EXHAUSTED: &str = "fuel-exhausted";
/// The named ending of a run that a stop request ended.
const ENDING_STOPPED: &str = "stopped";

/// A test blocks one thread here and releases it from another.
#[cfg(test)]
pub struct TestGate {
    entered: Mutex<bool>,
    enter: Condvar,
    release: Mutex<bool>,
    go: Condvar,
}

#[cfg(test)]
impl TestGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Mutex::new(false),
            enter: Condvar::new(),
            release: Mutex::new(false),
            go: Condvar::new(),
        })
    }

    fn wait(&self) {
        let mut entered = self.entered.lock().expect("gate");
        *entered = true;
        self.enter.notify_all();
        drop(entered);
        let guard = self.release.lock().expect("gate");
        let _guard = self.go.wait_while(guard, |open| !*open).expect("gate");
    }

    pub fn entered(&self) {
        let guard = self.entered.lock().expect("gate");
        let _guard = self
            .enter
            .wait_while(guard, |entered| !*entered)
            .expect("gate");
    }

    pub fn open(&self) {
        *self.release.lock().expect("gate") = true;
        self.go.notify_all();
    }
}

struct ComponentActivation {
    engine: Engine,
    component: Component,
    status: CapsuleStatus,
    manifest: CapsuleManifest,
    /// Loaded with no bridge: see [`ComponentProvider::load_admitted_sealed`].
    sealed: bool,
    /// Set by [`ComputeProvider::stop`] for a running v1 activation and read
    /// by the guest's epoch callback, which traps the guest as `stopped`.
    stop_requested: Arc<AtomicBool>,
    /// This activation's own-code limits; the shipped values unless a test
    /// sets them on the entry before start.
    fuel: u64,
    /// Fuel a v2 resident starts with. v1 keeps `fuel`.
    v2_fuel: u64,
    run_deadline: Duration,
    events: Option<mpsc::UnboundedSender<v2::elastos::bus::types::Event>>,
    cancel_requested: Arc<AtomicBool>,
    task: Option<tokio::task::AbortHandle>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// The one join of this guest's worker. A later stop waits on it and does
    /// not free the slot while the worker has not ended.
    join: Option<Arc<V2Join>>,
    /// The join is stored and this slot counts toward the cap, before status
    /// is Running. Set under the start lock, before that lock is dropped.
    starting: bool,
    /// How long a stop waits for that join before it answers "still running".
    join_bound: Duration,
    /// Wakes one clock sleep. Stop and cancel store the flag, then notify.
    wake: Arc<tokio::sync::Notify>,
    /// Set for the wait inside `sleep-until`. A test reads it.
    #[cfg(test)]
    in_clock_sleep: Arc<AtomicBool>,
    /// The test asks the next join to skip spawning its owner thread.
    #[cfg(test)]
    refuse_join_owner: bool,
    /// The test holds start here until it has the task, before the worker is published.
    #[cfg(test)]
    publish_gate: Option<Arc<TestGate>>,
    #[cfg(feature = "test-fixtures")]
    publish_hold: Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>,
    #[cfg(test)]
    attach_gate: Option<Arc<TestGate>>,
    /// The test holds a natural exit here after the worker has signalled done.
    #[cfg(test)]
    exit_gate: Option<Arc<TestGate>>,
    /// Present waits here while it still holds the book lock.
    #[cfg(test)]
    present_gate: Option<Arc<TestGate>>,
    #[cfg(test)]
    test_max_ticks: u64,
    #[cfg(test)]
    pending_read: Arc<AtomicBool>,
    #[cfg(test)]
    test_wall_clock: bool,
    /// After a host wait arms the deadline, sleep this many ms before the
    /// guest runs. Proves an unburned tick is not charged.
    #[cfg(test)]
    host_deadline_tail_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Grants this activation's guest already holds. `capabilities.request`
    /// on the v1 seam and a successful v2 read record them. Present reads
    /// the record and does not ask for a new grant.
    grants: Arc<Mutex<crate::providers::bus2_ui::GrantBook>>,
}

/// Takes an activation's entry away when the run ends, including on unwind,
/// so a panicked worker cannot leave a `Running` entry behind.
struct ActivationEntryGuard {
    instances: Arc<RwLock<HashMap<CapsuleId, ComponentActivation>>>,
    id: CapsuleId,
}

impl Drop for ActivationEntryGuard {
    fn drop(&mut self) {
        self.instances.blocking_write().remove(&self.id);
    }
}

/// How one resident activation ended, published by its worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// The guest's `run` export returned success.
    Returned,
    /// The guest trapped; the message leads with its cause.
    Trapped(String),
    /// A stop request trapped the guest in its epoch callback.
    Stopped,
}

impl std::fmt::Display for ActivationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Returned => write!(f, "returned"),
            Self::Trapped(message) => write!(f, "Compute error: {message}"),
            Self::Stopped => write!(f, "Compute error: stopped by request"),
        }
    }
}

/// A started, still-running v1 activation. The guest runs on a blocking
/// thread; dropping this handle does not end it.
pub struct ResidentActivation {
    pub handle: CapsuleHandle,
    outcome: tokio::sync::watch::Receiver<Option<ActivationOutcome>>,
}

impl ResidentActivation {
    /// Waits for the worker to publish this activation's outcome.
    pub async fn ended(&mut self) -> ActivationOutcome {
        loop {
            if let Some(outcome) = self.outcome.borrow_and_update().clone() {
                return outcome;
            }
            if self.outcome.changed().await.is_err() {
                // The worker is gone without an outcome (a panic or a dropped
                // store); report it as a trap rather than waiting for ever.
                return ActivationOutcome::Trapped(
                    "Component run ended without publishing an outcome".into(),
                );
            }
        }
    }

    /// The outcome if the worker has already published it.
    pub fn outcome(&self) -> Option<ActivationOutcome> {
        self.outcome.borrow().clone()
    }
}

struct V2RunControl {
    stop_requested: Arc<AtomicBool>,
    cancel_requested: Arc<AtomicBool>,
    max_ticks: u64,
    fuel: u64,
    fuel_slice: u64,
    #[cfg(test)]
    pending_read: Arc<AtomicBool>,
    #[cfg(test)]
    wall_clock: bool,
}

/// What a sealed component gets for any call to the bridge.
pub const SEALED_BRIDGE: &str = "this capsule was started with no authority: it has no bridge";

/// The start error of an activation whose stop interrupted its start function.
pub const STOPPED_BEFORE_RUN: &str = "component was stopped before its run began";
/// A v2 start that a stop interrupted before the guest was published.
pub const STOPPED_DURING_START: &str = "v2 guest was stopped before it was published";
/// A v2 start task that ended without answering. No stop was requested.
const START_TASK_ENDED: &str = "v2 guest start task ended without answering";
const BOOK_CLOSED: &str = "the grant book is closed";

struct ComponentState {
    /// A sealed activation's call to the bridge is refused here, before any
    /// handler is looked at.
    sealed: bool,
    hostcall: Option<BridgeHostcall>,
    capsule_id: String,
    principal_id: Option<String>,
    limits: StoreLimits,
    fuel: u64,
    run_deadline: Duration,
    run_started: Instant,
    in_bus: Duration,
    /// Shared with the activation entry; `stop` sets it and the epoch
    /// callback traps the guest as `stopped`.
    stop_requested: Arc<AtomicBool>,
    /// Set by the epoch callback when it interrupts *because* of a stop
    /// request, so a trap is named `stopped` only when the stop caused it.
    ended_by_stop: bool,
    /// The v2 activation's cancel flag. v1 leaves this unset.
    cancel_requested: Arc<AtomicBool>,
    /// Wakes a v2 clock sleep. v1 does not wait on it.
    wake: Arc<tokio::sync::Notify>,
    /// Set while a v2 clock sleep is waiting.
    #[cfg(test)]
    in_clock_sleep: Arc<AtomicBool>,
    /// The v2 token bucket. v1 has none.
    fuel_bucket: Option<Arc<Mutex<crate::providers::fuel_bucket::FuelBucket>>>,
    /// v2's own limiter. v1 keeps [`ComponentState::limits`].
    guest_memory: super::fuel_bucket::GuestMemory,
    grants: Arc<Mutex<crate::providers::bus2_ui::GrantBook>>,
    /// The one presented frame, keyed by capsule id, with the principal who
    /// presented it. A second present replaces it.
    frames: Arc<Mutex<HashMap<String, StoredFrame>>>,
    /// This guest's provider budget. Guests of one provider share it.
    reads: Arc<super::bus2_stream::ReadBudget>,
    /// v2 bridge. Awaited on the guest runtime. v1 leaves this empty.
    async_hostcall: Option<BridgeHostcallAsync>,
    /// Present pauses here while it still holds the book lock.
    #[cfg(test)]
    present_gate: Option<Arc<TestGate>>,
    /// See [`ComponentActivation::host_deadline_tail_ms`].
    #[cfg(test)]
    host_deadline_tail_ms: Arc<std::sync::atomic::AtomicU64>,
}

/// The host's copy of one presented frame. The principal is the caller the
/// shell read must match.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredFrame {
    principal: Option<String>,
    frame: crate::providers::bus2_ui::Frame,
}

/// Component compute provider.
///
/// This runner exposes no WASI, environment, filesystem preopen, FIFO, raw
/// socket, or gateway authority. Every guest effect goes through the Bus
/// hostcall configured by Runtime.
pub struct ComponentProvider {
    instances: Arc<RwLock<HashMap<CapsuleId, ComponentActivation>>>,
    #[cfg(test)]
    endings: Arc<RwLock<HashMap<CapsuleId, String>>>,
    bus_hostcall: std::sync::RwLock<Option<BridgeHostcall>>,
    bus_hostcall_async: std::sync::RwLock<Option<BridgeHostcallAsync>>,
    /// Revoke-all pauses here before it sweeps live guests.
    #[cfg(test)]
    revoke_gate: Mutex<Option<Arc<TestGate>>>,
    bridge_principals: Arc<RwLock<HashMap<CapsuleId, Option<String>>>>,
    frames: Arc<Mutex<HashMap<String, StoredFrame>>>,
    /// Test only: a frame read waits this long instead of the route deadline.
    #[cfg(test)]
    frame_read_bound: Mutex<Option<Duration>>,
    read_budget: Arc<super::bus2_stream::ReadBudget>,
    compile_slot: Arc<Semaphore>,
    /// Test only: holds the next compile job just after its worker has taken
    /// the compile slot, so a test can act while a compile is in progress.
    #[cfg(test)]
    worker_gate: std::sync::Mutex<Option<tests::WorkerGate>>,
    /// The next v2 start task panics. Tests and the server's fixture feature set it.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub panic_next_v2: AtomicBool,
    /// v2 guest threads that have entered their run and not left it.
    #[cfg(test)]
    threads_live: Arc<AtomicUsize>,
}

#[cfg(any(test, feature = "test-fixtures"))]
pub struct TestingOpenRead {
    window: crate::providers::bus2_stream::WindowRead,
    trailer: tokio::sync::oneshot::Receiver<std::result::Result<(), String>>,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl TestingOpenRead {
    pub fn pull(&mut self, n: usize) -> Option<Vec<u8>> {
        self.window.pull(n)
    }

    pub fn trailer(&mut self) -> Option<std::result::Result<(), String>> {
        self.trailer.try_recv().ok()
    }
}

impl ComponentProvider {
    pub fn new() -> Self {
        Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(test)]
            endings: Arc::new(RwLock::new(HashMap::new())),
            bus_hostcall: std::sync::RwLock::new(None),
            bus_hostcall_async: std::sync::RwLock::new(None),
            #[cfg(test)]
            revoke_gate: Mutex::new(None),
            bridge_principals: Arc::new(RwLock::new(HashMap::new())),
            frames: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            frame_read_bound: Mutex::new(None),
            read_budget: super::bus2_stream::ReadBudget::new(),
            // One compile at a time: a burst of loads queues instead of
            // starting competing compiler jobs.
            compile_slot: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            worker_gate: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            panic_next_v2: AtomicBool::new(false),
            #[cfg(test)]
            threads_live: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn set_bus_hostcall(&self, hostcall: BridgeHostcall) {
        *self.bus_hostcall.write().unwrap() = Some(hostcall);
    }

    /// v2 awaits this future on the guest runtime. No thread is started for the call.
    pub fn set_bus_hostcall_async(&self, hostcall: BridgeHostcallAsync) {
        *self.bus_hostcall_async.write().unwrap() = Some(hostcall);
    }

    #[cfg(feature = "test-fixtures")]
    pub async fn testing_hold_publish(
        &self,
        id: &elastos_common::CapsuleId,
    ) -> Arc<(tokio::sync::Notify, tokio::sync::Notify)> {
        let hold = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        if let Some(instance) = self.instances.write().await.get_mut(id) {
            instance.publish_hold = Some(hold.clone());
        }
        hold
    }

    /// Records `grant` on a loaded guest. A test uses this before the guest runs.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn testing_hold_grant(
        &self,
        id: &CapsuleId,
        grant: &str,
        resource: &str,
        action: &str,
    ) {
        if let Some(instance) = self.instances.read().await.get(id) {
            instance
                .grants
                .lock()
                .expect("grant book")
                .hold(grant, resource, action);
        }
    }

    /// True when a live guest for `id` still holds `grant` unexpired in its
    /// GrantBook. A spent once grant still counts while the book holds it.
    pub async fn guest_holds_grant(&self, id: &CapsuleId, grant: &str) -> bool {
        let book = {
            let instances = self.instances.read().await;
            instances.get(id).map(|instance| instance.grants.clone())
        };
        let Some(book) = book else {
            return false;
        };
        let held = book.lock().expect("grant book").holds_unexpired(grant);
        held
    }

    /// Revokes every grant on every live v2 guest and drops that guest's frame.
    /// Lock order is the book, then the frames. A grant recorded before this
    /// sweep, including one recorded while the sweep waited, is included.
    pub async fn deliver_revoke_all(&self) {
        #[cfg(test)]
        if let Some(gate) = self.revoke_gate.lock().expect("revoke gate").clone() {
            gate.wait();
        }
        let guests: Vec<(String, Arc<Mutex<crate::providers::bus2_ui::GrantBook>>)> = {
            let instances = self.instances.read().await;
            instances
                .iter()
                .filter(|(_, instance)| {
                    instance.manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT)
                })
                .map(|(id, instance)| (id.0.clone(), instance.grants.clone()))
                .collect()
        };
        for (id, book) in guests {
            let mut book = book.lock().expect("grant book");
            book.revoke_all_held();
            self.frames.lock().expect("frames").remove(&id);
        }
    }

    /// The frame for `id` when `caller` presented it and the guest's book
    /// still allows it. The wait is [`V2_FRAME_ROUTE_DEADLINE`], the frame
    /// route's own deadline. On that deadline the answer is empty, never the
    /// stored frame. A closed book answers nothing, text included. A frame
    /// stored with no guest is not returned: the route calls this, and only
    /// a live guest has a book to check.
    pub async fn read_v2_frame(
        &self,
        caller: Option<&str>,
        id: &str,
    ) -> Option<crate::providers::bus2_ui::Frame> {
        let bound = {
            #[cfg(test)]
            {
                self.frame_read_bound
                    .lock()
                    .expect("frame bound")
                    .unwrap_or(V2_FRAME_ROUTE_DEADLINE)
            }
            #[cfg(not(test))]
            {
                V2_FRAME_ROUTE_DEADLINE
            }
        };
        let book = tokio::time::timeout(bound, self.instances.read())
            .await
            .ok()
            .and_then(|instances| {
                instances
                    .get(&elastos_common::CapsuleId::new(id))
                    .map(|instance| instance.grants.clone())
            })?;
        // Book, then frames: the same order as stop, forget, and the exit task.
        let book = book.lock().expect("grant book");
        if book.closed {
            return None;
        }
        let stored = {
            let frames = self.frames.lock().expect("frames");
            let stored = frames.get(id)?;
            if stored.principal.as_deref() != caller {
                return None;
            }
            stored.frame.clone()
        };
        Some(crate::providers::bus2_ui::Frame {
            nodes: stored
                .nodes
                .into_iter()
                .filter(|node| match node {
                    crate::providers::bus2_ui::FrameNode::Text(_) => true,
                    crate::providers::bus2_ui::FrameNode::Image { grant, .. } => {
                        // Authorised at present. Spending the last use on that
                        // present leaves the node. Revoke, eviction, expiry,
                        // and a closed book remove it.
                        !book.blocks_presented_image(grant)
                    }
                })
                .collect(),
        })
    }

    /// Stores one frame so a same-process test can read it back through a
    /// live guest. A guest present is the production writer. This store does
    /// not answer a read: [`Self::read_v2_frame`] requires that guest's book.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn testing_store_v2_frame(
        &self,
        id: &str,
        principal: Option<&str>,
        nodes: Vec<crate::providers::bus2_ui::FrameNode>,
    ) {
        self.frames.lock().expect("frames").insert(
            id.to_string(),
            StoredFrame {
                principal: principal.map(str::to_string),
                frame: crate::providers::bus2_ui::Frame { nodes },
            },
        );
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn testing_open_read(
        &self,
        id: &CapsuleId,
        grant: &str,
        bytes: &[u8],
    ) -> Option<TestingOpenRead> {
        let instances = self.instances.read().await;
        let instance = instances.get(id)?;
        let stop = instance.stop_requested.clone();
        let cancel = instance.cancel_requested.clone();
        let grants = instance.grants.clone();
        drop(instances);
        use crate::providers::bus2_stream::{ReadHold, WindowRead};
        let hold = ReadHold::try_reserve(&self.read_budget, bytes.len())?;
        let (tx, trailer) = tokio::sync::oneshot::channel();
        let grant = grant.to_string();
        let end = Arc::new(move || v2_read_stopped(&stop, &cancel, &grants, &grant));
        let window = WindowRead::new(bytes.to_vec(), tx, hold).stop_when(end);
        Some(TestingOpenRead { window, trailer })
    }

    /// Revokes `grant` in the guest's book and drops a frame that names it,
    /// then tells the guest. The book changes here, not when the guest polls.
    /// Lock order is the book, then the frames.
    pub async fn deliver_grant_revoked(&self, id: &CapsuleId, grant: &str) -> Result<()> {
        let found = {
            let instances = self.instances.read().await;
            instances
                .get(id)
                .map(|instance| (instance.grants.clone(), instance.events.clone()))
        };
        let Some((book, sender)) = found else {
            // A stored frame can outlive the guest. Drop it even when the
            // book is already gone. There is no book to lock.
            drop_frame_naming(&self.frames, &id.0, grant);
            tracing::warn!(capsule_id = %id, "grant revoke delivery had no guest");
            return Err(ElastosError::CapsuleNotFound(id.0.clone()));
        };
        {
            let mut book = book.lock().expect("grant book");
            book.revoke(grant);
            drop_frame_naming(&self.frames, &id.0, grant);
        }
        let Some(sender) = sender else {
            tracing::warn!(capsule_id = %id, "grant revoke delivery had no event stream");
            return Ok(());
        };
        if let Err(error) = sender.send(v2::elastos::bus::types::Event::GrantRevoked(
            grant.to_string(),
        )) {
            tracing::warn!(%error, capsule_id = %id, "grant revoke delivery");
            return Err(ElastosError::Compute(
                "the guest is not reading events".into(),
            ));
        }
        Ok(())
    }

    /// The hostcall a dependent's tests call. This crate's tests compile it,
    /// and so does `test-hooks`, which only a dev-dependency enables.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn call_bus_hostcall_for_test(
        &self,
        line: &str,
        capsule_id: &str,
        principal_id: Option<&str>,
    ) -> std::result::Result<String, String> {
        let hostcall = self
            .bus_hostcall
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
            .ok_or_else(|| "component bridge is not configured".to_string())?;
        hostcall(line, capsule_id, principal_id)
    }

    pub async fn set_bridge_principal(&self, capsule_id: &CapsuleId, principal_id: Option<String>) {
        self.bridge_principals
            .write()
            .await
            .insert(capsule_id.clone(), principal_id);
    }

    pub async fn clear_bridge_principal(&self, capsule_id: &CapsuleId) {
        self.bridge_principals.write().await.remove(capsule_id);
    }

    /// The principal this capsule's activation runs for, if one is bound:
    /// `Some(None)` is an activation bound to no principal, `None` that the
    /// provider holds no binding for it. The Runtime's one end takes it away
    /// with the activation entry ([`Self::forget_instance`]).
    pub async fn bridge_principal(&self, capsule_id: &CapsuleId) -> Option<Option<String>> {
        self.bridge_principals.read().await.get(capsule_id).cloned()
    }

    /// Takes this capsule's activation entry away, with the principal it ran
    /// for. The Runtime's one end path calls this, so a stopped, cancelled or
    /// failed activation leaves nothing the provider could still run, ask
    /// with, or hand a late call. A worker that still runs keeps the engine
    /// and component it took out of the entry; its own removal then finds no
    /// entry to take.
    pub async fn forget_instance(&self, capsule_id: &CapsuleId) {
        let join = {
            let mut instances = self.instances.write().await;
            let Some(instance) = instances.get_mut(capsule_id) else {
                drop(instances);
                self.frames.lock().expect("frames").remove(&capsule_id.0);
                self.clear_bridge_principal(capsule_id).await;
                return;
            };
            raise_flag(&instance.stop_requested, &instance.wake);
            instance.grants.lock().expect("grant book").clear();
            self.frames.lock().expect("frames").remove(&capsule_id.0);
            drop(instance.events.take());
            let join = begin_v2_join(instance);
            if join.is_none() {
                instances.remove(capsule_id);
            }
            join
        };
        self.clear_bridge_principal(capsule_id).await;
        let Some(join) = join else {
            self.frames.lock().expect("frames").remove(&capsule_id.0);
            return;
        };
        let id = capsule_id.clone();
        let bound = self
            .instances
            .read()
            .await
            .get(&id)
            .map(|instance| instance.join_bound)
            .unwrap_or(V2_HOST_DEADLINE);
        if wait_v2_join(join, bound).await {
            self.instances.write().await.remove(&id);
            self.frames.lock().expect("frames").remove(&id.0);
        } else {
            tracing::error!(capsule_id = %id, "forget left a guest thread running");
        }
    }

    /// A long fuel budget, and when `v2` the stop path that removes a running
    /// v2 entry. Server tests reach this through the `test-hooks` feature.
    #[cfg(any(test, feature = "test-hooks"))]
    pub async fn prepare_stop_target_for_test(&self, id: &CapsuleId, v2: bool) -> bool {
        let mut instances = self.instances.write().await;
        let Some(entry) = instances.get_mut(id) else {
            return false;
        };
        entry.fuel = u64::MAX;
        entry.run_deadline = Duration::from_secs(30);
        if v2 {
            entry.status = CapsuleStatus::Running;
            entry.manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        }
        true
    }

    /// The one engine every v1 component in this process compiles and runs on.
    /// The v1 ABI uses none of these proposals, so they are off here as well as
    /// compiled out of the build (`threads`, `gc`, `stack-switching` in Cargo.toml).
    fn engine() -> Result<Engine> {
        static ENGINE: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();
        ENGINE
            .get_or_init(|| {
                let mut config = Config::new();
                config.wasm_component_model(true);
                // The Cargo feature makes async the Wasmtime default; v1 opts out.
                config.wasm_component_model_async(false);
                config.concurrency_support(false);
                config.consume_fuel(true);
                config.epoch_interruption(true);
                config.wasm_features(
                    WasmFeatures::THREADS
                        | WasmFeatures::SHARED_EVERYTHING_THREADS
                        | WasmFeatures::GC
                        | WasmFeatures::STACK_SWITCHING,
                    false,
                );
                // Wasmtime's macOS Mach handler thread aborts the process on an
                // interrupted receive; the Unix signal handler traps on the
                // faulting thread instead. Signals-based traps stay on.
                config.macos_use_mach_ports(false);
                let engine = Engine::new(&config).map_err(|err| err.to_string())?;
                // The one ticker. A store with no deadline set traps at once,
                // so a run can never be left without one.
                let ticker = engine.clone();
                std::thread::Builder::new()
                    .name("component-deadline-tick".into())
                    .spawn(move || loop {
                        std::thread::sleep(DEADLINE_TICK);
                        ticker.increment_epoch();
                    })
                    .map_err(|err| format!("deadline ticker: {err}"))?;
                Ok(engine)
            })
            .clone()
            .map_err(|err| {
                ElastosError::Compute(format!("Failed to configure component engine: {err}"))
            })
    }

    /// Bus v2 has its own engine so its async ABI cannot change v1 admission.
    pub(crate) fn v2_engine() -> Result<Engine> {
        static ENGINE: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();
        ENGINE
            .get_or_init(|| {
                let mut config = Self::v2_config();
                // The same signal-trap choice as v1: the two engines are in one
                // process and wasmtime's global trap handler must agree.
                config.macos_use_mach_ports(false);
                let engine = Engine::new(&config).map_err(|err| err.to_string())?;
                let ticker = engine.clone();
                std::thread::Builder::new()
                    .name("component-v2-deadline-tick".into())
                    .spawn(move || loop {
                        std::thread::sleep(DEADLINE_TICK);
                        ticker.increment_epoch();
                    })
                    .map_err(|err| format!("v2 deadline ticker: {err}"))?;
                Ok(engine)
            })
            .clone()
            .map_err(|err| {
                ElastosError::Compute(format!("Failed to configure v2 component engine: {err}"))
            })
    }

    fn v2_config() -> Config {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .wasm_component_model_async(true)
            .concurrency_support(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            // A guest's own calls stop at this stack and trap. The host
            // scanner does not borrow that stack. 512 KiB is Wasmtime's own
            // default, named here so a later config cannot leave it open.
            .max_wasm_stack(512 * 1024)
            .wasm_features(
                WasmFeatures::THREADS
                    | WasmFeatures::SHARED_EVERYTHING_THREADS
                    | WasmFeatures::GC
                    | WasmFeatures::STACK_SWITCHING,
                false,
            );
        config
    }

    /// Reads a component file once, and never more than one byte past the cap.
    pub async fn read_component(path: &Path) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        let file = tokio::fs::File::open(path).await?;
        file.take(COMPONENT_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > COMPONENT_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("component file is larger than the {COMPONENT_MAX_BYTES} byte limit"),
            ));
        }
        Ok(bytes)
    }

    /// Compiles the bytes the caller already checked. The Runtime passes the
    /// same buffer its signature and import checks read, so a file replaced
    /// after those checks cannot change what runs.
    pub async fn load_admitted(
        &self,
        bytes: Vec<u8>,
        manifest: CapsuleManifest,
    ) -> Result<CapsuleHandle> {
        self.load_checked(bytes, manifest, false).await
    }

    /// [`ComponentProvider::load_admitted`] for a capsule that is given no
    /// authority. The activation is sealed: when it runs, every call it makes
    /// to the bridge is refused by this provider, and no handler sees it,
    /// whichever handler is installed and whenever. The seal is a mark on
    /// this one activation's entry and on nothing else, so it can never seal
    /// another capsule. The entry is taken away when the run ends, by the
    /// worker that ran it; a cancelled v1 start leaves that worker running
    /// until its end. `stop` removes a loading entry or asks a running v1
    /// guest to end at its next epoch check. A resident v2 entry stays until
    /// its task ends or stop closes its events stream.
    pub async fn load_admitted_sealed(
        &self,
        bytes: Vec<u8>,
        manifest: CapsuleManifest,
    ) -> Result<CapsuleHandle> {
        self.load_checked(bytes, manifest, true).await
    }

    async fn load_checked(
        &self,
        bytes: Vec<u8>,
        manifest: CapsuleManifest,
        sealed: bool,
    ) -> Result<CapsuleHandle> {
        Self::require_component_manifest(&manifest)?;
        if bytes.len() > COMPONENT_MAX_BYTES {
            return Err(ElastosError::Compute(format!(
                "component is larger than the {COMPONENT_MAX_BYTES} byte limit"
            )));
        }
        // Compiling can take a long time, so it runs off the async workers and
        // one at a time. The wait for the slot is bounded. The compile job owns
        // its slot until it ends, also when its caller was cancelled.
        let compile_permit = tokio::time::timeout(
            COMPONENT_COMPILE_WAIT_TIMEOUT,
            self.compile_slot.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ElastosError::Compute("Timed out waiting for the component compiler".into()))?
        .map_err(|_| ElastosError::Compute("Component compiler is unavailable".into()))?;
        #[cfg(test)]
        let worker_gate = self.worker_gate.lock().unwrap().take();
        let is_v2 = manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT);
        let (engine, component) =
            tokio::task::spawn_blocking(move || -> Result<(Engine, Component)> {
                let _compile_permit = compile_permit;
                #[cfg(test)]
                if let Some(gate) = worker_gate {
                    gate.hold();
                }
                let engine = if is_v2 {
                    Self::v2_engine()?
                } else {
                    Self::engine()?
                };
                let component = Component::from_binary(&engine, &bytes).map_err(|err| {
                    ElastosError::Compute(format!("Failed to compile component capsule: {err}"))
                })?;
                Ok((engine, component))
            })
            .await
            .map_err(|err| {
                ElastosError::Compute(format!("Component load task join error: {err}"))
            })??;
        let id = CapsuleId::new(format!("component-{}", uuid::Uuid::new_v4()));

        self.instances.write().await.insert(
            id.clone(),
            ComponentActivation {
                engine,
                component,
                status: CapsuleStatus::Loading,
                manifest: manifest.clone(),
                sealed,
                stop_requested: Arc::new(AtomicBool::new(false)),
                fuel: COMPONENT_FUEL,
                v2_fuel: super::fuel_bucket::V2_BUCKET_CAPACITY,
                run_deadline: COMPONENT_RUN_DEADLINE,
                events: None,
                cancel_requested: Arc::new(AtomicBool::new(false)),
                task: None,
                worker: None,
                join: None,
                starting: false,
                join_bound: V2_HOST_DEADLINE,
                wake: Arc::new(tokio::sync::Notify::new()),
                #[cfg(test)]
                in_clock_sleep: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                refuse_join_owner: false,
                #[cfg(test)]
                publish_gate: None,
                #[cfg(feature = "test-fixtures")]
                publish_hold: None,
                #[cfg(test)]
                attach_gate: None,
                #[cfg(test)]
                exit_gate: None,
                #[cfg(test)]
                present_gate: None,
                #[cfg(test)]
                test_max_ticks: V2_TEST_EPOCH_TICKS,
                #[cfg(test)]
                pending_read: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                test_wall_clock: false,
                #[cfg(test)]
                host_deadline_tail_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                grants: Arc::new(Mutex::new(crate::providers::bus2_ui::GrantBook::default())),
            },
        );

        Ok(CapsuleHandle {
            id,
            manifest,
            args: Vec::new(),
        })
    }

    /// A v2 guest on its own thread. The call returns when the guest is ready.
    /// The thread publishes the ending, and this task turns that ending into
    /// the activation's outcome.
    async fn start_v2_resident(&self, handle: &CapsuleHandle) -> Result<ResidentActivation> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let hostcall = self.bus_hostcall.read().unwrap().clone();
        let principal_id = self
            .bridge_principals
            .read()
            .await
            .get(&handle.id)
            .cloned()
            .flatten();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let (outcome_tx, outcome_rx) = tokio::sync::watch::channel(None);
        let instances = self.instances.clone();
        #[cfg(test)]
        let endings = self.endings.clone();
        let frames = self.frames.clone();
        let mut entries = self.instances.write().await;
        let running = entries.values().filter(|item| v2_slot(item)).count();
        if running >= V2_RESIDENT_CAP {
            return Err(ElastosError::Compute(format!(
                "v2 resident cap {V2_RESIDENT_CAP}"
            )));
        }
        let instance = entries
            .get_mut(&handle.id)
            .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?;
        if instance.status != CapsuleStatus::Loading || instance.starting || instance.join.is_some()
        {
            return Err(ElastosError::Compute(
                "v2 component is already running".into(),
            ));
        }
        let reads = self.read_budget.clone();
        let async_hostcall = self.bus_hostcall_async.read().unwrap().clone();
        #[cfg(test)]
        let publish_gate = instance.publish_gate.clone();
        #[cfg(feature = "test-fixtures")]
        let publish_hold = instance.publish_hold.take();
        #[cfg(test)]
        let exit_gate = instance.exit_gate.clone();
        let state = ComponentState {
            sealed: instance.sealed,
            grants: instance.grants.clone(),
            frames,
            reads,
            stop_requested: instance.stop_requested.clone(),
            cancel_requested: instance.cancel_requested.clone(),
            wake: instance.wake.clone(),
            async_hostcall,
            #[cfg(test)]
            in_clock_sleep: instance.in_clock_sleep.clone(),
            #[cfg(test)]
            present_gate: instance.present_gate.clone(),
            #[cfg(test)]
            host_deadline_tail_ms: instance.host_deadline_tail_ms.clone(),
            ..ComponentState::new(hostcall, handle.id.0.clone(), principal_id)
        };
        let (engine, component) = (instance.engine.clone(), instance.component.clone());
        let control = V2RunControl {
            stop_requested: instance.stop_requested.clone(),
            cancel_requested: instance.cancel_requested.clone(),
            #[cfg(test)]
            max_ticks: instance.test_max_ticks,
            #[cfg(not(test))]
            max_ticks: V2_EPOCH_TICKS,
            fuel: instance.v2_fuel,
            fuel_slice: V2_FUEL_SLICE,
            #[cfg(test)]
            pending_read: instance.pending_read.clone(),
            #[cfg(test)]
            wall_clock: instance.test_wall_clock,
        };
        let ending_cancel = control.cancel_requested.clone();
        #[cfg(any(test, feature = "test-fixtures"))]
        let panic_now = self.panic_next_v2.swap(false, Ordering::AcqRel);
        #[cfg(not(any(test, feature = "test-fixtures")))]
        let panic_now = false;
        let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
        #[cfg(test)]
        let threads_live = self.threads_live.clone();
        let spawned_worker = std::thread::Builder::new()
            .name("component-v2".into())
            .spawn(move || {
                #[cfg(test)]
                struct LiveGuard(Arc<AtomicUsize>);
                #[cfg(test)]
                impl Drop for LiveGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(err) => {
                        let _ = ready_tx.send(Err(ElastosError::Compute(format!(
                            "v2 guest runtime: {err}"
                        ))));
                        return;
                    }
                };
                #[cfg(test)]
                threads_live.fetch_add(1, Ordering::AcqRel);
                #[cfg(test)]
                let _live = LiveGuard(threads_live);
                let task = rt.spawn(async move {
                    #[cfg(any(test, feature = "test-fixtures"))]
                    if panic_now {
                        panic!("injected v2 task panic");
                    }
                    #[cfg(not(any(test, feature = "test-fixtures")))]
                    let _ = panic_now;
                    Self::run_v2(engine, component, state, receiver, control, ready_tx).await
                });
                let _ = abort_tx.send(task.abort_handle());
                let ending = match rt.block_on(task) {
                    Ok(Ok(ending)) => ending.to_string(),
                    Ok(Err(_)) if ending_cancel.load(Ordering::Acquire) => "cancelled".to_string(),
                    Ok(Err(error)) => error.to_string(),
                    Err(error) if error.is_cancelled() => "cancelled".to_string(),
                    Err(error) => format!("panicked: {error}"),
                };
                let _ = done_tx.send(ending);
                // The natural-exit task joins this thread before it frees the slot.
                #[cfg(test)]
                if let Some(gate) = exit_gate {
                    gate.wait();
                }
            });
        let worker = match spawned_worker {
            Ok(worker) => worker,
            Err(err) => {
                drop(entries);
                if let Some(instance) = self.instances.write().await.remove(&handle.id) {
                    instance.grants.lock().expect("grant book").clear();
                }
                self.frames.lock().expect("frames").remove(&handle.id.0);
                return Err(ElastosError::Compute(format!("v2 guest thread: {err}")));
            }
        };
        // The join owns the worker before this lock is dropped. A second start
        // sees `starting`, and a stop in the gap joins this thread.
        let join = {
            let instance = entries.get_mut(&handle.id).expect("entry");
            #[cfg(test)]
            let refuse_spawn = instance.refuse_join_owner;
            #[cfg(test)]
            let attach_gate = instance.attach_gate.clone();
            let join = V2Join::prepare(
                None,
                Some(worker),
                instance.cancel_requested.clone(),
                instance.wake.clone(),
                #[cfg(test)]
                refuse_spawn,
                #[cfg(test)]
                attach_gate,
            );
            instance.join = Some(join.clone());
            instance.starting = true;
            join
        };
        drop(entries);
        let abort = match abort_rx.await {
            Ok(abort) => abort,
            Err(_) => {
                join.start();
                let join_for_wait = join.clone();
                let _ = tokio::task::spawn_blocking(move || join_for_wait.wait_finished()).await;
                drop(join);
                self.instances.write().await.remove(&handle.id);
                return Err(ElastosError::Compute(
                    "v2 guest thread ended before it started".into(),
                ));
            }
        };
        join.attach_task(abort.clone());
        #[cfg(test)]
        if let Some(gate) = publish_gate {
            gate.wait();
        }
        #[cfg(feature = "test-fixtures")]
        if let Some(hold) = publish_hold {
            hold.0.notify_one();
            hold.1.notified().await;
        }
        {
            let mut entries = self.instances.write().await;
            let Some(instance) = entries.get_mut(&handle.id) else {
                drop(entries);
                join.abort_task(&abort);
                drop(sender);
                return Err(ElastosError::Compute(STOPPED_DURING_START.into()));
            };
            if instance
                .join
                .as_ref()
                .is_some_and(|held| held.was_started())
            {
                drop(entries);
                join.abort_task(&abort);
                drop(sender);
                return Err(ElastosError::Compute(STOPPED_DURING_START.into()));
            }
            instance.task = Some(abort);
            instance.starting = false;
            instance.status = CapsuleStatus::Running;
            instance.events = Some(sender);
        }

        let id_for_end = handle.id.clone();
        let frames_for_end = self.frames.clone();
        tokio::spawn(async move {
            let ending = done_rx
                .await
                .unwrap_or_else(|_| "v2 guest thread ended".to_string());
            tracing::info!(capsule_id = %id_for_end, %ending, "component v2 run ended");
            let outcome = match ending.as_str() {
                "returned" => ActivationOutcome::Returned,
                "stopped" | "cancelled" => ActivationOutcome::Stopped,
                _ => ActivationOutcome::Trapped(ending.clone()),
            };
            let _ = outcome_tx.send(Some(outcome));
            // Publish the join under the same lock that takes the worker.
            // A stop that arrives here waits on that join, so the slot stays
            // until the worker has been joined.
            let (join, exit_owns_slot) = {
                let mut held = instances.write().await;
                match held.get_mut(&id_for_end) {
                    Some(instance)
                        if instance
                            .join
                            .as_ref()
                            .is_none_or(|join| !join.was_started()) =>
                    {
                        // The book and the frame go before the join wait, so a
                        // read during that wait does not answer the old frame.
                        instance.grants.lock().expect("grant book").clear();
                        frames_for_end.lock().expect("frames").remove(&id_for_end.0);
                        (begin_v2_join(instance), true)
                    }
                    _ => (None, false),
                }
            };
            if let Some(join) = join {
                let _ = tokio::task::spawn_blocking(move || join.wait_finished()).await;
            }
            if exit_owns_slot {
                instances.write().await.remove(&id_for_end);
            }
            #[cfg(test)]
            endings.write().await.insert(id_for_end, ending);
        });
        match ready_rx.await {
            Ok(result) => result?,
            Err(_) => {
                let stopped = self
                    .instances
                    .read()
                    .await
                    .get(&handle.id)
                    .is_some_and(|instance| instance.stop_requested.load(Ordering::Acquire));
                let message = if stopped {
                    STOPPED_DURING_START
                } else {
                    START_TASK_ENDED
                };
                return Err(ElastosError::Compute(message.into()));
            }
        }
        Ok(ResidentActivation {
            handle: handle.clone(),
            outcome: outcome_rx,
        })
    }

    /// Drops entries whose worker has joined after a stop window timed out.
    /// Each entry's frame goes with it. A guest that is still stopping stays
    /// and keeps its slot.
    pub async fn reap_joined_residents(&self) {
        let finished: Vec<CapsuleId> = {
            let instances = self.instances.read().await;
            instances
                .iter()
                .filter(|(_, instance)| instance.join.as_ref().is_some_and(|join| join.finished()))
                .map(|(id, _)| id.clone())
                .collect()
        };
        if finished.is_empty() {
            return;
        }
        let mut removed = Vec::new();
        {
            let mut instances = self.instances.write().await;
            for id in finished {
                let done = instances
                    .get(&id)
                    .and_then(|instance| instance.join.as_ref())
                    .is_some_and(|join| join.finished());
                if !done {
                    continue;
                }
                if let Some(instance) = instances.remove(&id) {
                    instance.grants.lock().expect("grant book").clear();
                    removed.push(id);
                }
            }
        }
        let mut frames = self.frames.lock().expect("frames");
        for id in removed {
            frames.remove(&id.0);
        }
    }

    /// Starts a loaded activation and returns once the guest is ready. A v1
    /// guest runs on a blocking thread. A v2 guest runs on its own thread, so
    /// a request worker is not the one inside the guest. Dropping the handle
    /// does not end the guest. The worker publishes the outcome and removes
    /// the activation entry when the run ends.
    pub async fn start_resident(&self, handle: &CapsuleHandle) -> Result<ResidentActivation> {
        self.reap_joined_residents().await;
        let is_v2 = self
            .instances
            .read()
            .await
            .get(&handle.id)
            .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?
            .manifest
            .bus_contract
            .as_deref()
            == Some(ELASTOS_BUS_V2_CONTRACT);
        if is_v2 {
            return self.start_v2_resident(handle).await;
        }
        let hostcall = self.bus_hostcall.read().unwrap().clone();
        let principal_id = self
            .bridge_principals
            .read()
            .await
            .get(&handle.id)
            .cloned()
            .flatten();
        let (engine, component, sealed, stop_requested, fuel, run_deadline) = {
            let mut instances = self.instances.write().await;
            let instance = instances
                .get_mut(&handle.id)
                .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?;
            if instance.status != CapsuleStatus::Loading {
                return Err(ElastosError::Compute(format!(
                    "component {} is already running",
                    handle.id.0
                )));
            }
            instance.status = CapsuleStatus::Running;
            (
                instance.engine.clone(),
                instance.component.clone(),
                instance.sealed,
                instance.stop_requested.clone(),
                instance.fuel,
                instance.run_deadline,
            )
        };

        let reads = self.read_budget.clone();
        let state = ComponentState {
            sealed,
            fuel,
            run_deadline,
            stop_requested,
            reads,
            ..ComponentState::new(hostcall, handle.id.0.clone(), principal_id)
        };

        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (outcome_tx, outcome_rx) = tokio::sync::watch::channel(None);
        let id = handle.id.clone();
        let instances = self.instances.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Keep the entry until the run ends, then take it away before the
            // outcome is visible, so an observer of the outcome never sees a
            // running entry.
            let entry = ActivationEntryGuard { instances, id };
            let outcome =
                match Self::instantiate_component(&engine, &component, state, Some(started)) {
                    Ok(()) => ActivationOutcome::Returned,
                    Err(outcome) => outcome,
                };
            drop(entry);
            let _ = outcome_tx.send(Some(outcome));
        });

        match started_rx.await {
            Ok(()) => Ok(ResidentActivation {
                handle: handle.clone(),
                outcome: outcome_rx,
            }),
            Err(_) => {
                // The worker ended before entering `run`: an instantiation
                // error, an early trap, or a panic.
                let joined = task.await;
                let outcome = outcome_rx.borrow().clone();
                match joined {
                    Err(err) => Err(ElastosError::Compute(format!(
                        "Component task join error: {err}"
                    ))),
                    Ok(()) => match outcome {
                        Some(ActivationOutcome::Trapped(message)) => {
                            Err(ElastosError::Compute(message))
                        }
                        Some(ActivationOutcome::Stopped) => {
                            Err(ElastosError::Compute(STOPPED_BEFORE_RUN.into()))
                        }
                        _ => Err(ElastosError::Compute(
                            "component run ended before the guest started".into(),
                        )),
                    },
                }
            }
        }
    }

    fn require_component_manifest(manifest: &CapsuleManifest) -> Result<()> {
        if manifest.validate().is_err() || !Self::is_component_manifest(manifest) {
            return Err(ElastosError::Compute(
                "ComponentProvider only accepts elastos.component/v1 manifests".into(),
            ));
        }
        Ok(())
    }

    fn store_limits() -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(COMPONENT_MEMORY_SIZE)
            .instances(16)
            .tables(32)
            .memories(4)
            .trap_on_grow_failure(true)
            .build()
    }

    fn is_component_manifest(manifest: &CapsuleManifest) -> bool {
        manifest.runtime_abi.as_ref() == Some(&CapsuleRuntimeAbi::ElastosComponentV1)
    }

    fn instantiate_component(
        engine: &Engine,
        component: &Component,
        mut state: ComponentState,
        started: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> std::result::Result<(), ActivationOutcome> {
        // The deadline is armed before instantiation: a start function is guest code.
        state.run_started = Instant::now();
        // One tick at a time: the callback is the only place a stop request is
        // seen, so it must run every tick rather than only at the deadline.
        let mut store = Store::new(engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|mut context| Ok(context.data_mut().deadline_update()));
        store.set_fuel(store.data().fuel).map_err(|err| {
            ActivationOutcome::Trapped(format!("Failed to set component fuel: {err}"))
        })?;

        let mut linker = Linker::new(engine);
        ProductCapsuleV1::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).map_err(
            |err| ActivationOutcome::Trapped(format!("Failed to link bus imports: {err}")),
        )?;
        let bindings =
            ProductCapsuleV1::instantiate(&mut store, component, &linker).map_err(|err| {
                let stopped = store.data().ended_by_stop;
                if stopped && matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
                    ActivationOutcome::Stopped
                } else {
                    ActivationOutcome::Trapped(run_ending(
                        "Failed to instantiate component capsule",
                        err,
                        stopped,
                    ))
                }
            })?;
        if let Some(started) = started {
            let _ = started.send(());
        }
        bindings
            .elastos_bus_lifecycle()
            .call_run(&mut store)
            .map_err(|err| {
                let stopped = store.data().ended_by_stop;
                if stopped && matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
                    ActivationOutcome::Stopped
                } else {
                    ActivationOutcome::Trapped(run_ending(
                        "Component lifecycle run failed",
                        err,
                        stopped,
                    ))
                }
            })?
            .map_err(|err| {
                ActivationOutcome::Trapped(format!("Component capsule denied: {err:?}"))
            })?;

        Ok(())
    }

    async fn run_v2(
        engine: Engine,
        component: Component,
        mut state: ComponentState,
        receiver: mpsc::UnboundedReceiver<v2::elastos::bus::types::Event>,
        control: V2RunControl,
        ready: tokio::sync::oneshot::Sender<Result<()>>,
    ) -> Result<&'static str> {
        let fuel = crate::providers::fuel_bucket::FuelBucket::full(control.fuel, Instant::now());
        #[cfg(test)]
        let fuel = arm_test_wall(fuel, control.wall_clock);
        let bucket = Arc::new(Mutex::new(fuel));
        state.fuel_bucket = Some(bucket.clone());
        let grants = state.grants.clone();
        let frames = state.frames.clone();
        let capsule_id = state.capsule_id.clone();
        let mut store = Store::new(&engine, state);
        store.limiter(|state| &mut state.guest_memory);
        store
            .fuel_async_yield_interval(Some(control.fuel_slice))
            .map_err(|err| run_error("v2 fuel slice", err))?;
        store
            .set_fuel(control.fuel)
            .map_err(|err| run_error("v2 fuel", err))?;
        // Epochs are only the wall-clock backstop. A guest parked in a host
        // wait does not spend a tick. Fuel is the bucket, settled at waits.
        store.set_epoch_deadline(1);
        let cancel_requested = control.cancel_requested.clone();
        let max_ticks = control.max_ticks;
        store.epoch_deadline_callback(move |context| {
            if cancel_requested.load(Ordering::Acquire) {
                return Ok(UpdateDeadline::Interrupt);
            }
            let remaining = context.get_fuel().ok();
            let Some(bucket) = context.data().fuel_bucket.clone() else {
                return Ok(UpdateDeadline::Continue(1));
            };
            let mut bucket = bucket.lock().expect("fuel");
            if bucket.fault.is_some() {
                return Ok(UpdateDeadline::Interrupt);
            }
            // A parked guest does not spend a tick. An arm after a host wait
            // with no guest burn is host or scheduler time on a slow machine,
            // not guest running time: skip it. `wake_from_park` is the one
            // refill, and only while `parked` is still set.
            if bucket.parked {
                return Ok(UpdateDeadline::Continue(1));
            }
            if let Some(left) = remaining {
                if bucket.take_host_arm_if_unburned(left) {
                    return Ok(UpdateDeadline::Continue(1));
                }
            } else {
                bucket.host_arm = None;
            }
            bucket.parked = false;
            bucket.note_guest_ran();
            let used = bucket.window_ticks.saturating_add(1);
            bucket.window_ticks = used;
            if used >= max_ticks {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let mut linker = Linker::new(&engine);
        v2::ProductCapsuleV2::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|err| run_error("Failed to link v2 bus imports", err))?;
        let bindings =
            match v2::ProductCapsuleV2::instantiate_async(&mut store, &component, &linker).await {
                Ok(bindings) => bindings,
                Err(err) => {
                    let error = run_error("Failed to instantiate v2 component", err);
                    let _ = ready.send(Err(ElastosError::Compute(error.to_string())));
                    return Err(error);
                }
            };
        let events = StreamReader::new(
            &mut store,
            V2EventFeed(
                receiver,
                grants,
                frames,
                capsule_id,
                bucket,
                #[cfg(test)]
                control.pending_read.clone(),
            ),
        )
        .map_err(|err| run_error("Failed to open v2 events", err))?;
        let _ = ready.send(Ok(()));
        let ran = store
            .run_concurrent(async move |accessor| {
                bindings
                    .elastos_bus_lifecycle()
                    .call_run(accessor, events)
                    .await
            })
            .await;
        let fault = store
            .data()
            .fuel_bucket
            .as_ref()
            .and_then(|bucket| bucket.lock().expect("fuel").fault);
        ran.map_err(|err| {
            if let Some(name) = fault {
                return ElastosError::Compute(format!("V2 lifecycle run failed: (ending: {name})"));
            }
            if out_of_fuel(&err) {
                ElastosError::Compute(format!(
                    "V2 lifecycle run failed: (ending: {ENDING_EXECUTION_BOUND})"
                ))
            } else {
                run_error("V2 lifecycle run failed", err)
            }
        })?
        .map_err(|err| run_error("V2 lifecycle run failed", err))?
        .map_err(|err| ElastosError::Compute(format!("V2 lifecycle denied: {err:?}")))?;
        Ok(if control.stop_requested.load(Ordering::Acquire) {
            "stopped"
        } else {
            "returned"
        })
    }
}

struct V2EventFeed(
    mpsc::UnboundedReceiver<v2::elastos::bus::types::Event>,
    Arc<Mutex<crate::providers::bus2_ui::GrantBook>>,
    Arc<Mutex<HashMap<String, StoredFrame>>>,
    String,
    Arc<Mutex<crate::providers::fuel_bucket::FuelBucket>>,
    #[cfg(test)] Arc<AtomicBool>,
);

impl<D> StreamProducer<D> for V2EventFeed {
    type Item = v2::elastos::bus::types::Event;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        // One read per suspension. A spurious wake leaves the loan alone.
        // The wait itself ends when stop drops the sender, or when stop
        // aborts the task after [`V2_STOP_GRACE`].
        if let Err(name) = charge_bucket(&self.4, &mut store) {
            return Poll::Ready(Err(wasmtime::format_err!("{name}")));
        }
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                end_event_wait(&self.4);
                close_wait_loan(&self.4, &mut store);
                // Epochs that passed while the guest was parked are not ticks.
                store.set_epoch_deadline(1);
                note_delivered_event(&self.1, &self.2, &self.3, &event);
                destination.set_buffer(Some(event));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => {
                end_event_wait(&self.4);
                close_wait_loan(&self.4, &mut store);
                store.set_epoch_deadline(1);
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Poll::Pending if finish => {
                end_event_wait(&self.4);
                close_wait_loan(&self.4, &mut store);
                store.set_epoch_deadline(1);
                Poll::Ready(Ok(StreamResult::Cancelled))
            }
            Poll::Pending => {
                // Not parked yet. The guest may still be burning, and the
                // event that arrives then must not refill `window_ticks`.
                // A gap where the guest never runs is marked parked when it ends.
                self.4
                    .lock()
                    .expect("fuel")
                    .begin_event_wait(Instant::now());
                #[cfg(test)]
                self.5.store(true, Ordering::Release);
                Poll::Pending
            }
        }
    }
}

impl Drop for V2EventFeed {
    fn drop(&mut self) {
        self.4.lock().expect("fuel").resume();
    }
}

/// The message of a run that trapped: it leads with the cause Wasmtime gave
/// (the root of its error chain: the outer error alone only says "error while
/// executing"), names the ending of a run that a limit or a stop ended, and
/// keeps the outer text, the wasm backtrace, after it.
fn run_ending(stage: &str, err: wasmtime::Error, stopped: bool) -> String {
    let ending = match err.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) if stopped => format!(" (ending: {ENDING_STOPPED})"),
        Some(Trap::Interrupt) => format!(" (ending: {ENDING_EPOCH_DEADLINE})"),
        Some(Trap::OutOfFuel) => format!(" (ending: {ENDING_FUEL_EXHAUSTED})"),
        _ => String::new(),
    };
    let mut chain: Vec<String> = err.chain().map(|link| link.to_string()).collect();
    let cause = chain.pop().unwrap_or_default();
    let context: String = chain.iter().map(|outer| format!("\n{outer}")).collect();
    format!("{stage}: {cause}{ending}{context}")
}

fn run_error(stage: &str, err: wasmtime::Error) -> ElastosError {
    ElastosError::Compute(run_ending(stage, err, false))
}

fn out_of_fuel(err: &wasmtime::Error) -> bool {
    err.chain()
        .any(|link| matches!(link.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)))
}

struct JoinedTask {
    task: Option<tokio::task::AbortHandle>,
    aborted: bool,
}

/// One owner of a v2 worker. Later stops wait on this completion. The slot
/// stays until `wait` reports the worker has ended.
struct V2Join {
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    task: Mutex<JoinedTask>,
    cancel: Arc<AtomicBool>,
    done: Mutex<bool>,
    cv: Condvar,
    started: AtomicBool,
    /// The owner thread was spawned. False when the caller joins inline.
    spawned: AtomicBool,
    /// One caller runs `own`. A second caller waits until that one sets `done`.
    owning: AtomicBool,
    /// The owner thread was not spawned. `wait` joins on its caller.
    inline: AtomicBool,
    /// The guest's clock-sleep wake. Cancel notifies it.
    wake: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    refuse_spawn: AtomicBool,
    #[cfg(test)]
    attach_gate: Option<Arc<TestGate>>,
}

impl V2Join {
    fn prepare(
        task: Option<tokio::task::AbortHandle>,
        worker: Option<std::thread::JoinHandle<()>>,
        cancel: Arc<AtomicBool>,
        wake: Arc<tokio::sync::Notify>,
        #[cfg(test)] refuse_spawn: bool,
        #[cfg(test)] attach_gate: Option<Arc<TestGate>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            worker: Mutex::new(worker),
            task: Mutex::new(JoinedTask {
                task,
                aborted: false,
            }),
            cancel,
            done: Mutex::new(false),
            cv: Condvar::new(),
            started: AtomicBool::new(false),
            spawned: AtomicBool::new(false),
            owning: AtomicBool::new(false),
            inline: AtomicBool::new(false),
            wake,
            #[cfg(test)]
            refuse_spawn: AtomicBool::new(refuse_spawn),
            #[cfg(test)]
            attach_gate,
        })
    }

    /// Stop reads the flag after start has stored this join.
    #[cfg(test)]
    fn note_refuse(&self, refuse: bool) {
        self.refuse_spawn.store(refuse, Ordering::Release);
    }

    fn was_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    fn abort_task(&self, task: &tokio::task::AbortHandle) {
        raise_flag(&self.cancel, &self.wake);
        task.abort();
    }

    fn attach_task(&self, task: tokio::task::AbortHandle) {
        #[cfg(test)]
        if let Some(gate) = &self.attach_gate {
            gate.wait();
        }
        let mut slot = self.task.lock().expect("join");
        let late = slot.aborted;
        if !late {
            slot.task = Some(task.clone());
        }
        drop(slot);
        if late {
            self.abort_task(&task);
        }
    }

    #[cfg(test)]
    fn is_aborted(&self) -> bool {
        self.task.lock().expect("join").aborted
    }

    /// Starts the single owner thread. A second call does nothing. When the
    /// owner thread cannot be spawned, the caller of `wait` joins instead.
    fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        #[cfg(test)]
        let refuse = self.refuse_spawn.load(Ordering::Acquire);
        #[cfg(not(test))]
        let refuse = false;
        if refuse {
            tracing::error!("join-owner");
            self.inline.store(true, Ordering::Release);
            return;
        }
        let join = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("component-v2-join".into())
            .spawn(move || join.own());
        if spawned.is_ok() {
            self.spawned.store(true, Ordering::Release);
        } else {
            tracing::error!("join-owner");
            self.inline.store(true, Ordering::Release);
        }
    }

    fn own(&self) {
        if self.owning.swap(true, Ordering::AcqRel) {
            let guard = self.done.lock().expect("join");
            let _guard = self.cv.wait_while(guard, |done| !*done).expect("join");
            return;
        }
        std::thread::sleep(V2_STOP_GRACE);
        let mut slot = self.task.lock().expect("join");
        slot.aborted = true;
        let task = slot.task.take().filter(|task| !task.is_finished());
        drop(slot);
        if let Some(task) = task {
            self.abort_task(&task);
        }
        if let Some(worker) = self.worker.lock().expect("join").take() {
            let _ = worker.join();
        }
        *self.done.lock().expect("join") = true;
        self.cv.notify_all();
    }

    /// Wait until the worker has been joined. A natural exit uses this so a
    /// timeout cannot free the slot while the thread is still running.
    fn wait_finished(&self) {
        if self.inline.load(Ordering::Acquire) {
            self.own();
            return;
        }
        let guard = self.done.lock().expect("join");
        let _guard = self.cv.wait_while(guard, |done| !*done).expect("join");
    }

    fn wait(&self, bound: Duration) -> bool {
        if self.inline.load(Ordering::Acquire) {
            self.own();
            return self.finished();
        }
        let guard = self.done.lock().expect("join");
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, bound, |done| !*done)
            .expect("join");
        *guard
    }

    fn owns_thread(&self) -> bool {
        self.spawned.load(Ordering::Acquire)
    }

    /// The worker has been joined. A later stop does not need to wait again.
    fn finished(&self) -> bool {
        *self.done.lock().expect("join")
    }
}

/// Stores a stop or cancel flag and wakes one clock sleep.
fn raise_flag(flag: &AtomicBool, wake: &tokio::sync::Notify) {
    flag.store(true, Ordering::Release);
    wake.notify_one();
}

/// Moves this guest's worker into the one join, or returns the join a stop
/// already owns. `None` means there is no worker to join.
fn begin_v2_join(instance: &mut ComponentActivation) -> Option<Arc<V2Join>> {
    if let Some(join) = instance.join.clone() {
        instance.starting = false;
        #[cfg(test)]
        join.note_refuse(instance.refuse_join_owner);
        if !join.was_started() {
            instance.status = CapsuleStatus::Stopping;
            join.start();
        }
        return Some(join);
    }
    let task = instance.task.take();
    let worker = instance.worker.take();
    if task.is_none() && worker.is_none() {
        return None;
    }
    #[cfg(test)]
    let refuse_spawn = instance.refuse_join_owner;
    #[cfg(test)]
    let attach_gate = instance.attach_gate.clone();
    let wake = instance.wake.clone();
    let join = V2Join::prepare(
        task,
        worker,
        instance.cancel_requested.clone(),
        wake,
        #[cfg(test)]
        refuse_spawn,
        #[cfg(test)]
        attach_gate,
    );
    instance.join = Some(join.clone());
    instance.status = CapsuleStatus::Stopping;
    join.start();
    Some(join)
}

async fn wait_v2_join(join: Arc<V2Join>, bound: Duration) -> bool {
    tokio::task::spawn_blocking(move || join.wait(bound))
        .await
        .unwrap_or(false)
}

fn read_fuel(store: &impl wasmtime::AsContext) -> std::result::Result<u64, &'static str> {
    store.as_context().get_fuel().map_err(|_| "get_fuel")
}

fn write_fuel(
    store: &mut impl wasmtime::AsContextMut,
    fuel: u64,
) -> std::result::Result<(), &'static str> {
    store
        .as_context_mut()
        .set_fuel(fuel)
        .map_err(|_| "set_fuel")
}

/// Charges the loan once. A bucket that is already open is left unread.
/// A fuel error is named `get_fuel` or `set_fuel` and stored on the bucket.
fn charge_bucket(
    bucket: &Mutex<crate::providers::fuel_bucket::FuelBucket>,
    store: &mut impl wasmtime::AsContextMut,
) -> std::result::Result<bool, &'static str> {
    let mut slot = bucket.lock().expect("fuel");
    if let Some(name) = slot.fault {
        return Err(name);
    }
    if slot.open {
        return Ok(false);
    }
    let remaining = match read_fuel(store) {
        Ok(value) => value,
        Err(name) => {
            slot.fault = Some(name);
            return Err(name);
        }
    };
    let lend = slot.settle(remaining, Instant::now()).unwrap_or(0);
    drop(slot);
    if let Err(name) = write_fuel(store, lend) {
        bucket.lock().expect("fuel").fault = Some(name);
        return Err(name);
    }
    Ok(true)
}

/// Clears `open` if the host future is dropped. A drop is not a park.
struct ResumeOnDrop(Option<Arc<Mutex<crate::providers::fuel_bucket::FuelBucket>>>);

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        if let Some(bucket) = self.0.take() {
            let mut slot = bucket.lock().expect("fuel");
            slot.open = false;
            slot.clear_sleep_wait();
        }
    }
}

fn resume_guard(
    bucket: &Option<Arc<Mutex<crate::providers::fuel_bucket::FuelBucket>>>,
) -> ResumeOnDrop {
    ResumeOnDrop(bucket.clone())
}

/// The wait is over. Settle the loan from the moment it was opened, write
/// that fuel, and wake. A dropped guard still clears `open` without a store.
/// The event read ended. An idle gap becomes a parked wait so
/// [`FuelBucket::wake_from_park`] can refill the window. A burn does not.
fn end_event_wait(bucket: &Mutex<crate::providers::fuel_bucket::FuelBucket>) {
    bucket
        .lock()
        .expect("fuel")
        .end_event_wait(Instant::now(), DEADLINE_TICK);
}

fn close_wait_loan(
    bucket: &Mutex<crate::providers::fuel_bucket::FuelBucket>,
    store: &mut impl wasmtime::AsContextMut,
) {
    let lend = {
        let mut slot = bucket.lock().expect("fuel");
        let remaining = match read_fuel(store) {
            Ok(value) => value,
            Err(name) => {
                slot.fault = Some(name);
                return;
            }
        };
        if slot.open {
            slot.open = false;
        }
        let lend = slot.settle(remaining, Instant::now()).unwrap_or(0);
        slot.resume();
        lend
    };
    if let Err(name) = write_fuel(store, lend) {
        bucket.lock().expect("fuel").fault = Some(name);
    }
}

fn charge_access(access: &mut impl wasmtime::AsContextMut<Data = ComponentState>) -> bool {
    let Some(bucket) = access.as_context().data().fuel_bucket.clone() else {
        return false;
    };
    charge_bucket(&bucket, access).unwrap_or(false)
}

fn release_access(access: &mut impl wasmtime::AsContextMut<Data = ComponentState>) {
    if let Some(bucket) = access.as_context().data().fuel_bucket.clone() {
        close_wait_loan(&bucket, access);
        if let Ok(fuel) = read_fuel(access) {
            bucket.lock().expect("fuel").arm_after_host(fuel);
        }
    }
    // Host and scheduler time after this arm is not guest time: the epoch
    // callback skips a tick with no burn since the arm.
    access.as_context_mut().set_epoch_deadline(1);
    #[cfg(test)]
    {
        let ms = access
            .as_context()
            .data()
            .host_deadline_tail_ms
            .load(Ordering::Acquire);
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
}

/// The guard clears `open` if the future is dropped before it resumes.
/// The call does not park. Ticks count time the guest ran. The resume
/// settles fuel and resets the deadline, even when an events read holds `open`.
fn arm_host_wait(
    opened: bool,
    bucket: &Option<Arc<Mutex<crate::providers::fuel_bucket::FuelBucket>>>,
) -> ResumeOnDrop {
    resume_guard(&if opened { bucket.clone() } else { None })
}

/// Charge the burn of a call that does not wait. `open` ends clear, and
/// `window_ticks` and the epoch deadline are left as they are.
fn settle_guest_burn(
    bucket: &Mutex<crate::providers::fuel_bucket::FuelBucket>,
    store: &mut impl wasmtime::AsContextMut,
) {
    let lend = {
        let mut slot = bucket.lock().expect("fuel");
        if slot.fault.is_some() {
            return;
        }
        slot.open = false;
        let remaining = match read_fuel(store) {
            Ok(value) => value,
            Err(name) => {
                slot.fault = Some(name);
                return;
            }
        };
        let lend = slot.settle(remaining, Instant::now()).unwrap_or(0);
        slot.open = false;
        lend
    };
    if let Err(name) = write_fuel(store, lend) {
        bucket.lock().expect("fuel").fault = Some(name);
    }
}

/// A v2 bridge on the guest runtime. The list stops at the first refusal, so
/// the Runtime never counts a grant after it. An async host call is awaited and dropped
/// when `deadline` passes, so a timeout keeps no thread. A call that blocks
/// this poll runs to the end first. A sync host call, used by tests, runs on
/// this thread and adds none.
#[rustfmt::skip]
async fn await_bridges(bridges: &[OpenBridge], deadline: std::time::Instant, spend: bool) -> Vec<HostAnswer> {
    let mut raws = Vec::with_capacity(bridges.len());
    for bridge in bridges {
        raws.push(await_v2_bridge(bridge, deadline.saturating_duration_since(std::time::Instant::now())).await);
        if raws.last().is_some_and(|raw| grant_counted(raw, spend).is_err()) { break; }
    }
    raws
}

async fn await_v2_bridge(bridge: &OpenBridge, deadline: Duration) -> HostAnswer {
    let line = bridge.line.as_str();
    let capsule_id = bridge.capsule_id.as_str();
    let principal = bridge.principal.as_deref();
    if let Some(call) = &bridge.async_host {
        return match tokio::time::timeout(deadline, call(line, capsule_id, principal)).await {
            Ok(result) => result,
            Err(_) => Err("timeout".into()),
        };
    }
    let Some(call) = &bridge.sync_host else {
        return Err("component bridge is not configured".into());
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call(line, capsule_id, principal)
    })) {
        Ok(result) => result,
        Err(_) => Err("panicked".into()),
    }
}

#[cfg(test)]
async fn test_bridge(
    async_host: Option<BridgeHostcallAsync>,
    sync_host: Option<BridgeHostcall>,
    deadline: Duration,
) -> HostAnswer {
    await_v2_bridge(
        &OpenBridge {
            line: String::new(),
            async_host,
            sync_host,
            capsule_id: "capsule".into(),
            principal: None,
        },
        deadline,
    )
    .await
}

fn bridge_failure(err: String) -> elastos::bus::types::BusError {
    if err == "timeout" {
        elastos::bus::types::BusError::Timeout(err)
    } else {
        bus_error("internal", err)
    }
}

/// A v2 guest that is running, stopping, or still has a worker that has not
/// joined. A stop/start loop cannot pass the cap by leaving the thread up.
fn v2_slot(item: &ComponentActivation) -> bool {
    item.manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT)
        && (item.starting
            || item.join.is_some()
            || matches!(
                item.status,
                CapsuleStatus::Running | CapsuleStatus::Stopping
            )
            || item.worker.is_some()
            || item.task.is_some())
}

impl Drop for ComponentProvider {
    fn drop(&mut self) {
        let bound = Instant::now() + V2_HOST_DEADLINE;
        let mut instances = loop {
            if let Ok(guard) = self.instances.try_write() {
                break guard;
            }
            if Instant::now() >= bound {
                // The lock is still held. Keep the map so each worker's join
                // handle is not dropped and the thread is not detached.
                tracing::error!(
                    "drop waited {} ms and the instance lock was still held; worker handles are kept",
                    V2_HOST_DEADLINE.as_millis()
                );
                let kept =
                    std::mem::replace(&mut self.instances, Arc::new(RwLock::new(HashMap::new())));
                std::mem::forget(kept);
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut joins = Vec::new();
        for (id, instance) in instances.iter_mut() {
            drop(instance.events.take());
            raise_flag(&instance.cancel_requested, &instance.wake);
            raise_flag(&instance.stop_requested, &instance.wake);
            let Some(join) = begin_v2_join(instance) else {
                continue;
            };
            joins.push((id.clone(), join));
        }
        drop(instances);
        for (id, join) in joins {
            if join.wait(V2_HOST_DEADLINE) {
                continue;
            }
            tracing::error!(capsule_id = %id, "drop left a guest thread running");
            // The owner thread holds the join handle until the worker ends.
            // With no owner, the handle must stay allocated so the thread is
            // not detached while it still runs.
            if !join.owns_thread() {
                std::mem::forget(join);
            }
        }
    }
}

impl Default for ComponentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ComputeProvider for ComponentProvider {
    async fn load(&self, path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
        Self::require_component_manifest(&manifest)?;
        let component_path = path.join(&manifest.entrypoint);
        let bytes =
            Self::read_component(&component_path)
                .await
                .map_err(|err| match err.kind() {
                    std::io::ErrorKind::NotFound => ElastosError::CapsuleNotFound(format!(
                        "component file not found: {}",
                        component_path.display()
                    )),
                    _ => ElastosError::Compute(format!("Failed to read component capsule: {err}")),
                })?;
        self.load_admitted(bytes, manifest).await
    }

    /// Starts the guest and waits for it to end, as a bounded activation. A
    /// v2 guest stays up: this returns when that guest is ready. A resident
    /// caller uses [`ComponentProvider::start_resident`] and waits for the end.
    async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
        let mut resident = self.start_resident(handle).await?;
        if resident.handle.manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT) {
            return Ok(());
        }
        match resident.ended().await {
            ActivationOutcome::Trapped(message) => Err(ElastosError::Compute(message)),
            // A natural return and an intentional stop both end well.
            ActivationOutcome::Returned | ActivationOutcome::Stopped => Ok(()),
        }
    }

    async fn stop(&self, handle: &CapsuleHandle) -> Result<()> {
        self.reap_joined_residents().await;
        // One lock for the look and the action: a start cannot mark the
        // entry running between the two.
        let mut instances = self.instances.write().await;
        let Some(instance) = instances.get_mut(&handle.id) else {
            drop(instances);
            self.frames.lock().expect("frames").remove(&handle.id.0);
            return Ok(());
        };
        let id = handle.id.clone();
        let v2 = instance.manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT);
        if !v2 && instance.status == CapsuleStatus::Running {
            // A resident v1 activation is ended by its own epoch callback; the
            // worker removes the entry when the run ends.
            raise_flag(&instance.stop_requested, &instance.wake);
            return Ok(());
        }
        if !v2 {
            instances.remove(&id);
            drop(instances);
            self.frames.lock().expect("frames").remove(&id.0);
            return Ok(());
        }
        raise_flag(&instance.stop_requested, &instance.wake);
        instance.grants.lock().expect("grant book").clear();
        self.frames.lock().expect("frames").remove(&id.0);
        drop(instance.events.take());
        let bound = instance.join_bound;
        let join = begin_v2_join(instance);
        if join.is_none() {
            instances.remove(&id);
        }
        drop(instances);
        let Some(join) = join else {
            self.frames.lock().expect("frames").remove(&id.0);
            return Ok(());
        };
        if wait_v2_join(join, bound).await {
            self.instances.write().await.remove(&id);
            self.frames.lock().expect("frames").remove(&id.0);
            Ok(())
        } else {
            tracing::error!(capsule_id = %id, "stop left a guest thread running");
            Err(ElastosError::Compute(format!(
                "guest {id} is still running"
            )))
        }
    }

    async fn status(&self, handle: &CapsuleHandle) -> Result<CapsuleStatus> {
        self.reap_joined_residents().await;
        self.instances
            .read()
            .await
            .get(&handle.id)
            .map(|instance| instance.status)
            .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))
    }

    async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
        self.reap_joined_residents().await;
        let instances = self.instances.read().await;
        let instance = instances
            .get(&handle.id)
            .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?;

        Ok(CapsuleInfo {
            id: handle.id.clone(),
            name: instance.manifest.name.clone(),
            status: instance.status,
            memory_used_mb: 0,
        })
    }

    fn supports(&self, capsule_type: &CapsuleType) -> bool {
        matches!(capsule_type, CapsuleType::Wasm)
    }
}

/// The trailer's only wait. It ends when the stream is drained or dropped.
async fn await_read_trailer(
    rx: tokio::sync::oneshot::Receiver<std::result::Result<(), String>>,
) -> std::result::Result<(), String> {
    rx.await
        .map_err(|_| "the provider ended without a result".to_string())?
}

fn v2_error(err: elastos::bus::types::BusError) -> V2BusError {
    use elastos::bus::types::BusError as V1;
    match err {
        V1::Denied(message) => V2BusError::Denied(message),
        V1::NotFound(message) => V2BusError::NotFound(message),
        V1::Invalid(message) => V2BusError::Invalid(message),
        V1::Unavailable(message) => V2BusError::Unavailable(message),
        V1::Timeout(message) => V2BusError::Timeout(message),
        V1::Internal(message) => V2BusError::Internal(message),
    }
}

fn window_bytes(data: &serde_json::Value) -> V2Result<Vec<u8>> {
    let Some(content) = data.get("content") else {
        return Err(V2BusError::Invalid("read result has no content".into()));
    };
    if let Some(text) = content.as_str() {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(encoded) = content.get("b64").and_then(|value| value.as_str()) {
        return decode_b64(encoded)
            .ok_or_else(|| V2BusError::Invalid("read content is not bytes".into()));
    }
    Err(V2BusError::Invalid("read content is not bytes".into()))
}

/// Standard base64, with padding. A JSON array of one number per byte is refused.
fn decode_b64(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut bits = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                if index < 4 - pad {
                    return None;
                }
                continue;
            }
            bits = (bits << 6) | u32::from(value(*byte)?);
        }
        bits <<= 6 * pad as u32;
        let produced = 3 - pad;
        for shift in (3 - produced..3).rev() {
            out.push((bits >> (8 * shift)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
fn encode_b64(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let packed = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        for shift in [18u32, 12, 6, 0] {
            out.push(ALPHA[((packed >> shift) & 63) as usize] as char);
        }
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest > 0 {
        let mut packed = u32::from(bytes[index]) << 16;
        if rest == 2 {
            packed |= u32::from(bytes[index + 1]) << 8;
        }
        out.push(ALPHA[((packed >> 18) & 63) as usize] as char);
        out.push(ALPHA[((packed >> 12) & 63) as usize] as char);
        if rest == 2 {
            out.push(ALPHA[((packed >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

fn bus_error(code: &str, message: impl Into<String>) -> elastos::bus::types::BusError {
    let message = message.into();
    match code {
        "denied" | "capability_denied" | "missing_token" | "invalid_token" => {
            elastos::bus::types::BusError::Denied(message)
        }
        "not_found" => elastos::bus::types::BusError::NotFound(message),
        "timeout" => elastos::bus::types::BusError::Timeout(message),
        "unavailable" => elastos::bus::types::BusError::Unavailable(message),
        // The bridge refuses these before storage, so nothing was written: the
        // guest may treat them as a refusal, not an unknown result.
        "invalid"
        | "invalid_action"
        | "invalid_resource_invoke"
        | "root_not_offered"
        | "revision_required"
        | "revision_conflict"
        | "principal_root_protection_required"
        | "invalid_localhost_path"
        | "append_not_allowed"
        | "operation_not_allowed"
        | "invalid_content" => elastos::bus::types::BusError::Invalid(message),
        _ => elastos::bus::types::BusError::Internal(message),
    }
}

fn response_error(response: &RuntimeResponse) -> elastos::bus::types::BusError {
    match response {
        RuntimeResponse::Error { code, message } => bus_error(code, message.clone()),
        other => bus_error(
            "internal",
            format!("unexpected component bridge response: {other:?}"),
        ),
    }
}

fn json_body(
    bytes: &[u8],
) -> std::result::Result<serde_json::Value, elastos::bus::types::BusError> {
    if bytes.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(bytes).map_err(|err| {
        elastos::bus::types::BusError::Invalid(format!("component invoke body must be JSON: {err}"))
    })
}

/// One v2 host call that has not run yet. The guest awaits it, then checks
/// the grant again. Dropping it drops the call.
#[derive(Clone)]
struct OpenBridge {
    line: String,
    async_host: Option<BridgeHostcallAsync>,
    sync_host: Option<BridgeHostcall>,
    capsule_id: String,
    principal: Option<String>,
}

struct PendingRead {
    bridge: OpenBridge,
    cap: usize,
    grant: String,
    hold: super::bus2_stream::ReadHold,
}

struct PendingGrant {
    bridge: OpenBridge,
    resource: String,
    action: String,
    epoch: u64,
}

impl ComponentState {
    fn new(
        hostcall: Option<BridgeHostcall>,
        capsule_id: String,
        principal_id: Option<String>,
    ) -> Self {
        Self {
            sealed: false,
            hostcall,
            capsule_id,
            principal_id,
            limits: ComponentProvider::store_limits(),
            fuel: COMPONENT_FUEL,
            run_deadline: COMPONENT_RUN_DEADLINE,
            run_started: Instant::now(),
            in_bus: Duration::ZERO,
            stop_requested: Arc::new(AtomicBool::new(false)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            wake: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            in_clock_sleep: Arc::new(AtomicBool::new(false)),
            ended_by_stop: false,
            fuel_bucket: None,
            guest_memory: super::fuel_bucket::GuestMemory::default(),
            grants: Arc::new(Mutex::new(crate::providers::bus2_ui::GrantBook::default())),
            frames: Arc::new(Mutex::new(HashMap::new())),
            reads: super::bus2_stream::ReadBudget::new(),
            async_hostcall: None,
            #[cfg(test)]
            present_gate: None,
            #[cfg(test)]
            host_deadline_tail_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Called every tick: stop when a stop was requested, or when this run's
    /// own running time is used up; otherwise go on for one more tick. Time
    /// this run spent inside Bus calls does not count as its own running.
    fn deadline_update(&mut self) -> UpdateDeadline {
        if self.stop_requested.load(Ordering::Acquire) {
            self.ended_by_stop = true;
            return UpdateDeadline::Interrupt;
        }
        let ran = self.run_started.elapsed().saturating_sub(self.in_bus);
        match self.run_deadline.checked_sub(ran) {
            Some(left) if left >= DEADLINE_TICK => UpdateDeadline::Continue(1),
            _ => UpdateDeadline::Interrupt,
        }
    }

    /// v1 only. The call stays on this thread and has no cap. v2 uses
    /// [`Self::await_v2_bridge`] so a call adds no thread.
    fn call_bridge(
        &mut self,
        request: RuntimeRequest,
    ) -> std::result::Result<RuntimeResponse, elastos::bus::types::BusError> {
        if self.sealed {
            return Err(bus_error("denied", SEALED_BRIDGE));
        }
        let hostcall = self
            .hostcall
            .clone()
            .ok_or_else(|| bus_error("unavailable", "component bridge is not configured"))?;
        let line = guest_bus::bridge_envelope_json(1, request)
            .map_err(|err| bus_error("internal", err.to_string()))?;
        let asked = Instant::now();
        let _leg = BridgeLegGuard::enter(ComponentBridgeLeg::Caller);
        let raw = hostcall(&line, &self.capsule_id, self.principal_id.as_deref());
        self.in_bus += asked.elapsed();
        let raw = raw.map_err(|err| bus_error("internal", err))?;
        let envelope: ResponseEnvelope =
            serde_json::from_str(&raw).map_err(|err| bus_error("internal", err.to_string()))?;
        if matches!(&envelope.response, RuntimeResponse::Error { .. }) {
            return Err(response_error(&envelope.response));
        }
        Ok(envelope.response)
    }

    /// Checks, then one line that asks for `cap + 1` bytes. The call itself
    /// happens after this returns, and the grant is checked again after it.
    fn begin_read(
        &self,
        request: &v2::elastos::bus::types::InvokeRequest,
        had_body: bool,
    ) -> V2Result<PendingRead> {
        if self.sealed {
            return Err(V2BusError::Denied(SEALED_BRIDGE.into()));
        }
        if request.operation != "read" {
            return Err(V2BusError::Unavailable(
                "providers are not available in this slice".into(),
            ));
        }
        if had_body {
            return Err(V2BusError::Invalid("a read takes no body".into()));
        }
        let cap = super::bus2_stream::read_cap(&request.params).map_err(V2BusError::Invalid)?;
        let grant = request
            .grant
            .clone()
            .filter(|grant| !grant.is_empty())
            .ok_or_else(|| {
                V2BusError::Denied("resource invoke requires a capability grant".into())
            })?;
        {
            let book = self.grants.lock().expect("grant book");
            if book.blocks_read(&grant) {
                // Spent is the one refusal that still holds the grant. A
                // revoke, an eviction, an expiry, or a closed book is closed.
                let why = if book.blocks_presented_image(&grant) {
                    "closed"
                } else {
                    "spent"
                };
                return Err(V2BusError::Denied(format!("the grant is {why}")));
            }
        }
        let hold = super::bus2_stream::ReadHold::try_reserve(&self.reads, cap)
            .ok_or_else(|| V2BusError::Unavailable("the host read cap is already in use".into()))?;
        let line = guest_bus::bridge_envelope_json(
            1,
            guest_bus::invoke_request(guest_bus::InvokeRequest {
                resource: request.resource.clone(),
                operation: "read".into(),
                body: serde_json::json!({
                    "path": request.resource,
                    "offset": 0,
                    "length": cap as u64 + 1,
                    "check_revision": true,
                }),
                grant: Some(grant.clone()),
            }),
        )
        .map_err(|err| V2BusError::Internal(err.to_string()))?;
        Ok(PendingRead {
            bridge: self.open_bridge(line),
            cap,
            grant,
            hold,
        })
    }

    /// The host answer is refused when the grant or the stop arrived during the call.
    fn finish_read(
        &mut self,
        mut pending: PendingRead,
        raw: std::result::Result<String, String>,
    ) -> V2Result<super::bus2_stream::PreparedRead> {
        if self.book_closed() {
            return Err(V2BusError::Denied(BOOK_CLOSED.into()));
        }
        let book = Arc::clone(&self.grants);
        let spent = matches!(raw.as_ref(), Ok(text) if runtime_spent_use(text));
        let grant = pending.grant.clone();
        let finished = (move || {
            let response = decode_bridge(raw).map_err(v2_error)?;
            let (result, audit) = match response {
                RuntimeResponse::ResourceResult { result, audit } => (result, audit),
                other => return Err(v2_error(response_error(&other))),
            };
            if result.get("status").and_then(|value| value.as_str()) != Some("ok") {
                let code = result
                    .get("code")
                    .and_then(|value| value.as_str())
                    .unwrap_or("invalid");
                let message = result
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("read failed");
                return Err(v2_error(bus_error(code, message)));
            }
            let data = result.get("data").unwrap_or(&result);
            if book.lock().expect("grant book").blocks_read(&pending.grant) {
                return Err(V2BusError::Denied("the grant is closed".into()));
            }
            let bytes = window_bytes(data)?;
            if bytes.len() > pending.cap {
                return Err(V2BusError::Invalid(format!(
                    "object is {} bytes, over the cap of {}",
                    bytes.len(),
                    pending.cap
                )));
            }
            pending.hold.shrink(bytes.len());
            book.lock().expect("grant book").spend(&pending.grant);
            Ok(super::bus2_stream::PreparedRead {
                bytes,
                audit,
                hold: pending.hold,
            })
        })();
        if spent && finished.is_err() {
            self.grants.lock().expect("grant book").spend(&grant);
        }
        finished
    }

    /// A v2 read on this thread. Tests use it. The guest awaits [`Self::begin_read`].
    #[cfg(test)]
    fn windowed_read(
        &mut self,
        request: &v2::elastos::bus::types::InvokeRequest,
        had_body: bool,
    ) -> V2Result<super::bus2_stream::PreparedRead> {
        let pending = self.begin_read(request, had_body)?;
        let raw = sync_bridge(&pending.bridge);
        self.finish_read(pending, raw)
    }

    fn book_closed(&self) -> bool {
        self.stop_requested.load(Ordering::Acquire) || self.cancel_requested.load(Ordering::Acquire)
    }

    fn present_parts(&self, media: &str, document: &[u8]) -> V2Result<(Frame, Vec<OpenBridge>)> {
        if self.sealed {
            return Err(V2BusError::Denied(SEALED_BRIDGE.into()));
        }
        if self.book_closed() {
            return Err(V2BusError::Denied(BOOK_CLOSED.into()));
        }
        let book = self.grants.lock().expect("grant book");
        let frame = crate::providers::bus2_ui::present_frame(media, document, &book)
            .map_err(present_error)?;
        let grants = image_grants(&frame);
        let mut bridges = Vec::new();
        for spend in [false, true] {
            for (grant, resource) in &grants {
                bridges.push(self.open_bridge(grant_line(grant, resource, spend)));
            }
        }
        Ok((frame, bridges))
    }

    fn store_present(&mut self, frame: Frame, raws: &[HostAnswer], checks: usize) -> V2Result<()> {
        for raw in &raws[..checks] {
            grant_counted(raw, false)?;
        }
        // The guest book follows the Runtime: every answer that says
        // `use_spent` is spent here, even after an earlier refusal.
        let mut counted: Vec<String> = Vec::new();
        let mut refused = None;
        for (raw, (grant, _)) in raws[checks..].iter().zip(&image_grants(&frame)) {
            if raw.as_deref().is_ok_and(runtime_spent_use) {
                counted.push(grant.clone());
            }
            if let Err(err) = grant_counted(raw, true) {
                refused.get_or_insert(err);
            }
        }
        if let Some(err) = refused {
            let mut book = self.grants.lock().expect("grant book");
            for id in &counted {
                book.spend(id);
            }
            return Err(err);
        }
        let mut book = self.grants.lock().expect("grant book");
        #[cfg(test)]
        if let Some(gate) = &self.present_gate {
            gate.wait();
        }
        let stopped = self.book_closed();
        let blocked = counted.iter().any(|id| book.blocks_presented_image(id));
        for id in &counted {
            book.spend(id);
        }
        if stopped || blocked {
            let why = [BOOK_CLOSED, "the grant is spent"][usize::from(!stopped)];
            return Err(V2BusError::Denied(why.into()));
        }
        self.frames.lock().expect("frames").insert(
            self.capsule_id.clone(),
            StoredFrame {
                principal: self.principal_id.clone(),
                frame,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    fn present_document(&mut self, media: &str, document: &[u8]) -> V2Result<()> {
        let (frame, bridges) = self.present_parts(media, document)?;
        let half = bridges.len() / 2;
        let mut raws: Vec<_> = bridges[..half].iter().map(sync_bridge).collect();
        let checks = raws.len();
        if !raws.iter().any(|raw| grant_counted(raw, false).is_err()) {
            for bridge in &bridges[half..] {
                raws.push(sync_bridge(bridge));
                if grant_counted(&raws[raws.len() - 1], true).is_err() {
                    break;
                }
            }
        }
        self.store_present(frame, &raws, checks)
    }

    fn open_bridge(&self, line: String) -> OpenBridge {
        OpenBridge {
            line,
            async_host: self.async_hostcall.clone(),
            sync_host: self.hostcall.clone(),
            capsule_id: self.capsule_id.clone(),
            principal: self.principal_id.clone(),
        }
    }
}

#[cfg(test)]
fn sync_bridge(bridge: &OpenBridge) -> std::result::Result<String, String> {
    let Some(call) = &bridge.sync_host else {
        return Err("component bridge is not configured".into());
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call(
            &bridge.line,
            &bridge.capsule_id,
            bridge.principal.as_deref(),
        )
    })) {
        Ok(result) => result,
        Err(_) => Err("panicked".into()),
    }
}

#[rustfmt::skip]
fn image_grants(frame: &Frame) -> Vec<(String, String)> {
    let mut grants = Vec::new();
    for node in &frame.nodes { if let FrameNode::Image { grant, resource } = node { if grants.iter().all(|(id, _)| id != grant) { grants.push((grant.clone(), resource.clone())); } } }
    grants
}

#[rustfmt::skip]
fn grant_line(grant: &str, resource: &str, spend: bool) -> String {
    let mark = ["\"count_use\":false", "\"use_grant\":true"][usize::from(spend)];
    format!(r#"{{"id":1,"request":{{"type":"resource_invoke","uri":{resource:?},"operation":"read","token":{grant:?},"body":{{"path":{resource:?},{mark}}}}}}}"#) }

#[rustfmt::skip]
fn grant_counted(raw: &HostAnswer, spend: bool) -> V2Result<()> {
    let text = raw.as_ref().map_err(|err| V2BusError::Internal(err.clone()))?;
    let response = decode_bridge(Ok(text.clone())).map_err(v2_error)?;
    let RuntimeResponse::ResourceResult { result, .. } = &response else { return Err(v2_error(response_error(&response))); };
    if result.get("status").and_then(|v| v.as_str()) == Some("ok") && (!spend || runtime_spent_use(text)) { return Ok(()); }
    Err(V2BusError::Denied(["present failed", "the runtime did not count the grant"][usize::from(spend)].into()))
}

/// The bridge spent this use. The stamp is `response.use_spent` on the
/// envelope, a JSON bool. The same text inside the body is file content.
fn runtime_spent_use(raw: &str) -> bool {
    let Ok(envelope) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    matches!(
        envelope
            .get("response")
            .and_then(|response| response.get("use_spent")),
        Some(serde_json::Value::Bool(true))
    )
}

fn decode_bridge(
    raw: std::result::Result<String, String>,
) -> std::result::Result<RuntimeResponse, elastos::bus::types::BusError> {
    let raw = raw.map_err(bridge_failure)?;
    let envelope: ResponseEnvelope =
        serde_json::from_str(&raw).map_err(|err| bus_error("internal", err.to_string()))?;
    if matches!(&envelope.response, RuntimeResponse::Error { .. }) {
        return Err(response_error(&envelope.response));
    }
    Ok(envelope.response)
}

impl elastos::bus::types::Host for ComponentState {}

impl elastos::bus::runtime::Host for ComponentState {
    fn info(&mut self) -> elastos::bus::types::RuntimeInfo {
        elastos::bus::types::RuntimeInfo {
            abi: "elastos.component/v1".to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl elastos::bus::identity::Host for ComponentState {
    fn context(&mut self) -> elastos::bus::types::IdentityContext {
        elastos::bus::types::IdentityContext {
            principal: self.principal_id.clone(),
            capsule: self.capsule_id.clone(),
            session: self.capsule_id.clone(),
            device: None,
        }
    }
}

impl ComponentState {
    /// v1. The call stays on this thread. A refused hold still returns the token.
    fn capability_request(
        &mut self,
        request: elastos::bus::types::CapabilityRequest,
    ) -> std::result::Result<elastos::bus::types::CapabilityGrant, elastos::bus::types::BusError>
    {
        if request.actions.len() != 1 {
            return Err(elastos::bus::types::BusError::Invalid(
                "component capability requests currently require exactly one action".into(),
            ));
        }
        let resource = request.resource;
        let action = request.actions[0].clone();
        let response = self.call_bridge(
            guest_bus::capability_request(guest_bus::CapabilityRequest {
                resource: resource.clone(),
                actions: vec![action.clone()],
                reason: request.reason,
            })
            .map_err(|err| bus_error("invalid", err))?,
        )?;
        let token = match response {
            RuntimeResponse::CapabilityToken { token, .. } => token,
            response => return Err(response_error(&response)),
        };
        let _held = self
            .grants
            .lock()
            .expect("grant book")
            .hold(&token, &resource, &action);
        Ok(elastos::bus::types::CapabilityGrant {
            id: token,
            resource,
            actions: vec![action],
            expires_at_ms: None,
        })
    }
}

impl elastos::bus::capabilities::Host for ComponentState {
    fn request(
        &mut self,
        request: elastos::bus::types::CapabilityRequest,
    ) -> std::result::Result<elastos::bus::types::CapabilityGrant, elastos::bus::types::BusError>
    {
        self.capability_request(request)
    }
}

impl ComponentState {
    /// The epoch is the book's generation. Revoke-all moves it, so a grant
    /// that arrives after that move is refused even when the host minted it.
    fn begin_grant(
        &self,
        request: elastos::bus::types::CapabilityRequest,
    ) -> std::result::Result<PendingGrant, elastos::bus::types::BusError> {
        if self.sealed {
            return Err(bus_error("denied", SEALED_BRIDGE));
        }
        if self.stop_requested.load(Ordering::Acquire)
            || self.cancel_requested.load(Ordering::Acquire)
        {
            return Err(elastos::bus::types::BusError::Denied(
                "the grant book is closed".into(),
            ));
        }
        if request.actions.len() != 1 {
            return Err(elastos::bus::types::BusError::Invalid(
                "component capability requests currently require exactly one action".into(),
            ));
        }
        let epoch = self.grants.lock().expect("grant book").epoch();
        let resource = request.resource;
        let action = request.actions[0].clone();
        let line = guest_bus::bridge_envelope_json(
            1,
            guest_bus::capability_request(guest_bus::CapabilityRequest {
                resource: resource.clone(),
                actions: vec![action.clone()],
                reason: request.reason,
            })
            .map_err(|err| bus_error("invalid", err))?,
        )
        .map_err(|err| bus_error("internal", err.to_string()))?;
        Ok(PendingGrant {
            bridge: self.open_bridge(line),
            resource,
            action,
            epoch,
        })
    }

    fn finish_grant(
        &mut self,
        pending: PendingGrant,
        raw: std::result::Result<String, String>,
    ) -> std::result::Result<elastos::bus::types::CapabilityGrant, elastos::bus::types::BusError>
    {
        if self.stop_requested.load(Ordering::Acquire)
            || self.cancel_requested.load(Ordering::Acquire)
        {
            return Err(elastos::bus::types::BusError::Denied(
                "the grant book is closed".into(),
            ));
        }
        let response = decode_bridge(raw)?;
        let (token, max_uses, expires_at_ms) = match response {
            RuntimeResponse::CapabilityToken {
                token,
                max_uses,
                expires_at_ms,
            } => (token, max_uses, expires_at_ms),
            response => return Err(response_error(&response)),
        };
        let mut book = self.grants.lock().expect("grant book");
        if book.epoch() != pending.epoch
            || !book.hold_limited(
                &token,
                &pending.resource,
                &pending.action,
                max_uses,
                expires_at_ms,
            )
        {
            return Err(elastos::bus::types::BusError::Denied(
                "the grant was revoked".into(),
            ));
        }
        Ok(elastos::bus::types::CapabilityGrant {
            id: token,
            resource: pending.resource,
            actions: vec![pending.action],
            expires_at_ms,
        })
    }
}

impl elastos::bus::providers::Host for ComponentState {
    fn invoke(
        &mut self,
        request: elastos::bus::types::InvokeRequest,
    ) -> std::result::Result<elastos::bus::types::InvokeResponse, elastos::bus::types::BusError>
    {
        let Some(grant) = request.grant.filter(|grant| !grant.is_empty()) else {
            return Err(elastos::bus::types::BusError::Denied(
                "resource invoke requires a capability grant".into(),
            ));
        };
        let body = json_body(&request.body)?;
        let response = self.call_bridge(guest_bus::invoke_request(guest_bus::InvokeRequest {
            resource: request.resource,
            operation: request.operation,
            body,
            grant: Some(grant),
        }))?;
        let (result, audit) = match response {
            RuntimeResponse::ResourceResult { result, audit } => (result, audit),
            response => return Err(response_error(&response)),
        };
        let status = result
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("ok")
            .to_string();
        let body = serde_json::to_vec(&result).map_err(|err| {
            bus_error(
                "internal",
                format!("failed to encode provider result: {err}"),
            )
        })?;
        Ok(elastos::bus::types::InvokeResponse {
            status,
            body,
            audit,
        })
    }
}

impl v2::elastos::bus::types::Host for ComponentState {}

impl v2::elastos::bus::runtime::Host for ComponentState {
    fn info(&mut self) -> v2::elastos::bus::runtime::RuntimeInfo {
        v2::elastos::bus::runtime::RuntimeInfo {
            abi: ELASTOS_BUS_V2_CONTRACT.into(),
            runtime_version: env!("CARGO_PKG_VERSION").into(),
            capsule_cid: None,
        }
    }
}

impl v2::elastos::bus::identity::Host for ComponentState {
    fn context(&mut self) -> v2::elastos::bus::identity::IdentityContext {
        v2::elastos::bus::identity::IdentityContext {
            principal: self.principal_id.clone(),
            capsule: self.capsule_id.clone(),
            session: self.capsule_id.clone(),
            device: None,
        }
    }
}

impl v2::elastos::bus::clock::Host for ComponentState {
    fn now_ms(&mut self) -> u64 {
        #[cfg(test)]
        if let Some(ms) = test_wall_ms(self) {
            return ms;
        }
        self.fuel_bucket
            .as_ref()
            .map(|bucket| bucket.lock().expect("fuel").now_ms())
            .unwrap_or(0)
    }
}

#[cfg(test)]
fn test_wall_ms(state: &ComponentState) -> Option<u64> {
    let start = state
        .fuel_bucket
        .as_ref()?
        .lock()
        .expect("fuel")
        .wall_origin?;
    Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
fn arm_test_wall(
    mut fuel: crate::providers::fuel_bucket::FuelBucket,
    on: bool,
) -> crate::providers::fuel_bucket::FuelBucket {
    if on {
        fuel.wall_origin = Some(Instant::now());
    }
    fuel
}

impl v2::elastos::bus::clock::HostWithStore<ComponentState> for HasSelf<ComponentState> {
    async fn sleep_until_ms(
        accessor: &wasmtime::component::Accessor<ComponentState, Self>,
        deadline_ms: u64,
    ) {
        let (wait, cancel, stop, bucket, wake, sleeping) = accessor.with(|mut access| {
            let bucket = access.get().fuel_bucket.clone();
            let wait = bucket
                .as_ref()
                .map(|bucket| bucket.lock().expect("fuel").sleep_for(deadline_ms))
                .unwrap_or(Duration::ZERO);
            // Nothing to wait for. The call still costs fuel. It does not
            // park, and it does not reset the tick window or the deadline.
            if wait.is_zero() {
                if let Some(bucket) = &bucket {
                    settle_guest_burn(bucket, &mut access);
                }
            } else {
                let _opened = charge_access(&mut access);
            }
            let state = access.get();
            #[cfg(test)]
            let sleeping = Some(state.in_clock_sleep.clone());
            #[cfg(not(test))]
            let sleeping: Option<Arc<AtomicBool>> = None;
            (
                wait,
                state.cancel_requested.clone(),
                state.stop_requested.clone(),
                bucket,
                state.wake.clone(),
                sleeping,
            )
        });
        if wait.is_zero() {
            return;
        }
        if let Some(bucket) = &bucket {
            bucket
                .lock()
                .expect("fuel")
                .begin_sleep_wait(Instant::now());
        }
        let _guard = resume_guard(&bucket);
        // Cancel, drop, or a wait inside one tick does not park.
        // A positive wait is at least [`V2_SLEEP_FLOOR`], so a 1 ms loop yields.
        let host_wait = wait.max(V2_SLEEP_FLOOR);
        let notified = wake.notified();
        tokio::pin!(notified);
        if let Some(flag) = &sleeping {
            flag.store(true, Ordering::Release);
        }
        let mut finished = false;
        if !cancel.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            finished = tokio::select! {
                biased;
                _ = &mut notified => false,
                _ = tokio::time::sleep(host_wait) => true,
            };
        }
        if let Some(flag) = &sleeping {
            flag.store(false, Ordering::Release);
        }
        if let Some(bucket) = &bucket {
            let mut slot = bucket.lock().expect("fuel");
            if finished {
                slot.end_sleep_wait(Instant::now(), DEADLINE_TICK);
            } else {
                slot.clear_sleep_wait();
            }
        }
        accessor.with(|mut access| release_access(&mut access));
    }
}

impl v2::elastos::bus::random::Host for ComponentState {
    fn fill(&mut self, _: u32) -> Vec<u8> {
        Vec::new()
    }
}

impl v2::elastos::bus::credentials::Host for ComponentState {
    fn presented(&mut self) -> Vec<v2::elastos::bus::types::Credential> {
        Vec::new()
    }
}

impl v2::elastos::bus::capabilities::Host for ComponentState {}
impl v2::elastos::bus::capabilities::HostWithStore<ComponentState> for HasSelf<ComponentState> {
    /// The same call the v1 request makes: one action, the same bridge line,
    /// the same pending store, and the owner's decision. This function grants
    /// nothing by itself.
    async fn request(
        accessor: &wasmtime::component::Accessor<ComponentState, Self>,
        resource: String,
        actions: Vec<String>,
        reason: String,
    ) -> std::result::Result<v2::elastos::bus::types::Grant, v2::elastos::bus::types::BusError>
    {
        let (opened, bucket, pending) = accessor.with(|mut access| {
            let opened = charge_access(&mut access);
            let bucket = access.get().fuel_bucket.clone();
            let pending = access
                .get()
                .begin_grant(elastos::bus::types::CapabilityRequest {
                    resource,
                    actions,
                    reason,
                });
            (opened, bucket, pending)
        });
        let _guard = arm_host_wait(opened, &bucket);
        let pending = pending.map_err(v2_error)?;
        let raw = await_v2_bridge(&pending.bridge, V2_APPROVAL_DEADLINE).await;
        let decided = accessor.with(|mut access| {
            release_access(&mut access);
            access.get().finish_grant(pending, raw)
        });
        match decided {
            Ok(grant) => Ok(v2::elastos::bus::types::Grant {
                id: grant.id,
                resource: grant.resource,
                actions: grant.actions,
                expires_at_ms: grant.expires_at_ms,
            }),
            Err(err) => Err(v2_error(err)),
        }
    }
}

impl v2::elastos::bus::providers::Host for ComponentState {}
impl v2::elastos::bus::providers::HostWithStore<ComponentState> for HasSelf<ComponentState> {
    async fn invoke(
        accessor: &wasmtime::component::Accessor<ComponentState, Self>,
        request: v2::elastos::bus::types::InvokeRequest,
        body: Option<StreamReader<u8>>,
    ) -> std::result::Result<
        (
            v2::elastos::bus::types::InvokeStatus,
            StreamReader<u8>,
            wasmtime::component::FutureReader<std::result::Result<(), V2BusError>>,
        ),
        V2BusError,
    > {
        let had_body = body.is_some();
        if let Some(mut body) = body {
            let _ = accessor.with(|mut access| body.close(&mut access));
        }
        let (opened, bucket, pending, grants, stop_requested, cancel_requested) =
            accessor.with(|mut access| {
                let opened = charge_access(&mut access);
                let bucket = access.get().fuel_bucket.clone();
                let grants = access.get().grants.clone();
                let stop_requested = access.get().stop_requested.clone();
                let cancel_requested = access.get().cancel_requested.clone();
                let pending = access.get().begin_read(&request, had_body);
                (
                    opened,
                    bucket,
                    pending,
                    grants,
                    stop_requested,
                    cancel_requested,
                )
            });
        let _guard = arm_host_wait(opened, &bucket);
        let pending = pending?;
        let grant_id = pending.grant.clone();
        let raw = await_v2_bridge(&pending.bridge, V2_HOST_DEADLINE).await;
        let super::bus2_stream::PreparedRead { bytes, audit, hold } =
            accessor.with(|mut access| {
                release_access(&mut access);
                access.get().finish_read(pending, raw)
            })?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        accessor
            .with(|mut access| {
                let stop = Arc::new(move || {
                    v2_read_stopped(&stop_requested, &cancel_requested, &grants, &grant_id)
                });
                let stream = StreamReader::new(
                    &mut access,
                    super::bus2_stream::WindowRead::new(bytes, tx, hold).stop_when(stop),
                )?;
                let trailer = wasmtime::component::FutureReader::new(&mut access, async move {
                    Ok::<_, wasmtime::Error>(
                        await_read_trailer(rx).await.map_err(V2BusError::Invalid),
                    )
                })?;
                Ok::<_, wasmtime::Error>((
                    v2::elastos::bus::types::InvokeStatus {
                        status: "ok".into(),
                        audit,
                    },
                    stream,
                    trailer,
                ))
            })
            .map_err(|err| V2BusError::Internal(format!("could not open the read: {err}")))
    }
}

impl v2::elastos::bus::ui::Host for ComponentState {}
impl v2::elastos::bus::ui::HostWithStore<ComponentState> for HasSelf<ComponentState> {
    async fn present(
        accessor: &wasmtime::component::Accessor<ComponentState, Self>,
        media_type: String,
        document: Vec<u8>,
    ) -> std::result::Result<(), v2::elastos::bus::types::BusError> {
        let (opened, bucket, prepared) = accessor.with(|mut access| {
            let opened = charge_access(&mut access);
            let bucket = access.get().fuel_bucket.clone();
            let prepared = access.get().present_parts(&media_type, &document);
            (opened, bucket, prepared)
        });
        let _guard = arm_host_wait(opened, &bucket);
        let deadline = std::time::Instant::now() + V2_HOST_DEADLINE;
        let outcome = async {
            let (frame, bridges) = prepared?;
            let half = bridges.len() / 2;
            let mut raws = await_bridges(&bridges[..half], deadline, false).await;
            let checks = raws.len();
            if !raws.iter().any(|raw| grant_counted(raw, false).is_err()) {
                raws.extend(await_bridges(&bridges[half..], deadline, true).await);
            }
            Ok((frame, raws, checks))
        }
        .await;
        accessor.with(|mut access| {
            release_access(&mut access);
            outcome
                .and_then(|(frame, raws, checks)| access.get().store_present(frame, &raws, checks))
        })
    }
}

fn present_error(err: crate::providers::bus2_ui::PresentError) -> V2BusError {
    match err {
        crate::providers::bus2_ui::PresentError::Invalid(message) => V2BusError::Invalid(message),
        crate::providers::bus2_ui::PresentError::Denied(message) => V2BusError::Denied(message),
    }
}

/// The product stop for a v2 read stream. A spent use still delivers its
/// bytes. Revoke, eviction, expiry, a closed book, a guest stop, or a
/// cancelled call ends the stream.
pub(crate) fn v2_read_stopped(
    stop_requested: &AtomicBool,
    cancel_requested: &AtomicBool,
    grants: &Mutex<crate::providers::bus2_ui::GrantBook>,
    grant: &str,
) -> bool {
    stop_requested.load(Ordering::Acquire)
        || cancel_requested.load(Ordering::Acquire)
        || grants
            .lock()
            .expect("grant book")
            .blocks_presented_image(grant)
}

/// A delivered `grant-revoked` marks that grant and drops the host's stored
/// frame when that frame names the grant. The draft leaves a frame already
/// drawn unstated (WIT note 11). This drops the host's own copy. It does not
/// clear a screen.
fn note_delivered_event(
    book: &Mutex<crate::providers::bus2_ui::GrantBook>,
    frames: &Mutex<HashMap<String, StoredFrame>>,
    capsule_id: &str,
    event: &v2::elastos::bus::types::Event,
) {
    let v2::elastos::bus::types::Event::GrantRevoked(id) = event else {
        return;
    };
    book.lock().expect("grant book").revoke(id);
    drop_frame_naming(frames, capsule_id, id);
}

/// Drops the host frame for `capsule_id` when an image node names `grant`.
fn drop_frame_naming(frames: &Mutex<HashMap<String, StoredFrame>>, capsule_id: &str, grant: &str) {
    let mut frames = frames.lock().expect("frames");
    let names = frames.get(capsule_id).is_some_and(|stored| {
        stored.frame.nodes.iter().any(|node| match node {
            crate::providers::bus2_ui::FrameNode::Image { grant: named, .. } => named == grant,
            crate::providers::bus2_ui::FrameNode::Text(_) => false,
        })
    });
    if names {
        frames.remove(capsule_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Linux counts the tasks in this directory. A missing directory is the
    /// macOS path, which uses `ps -M` instead.
    fn task_threads(dir: &std::path::Path) -> Option<usize> {
        let count = std::fs::read_dir(dir)
            .ok()?
            .filter(|entry| entry.is_ok())
            .count();
        (count > 0).then_some(count)
    }

    #[test]
    fn linux_task_dir_counts_threads() {
        assert!(task_threads(std::path::Path::new("/no/such/task/dir")).is_none());
        let here = std::env::current_dir().expect("cwd");
        assert!(task_threads(&here).unwrap() > 0);
    }

    /// A poll that blocks the worker runs past the deadline and still returns.
    /// A poll that yields is cut, and the answer is `timeout`.
    #[tokio::test]
    async fn a_blocking_host_call_is_not_cut_by_the_deadline() {
        let blocking: super::BridgeHostcallAsync = std::sync::Arc::new(|_, _, _| {
            Box::pin(async {
                std::thread::sleep(Duration::from_millis(80));
                Ok("kept".to_string())
            })
        });
        let started = Instant::now();
        let kept = super::test_bridge(Some(blocking), None, Duration::from_millis(20)).await;
        assert!(started.elapsed() >= Duration::from_millis(80));
        assert_eq!(kept.unwrap(), "kept");
        let yielding: super::BridgeHostcallAsync = std::sync::Arc::new(|_, _, _| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(80)).await;
                Ok("cut".to_string())
            })
        });
        let cut = super::test_bridge(Some(yielding), None, Duration::from_millis(20)).await;
        assert_eq!(cut.unwrap_err(), "timeout");
    }

    fn json_line(line: &str) -> serde_json::Value {
        serde_json::from_str(line).expect("captured bridge line must be JSON")
    }

    /// A component holding one core module with one memory of one page.
    /// `shared` marks the memory shared, which only the threads proposal allows.
    fn component_with_memory(shared: bool) -> Vec<u8> {
        let limits = if shared { 0x03 } else { 0x01 }; // has a maximum, and shared
        let memory_section = [0x05, 0x04, 0x01, limits, 0x01, 0x01];
        let module = [b"\0asm\x01\0\0\0".as_slice(), &memory_section].concat();
        let mut component = b"\0asm\x0d\0\x01\0".to_vec();
        component.extend([0x01, module.len() as u8]); // a core module section
        component.extend(module);
        component
    }

    #[test]
    fn every_load_shares_one_engine() {
        let first = ComponentProvider::engine().expect("component engine");
        let second = ComponentProvider::engine().expect("component engine");
        assert!(
            Engine::same(&first, &second),
            "each load must compile on the one process engine"
        );
    }

    #[test]
    fn engine_refuses_a_threads_module() {
        let engine = ComponentProvider::engine().expect("component engine");
        Component::new(&engine, component_with_memory(false))
            .expect("the same component with an unshared memory compiles");
        let err = Component::new(&engine, component_with_memory(true))
            .expect_err("a shared memory needs the threads proposal, which is off");
        assert!(format!("{err:?}").contains("threads"), "{err:?}");
    }

    #[test]
    fn v1_engine_stays_synchronous_and_v2_engine_accepts_async() {
        let bytes = wat::parse_str(
            r#"(component
                (type $body (stream u8))
                (type $accept (func async (param "body" $body)))
                (import "accept" (func (type $accept))))"#,
        )
        .expect("async component fixture");
        let v1 = ComponentProvider::engine().expect("v1 engine");
        let v2 = ComponentProvider::v2_engine().expect("v2 engine");
        assert!(
            !Engine::same(&v1, &v2),
            "Bus versions need separate engines"
        );
        assert!(
            Component::new(&v1, &bytes).is_err(),
            "v1 must refuse component-model async"
        );
        Component::new(&v2, &bytes).expect("v2 accepts component-model async");
        assert!(!v1.get_concurrency_support(), "v1 stays synchronous");
        assert!(v2.get_concurrency_support(), "v2 supports concurrency");
    }

    #[test]
    fn v2_engine_keeps_v1_limits() {
        let v1 = ComponentProvider::engine().expect("v1 engine");
        let v2 = ComponentProvider::v2_engine().expect("v2 engine");
        assert!(v1.get_consume_fuel(), "v1 fuel stays on");
        assert!(v2.get_consume_fuel(), "v2 fuel stays on");
        assert!(v1.get_epoch_interruption(), "v1 epoch stays on");
        assert!(v2.get_epoch_interruption(), "v2 epoch stays on");
        assert_eq!(
            v1.get_wasm_features() ^ v2.get_wasm_features(),
            WasmFeatures::CM_ASYNC,
            "v2 enables only its component-model async features beyond v1"
        );
        assert_eq!(
            v2.get_max_wasm_stack(),
            512 * 1024,
            "a v2 guest's own recursion traps inside the named wasm stack"
        );
    }

    /// WIT `ui.present` takes a flat `list<u8>`. This is the other recursion a
    /// guest can drive: its own calls. The wasm stack traps them.
    #[test]
    fn v2_guest_recursion_traps_inside_the_wasm_stack() {
        let engine = ComponentProvider::v2_engine().expect("v2 engine");
        let bytes = wat::parse_str(
            r#"(module (func $again call $again) (func (export "go") call $again))"#,
        )
        .expect("recursive wat");
        let module = wasmtime::Module::new(&engine, &bytes).expect("recursive module");
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_fuel(1_000_000_000).expect("fuel");
        store.set_epoch_deadline(1_000_000);
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instance");
        let go = instance
            .get_typed_func::<(), ()>(&mut store, "go")
            .expect("go");
        let err = go.call(&mut store, ()).expect_err("recursion traps");
        let text = format!("{err:?}");
        assert!(
            text.contains("stack"),
            "recursive guest traps inside the wasm stack, got {text}"
        );
    }

    /// A v1 component whose core module loops for ever: in `run`, or with
    /// `at_start` in its start function. `spin: false` gives the same
    /// component with no loop.
    fn lifecycle_component(spin: bool, at_start: bool) -> Component {
        let engine = ComponentProvider::engine().expect("component engine");
        Component::new(&engine, lifecycle_component_bytes(spin, at_start)).expect("compiles")
    }

    fn lifecycle_component_bytes(spin: bool, at_start: bool) -> Vec<u8> {
        let start = if spin && at_start {
            "(start $spin)"
        } else {
            ""
        };
        let run = if spin && !at_start {
            "(call $spin)"
        } else {
            ""
        };
        let text = format!(
            r#"(component
              (import "elastos:bus/types@1.0.0" (instance $types
                (type $error (variant
                  (case "denied" string) (case "not-found" string) (case "invalid" string)
                  (case "unavailable" string) (case "timeout" string) (case "internal" string)))
                (export "bus-error" (type (eq $error)))))
              (alias export $types "bus-error" (type $bus-error))
              (core module $m
                (memory (export "memory") 1)
                (func $spin (loop $again (br $again)))
                (func (export "run") (result i32) {run} (i32.const 0))
                {start})
              (core instance $i (instantiate $m))
              (func $run (result (result (error $bus-error)))
                (canon lift (core func $i "run") (memory $i "memory")))
              (instance $lifecycle (export "run" (func $run)))
              (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#
        );
        wat::parse_str(text).expect("component text")
    }

    /// An activation with the given time limit and fuel that never runs out,
    /// so that only the deadline can end a loop.
    /// The committed Bus v1 conformance capsule: its folder and its manifest.
    fn component_fixture() -> (std::path::PathBuf, CapsuleManifest) {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let manifest =
            serde_json::from_slice(&std::fs::read(path.join("capsule.json")).unwrap()).unwrap();
        (path, manifest)
    }

    #[tokio::test]
    async fn provider_accepts_a_v2_contract_with_the_v2_engine() {
        let provider = ComponentProvider::new();
        let (_, mut manifest) = component_fixture();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        manifest.validate().unwrap();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = provider.load_admitted(bytes, manifest).await.unwrap();
        let instances = provider.instances.read().await;
        assert!(Engine::same(
            &instances[&handle.id].engine,
            &ComponentProvider::v2_engine().unwrap()
        ));
        drop(instances);
        provider.stop(&handle).await.unwrap();
        assert!(provider.instances.read().await.is_empty());
    }

    #[tokio::test]
    async fn v2_guest_returns_stopped_when_the_events_stream_closes() {
        let provider = ComponentProvider::new();
        let (_, mut manifest) = component_fixture();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = provider.load_admitted(bytes, manifest).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), provider.start(&handle))
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            provider.status(&handle).await.unwrap(),
            CapsuleStatus::Running
        );
        assert!(!provider.endings.read().await.contains_key(&handle.id));
        provider.stop(&handle).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    assert_eq!(ending, "stopped");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closing the events stream must record stopped");
    }

    fn v2_variant(changes: &[(&str, &str)]) -> Vec<u8> {
        let mut source =
            include_str!("../../../../tests/fixtures/components/v2-resident.wat").to_string();
        for (from, to) in changes {
            assert!(source.contains(from), "WAT variant must replace guest code");
            source = source.replacen(from, to, 1);
        }
        wat::parse_str(source).unwrap()
    }

    async fn load_v2_fixture(provider: &ComponentProvider, bytes: Vec<u8>) -> CapsuleHandle {
        let (_, mut manifest) = component_fixture();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        provider.load_admitted(bytes, manifest).await.unwrap()
    }

    async fn v2_ending(provider: &ComponentProvider, handle: &CapsuleHandle) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("v2 task must end within the test bound")
    }

    async fn v2_pending_read(provider: &ComponentProvider, handle: &CapsuleHandle) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if provider.instances.read().await[&handle.id]
                    .pending_read
                    .load(Ordering::Acquire)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("guest must enter its events read before stop");
    }

    #[tokio::test]
    async fn v2_stream_wait_outlives_v1_deadline() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        tokio::time::timeout(Duration::from_secs(2), provider.start(&handle))
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(COMPONENT_RUN_DEADLINE + Duration::from_millis(150)).await;
        assert_eq!(
            provider.status(&handle).await.unwrap(),
            CapsuleStatus::Running
        );
        provider.stop(&handle).await.unwrap();
        assert_eq!(v2_ending(&provider, &handle).await, "stopped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_ignore_close_ends_cancelled_after_grace() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "local.get $event i32.const 2 i32.eq\n      if",
            "(loop $ignore br $ignore)\n      local.get $event i32.const 2 i32.eq\n      if",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.unwrap();
        v2_pending_read(&provider, &handle).await;
        let stopped_at = Instant::now();
        provider.stop(&handle).await.unwrap();
        assert_eq!(v2_ending(&provider, &handle).await, "cancelled");
        assert!(stopped_at.elapsed() >= V2_STOP_GRACE);
        assert!(
            stopped_at.elapsed() < Duration::from_millis(180),
            "stop cancellation must beat the 30-tick execution budget"
        );
        assert!(provider.instances.read().await.is_empty());
    }

    /// Stop's grace used to be a task on the caller's runtime. Dropping that
    /// runtime left a guest that ignores the closed stream running.
    #[test]
    fn v2_ignore_close_is_gone_when_the_caller_runtime_drops() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = v2_variant(&[(
            "local.get $event i32.const 2 i32.eq\n      if",
            "(loop $ignore br $ignore)\n      local.get $event i32.const 2 i32.eq\n      if",
        )]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = rt.block_on(async {
            let handle = load_v2_fixture(&provider, bytes).await;
            provider.start(&handle).await.unwrap();
            v2_pending_read(&provider, &handle).await;
            tokio::time::timeout(Duration::from_secs(2), async {
                while provider.threads_live.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the guest thread starts");
            handle
        });
        let started = Instant::now();
        rt.block_on(provider.stop(&handle)).unwrap();
        drop(rt);
        // Shorter than the 30-tick execution budget, so a guest that merely
        // runs out of ticks does not pass this row.
        let bound = V2_STOP_GRACE + Duration::from_millis(80);
        while provider.threads_live.load(Ordering::Acquire) != 0 {
            assert!(
                started.elapsed() < bound,
                "a guest that ignores the closed stream is still running"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Two residents may run. The next start is refused, and the refusal names the cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_resident_cap_is_refused_by_name() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let first = load_v2_fixture(&provider, bytes.clone()).await;
        let second = load_v2_fixture(&provider, bytes.clone()).await;
        let third = load_v2_fixture(&provider, bytes).await;
        provider.start(&first).await.unwrap();
        provider.start(&second).await.unwrap();
        let err = provider.start(&third).await.unwrap_err().to_string();
        assert!(
            err.contains("v2 resident cap"),
            "the refusal names the cap, got {err}"
        );
        provider.stop(&first).await.unwrap();
        provider.start(&third).await.unwrap();
        provider.stop(&second).await.unwrap();
        provider.stop(&third).await.unwrap();
    }

    /// A stop keeps the slot until the worker joins, so a third start is refused
    /// while the first guest is still inside its host wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_a_stopping_guest_still_occupies_the_cap() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let first = load_v2_fixture(&provider, bytes.clone()).await;
        let second = load_v2_fixture(&provider, bytes.clone()).await;
        let third = load_v2_fixture(&provider, bytes).await;
        provider.start(&first).await.unwrap();
        provider.start(&second).await.unwrap();
        let stopping = {
            let provider = provider.clone();
            let first = first.clone();
            tokio::spawn(async move { provider.stop(&first).await.unwrap() })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if provider.status(&first).await.unwrap() == CapsuleStatus::Stopping {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stop says stopping while the worker has not joined");
        let err = provider.start(&third).await.unwrap_err().to_string();
        assert!(err.contains("v2 resident cap"), "{err}");
        stopping.await.unwrap();
        provider.start(&third).await.unwrap();
        provider.stop(&second).await.unwrap();
        provider.stop(&third).await.unwrap();
    }

    /// Two stops at once, and a retry after "still running", leave the slot
    /// and the worker in place while the guest is inside a host call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_two_stops_keep_the_slot_until_the_worker_joins() {
        let provider = Arc::new(ComponentProvider::new());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let gate = release.clone();
        provider.set_bus_hostcall(Arc::new(move |_line, _, _| {
            let _ = entered_tx.send(());
            let (lock, cv) = &*gate;
            let mut open = lock.lock().expect("release");
            while !*open {
                open = cv.wait(open).expect("release");
            }
            Ok(serde_json::json!({
                "id": 1,
                "response": {
                    "type": "resource_result",
                    "result": { "status": "ok", "data": { "content": "ok", "size": 2 } },
                    "audit": "read-1"
                }
            })
            .to_string())
        }));
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-read-stream.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        {
            let mut entries = provider.instances.write().await;
            let instance = entries.get_mut(&handle.id).unwrap();
            instance.join_bound = Duration::from_millis(40);
            hold_note_grant(&instance.grants);
        }
        provider.start(&handle).await.unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the guest enters the host call");
        let first = {
            let provider = provider.clone();
            let handle = handle.clone();
            tokio::spawn(async move { provider.stop(&handle).await })
        };
        let second = {
            let provider = provider.clone();
            let handle = handle.clone();
            tokio::spawn(async move { provider.stop(&handle).await })
        };
        let (one, two) = tokio::join!(first, second);
        for result in [one.unwrap(), two.unwrap()] {
            let err = result.expect_err("a stop during the host call does not free the worker");
            assert!(
                err.to_string().contains("still running"),
                "later stop waits on the same join, got {err}"
            );
        }
        {
            let instances = provider.instances.read().await;
            let slot = instances
                .get(&handle.id)
                .expect("the slot stays until joined");
            assert_eq!(slot.status, CapsuleStatus::Stopping);
            assert!(slot.join.is_some(), "one join owns the worker");
            assert!(slot.worker.is_none(), "the handle lives in that join");
        }
        assert!(
            provider.threads_live.load(Ordering::Acquire) >= 1,
            "the worker, and the memory it holds, is still alive"
        );
        let again = provider.stop(&handle).await.unwrap_err().to_string();
        assert!(
            again.contains("still running"),
            "a retry after still running does not free the slot, got {again}"
        );
        assert!(provider.instances.read().await.contains_key(&handle.id));
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release") = true;
            cv.notify_all();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match provider.stop(&handle).await {
                Ok(()) => break,
                Err(err) if err.to_string().contains("still running") => {
                    assert!(
                        Instant::now() < deadline,
                        "the worker did not join after the host call returned"
                    );
                }
                Err(err) => panic!("stop after the host call: {err}"),
            }
        }
        assert!(provider.instances.read().await.is_empty());
        let quiet = Instant::now() + Duration::from_secs(2);
        while provider.threads_live.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < quiet, "the worker did not leave");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// A worker that joins after both stop windows still holds its slot.
    /// The frame and the book are already gone. The next launch removes the
    /// slot, so a new guest fits the cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_a_late_join_then_launch_fits_the_cap() {
        let provider = Arc::new(ComponentProvider::new());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let gate = release.clone();
        provider.set_bus_hostcall(Arc::new(move |_line, _, _| {
            let _ = entered_tx.send(());
            let (lock, cv) = &*gate;
            let mut open = lock.lock().expect("release");
            while !*open {
                open = cv.wait(open).expect("release");
            }
            Ok(serde_json::json!({
                "id": 1,
                "response": {
                    "type": "resource_result",
                    "result": { "status": "ok", "data": { "content": "ok", "size": 2 } },
                    "audit": "read-1"
                }
            })
            .to_string())
        }));
        let blocked = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-read-stream.wat"
        ))
        .unwrap();
        let resident = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let first = load_v2_fixture(&provider, blocked).await;
        {
            let mut entries = provider.instances.write().await;
            let instance = entries.get_mut(&first.id).unwrap();
            instance.join_bound = Duration::from_millis(40);
            hold_note_grant(&instance.grants);
        }
        provider.start(&first).await.unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the guest enters the host call");
        let second = load_v2_fixture(&provider, resident.clone()).await;
        provider.start(&second).await.unwrap();
        provider.testing_store_v2_frame(
            &first.id.0,
            None,
            vec![crate::providers::bus2_ui::FrameNode::Text("late".into())],
        );
        let err = provider.stop(&first).await.unwrap_err().to_string();
        assert!(
            err.contains("still running"),
            "the first stop window leaves the entry, got {err}"
        );
        provider.forget_instance(&first.id).await;
        {
            let instances = provider.instances.read().await;
            let slot = instances
                .get(&first.id)
                .expect("both stop windows left the entry");
            assert_eq!(slot.status, CapsuleStatus::Stopping);
            assert!(
                slot.join.as_ref().is_some_and(|join| !join.finished()),
                "the worker has not joined yet"
            );
        }
        assert!(
            provider
                .frames
                .lock()
                .expect("frames")
                .get(&first.id.0)
                .is_none(),
            "the frame is cleared before the join wait"
        );
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release") = true;
            cv.notify_all();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let done = provider
                .instances
                .read()
                .await
                .get(&first.id)
                .and_then(|instance| instance.join.as_ref().map(|join| join.finished()))
                .unwrap_or(false);
            if done {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the worker did not join after the host call returned"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            provider.instances.read().await.contains_key(&first.id),
            "a joined worker stays until the next status, stop, list, or launch"
        );
        assert!(
            provider
                .frames
                .lock()
                .expect("frames")
                .get(&first.id.0)
                .is_none(),
            "the frame stays gone while the slot waits for the next launch"
        );
        let third = load_v2_fixture(&provider, resident).await;
        provider
            .start(&third)
            .await
            .expect("a late join leaves a slot for the next launch");
        assert!(
            !provider.instances.read().await.contains_key(&first.id),
            "launch removes the joined entry"
        );
        assert!(
            provider
                .frames
                .lock()
                .expect("frames")
                .get(&first.id.0)
                .is_none(),
            "launch removes that entry's frame"
        );
        assert!(provider.instances.read().await.contains_key(&second.id));
        assert!(provider.instances.read().await.contains_key(&third.id));
        provider.stop(&second).await.unwrap();
        provider.stop(&third).await.unwrap();
    }

    /// The owner thread is not spawned. Stop joins the worker on its caller
    /// and the slot is free.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_join_owner_that_cannot_spawn_joins_inline() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.unwrap();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .refuse_join_owner = true;
        provider
            .stop(&handle)
            .await
            .expect("a join-owner that cannot be spawned joins on the caller");
        assert!(
            provider.instances.read().await.is_empty(),
            "the inline join frees the slot"
        );
        assert_eq!(
            provider.threads_live.load(Ordering::Acquire),
            0,
            "the worker was joined"
        );
    }

    /// Revoke, revoke-all, and activation end change the book before any poll.
    #[tokio::test]
    async fn v2_revoke_denies_present_and_read_before_the_guest_polls() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let book = provider
            .instances
            .read()
            .await
            .get(&handle.id)
            .unwrap()
            .grants
            .clone();
        book.lock().unwrap().hold("g1", "file", "read");
        book.lock().unwrap().hold("g2", "file", "read");
        provider.frames.lock().unwrap().insert(
            handle.id.0.clone(),
            StoredFrame {
                principal: None,
                frame: crate::providers::bus2_ui::Frame {
                    nodes: vec![crate::providers::bus2_ui::FrameNode::Image {
                        grant: "g1".into(),
                        resource: "file".into(),
                    }],
                },
            },
        );
        provider
            .deliver_grant_revoked(&handle.id, "g1")
            .await
            .unwrap();
        provider
            .deliver_grant_revoked(&handle.id, "g2")
            .await
            .unwrap();
        assert!(book.lock().unwrap().blocks_read("g1"));
        assert!(book.lock().unwrap().blocks_read("g2"));
        assert!(provider.frames.lock().unwrap().get(&handle.id.0).is_none());
        let called = Arc::new(AtomicBool::new(false));
        let seen = called.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |_, _, _| {
                seen.store(true, Ordering::Release);
                Ok(String::new())
            })),
            handle.id.0.clone(),
            None,
        );
        state.grants = book.clone();
        let media = crate::providers::bus2_ui::UI_MEDIA_TYPE;
        let present = crate::providers::bus2_ui::present_frame(
            media,
            br#"{"frame":[{"image":{"grant":"g1"}}]}"#,
            &book.lock().unwrap(),
        );
        assert!(present.is_err(), "{present:?}");
        let mut request = read_request(8);
        request.grant = Some("g1".into());
        let read = state.windowed_read(&request, false);
        assert!(read.is_err(), "{read:?}");
        assert!(
            !called.load(Ordering::Acquire),
            "a closed grant must not reach the bridge"
        );
        book.lock().unwrap().clear();
        assert!(book.lock().unwrap().blocks_read("later"));
        let present = crate::providers::bus2_ui::present_frame(
            media,
            br#"{"frame":[{"text":"still"}]}"#,
            &book.lock().unwrap(),
        );
        assert!(
            present.is_err(),
            "activation end closes present, got {present:?}"
        );
    }

    /// Prints the measured burn. The bucket bound is the constant property test.
    #[ignore = "prints the measured burn; the bucket bound is the constant property test"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_bucket_matches_two_seconds_of_the_shipped_busy_loop() {
        const SAMPLE: u64 = 50_000_000;
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        {
            let mut entries = provider.instances.write().await;
            let instance = entries.get_mut(&handle.id).unwrap();
            instance.v2_fuel = SAMPLE;
            instance.test_max_ticks = 1_000_000;
        }
        let started = Instant::now();
        provider.start(&handle).await.unwrap();
        let ending = tokio::time::timeout(Duration::from_secs(60), v2_ending(&provider, &handle))
            .await
            .expect("the busy loop ends")
            .to_string();
        let elapsed = started.elapsed().as_secs_f64();
        assert!(
            ending.contains(ENDING_EXECUTION_BOUND),
            "{ending} after {elapsed:.3}s"
        );
        let rate = SAMPLE as f64 / elapsed;
        let seconds = crate::providers::fuel_bucket::V2_BUCKET_CAPACITY as f64 / rate;
        let refill = crate::providers::fuel_bucket::V2_BUCKET_REFILL_PER_SEC;
        eprintln!(
            "calibration fuel_per_second={rate:.0} bucket_seconds={seconds:.3} refill_per_second={refill}"
        );
    }

    #[test]
    fn v2_four_memories_share_one_total() {
        let engine = quiet_v2_engine();
        let wasm = wat::parse_str(
            r#"(module
                (memory 1) (memory 1) (memory 1) (memory 1)
                (func (export "grow") (param i32) (result i32)
                    (memory.grow (local.get 0))))"#,
        )
        .expect("four memories");
        let module = wasmtime::Module::new(&engine, &wasm).expect("four memories");
        let mut store = Store::new(
            &engine,
            crate::providers::fuel_bucket::GuestMemory::default(),
        );
        store.limiter(|memory| memory);
        store.set_epoch_deadline(1_000_000);
        store.set_fuel(1_000_000).unwrap();
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
        let grow = instance
            .get_typed_func::<i32, i32>(&mut store, "grow")
            .unwrap();
        let grew = grow.call(&mut store, 2048).unwrap();
        assert_eq!(
            grew, -1,
            "four memories cannot grow past the one guest total"
        );
    }

    #[test]
    fn a_bridge_call_ends_at_its_deadline() {
        let slow: BridgeHostcallAsync = Arc::new(|_, _, _| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(String::new())
            })
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let err = rt
            .block_on(test_bridge(Some(slow), None, Duration::from_millis(40)))
            .expect_err("the guest must unblock");
        assert!(err.contains("timeout"), "{err}");
    }

    #[test]
    fn a_panicking_bridge_is_named_panicked() {
        let boom: BridgeHostcall = Arc::new(|_, _, _| panic!("bridge"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let err = rt
            .block_on(test_bridge(None, Some(boom), Duration::from_secs(2)))
            .expect_err("a panic must not look like success");
        assert!(err.contains("panicked"), "{err}");
        assert!(!err.contains("timeout"), "{err}");
    }

    /// The compute invoke calls this closure on the caller thread and has no
    /// 2 s cap. The thread `block_on_component_bridge` adds is the server row
    /// `v1_bridge_on_a_blocking_thread_adds_no_thread`.
    #[test]
    fn v1_read_slower_than_two_seconds_stays_on_the_caller_thread() {
        let caller = std::thread::current().id();
        let mut state = ComponentState::new(
            Some(Arc::new(move |_, _, _| {
                assert_eq!(
                    std::thread::current().id(),
                    caller,
                    "a v1 bridge adds no thread"
                );
                std::thread::sleep(Duration::from_millis(2100));
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": { "status": "ok", "data": { "content": {"b64": "Bw=="}, "size": 1 } },
                        "audit": "read-1"
                    }
                })
                .to_string())
            })),
            "capsule".into(),
            None,
        );
        let started = Instant::now();
        let response = elastos::bus::providers::Host::invoke(
            &mut state,
            elastos::bus::types::InvokeRequest {
                resource: "file".into(),
                operation: "read".into(),
                body: Vec::new(),
                grant: Some("g".into()),
            },
        )
        .expect("a v1 read slower than the v2 cap still succeeds");
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(response.status, "ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_an_idle_resident_stays_up_for_many_epochs() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 2;
        provider.start(&handle).await.unwrap();
        for _ in 0..24 {
            let sender = provider
                .instances
                .read()
                .await
                .get(&handle.id)
                .and_then(|instance| instance.events.clone());
            if let Some(sender) = sender {
                let _ = sender.send(v2::elastos::bus::types::Event::Message(Vec::new()));
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
            assert!(
                !provider.endings.read().await.contains_key(&handle.id),
                "an idle resident ended during the many epochs: {:?}",
                provider.endings.read().await.get(&handle.id)
            );
        }
        provider.stop(&handle).await.unwrap();
        assert_eq!(v2_ending(&provider, &handle).await, "stopped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_wait_after_close_ends_cancelled_after_grace() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "local.get $event i32.const 2 i32.eq\n      if",
            "call $new-stream global.set $other\n      global.get $other i32.wrap_i64 global.set $events\n      global.get $events i32.const 128 i32.const 1 call $read\n      i32.const -1 i32.ne if unreachable end\n      global.get $events global.get $set call $join\n      global.get $set i32.const 4 i32.shl i32.const 2 i32.or return\n      local.get $event i32.const 2 i32.eq\n      if",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.unwrap();
        v2_pending_read(&provider, &handle).await;
        provider.stop(&handle).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), v2_ending(&provider, &handle))
                .await
                .expect("waiting guest must be aborted after grace"),
            "cancelled"
        );
        assert!(provider.instances.read().await.is_empty());
    }

    #[tokio::test]
    async fn v2_event_wakes_do_not_spend_the_execution_budget() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 8;
        provider.start(&handle).await.unwrap();
        for _ in 0..10 {
            let sender = provider
                .instances
                .read()
                .await
                .get(&handle.id)
                .and_then(|instance| instance.events.clone());
            if let Some(sender) = sender {
                let _ = sender.send(v2::elastos::bus::types::Event::Message(Vec::new()));
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        provider.stop(&handle).await.unwrap();
        assert_eq!(v2_ending(&provider, &handle).await, "stopped");
    }

    /// `$next` burns Wasm, then reads one event, and repeats. The burn is
    /// longer than one 10 ms tick and shorter than the six-tick cap, so a
    /// tick lands while the guest is still in Wasm. The read delivers an
    /// event in that window. A delivery leaves the tick count as it is, and
    /// the guest ends on the tick bound.
    ///
    /// Six ticks are 60 ms when the shared ticker is on time. One fuel bucket
    /// is about two seconds of a tight burn, and a late ticker makes those
    /// six ticks take longer than that bucket. The fuel here is many buckets,
    /// so the execution bound cannot win the race. The sender and the waiter
    /// sleep. The guest's burn is the only spinning work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_a_delivered_event_does_not_clear_the_tick_bound() {
        let provider = ComponentProvider::new();
        let bytes = tick_bound_guest(wasm_burn_iterations(Duration::from_millis(30)));
        let handle = load_v2_fixture(&provider, bytes).await;
        {
            let mut instances = provider.instances.write().await;
            let guest = instances.get_mut(&handle.id).unwrap();
            guest.test_max_ticks = 6;
            guest.v2_fuel = crate::providers::fuel_bucket::V2_BUCKET_CAPACITY.saturating_mul(64);
        }
        provider.start(&handle).await.unwrap();
        let sender = provider
            .instances
            .read()
            .await
            .get(&handle.id)
            .and_then(|instance| instance.events.clone())
            .expect("the guest is reading events");
        for _ in 0..8 {
            sender
                .send(v2::elastos::bus::types::Event::Message(Vec::new()))
                .expect("the guest accepts the first events");
        }
        let source = std::thread::spawn(move || loop {
            for _ in 0..8 {
                if sender
                    .send(v2::elastos::bus::types::Event::Message(Vec::new()))
                    .is_err()
                {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        });
        let ending = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the tick bound did not end the guest");
        source.join().expect("the event source");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "a stream of events must still end on the tick bound, got {ending}"
        );
    }

    /// How many iterations of the `$next` burn take about `burn` on this
    /// engine. Debug and release run the same Wasm at different speeds, so a
    /// fixed count is either too short to hold a tick or long enough to hit
    /// the six-tick cap before a delivery. The sample is the same loop the
    /// guest runs. Two timed calls follow one warmup, and the count is their
    /// average.
    fn wasm_burn_iterations(burn: Duration) -> u32 {
        const SAMPLE: i32 = 100_000;
        let engine = ComponentProvider::v2_engine().expect("v2 engine");
        let bytes = wat::parse_str(
            r#"(module
                (func (export "burn") (param $n i32)
                  (local $i i32)
                  (loop $again
                    local.get $i
                    i32.const 1
                    i32.add
                    local.tee $i
                    local.get $n
                    i32.ne
                    br_if $again)))"#,
        )
        .expect("burn module");
        let module = wasmtime::Module::new(&engine, bytes).expect("burn module");
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_fuel(4_000_000_000).expect("fuel");
        store.set_epoch_deadline(1_000_000_000);
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("burn instance");
        let burn_fn = instance
            .get_typed_func::<i32, ()>(&mut store, "burn")
            .expect("burn");
        burn_fn.call(&mut store, SAMPLE).expect("warmup");
        let mut elapsed = Duration::ZERO;
        for _ in 0..2 {
            let started = Instant::now();
            burn_fn.call(&mut store, SAMPLE).expect("sample burn");
            elapsed += started.elapsed();
        }
        let elapsed = (elapsed / 2).max(Duration::from_micros(1));
        let iterations = (burn.as_secs_f64() / elapsed.as_secs_f64() * f64::from(SAMPLE))
            .ceil()
            .clamp(1_000.0, 200_000_000.0);
        iterations as u32
    }

    /// The resident `$next`, with a Wasm burn before every read.
    fn tick_bound_guest(iterations: u32) -> Vec<u8> {
        let next = format!(
            "(func $next (result i32)\n      \
             (local $code i32)\n      \
             (local $spin i32)\n      \
             (loop $again\n        \
             (loop $burn\n          \
             local.get $spin\n          \
             i32.const 1\n          \
             i32.add\n          \
             local.tee $spin\n          \
             i32.const {iterations}\n          \
             i32.ne\n          \
             br_if $burn)\n        \
             i32.const 0\n        \
             local.set $spin\n        \
             global.get $events i32.const 128 i32.const 1 call $read"
        );
        v2_variant(&[(
            "(func $next (result i32)\n      \
             (local $code i32)\n      \
             (loop $again\n        \
             global.get $events i32.const 128 i32.const 1 call $read",
            &next,
        )])
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_spin_ends_epoch_deadline() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.unwrap();
        let ending = tokio::time::timeout(Duration::from_secs(1), v2_ending(&provider, &handle))
            .await
            .expect("spin must reach its execution budget");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "spin ending was {ending}"
        );
        assert!(provider.instances.read().await.is_empty());
    }

    /// A clock sleep is parked time. The tick cap is shorter than the sleep
    /// and does not end the guest, and the guest answers when it wakes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_sleep_past_the_run_deadline_returns() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-sleep.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        {
            let mut entries = provider.instances.write().await;
            entries.get_mut(&handle.id).unwrap().test_max_ticks = 4;
        }
        provider.start(&handle).await.expect("the sleeper starts");
        let started = Instant::now();
        let ending = v2_ending(&provider, &handle).await;
        let elapsed = started.elapsed();
        let tick_cap = DEADLINE_TICK.saturating_mul(u32::try_from(V2_TEST_EPOCH_TICKS).unwrap());
        assert!(
            elapsed >= tick_cap,
            "the sleep must outlast the {V2_TEST_EPOCH_TICKS}-tick cap, elapsed {} ms",
            elapsed.as_millis()
        );
        assert_eq!(ending, "returned", "{ending}");
    }

    /// Cancel wakes one long sleep. The wait is not a 10 ms poll.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_cancel_ends_a_very_long_sleep_within_100ms() {
        let provider = ComponentProvider::new();
        let source = include_str!("../../../../tests/fixtures/components/v2-sleep.wat")
            .replace("i64.const 400", "i64.const -1");
        let bytes = wat::parse_str(&source).expect("u64::MAX sleep");
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.expect("the sleeper starts");
        let (sleeping, wake, cancel) = {
            let instances = provider.instances.read().await;
            let instance = instances.get(&handle.id).expect("the guest is loaded");
            (
                instance.in_clock_sleep.clone(),
                instance.wake.clone(),
                instance.cancel_requested.clone(),
            )
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !sleeping.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the guest enters the clock sleep");
        assert!(
            provider.endings.read().await.get(&handle.id).is_none(),
            "the long sleep is still in progress"
        );
        let started = Instant::now();
        cancel.store(true, Ordering::Release);
        wake.notify_one();
        let ending = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancel ends a very long sleep within 100 ms");
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "elapsed {} ms",
            started.elapsed().as_millis()
        );
        assert!(
            ending == "returned"
                || ending.contains("stopped")
                || ending.contains(ENDING_EPOCH_DEADLINE),
            "{ending}"
        );
    }

    #[test]
    fn a_small_bucket_survives_many_wakes_and_a_rising_burn_ends() {
        let mut config = ComponentProvider::v2_config();
        config.macos_use_mach_ports(false);
        let engine = Engine::new(&config).expect("v2 engine");
        let mut store = Store::new(&engine, ());
        let bucket = Mutex::new(crate::providers::fuel_bucket::FuelBucket::full(
            100_000,
            Instant::now(),
        ));
        store.set_fuel(100_000).unwrap();
        for _ in 0..40 {
            bucket.lock().unwrap().resume();
            let lent = bucket.lock().unwrap().lent;
            store.set_fuel(lent.saturating_sub(1)).unwrap();
            std::thread::sleep(Duration::from_micros(900));
            charge_bucket(&bucket, &mut store).expect("a 0.9 ms wake charges");
            assert!(
                store.get_fuel().unwrap() > 1,
                "many short wakes must not empty a small bucket"
            );
        }
        let mut burn = 1_000u64;
        for _ in 0..20 {
            bucket.lock().unwrap().resume();
            bucket.lock().unwrap().close_the_gap();
            let lent = bucket.lock().unwrap().lent;
            let step = burn.min(lent);
            store.set_fuel(lent - step).unwrap();
            charge_bucket(&bucket, &mut store).expect("a rising burn charges");
            if store.get_fuel().unwrap() == 0 {
                break;
            }
            burn = burn.saturating_mul(2);
        }
        assert_eq!(store.get_fuel().unwrap(), 0, "a rising burn ends the loan");
    }

    #[test]
    fn fuel_errors_are_named_get_fuel_and_set_fuel() {
        let mut config = ComponentProvider::v2_config();
        config.consume_fuel(false);
        config.macos_use_mach_ports(false);
        let engine = Engine::new(&config).expect("engine");
        let mut store = Store::new(&engine, ());
        let bucket = Mutex::new(crate::providers::fuel_bucket::FuelBucket::full(
            8,
            Instant::now(),
        ));
        assert_eq!(
            charge_bucket(&bucket, &mut store).expect_err("fuel is off"),
            "get_fuel"
        );
        assert_eq!(bucket.lock().unwrap().fault, Some("get_fuel"));
        assert_eq!(
            write_fuel(&mut store, 1).expect_err("fuel is off"),
            "set_fuel"
        );
    }

    #[test]
    fn a_dropped_guard_clears_an_open_bucket() {
        let bucket = Arc::new(Mutex::new(crate::providers::fuel_bucket::FuelBucket::full(
            8,
            Instant::now(),
        )));
        {
            bucket.lock().unwrap().open = true;
            bucket.lock().unwrap().window_ticks = 9;
            bucket.lock().unwrap().begin_sleep_wait(Instant::now());
            let _guard = resume_guard(&Some(Arc::clone(&bucket)));
            assert!(bucket.lock().unwrap().open);
            assert!(!bucket.lock().unwrap().parked);
        }
        let slot = bucket.lock().unwrap();
        assert!(!slot.open);
        assert!(!slot.parked);
        assert_eq!(
            slot.window_ticks, 9,
            "a dropped sleep does not refill the window"
        );
    }

    #[test]
    fn spend_b_minus_one_sleep_past_a_refill_then_spend_lives() {
        let engine = quiet_v2_engine();
        let bucket = Arc::new(Mutex::new(crate::providers::fuel_bucket::FuelBucket::full(
            10_000,
            Instant::now(),
        )));
        let mut store = Store::new(&engine, ());
        store.set_fuel(10_000).unwrap();
        bucket.lock().unwrap().close_the_gap();
        store.set_fuel(1).unwrap();
        assert!(charge_bucket(&bucket, &mut store).unwrap());
        let loan = store.get_fuel().unwrap();
        assert_eq!(loan, 1, "the loan is the remainder");
        bucket.lock().unwrap().park();
        std::thread::sleep(Duration::from_millis(300));
        close_wait_loan(&bucket, &mut store);
        let fuel = store.get_fuel().unwrap();
        assert!(fuel > 1_000, "the wait wrote the refill, got {fuel}");
        store.set_fuel(fuel - 1_000).unwrap();
        assert!(charge_bucket(&bucket, &mut store).unwrap());
        assert!(store.get_fuel().unwrap() > 0);
    }

    #[test]
    fn an_error_from_begin_read_leaves_the_slot_usable() {
        let engine = quiet_v2_engine();
        let bucket = Arc::new(Mutex::new(crate::providers::fuel_bucket::FuelBucket::full(
            1_000,
            Instant::now(),
        )));
        let mut state = ComponentState::new(None, "capsule".into(), None);
        state.fuel_bucket = Some(bucket.clone());
        let mut store = Store::new(&engine, state);
        store.set_fuel(1_000).unwrap();
        let request = v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Local/a".into(),
            operation: "stat".into(),
            grant: Some("g".into()),
            params: Vec::new(),
        };
        let opened = charge_access(&mut store);
        assert!(opened);
        let pending = store.data().begin_read(&request, false);
        let guard = arm_host_wait(opened, &Some(bucket.clone()));
        assert!(pending.is_err(), "stat is not a read");
        drop(guard);
        assert!(!bucket.lock().unwrap().open, "the error left the loan open");
        let left = store.get_fuel().unwrap();
        store.set_fuel(left.saturating_sub(10)).unwrap();
        assert!(charge_bucket(&bucket, &mut store).is_ok());
        assert!(store.get_fuel().unwrap() > 0);
    }

    fn token_line(token: &str, extra: &str) -> String {
        format!(r#"{{"id":1,"response":{{"type":"capability_token","token":"{token}"{extra}}}}}"#)
    }

    fn one_read_grant(state: &mut ComponentState) -> PendingGrant {
        state
            .begin_grant(elastos::bus::types::CapabilityRequest {
                resource: "localhost://Local/a".into(),
                actions: vec!["read".into()],
                reason: String::new(),
            })
            .expect("begin grant")
    }

    #[test]
    fn thirty_three_revokes_refuse_an_in_flight_grant() {
        let mut state = ComponentState::new(None, "capsule".into(), None);
        let pending = one_read_grant(&mut state);
        let epoch = pending.epoch;
        for n in 0..33 {
            state
                .grants
                .lock()
                .expect("grant book")
                .revoke(&format!("other-{n}"));
        }
        let err = state
            .finish_grant(pending, Ok(token_line("g0", "")))
            .expect_err("the in-flight grant is refused");
        let message = format!("{err:?}");
        assert!(message.contains("revoked"), "{message}");
        assert!(state.grants.lock().expect("grant book").blocks_read("g0"));
        assert_ne!(state.grants.lock().expect("grant book").epoch(), epoch);
    }

    #[test]
    fn a_once_grant_read_then_present_is_refused() {
        let mut state = ComponentState::new(None, "capsule".into(), None);
        let pending = one_read_grant(&mut state);
        let grant = state
            .finish_grant(pending, Ok(token_line("once", r#","max_uses":1"#)))
            .expect("once grant");
        let request = v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Local/a".into(),
            operation: "read".into(),
            grant: Some(grant.id.clone()),
            params: br#"{"max_bytes":8}"#.to_vec(),
        };
        let read = state.begin_read(&request, false).expect("begin read");
        let body = r#"{"id":1,"response":{"type":"resource_result","result":{"status":"ok","data":{"content":{"b64":"aGk="},"size":2}}}}"#;
        state
            .finish_read(read, Ok(body.to_string()))
            .expect("the one read");
        assert!(state.grants.lock().expect("grant book").blocks_read("once"));
        let doc = r#"{"frame":[{"image":{"grant":"once"}}]}"#;
        let err = state
            .present_document(crate::providers::bus2_ui::UI_MEDIA_TYPE, doc.as_bytes())
            .expect_err("a spent grant is not presented");
        assert!(format!("{err:?}").contains("spent"), "{err:?}");

        let pending = one_read_grant(&mut state);
        let grant = state
            .finish_grant(pending, Ok(token_line("old", r#","expires_at_ms":1"#)))
            .expect("expired grant");
        assert_eq!(grant.id, "old");
        assert!(state.grants.lock().expect("grant book").blocks_read("old"));
        let doc = r#"{"frame":[{"image":{"grant":"old"}}]}"#;
        let err = state
            .present_document(crate::providers::bus2_ui::UI_MEDIA_TYPE, doc.as_bytes())
            .expect_err("an expired grant is not presented");
        assert!(format!("{err:?}").contains("expired"), "{err:?}");
    }

    /// A once grant is one count. A read validate spent is spent here too when
    /// the read then fails. A present spends that same count through the runtime.
    #[test]
    fn a_once_grant_is_one_count_for_a_failed_read_and_a_present() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _, _| {
                seen.lock().expect("lines").push(line.to_string());
                Ok(use_spent_host()("x", "y", None).expect("host"))
            })),
            "capsule".into(),
            None,
        );
        let media = crate::providers::bus2_ui::UI_MEDIA_TYPE;
        let once = |state: &mut ComponentState, id: &str| {
            let pending = one_read_grant(state);
            state
                .finish_grant(pending, Ok(token_line(id, r#","max_uses":1"#)))
                .expect("once grant")
        };
        let read_of = |id: &str| v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Local/a".into(),
            operation: "read".into(),
            grant: Some(id.into()),
            params: br#"{"max_bytes":8}"#.to_vec(),
        };
        let image = |id: &str| format!(r#"{{"frame":[{{"image":{{"grant":"{id}"}}}}]}}"#);
        let failed = once(&mut state, "fail");
        let pending = state
            .begin_read(&read_of(&failed.id), false)
            .expect("begin");
        state
            .finish_read(
                pending,
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "error",
                        "code": "not_found",
                        "message": "missing",
                        "use_spent": true
                    }
                })
                .to_string()),
            )
            .expect_err("the read fails");
        assert!(state.grants.lock().expect("grant book").blocks_read("fail"));
        let err = state
            .present_document(media, image("fail").as_bytes())
            .expect_err("a failed read spends the present");
        assert!(format!("{err:?}").contains("fail is spent"), "{err:?}");
        assert!(lines.lock().expect("lines").is_empty());

        let big = once(&mut state, "big");
        let pending = state.begin_read(&read_of(&big.id), false).expect("begin");
        state
            .finish_read(pending, Ok(ok_text_read("0123456789")))
            .expect_err("over the cap");
        assert!(state.grants.lock().expect("grant book").blocks_read("big"));
        let err = state
            .present_document(media, image("big").as_bytes())
            .expect_err("an oversize read spends the present");
        assert!(format!("{err:?}").contains("big is spent"), "{err:?}");

        let show = once(&mut state, "show");
        state
            .present_document(media, image(&show.id).as_bytes())
            .expect("present spends through the runtime");
        let called = lines.lock().expect("lines").clone();
        assert_eq!(called.len(), 2, "{called:?}");
        let check: serde_json::Value = serde_json::from_str(&called[0]).expect("check");
        let spend: serde_json::Value = serde_json::from_str(&called[1]).expect("spend");
        assert_eq!(check["request"]["body"]["count_use"], false);
        assert!(check["request"]["body"]["use_grant"].is_null());
        assert_eq!(spend["request"]["type"], "resource_invoke");
        assert_eq!(spend["request"]["operation"], "read");
        assert_eq!(spend["request"]["body"]["use_grant"], true);
        assert_eq!(spend["request"]["token"], show.id);
        let refused = state.begin_read(&read_of(&show.id), false);
        let Err(err) = refused else {
            panic!("the present spent the read");
        };
        assert!(format!("{err:?}").contains("the grant is spent"), "{err:?}");

        state.hostcall = Some(Arc::new(|_, _, _| {
            Ok(serde_json::json!({
                "id": 1,
                "response": {"type": "resource_result", "result": {"status": "ok"}}
            })
            .to_string())
        }));
        let bare = once(&mut state, "bare");
        state
            .present_document(media, image(&bare.id).as_bytes())
            .expect_err("a present with no runtime spend is refused");
        state
            .begin_read(&read_of(&bare.id), false)
            .expect("the book was not spent alone");
    }

    /// A file whose bytes are the stamp text spends one use of a two-use grant.
    /// The same text elsewhere in the envelope is not the stamp.
    #[test]
    fn a_file_that_says_use_spent_on_a_two_use_grant_leaves_one_use() {
        let mut state = ComponentState::new(None, "capsule".into(), None);
        let read_of = |id: &str| v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Local/a".into(),
            operation: "read".into(),
            grant: Some(id.into()),
            params: br#"{"max_bytes":64}"#.to_vec(),
        };
        let two = |state: &mut ComponentState, id: &str| {
            let pending = one_read_grant(state);
            state
                .finish_grant(pending, Ok(token_line(id, r#","max_uses":2"#)))
                .expect("two-use grant")
        };
        let file = r#""use_spent":true"#;
        let grant = two(&mut state, "file");
        let pending = state.begin_read(&read_of(&grant.id), false).expect("begin");
        let prepared = state
            .finish_read(
                pending,
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": {
                            "status": "ok",
                            "data": { "content": file, "size": file.len() },
                            "audit": "read-1"
                        },
                        "use_spent": true
                    }
                })
                .to_string()),
            )
            .expect("the file is read");
        assert_eq!(prepared.bytes, file.as_bytes());
        let pending = state
            .begin_read(&read_of(&grant.id), false)
            .expect("one use remains");
        state
            .finish_read(pending, Ok(ok_text_read("hi")))
            .expect("the last use");
        let refused = state.begin_read(&read_of(&grant.id), false);
        let Err(err) = refused else {
            panic!("two uses are gone");
        };
        assert!(format!("{err:?}").contains("the grant is spent"), "{err:?}");

        let body = two(&mut state, "body");
        let pending = state.begin_read(&read_of(&body.id), false).expect("begin");
        let raw = serde_json::json!({
            "id": 1,
            "response": {
                "type": "error",
                "code": "not_found",
                "message": "missing",
                "detail": {"use_spent": true}
            }
        })
        .to_string();
        assert!(raw.contains("\"use_spent\":true"), "{raw}");
        state
            .finish_read(pending, Ok(raw))
            .expect_err("the read fails");
        let pending = state
            .begin_read(&read_of(&body.id), false)
            .expect("the body text did not spend a use");
        state
            .finish_read(pending, Ok(ok_text_read("a")))
            .expect("the first use");
        let pending = state
            .begin_read(&read_of(&body.id), false)
            .expect("one use remains");
        state
            .finish_read(pending, Ok(ok_text_read("b")))
            .expect("the second use");
        let refused = state.begin_read(&read_of(&body.id), false);
        let Err(err) = refused else {
            panic!("both uses are gone");
        };
        assert!(format!("{err:?}").contains("the grant is spent"), "{err:?}");
    }

    /// The last use is spent when the read finishes. The product stop still
    /// sends every byte and an ok trailer. The next read is spent. A revoke
    /// in the middle of a stream ends it with an error trailer.
    #[test]
    fn a_once_grant_delivers_its_bytes_and_a_revoke_ends_the_stream() {
        let mut state = ComponentState::new(None, "capsule".into(), None);
        let pending = one_read_grant(&mut state);
        let grant = state
            .finish_grant(pending, Ok(token_line("once", r#","max_uses":1"#)))
            .expect("once grant");
        let mut request = v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Local/a".into(),
            operation: "read".into(),
            grant: Some(grant.id.clone()),
            params: br#"{"max_bytes":8}"#.to_vec(),
        };
        let read = state.begin_read(&request, false).expect("begin read");
        let prepared = state
            .finish_read(read, Ok(ok_text_read("hi")))
            .expect("the one read");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stop_requested = state.stop_requested.clone();
        let cancel_requested = state.cancel_requested.clone();
        let grants = state.grants.clone();
        let grant_id = grant.id.clone();
        let mut stream =
            crate::providers::bus2_stream::WindowRead::new(prepared.bytes, tx, prepared.hold)
                .stop_when(Arc::new(move || {
                    v2_read_stopped(&stop_requested, &cancel_requested, &grants, &grant_id)
                }));
        let mut got = Vec::new();
        while let Some(chunk) = stream.pull(usize::MAX) {
            got.extend(chunk);
        }
        assert_eq!(got, b"hi");
        assert!(rx.blocking_recv().expect("trailer").is_ok());
        let err = match state.begin_read(&request, false) {
            Err(err) => err,
            Ok(_) => panic!("a second read was accepted"),
        };
        let message = format!("{err:?}");
        assert!(message.contains("the grant is spent"), "{message}");

        let pending = one_read_grant(&mut state);
        let grant = state
            .finish_grant(pending, Ok(token_line("mid", r#","max_uses":1"#)))
            .expect("a second once grant");
        request.grant = Some(grant.id.clone());
        request.params = br#"{"max_bytes":64}"#.to_vec();
        let read = state
            .begin_read(&request, false)
            .expect("begin the mid read");
        let prepared = state
            .finish_read(read, Ok(ok_text_read("abcdefghij")))
            .expect("finish the mid read");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stop_requested = state.stop_requested.clone();
        let cancel_requested = state.cancel_requested.clone();
        let grants = state.grants.clone();
        let grant_id = grant.id.clone();
        let mut stream =
            crate::providers::bus2_stream::WindowRead::new(prepared.bytes, tx, prepared.hold)
                .stop_when(Arc::new(move || {
                    v2_read_stopped(&stop_requested, &cancel_requested, &grants, &grant_id)
                }));
        assert_eq!(stream.pull(1).as_deref(), Some(&b"a"[..]));
        state.grants.lock().expect("grant book").revoke("mid");
        assert!(stream.pull(8).is_none(), "a revoke ends the stream");
        let trailer = rx.blocking_recv().expect("error trailer");
        assert!(trailer.is_err(), "{trailer:?}");
    }

    fn ok_text_read(content: &str) -> String {
        serde_json::json!({
            "id": 1,
            "response": {
                "type": "resource_result",
                "result": {
                    "status": "ok",
                    "data": { "content": content, "size": content.len() },
                    "audit": "read-1"
                },
                "use_spent": true
            }
        })
        .to_string()
    }

    fn use_spent_host() -> BridgeHostcall {
        Arc::new(|_, _, _| {
            Ok(serde_json::json!({
                "id": 1,
                "response": {
                    "type": "resource_result",
                    "result": {"status": "ok"},
                    "use_spent": true
                }
            })
            .to_string())
        })
    }

    async fn presented_image(
        provider: &ComponentProvider,
        id: &str,
        grant: &str,
        uses_left: Option<u32>,
        expires_at_ms: Option<u64>,
    ) {
        let grants = provider.instances.read().await[&elastos_common::CapsuleId::new(id)]
            .grants
            .clone();
        grants.lock().expect("grant book").hold_limited(
            grant,
            "localhost://Users/self/Pictures/a.png",
            "read",
            uses_left,
            expires_at_ms,
        );
        let mut state = ComponentState::new(Some(use_spent_host()), id.into(), None);
        state.grants = grants;
        state.frames = provider.frames.clone();
        let doc = format!(r#"{{"frame":[{{"image":{{"grant":"{grant}"}}}},{{"text":"kept"}}]}}"#);
        state
            .present_document(crate::providers::bus2_ui::UI_MEDIA_TYPE, doc.as_bytes())
            .expect("the live grant is presented");
    }

    fn image_count(frame: &crate::providers::bus2_ui::Frame) -> usize {
        frame
            .nodes
            .iter()
            .filter(|node| matches!(node, crate::providers::bus2_ui::FrameNode::Image { .. }))
            .count()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_once_grant_stays_for_two_reads_until_revoke() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        presented_image(&provider, handle.id.as_str(), "pic", Some(1), None).await;
        assert!(
            provider.instances.read().await[&handle.id]
                .grants
                .lock()
                .expect("grant book")
                .blocks_read("pic"),
            "present spent the one use"
        );
        for _ in 0..2 {
            let frame = provider
                .read_v2_frame(None, handle.id.as_str())
                .await
                .expect("frame");
            assert_eq!(image_count(&frame), 1, "a spent present stays");
            assert!(matches!(
                frame.nodes.first(),
                Some(crate::providers::bus2_ui::FrameNode::Image { resource, .. })
                    if resource == "localhost://Users/self/Pictures/a.png"
            ));
        }
        provider
            .deliver_grant_revoked(&handle.id, "pic")
            .await
            .expect("revoke");
        assert!(
            provider
                .read_v2_frame(None, handle.id.as_str())
                .await
                .is_none(),
            "revoke removes the stored frame"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_present_then_expire_drops_the_image() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64
            + 200;
        presented_image(&provider, handle.id.as_str(), "pic", None, Some(expires)).await;
        let shown = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("frame");
        assert_eq!(image_count(&shown), 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let later = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("frame");
        assert_eq!(image_count(&later), 0);
        assert!(matches!(
            later.nodes.first(),
            Some(crate::providers::bus2_ui::FrameNode::Text(text)) if text == "kept"
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn thirty_two_newer_grants_drop_a_presented_image() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        presented_image(&provider, handle.id.as_str(), "pic", None, None).await;
        let book = provider.instances.read().await[&handle.id].grants.clone();
        for n in 0..32 {
            book.lock().expect("grant book").hold_limited(
                &format!("newer-{n}"),
                "localhost://Users/self/Pictures/a.png",
                "read",
                None,
                None,
            );
        }
        let frame = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("frame");
        assert_eq!(image_count(&frame), 0);
        assert!(matches!(
            frame.nodes.first(),
            Some(crate::providers::bus2_ui::FrameNode::Text(text)) if text == "kept"
        ));
    }

    /// A read that cannot take the instances lock answers empty. It does not
    /// return the stored frame. After the lock, expiry and eviction leave the
    /// text and drop the image. A closed book answers nothing, text included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_frame_read_answers_empty_until_it_can_check_the_book() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(&handle.id, "pic", "localhost://photo", "read")
            .await;
        let nodes = vec![
            crate::providers::bus2_ui::FrameNode::Text("kept".into()),
            crate::providers::bus2_ui::FrameNode::Image {
                grant: "pic".into(),
                resource: "localhost://photo".into(),
            },
        ];
        provider.testing_store_v2_frame(handle.id.as_str(), None, nodes);
        *provider.frame_read_bound.lock().expect("bound") = Some(Duration::from_millis(40));
        let hold = provider.instances.write().await;
        let reading = {
            let provider = provider.clone();
            let id = handle.id.0.clone();
            tokio::spawn(async move { provider.read_v2_frame(None, &id).await })
        };
        let answer = tokio::time::timeout(Duration::from_secs(1), reading)
            .await
            .expect("the read ends on the route deadline")
            .expect("read task");
        assert!(
            answer.is_none(),
            "a blocked book check answers empty, not the stored frame: {answer:?}"
        );
        assert!(provider
            .frames
            .lock()
            .expect("frames")
            .get(&handle.id.0)
            .is_some_and(|stored| {
                stored.frame.nodes.iter().any(|node| {
                    matches!(node, crate::providers::bus2_ui::FrameNode::Text(text) if text == "kept")
                })
            }));
        drop(hold);
        let live = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("the book is open");
        assert_eq!(image_count(&live), 1);

        let hold = provider.instances.write().await;
        hold[&handle.id]
            .grants
            .lock()
            .expect("grant book")
            .testing_expire("pic");
        let reading = {
            let provider = provider.clone();
            let id = handle.id.0.clone();
            tokio::spawn(async move { provider.read_v2_frame(None, &id).await })
        };
        let answer = tokio::time::timeout(Duration::from_secs(1), reading)
            .await
            .expect("expiry does not return the stored frame")
            .expect("read task");
        assert!(answer.is_none(), "{answer:?}");
        drop(hold);
        let expired = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("text stays after expiry");
        assert_eq!(image_count(&expired), 0);
        assert!(matches!(
            expired.nodes.first(),
            Some(crate::providers::bus2_ui::FrameNode::Text(text)) if text == "kept"
        ));

        provider.instances.read().await[&handle.id]
            .grants
            .lock()
            .expect("grant book")
            .hold("evict", "localhost://photo", "read");
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![
                crate::providers::bus2_ui::FrameNode::Text("kept".into()),
                crate::providers::bus2_ui::FrameNode::Image {
                    grant: "evict".into(),
                    resource: "localhost://photo".into(),
                },
            ],
        );
        let hold = provider.instances.write().await;
        let book = hold[&handle.id].grants.clone();
        for n in 0..32 {
            book.lock().expect("grant book").hold_limited(
                &format!("newer-{n}"),
                "localhost://Users/self/Pictures/a.png",
                "read",
                None,
                None,
            );
        }
        let reading = {
            let provider = provider.clone();
            let id = handle.id.0.clone();
            tokio::spawn(async move { provider.read_v2_frame(None, &id).await })
        };
        let answer = tokio::time::timeout(Duration::from_secs(1), reading)
            .await
            .expect("eviction does not return the stored frame")
            .expect("read task");
        assert!(answer.is_none(), "{answer:?}");
        drop(hold);
        let evicted = provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .expect("text stays after eviction");
        assert_eq!(image_count(&evicted), 0);
        assert!(matches!(
            evicted.nodes.first(),
            Some(crate::providers::bus2_ui::FrameNode::Text(text)) if text == "kept"
        ));

        provider.instances.read().await[&handle.id]
            .grants
            .lock()
            .expect("grant book")
            .clear();
        assert!(provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .is_none());
        assert!(provider
            .frames
            .lock()
            .expect("frames")
            .get(&handle.id.0)
            .is_some_and(|stored| {
                stored.frame.nodes.iter().any(|node| {
                    matches!(node, crate::providers::bus2_ui::FrameNode::Text(text) if text == "kept")
                })
            }));
    }

    fn quiet_v2_engine() -> Engine {
        let mut config = ComponentProvider::v2_config();
        config.macos_use_mach_ports(false);
        Engine::new(&config).expect("v2 engine without a ticker")
    }

    async fn drive_v2_guest(
        engine: &Engine,
        component: Component,
        fuel: u64,
        fuel_slice: u64,
        max_ticks: u64,
        close: bool,
    ) -> String {
        let (sender, receiver) = mpsc::unbounded_channel();
        let _open = (!close).then_some(sender);
        let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
        let control = V2RunControl {
            stop_requested: Arc::new(AtomicBool::new(close)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            max_ticks,
            fuel,
            fuel_slice,
            pending_read: Arc::new(AtomicBool::new(false)),
            wall_clock: false,
        };
        match ComponentProvider::run_v2(
            engine.clone(),
            component,
            ComponentState::new(None, "v2".into(), None),
            receiver,
            control,
            ready_tx,
        )
        .await
        {
            Ok(ending) => ending.to_string(),
            Err(error) => error.to_string(),
        }
    }

    /// One tick is four yields. The clock moves only when a guest gives the
    /// thread back, so the row does not use a wall-clock budget. Both guests
    /// use the production fuel and slice. A slice as large as that fuel lets
    /// the busy guest run without yielding.
    #[tokio::test(flavor = "current_thread")]
    async fn v2_busy_guest_does_not_finish_before_a_second_guest() {
        const TURNS_PER_TICK: u64 = 4;
        const SHORT_STARTS_AT: u64 = 2;
        const BUSY_TICKS: u64 = 12;
        let engine = quiet_v2_engine();
        let busy = Component::new(
            &engine,
            v2_variant(&[(
                "call $new global.set $set\n      call $next)",
                "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
            )]),
        )
        .expect("busy guest");
        let short = Component::new(&engine, v2_variant(&[])).expect("short guest");
        let turns = Arc::new(AtomicU64::new(0));
        let (clock_turns, busy_turns, short_turns) = (turns.clone(), turns.clone(), turns);
        let (engine_busy, engine_short, clock_engine) = (engine.clone(), engine.clone(), engine);
        let mut work = std::pin::pin!(async move {
            let busy_run = async move {
                let ending = drive_v2_guest(
                    &engine_busy,
                    busy,
                    crate::providers::fuel_bucket::V2_BUCKET_CAPACITY,
                    V2_FUEL_SLICE,
                    BUSY_TICKS,
                    false,
                )
                .await;
                (ending, busy_turns.load(Ordering::Relaxed) / TURNS_PER_TICK)
            };
            let short_run = async move {
                while short_turns.load(Ordering::Relaxed) / TURNS_PER_TICK < SHORT_STARTS_AT {
                    tokio::task::yield_now().await;
                }
                let ending = drive_v2_guest(
                    &engine_short,
                    short,
                    crate::providers::fuel_bucket::V2_BUCKET_CAPACITY,
                    V2_FUEL_SLICE,
                    BUSY_TICKS * 4,
                    true,
                )
                .await;
                (ending, short_turns.load(Ordering::Relaxed) / TURNS_PER_TICK)
            };
            tokio::join!(busy_run, short_run)
        });
        let ((busy_ending, busy_at), (short_ending, short_at)) = std::future::poll_fn(|context| {
            let poll = std::future::Future::poll(work.as_mut(), context);
            if poll.is_pending() {
                let turn = clock_turns.fetch_add(1, Ordering::Relaxed) + 1;
                if turn % TURNS_PER_TICK == 0 {
                    clock_engine.increment_epoch();
                }
                assert!(
                    turn <= BUSY_TICKS * TURNS_PER_TICK * 8,
                    "turns ran past the budget"
                );
            }
            poll
        })
        .await;
        assert!(
            short_at >= SHORT_STARTS_AT
                && short_at < busy_at
                && short_ending == "stopped"
                && busy_ending.contains(ENDING_EPOCH_DEADLINE),
            "short guest {short_ending} at tick {short_at}, busy guest {busy_ending} at tick {busy_at}"
        );
    }

    #[tokio::test]
    async fn v2_panic_and_abort_clean_up_activation() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        provider.panic_next_v2.store(true, Ordering::Release);
        let panicked = load_v2_fixture(&provider, bytes.clone()).await;
        assert!(provider.start(&panicked).await.is_err());
        assert!(v2_ending(&provider, &panicked)
            .await
            .starts_with("panicked:"));
        assert!(provider.instances.read().await.is_empty());

        let aborted = load_v2_fixture(&provider, bytes).await;
        provider.start(&aborted).await.unwrap();
        provider.instances.read().await[&aborted.id]
            .task
            .as_ref()
            .unwrap()
            .abort();
        assert_eq!(v2_ending(&provider, &aborted).await, "cancelled");
        assert!(provider.instances.read().await.is_empty());
    }

    /// A stop empties the grant book the guest holds and drops its frame.
    #[tokio::test]
    async fn v2_stop_clears_the_grant_book_and_the_frame() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let book = provider.instances.read().await[&handle.id].grants.clone();
        book.lock()
            .unwrap()
            .hold("g1", "localhost://Users/self/Documents/note.bin", "read");
        provider.frames.lock().expect("frames").insert(
            handle.id.0.clone(),
            StoredFrame {
                principal: None,
                frame: crate::providers::bus2_ui::Frame {
                    nodes: vec![crate::providers::bus2_ui::FrameNode::Text("up".into())],
                },
            },
        );
        provider.start(&handle).await.unwrap();
        assert!(provider.read_v2_frame(None, &handle.id.0).await.is_some());
        provider.stop(&handle).await.unwrap();
        assert!(book.lock().unwrap().is_empty());
        assert!(provider.read_v2_frame(None, &handle.id.0).await.is_none());
    }

    /// Forgetting a guest drops the book and the frame. A delivered
    /// grant-revoked drops the host's copy while the guest is still running,
    /// and only when the frame names that grant.
    #[tokio::test]
    async fn v2_forget_and_revoke_drop_the_host_frame() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let forgotten = load_v2_fixture(&provider, bytes.clone()).await;
        let book = provider.instances.read().await[&forgotten.id]
            .grants
            .clone();
        book.lock()
            .unwrap()
            .hold("g1", "localhost://Users/self/Documents/note.bin", "read");
        provider.frames.lock().expect("frames").insert(
            forgotten.id.0.clone(),
            StoredFrame {
                principal: Some("person:local:a".into()),
                frame: crate::providers::bus2_ui::Frame {
                    nodes: vec![crate::providers::bus2_ui::FrameNode::Text("up".into())],
                },
            },
        );
        provider.forget_instance(&forgotten.id).await;
        assert!(book.lock().unwrap().is_empty());
        assert!(provider
            .read_v2_frame(Some("person:local:a"), &forgotten.id.0)
            .await
            .is_none());

        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.unwrap();
        provider.frames.lock().expect("frames").insert(
            handle.id.0.clone(),
            StoredFrame {
                principal: None,
                frame: crate::providers::bus2_ui::Frame {
                    nodes: vec![crate::providers::bus2_ui::FrameNode::Text("stay".into())],
                },
            },
        );
        provider
            .deliver_grant_revoked(&handle.id, "g1")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            provider
                .read_v2_frame(None, &handle.id.0)
                .await
                .expect("a text frame stays")
                .nodes,
            vec![crate::providers::bus2_ui::FrameNode::Text("stay".into())]
        );
        provider.frames.lock().expect("frames").insert(
            handle.id.0.clone(),
            StoredFrame {
                principal: None,
                frame: crate::providers::bus2_ui::Frame {
                    nodes: vec![crate::providers::bus2_ui::FrameNode::Image {
                        grant: "g1".into(),
                        resource: "localhost://Local/x".into(),
                    }],
                },
            },
        );
        provider
            .deliver_grant_revoked(&handle.id, "g1")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if provider.read_v2_frame(None, &handle.id.0).await.is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the host frame stays after revoke");
        assert!(provider.instances.read().await.contains_key(&handle.id));
        provider.stop(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn v2_invoke_refusal_closes_guest_body_and_completes_its_writer() {
        let provider = ComponentProvider::new();
        let (_, mut manifest) = component_fixture();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-invoke-body.wat"
        ))
        .unwrap();
        let handle = provider.load_admitted(bytes, manifest).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), provider.start(&handle))
            .await
            .expect("guest start completes")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    assert_eq!(
                        ending, "returned",
                        "empty read params are invalid and the writer ends"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the refused body writer must finish after the host closes its reader");
        assert!(provider.instances.read().await.is_empty());
    }

    fn read_request(max_bytes: u64) -> v2::elastos::bus::types::InvokeRequest {
        v2::elastos::bus::types::InvokeRequest {
            resource: "localhost://Users/self/Documents/note.bin".into(),
            operation: "read".into(),
            grant: Some("grant-token".into()),
            params: format!(r#"{{"max_bytes":{max_bytes}}}"#).into_bytes(),
        }
    }

    /// The read rows name `grant-token`. A read is refused unless that id is
    /// still a held grant, so a row that reaches the bridge holds it first.
    fn hold_note_grant(book: &Mutex<crate::providers::bus2_ui::GrantBook>) {
        book.lock().expect("grant book").hold(
            "grant-token",
            "localhost://Users/self/Documents/note.bin",
            "read",
        );
    }

    /// The bridge answers one window. `calls` records each `length`.
    /// Each call has its own budget. Guests of one provider use [`state_on`].
    fn state_for(object: Vec<u8>, calls: Arc<Mutex<Vec<u64>>>) -> ComponentState {
        state_on(
            &crate::providers::bus2_stream::ReadBudget::new(),
            object,
            calls,
        )
    }

    /// Printable bytes travel as one JSON string. Anything else is standard
    /// base64. A number per byte of a 16 MiB window is not a read result.
    fn content_value(bytes: &[u8]) -> serde_json::Value {
        let printable = bytes
            .iter()
            .all(|byte| (0x20..0x7f).contains(byte) && *byte != b'"' && *byte != b'\\');
        if printable {
            serde_json::Value::String(String::from_utf8(bytes.to_vec()).expect("printable"))
        } else {
            serde_json::json!({"b64": encode_b64(bytes)})
        }
    }

    fn state_on(
        reads: &Arc<crate::providers::bus2_stream::ReadBudget>,
        object: Vec<u8>,
        calls: Arc<Mutex<Vec<u64>>>,
    ) -> ComponentState {
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _capsule, _principal| {
                let value: serde_json::Value = serde_json::from_str(line).expect("bridge line");
                let body = &value["request"]["body"];
                let offset = body["offset"].as_u64().expect("offset") as usize;
                let length = body["length"].as_u64().expect("length");
                calls.lock().unwrap().push(length);
                let start = offset.min(object.len());
                let end = start.saturating_add(length as usize).min(object.len());
                let window = object[start..end].to_vec();
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": {
                            "status": "ok",
                            "data": { "content": content_value(&window), "size": window.len() }
                        },
                        "audit": "read-1"
                    }
                })
                .to_string())
            })),
            "capsule-1".into(),
            Some("person:local:test".into()),
        );
        state.reads = reads.clone();
        state.grants.lock().expect("grant book").hold(
            "grant-token",
            "localhost://Users/self/Documents/note.bin",
            "read",
        );
        state
    }

    fn opened_chunks(prepared: crate::providers::bus2_stream::PreparedRead) -> usize {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let mut stream =
            crate::providers::bus2_stream::WindowRead::new(prepared.bytes, tx, prepared.hold);
        let mut chunks = 0;
        while stream.pull(usize::MAX).is_some() {
            chunks += 1;
        }
        chunks
    }

    #[test]
    fn v2_over_cap_read_is_refused_before_a_chunk() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut sealed = state_for(vec![9; 5], calls.clone());
        sealed.sealed = true;
        let err = sealed.windowed_read(&read_request(4), false).unwrap_err();
        assert!(matches!(err, V2BusError::Denied(message) if message == SEALED_BRIDGE));
        assert!(
            calls.lock().unwrap().is_empty(),
            "the seal runs before the bridge"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut state = state_for(vec![9; 5], calls.clone());
        let err = state
            .windowed_read(&read_request(4), false)
            .expect_err("an over-cap read is invalid");
        assert!(
            matches!(err, V2BusError::Invalid(ref message)
                if message == "object is 5 bytes, over the cap of 4"),
            "{err:?}"
        );
        let lengths = calls.lock().unwrap().clone();
        assert!(!lengths.is_empty(), "the size is learned from a window");
        assert!(lengths
            .iter()
            .all(|length| *length <= crate::providers::bus2_stream::READ_CHUNK as u64));
    }

    #[test]
    fn empty_read_params_are_invalid_and_other_operations_stay_unavailable() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut state = state_for(vec![1], calls);
        let mut request = read_request(4);
        request.params.clear();
        let err = state.windowed_read(&request, false).unwrap_err();
        assert!(
            matches!(err, V2BusError::Invalid(ref message) if message.contains("not JSON")),
            "{err:?}"
        );
        request.operation = "write".into();
        let err = state.windowed_read(&request, false).unwrap_err();
        assert!(matches!(err, V2BusError::Unavailable(_)), "{err:?}");
    }

    #[tokio::test]
    async fn v2_short_ok_is_refused() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = crate::providers::bus2_stream::WindowRead::new(
            vec![1, 2, 3, 4, 5],
            tx,
            crate::providers::bus2_stream::ReadHold::empty(),
        );
        assert_eq!(stream.pull(2).unwrap().len(), 2);
        drop(stream);
        let trailer = rx.await.expect("trailer");
        assert!(
            trailer.is_err(),
            "a short stream must not complete the trailer with ok: {trailer:?}"
        );
    }

    /// The trailer may be polled before the stream is drained, and for longer
    /// than the host-call deadline. Draining still makes it ok.
    #[tokio::test]
    async fn a_trailer_polled_before_the_drain_stays_ok_past_the_host_deadline() {
        let bytes = vec![7u8; 8];
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = crate::providers::bus2_stream::WindowRead::new(
            bytes.clone(),
            tx,
            crate::providers::bus2_stream::ReadHold::empty(),
        );
        let trailer = tokio::spawn(super::await_read_trailer(rx));
        tokio::time::sleep(super::V2_HOST_DEADLINE + Duration::from_millis(50)).await;
        let mut got = Vec::new();
        while let Some(chunk) = stream.pull(4) {
            got.extend(chunk);
        }
        drop(stream);
        let ended = trailer.await.expect("trailer task");
        assert!(ended.is_ok(), "{ended:?}");
        assert_eq!(got, bytes);
    }

    #[tokio::test]
    async fn v2_exact_cap_object_arrives_in_more_than_one_chunk() {
        let chunk = crate::providers::bus2_stream::READ_CHUNK;
        let cap = chunk * 2;
        let object = vec![b'g'; cap];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut state = state_for(object.clone(), calls.clone());
        let prepared = state
            .windowed_read(&read_request(cap as u64), false)
            .expect("an object at the cap is readable");
        assert_eq!(prepared.bytes, object);
        let lengths = calls.lock().unwrap().clone();
        assert_eq!(
            lengths,
            vec![cap as u64 + 1],
            "the sync bridge was asked once for the capped object"
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream =
            crate::providers::bus2_stream::WindowRead::new(prepared.bytes, tx, prepared.hold);
        let mut got = Vec::new();
        let mut chunks = 0usize;
        while let Some(part) = stream.pull(usize::MAX) {
            assert!(!part.is_empty() && part.len() <= chunk);
            got.extend(part);
            chunks += 1;
        }
        assert!(chunks > 1, "exact-cap object arrived in {chunks} chunks");
        assert_eq!(got, object);
        assert!(rx.await.expect("trailer").is_ok());
    }

    #[test]
    fn v2_guest_max_bytes_above_the_host_cap_is_the_host_cap() {
        let host = crate::providers::bus2_stream::HOST_MAX_READ_BYTES;
        let object = vec![b'a'; host + 1];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut state = state_for(object, calls.clone());
        let err = match state.windowed_read(&read_request((host as u64) + 1), false) {
            Ok(prepared) => {
                let chunks = opened_chunks(prepared);
                panic!("a guest ask above the host cap must not open a chunk, opened {chunks}");
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, V2BusError::Invalid(ref message)
                if *message == format!("object is {} bytes, over the cap of {host}", host + 1)),
            "{err:?}"
        );
        assert_eq!(
            calls.lock().unwrap().clone(),
            vec![host as u64 + 1],
            "one bounded read learns the size"
        );
    }

    /// One bridge call carries the whole capped read. A second guest that
    /// asks for the same cap is refused before its call.
    #[test]
    fn v2_one_bounded_read_and_a_second_guest_at_the_cap_is_refused() {
        let host = crate::providers::bus2_stream::HOST_MAX_READ_BYTES;
        let object = vec![b'c'; host];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let reads = crate::providers::bus2_stream::ReadBudget::new();
        let mut first = state_on(&reads, object.clone(), calls.clone());
        let prepared = first
            .windowed_read(&read_request(host as u64), false)
            .expect("the first guest reads an object at the cap");
        assert_eq!(prepared.bytes, object);
        assert_eq!(
            calls.lock().unwrap().clone(),
            vec![host as u64 + 1],
            "one bounded read of the object"
        );
        let mut second = state_on(&reads, object, calls.clone());
        let before = calls.lock().unwrap().len();
        let err = match second.windowed_read(&read_request(host as u64), false) {
            Err(err) => err,
            Ok(prepared) => panic!(
                "a second guest at the cap is refused, got {} bytes",
                prepared.bytes.len()
            ),
        };
        assert!(
            matches!(err, V2BusError::Unavailable(ref message) if message.contains("cap")),
            "{err:?}"
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            before,
            "the refusal happens before the bridge"
        );
        drop(prepared);
        let mut third = state_on(&reads, vec![4u8; 4], calls.clone());
        let again = third
            .windowed_read(&read_request(8), false)
            .expect("the cap is free once the first read ends");
        assert_eq!(again.bytes, vec![4, 4, 4, 4]);
    }

    /// Two providers each have a budget. One guest at the cap does not refuse
    /// a guest of the other provider.
    #[test]
    fn two_providers_do_not_share_the_read_cap() {
        let host = crate::providers::bus2_stream::HOST_MAX_READ_BYTES;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut first = state_on(
            &crate::providers::bus2_stream::ReadBudget::new(),
            vec![b'c'; host],
            calls.clone(),
        );
        let held = first
            .windowed_read(&read_request(host as u64), false)
            .expect("the first provider takes its own cap");
        let mut second = state_on(
            &crate::providers::bus2_stream::ReadBudget::new(),
            vec![4u8; 4],
            calls,
        );
        let again = second
            .windowed_read(&read_request(4), false)
            .expect("another provider reads while the first holds its cap");
        assert_eq!(again.bytes, vec![4, 4, 4, 4]);
        drop(held);
    }

    /// Eight slow fetches stay counted. Time does not free a live fetch.
    /// A ninth is refused. Dropping one lets the next reserve.
    #[test]
    fn eight_slow_fetches_stay_inside_the_read_cap() {
        let host = crate::providers::bus2_stream::HOST_MAX_READ_BYTES;
        let each = host / 8;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let reads = crate::providers::bus2_stream::ReadBudget::new();
        let mut held = Vec::new();
        for _ in 0..8 {
            let mut guest = state_on(&reads, vec![b'g'; each], calls.clone());
            held.push(
                guest
                    .windowed_read(&read_request(each as u64), false)
                    .expect("one eighth of the cap"),
            );
        }
        std::thread::sleep(Duration::from_millis(80));
        let mut ninth = state_on(&reads, vec![b'g'; each], calls.clone());
        let err = ninth
            .windowed_read(&read_request(each as u64), false)
            .expect_err("the ninth fetch is past the cap");
        assert!(matches!(err, V2BusError::Unavailable(_)), "{err:?}");
        drop(held.pop());
        let mut again = state_on(&reads, vec![b'g'; each], calls);
        again
            .windowed_read(&read_request(each as u64), false)
            .expect("dropping one live fetch frees its bytes");
    }

    /// The bridge reports that the object changed. The read must end as an
    /// error, from the one call that asked for that check.
    #[test]
    fn v2_a_revision_conflict_does_not_end_ok() {
        let calls = Arc::new(AtomicU64::new(0));
        let seen = calls.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _, _| {
                seen.fetch_add(1, Ordering::Relaxed);
                let value: serde_json::Value = serde_json::from_str(line).expect("bridge line");
                let body = &value["request"]["body"];
                if body.get("check_revision").and_then(|value| value.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "id": 1,
                        "response": {
                            "type": "resource_result",
                            "result": {
                                "status": "error",
                                "code": "revision_conflict",
                                "message": "the object changed during the read"
                            }
                        }
                    })
                    .to_string());
                }
                let length = body["length"].as_u64().expect("length") as usize;
                let window = vec![1u8; length.min(4)];
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": {
                            "status": "ok",
                            "data": { "content": content_value(&window), "size": window.len() }
                        },
                        "audit": "read-1"
                    }
                })
                .to_string())
            })),
            "capsule-1".into(),
            Some("person:local:test".into()),
        );
        hold_note_grant(&state.grants);
        let err = state
            .windowed_read(&read_request(8), false)
            .expect_err("a change during the read must not end ok");
        assert!(
            matches!(err, V2BusError::Invalid(ref message)
                if message == "the object changed during the read"),
            "{err:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1, "one bridge read");
    }

    #[test]
    fn v2_present_stores_the_grant_id_and_a_second_present_replaces_it() {
        let calls = Arc::new(AtomicU64::new(0));
        let seen = calls.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _, _| {
                seen.fetch_add(1, Ordering::Relaxed);
                let value: serde_json::Value = serde_json::from_str(line).expect("bridge line");
                let request = &value["request"];
                if request["type"].as_str() == Some("resource_invoke") {
                    return Ok(serde_json::json!({
                        "id": 1,
                        "response": {
                            "type": "resource_result",
                            "result": {"status": "ok"},
                            "use_spent": true
                        }
                    })
                    .to_string());
                }
                let token = match request["action"].as_str() {
                    Some("read")
                        if request["resource"]
                            .as_str()
                            .unwrap_or("")
                            .ends_with("gone.png") =>
                    {
                        "g-revoked"
                    }
                    Some("read") => "g-read",
                    _ => "g-write",
                };
                Ok(serde_json::json!({
                    "id": 1,
                    "response": { "type": "capability_token", "token": token }
                })
                .to_string())
            })),
            "capsule-1".into(),
            None,
        );
        let photo = "localhost://Users/self/Pictures/a.png";
        let ask = |state: &mut ComponentState, resource: &str, action: &str| {
            elastos::bus::capabilities::Host::request(
                state,
                elastos::bus::types::CapabilityRequest {
                    resource: resource.into(),
                    actions: vec![action.into()],
                    reason: "already held".into(),
                },
            )
            .expect("the existing seam returns the grant")
        };
        let read = ask(&mut state, photo, "read");
        let write = ask(&mut state, photo, "write");
        let revoked = ask(
            &mut state,
            "localhost://Users/self/Pictures/gone.png",
            "read",
        );
        assert_eq!(
            (read.id.as_str(), write.id.as_str(), revoked.id.as_str()),
            ("g-read", "g-write", "g-revoked")
        );
        note_delivered_event(
            &state.grants,
            &state.frames,
            "capsule-1",
            &v2::elastos::bus::types::Event::GrantRevoked(revoked.id.clone()),
        );
        let media = crate::providers::bus2_ui::UI_MEDIA_TYPE;
        let present = |state: &mut ComponentState, document: &str| {
            state.present_document(media, document.as_bytes())
        };
        present(&mut state, r#"{"frame":[{"text":"one"}]}"#).unwrap();
        let second = format!(
            r#"{{"frame":[{{"image":{{"grant":"{}"}}}},{{"text":"two"}}]}}"#,
            read.id
        );
        present(&mut state, &second).unwrap();
        let stored = state
            .frames
            .lock()
            .expect("frames")
            .get("capsule-1")
            .unwrap()
            .clone();
        assert_eq!(state.frames.lock().expect("frames").len(), 1, "one frame");
        assert_eq!(
            stored.frame.nodes,
            vec![
                crate::providers::bus2_ui::FrameNode::Image {
                    grant: read.id.clone(),
                    resource: photo.into(),
                },
                crate::providers::bus2_ui::FrameNode::Text("two".into()),
            ]
        );
        let denied = |state: &mut ComponentState, id: &str| {
            present(
                state,
                &format!(r#"{{"frame":[{{"image":{{"grant":"{id}"}}}}]}}"#),
            )
            .unwrap_err()
        };
        assert!(
            matches!(denied(&mut state, "g-missing"), V2BusError::Denied(message)
            if message.contains("is not a grant this guest holds"))
        );
        assert!(
            matches!(denied(&mut state, &revoked.id), V2BusError::Denied(message)
            if message.contains("was revoked"))
        );
        assert!(
            matches!(denied(&mut state, &write.id), V2BusError::Denied(message)
            if message.contains("does not allow read"))
        );
        let script = present(
            &mut state,
            r#"{"frame":[{"text":"x","script":"alert(1)"}]}"#,
        )
        .unwrap_err();
        assert!(matches!(script, V2BusError::Invalid(message) if message.contains("scripts")));
        assert_eq!(
            state
                .frames
                .lock()
                .expect("frames")
                .get("capsule-1")
                .unwrap(),
            &stored
        );
        state.sealed = true;
        let sealed = present(&mut state, r#"{"frame":[{"text":"no"}]}"#).unwrap_err();
        assert!(matches!(sealed, V2BusError::Denied(message) if message == SEALED_BRIDGE));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            5,
            "an image present checks the grant, then asks the runtime to count it"
        );
    }

    /// One frame checks every image before it counts any grant. A repeated id
    /// is one count. A check that fails counts nothing and stores nothing.
    /// A count that fails after an earlier count leaves that earlier grant
    /// counted and still stores nothing.
    #[test]
    fn a_frame_checks_every_image_then_counts_each_grant_once() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _, _| {
                seen.lock().expect("lines").push(line.to_string());
                let value: serde_json::Value = serde_json::from_str(line).expect("line");
                let token = value["request"]["token"].as_str().unwrap_or("");
                let spend = value["request"]["body"]["use_grant"].as_bool() == Some(true);
                if token == "bad" || (spend && token == "late") {
                    return Ok(serde_json::json!({
                        "id": 1,
                        "response": {"type": "error", "code": "denied", "message": "revoked"}
                    })
                    .to_string());
                }
                Ok(use_spent_host()("x", "y", None).expect("host"))
            })),
            "capsule".into(),
            None,
        );
        let media = crate::providers::bus2_ui::UI_MEDIA_TYPE;
        let once = |state: &mut ComponentState, id: &str| {
            let pending = one_read_grant(state);
            state
                .finish_grant(pending, Ok(token_line(id, r#","max_uses":1"#)))
                .expect("once")
        };
        let held = |state: &ComponentState, id: &str| {
            !state.grants.lock().expect("grant book").blocks_read(id)
        };
        let frame_of = |ids: &[&str]| {
            let nodes: Vec<_> = ids
                .iter()
                .map(|id| format!(r#"{{"image":{{"grant":"{id}"}}}}"#))
                .collect();
            format!(r#"{{"frame":[{}]}}"#, nodes.join(","))
        };
        let dup = once(&mut state, "dup");
        state
            .present_document(media, frame_of(&[&dup.id, &dup.id]).as_bytes())
            .expect("a repeated id is one frame");
        let called = lines.lock().expect("lines").clone();
        assert_eq!(called.len(), 2, "{called:?}");
        assert!(called[0].contains("\"count_use\":false"), "{called:?}");
        assert!(called[1].contains("\"use_grant\":true"), "{called:?}");
        assert_eq!(
            called
                .iter()
                .filter(|line| line.contains("\"dup\""))
                .count(),
            2
        );
        assert!(!held(&state, "dup"), "the one count is spent");
        let stored = state
            .frames
            .lock()
            .expect("frames")
            .get("capsule")
            .unwrap()
            .clone();
        assert_eq!(stored.frame.nodes.len(), 2, "both nodes stay on the frame");

        lines.lock().expect("lines").clear();
        let good = once(&mut state, "good");
        let bad = once(&mut state, "bad");
        let err = state
            .present_document(media, frame_of(&[&good.id, &bad.id]).as_bytes())
            .expect_err("a failed check stores nothing");
        assert!(
            matches!(err, V2BusError::Denied(ref message) if message == "revoked"),
            "{err:?}"
        );
        let called = lines.lock().expect("lines").clone();
        assert!(
            called
                .iter()
                .all(|line| line.contains("\"count_use\":false")),
            "{called:?}"
        );
        assert!(
            called
                .iter()
                .all(|line| !line.contains("\"use_grant\":true")),
            "{called:?}"
        );
        assert!(held(&state, "good") && held(&state, "bad"));
        assert!(state.frames.lock().expect("frames").get("capsule").unwrap().frame.nodes.iter().all(|node| {
            !matches!(node, crate::providers::bus2_ui::FrameNode::Image { grant, .. } if grant == "good" || grant == "bad")
        }));

        lines.lock().expect("lines").clear();
        let early = once(&mut state, "early");
        let late = once(&mut state, "late");
        let err = state
            .present_document(media, frame_of(&[&early.id, &late.id]).as_bytes())
            .expect_err("a failed count stores nothing");
        assert!(
            matches!(err, V2BusError::Denied(ref message) if message == "revoked"),
            "{err:?}"
        );
        let called = lines.lock().expect("lines").clone();
        assert_eq!(
            called
                .iter()
                .filter(|line| line.contains("\"use_grant\":true"))
                .count(),
            2,
            "{called:?}"
        );
        assert!(!held(&state, "early"), "the count that returned is spent");
        assert!(held(&state, "late"), "the failed count is not spent");
        assert!(state.frames.lock().expect("frames").get("capsule").is_some_and(|stored| {
            stored.frame.nodes.iter().all(|node| {
                !matches!(node, crate::providers::bus2_ui::FrameNode::Image { grant, .. } if grant == "early" || grant == "late")
            })
        }));
    }

    /// Two grants `[g1, g2]`, `g2` one-use, `g1` revoked after the checks. The
    /// guest's book follows the Runtime's count on every path: the Phase 2 list
    /// stops at the refusal, so the Runtime never counts `g2`; an answer that
    /// does say `use_spent` is spent in the book, whatever came before it.
    #[test]
    fn a_refused_present_keeps_the_book_equal_to_the_runtime() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |line, _, _| {
                seen.lock().expect("lines").push(line.to_string());
                let value: serde_json::Value = serde_json::from_str(line).expect("line");
                let spend = value["request"]["body"]["use_grant"].as_bool() == Some(true);
                if spend && value["request"]["token"] == "g1" {
                    return Ok(serde_json::json!({
                        "id": 1,
                        "response": {"type": "error", "code": "denied", "message": "revoked"}
                    })
                    .to_string());
                }
                Ok(use_spent_host()("x", "y", None).expect("host"))
            })),
            "capsule".into(),
            None,
        );
        let media = crate::providers::bus2_ui::UI_MEDIA_TYPE;
        let once = |state: &mut ComponentState, id: &str| {
            let pending = one_read_grant(state);
            state
                .finish_grant(pending, Ok(token_line(id, r#","max_uses":1"#)))
                .expect("once")
                .id
        };
        let frame_of = |ids: &[&str]| {
            let nodes: Vec<_> = ids
                .iter()
                .map(|id| format!(r#"{{"image":{{"grant":"{id}"}}}}"#))
                .collect();
            format!(r#"{{"frame":[{}]}}"#, nodes.join(","))
        };
        let held = |state: &ComponentState, id: &str| {
            !state.grants.lock().expect("grant book").blocks_read(id)
        };
        let spends = |lines: &Mutex<Vec<String>>, token: &str| {
            let quoted = format!("\"{token}\"");
            lines
                .lock()
                .expect("lines")
                .iter()
                .filter(|line| line.contains("\"use_grant\":true") && line.contains(&quoted))
                .count()
        };

        let (g1, g2) = (once(&mut state, "g1"), once(&mut state, "g2"));
        let err = state
            .present_document(media, frame_of(&[&g1, &g2]).as_bytes())
            .expect_err("the revoked grant fails the present by name");
        assert!(
            matches!(err, V2BusError::Denied(ref m) if m == "revoked"),
            "{err:?}"
        );
        assert_eq!(spends(&lines, "g2"), 0, "the Runtime never counted g2");
        assert!(held(&state, "g2"), "the book keeps g2, as the Runtime does");

        let g3 = once(&mut state, "g3");
        let err = state
            .present_document(media, frame_of(&[&g3, &g1]).as_bytes())
            .expect_err("the later refusal fails the present");
        assert!(matches!(err, V2BusError::Denied(_)), "{err:?}");
        assert_eq!(spends(&lines, "g3"), 1, "the Runtime counted g3");
        assert!(!held(&state, "g3"), "the book spent what the Runtime spent");
        let mut request = read_request(4);
        request.grant = Some("g3".into());
        let err = state.begin_read(&request, false).err().expect("refused");
        assert!(
            matches!(err, V2BusError::Denied(ref m) if m == "the grant is spent"),
            "{err:?}"
        );

        // A Runtime that answered for every grant after the refusal.
        let g4 = once(&mut state, "g4");
        let (frame, bridges) = state
            .present_parts(media, frame_of(&[&g1, &g4]).as_bytes())
            .expect("parts");
        let raws: Vec<_> = bridges.iter().map(sync_bridge).collect();
        state
            .store_present(frame, &raws, 2)
            .expect_err("g1 is refused");
        assert!(
            !held(&state, "g4"),
            "an answer after a refusal still spends"
        );

        // The Phase 2 list asks no further grant after the refusal.
        let g5 = once(&mut state, "g5");
        let (_, bridges) = state
            .present_parts(media, frame_of(&[&g1, &g5]).as_bytes())
            .expect("parts");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let answered = rt.block_on(await_bridges(
            &bridges[2..],
            std::time::Instant::now() + V2_HOST_DEADLINE,
            true,
        ));
        assert_eq!(answered.len(), 1, "the list stops at the first refusal");
        assert_eq!(spends(&lines, "g5"), 0);
        assert!(held(&state, "g5"));
    }

    #[test]
    fn a_stop_during_present_stores_nothing() {
        let mut state = ComponentState::new(None, "capsule-1".into(), None);
        state.stop_requested.store(true, Ordering::Release);
        let err = state
            .present_document(
                crate::providers::bus2_ui::UI_MEDIA_TYPE,
                br#"{"frame":[{"text":"late"}]}"#,
            )
            .expect_err("a stop denies present");
        assert!(matches!(err, V2BusError::Denied(_)), "{err:?}");
        assert!(state.frames.lock().expect("frames").is_empty());
        state.stop_requested.store(false, Ordering::Release);
        state.cancel_requested.store(true, Ordering::Release);
        let err = state
            .present_document(
                crate::providers::bus2_ui::UI_MEDIA_TYPE,
                br#"{"frame":[{"text":"late"}]}"#,
            )
            .expect_err("a cancel denies present");
        assert!(matches!(err, V2BusError::Denied(_)), "{err:?}");
        assert!(state.frames.lock().expect("frames").is_empty());
    }

    /// A v2 guest calls `providers.invoke`, reads the stream four bytes at a
    /// time, and records those bytes only after the trailer is ok. The same
    /// run then asks over the cap and sees an error with no chunk, and drops
    /// a one-chunk read whose trailer is an error and whose bytes are not
    /// recorded.
    #[tokio::test]
    async fn v2_guest_reads_the_stream_and_records_the_trailer() {
        let object = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall(Arc::new(move |line, _capsule, _principal| {
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| err.to_string())?;
            let body = &value["request"]["body"];
            let offset = body["offset"].as_u64().ok_or("offset")? as usize;
            let length = body["length"].as_u64().ok_or("length")?;
            seen.lock().unwrap().push(length);
            let start = offset.min(object.len());
            let end = start.saturating_add(length as usize).min(object.len());
            let window = object[start..end].to_vec();
            Ok(serde_json::json!({
                "id": 1,
                "response": {
                    "type": "resource_result",
                    "result": {
                        "status": "ok",
                        "data": { "content": content_value(&window), "size": window.len() }
                    },
                    "audit": "read-1"
                }
            })
            .to_string())
        }));
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-read-stream.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        hold_note_grant(
            &provider
                .instances
                .read()
                .await
                .get(&handle.id)
                .unwrap()
                .grants,
        );
        tokio::time::timeout(Duration::from_secs(2), provider.start(&handle))
            .await
            .expect("guest start completes")
            .unwrap();
        let ending = v2_ending(&provider, &handle).await;
        assert_eq!(
            ending, "returned",
            "the guest records two chunks, an ok trailer, an over-cap error with no chunk, and a short trailer that keeps no byte"
        );
        assert_eq!(
            calls.lock().unwrap().clone(),
            vec![9, 5, 9],
            "full read, over-cap read, short read, each one window"
        );
    }

    /// A file of `len` zero bytes named as the fixture manifest's entrypoint.
    fn capsule_dir_with_entrypoint_of(len: u64) -> (tempfile::TempDir, CapsuleManifest) {
        let (_, manifest) = component_fixture();
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join(&manifest.entrypoint)).unwrap();
        file.set_len(len).unwrap();
        (dir, manifest)
    }

    #[tokio::test]
    async fn a_component_file_is_read_up_to_the_cap_and_refused_one_byte_over() {
        assert_eq!(COMPONENT_MAX_BYTES, 8 * 1024 * 1024);
        let (dir, manifest) = capsule_dir_with_entrypoint_of(8 * 1024 * 1024);
        let path = dir.path().join(&manifest.entrypoint);
        let bytes = ComponentProvider::read_component(&path).await.unwrap();
        assert_eq!(bytes.len(), 8 * 1024 * 1024);

        let (dir, manifest) = capsule_dir_with_entrypoint_of(8 * 1024 * 1024 + 1);
        let path = dir.path().join(&manifest.entrypoint);
        let err = ComponentProvider::read_component(&path).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "component file is larger than the 8388608 byte limit"
        );
    }

    #[tokio::test]
    async fn load_refuses_a_file_over_the_cap_and_names_a_missing_one() {
        let provider = ComponentProvider::new();
        let (dir, manifest) = capsule_dir_with_entrypoint_of(8 * 1024 * 1024 + 1);
        let err = provider
            .load(dir.path(), manifest.clone())
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Compute error: Failed to read component capsule: \
             component file is larger than the 8388608 byte limit"
        );
        let empty = tempfile::tempdir().unwrap();
        let err = provider.load(empty.path(), manifest).await.unwrap_err();
        assert!(matches!(err, ElastosError::CapsuleNotFound(_)), "{err}");
        assert!(provider.instances.read().await.is_empty());
    }

    /// The fixture component with a custom section appended: still a valid
    /// component, of `total` bytes.
    fn fixture_component_padded_to(total: usize) -> Vec<u8> {
        let (path, manifest) = component_fixture();
        let mut bytes = std::fs::read(path.join(&manifest.entrypoint)).unwrap();
        let payload = total - bytes.len() - 6 - 4; // section id, 5-byte size, 1-byte name length, "pad"
        let size = (payload + 4) as u32;
        bytes.push(0);
        bytes.extend(
            (0..5).map(|i| ((size >> (7 * i)) & 0x7f) as u8 | if i < 4 { 0x80 } else { 0 }),
        );
        bytes.extend([3, b'p', b'a', b'd']);
        bytes.resize(total, 0);
        bytes
    }

    #[tokio::test]
    async fn admitted_bytes_over_the_cap_are_refused_before_the_compiler() {
        let provider = ComponentProvider::new();
        let (_, manifest) = component_fixture();
        // At the cap the padded component compiles, so the refusal one byte over is the size.
        let at_cap = fixture_component_padded_to(8 * 1024 * 1024);
        let handle = provider
            .load_admitted(at_cap, manifest.clone())
            .await
            .expect("a valid component of exactly the cap loads");
        provider.stop(&handle).await.unwrap();
        let over = fixture_component_padded_to(8 * 1024 * 1024 + 1);
        let err = provider.load_admitted(over, manifest).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "Compute error: component is larger than the 8388608 byte limit"
        );
        assert!(provider.instances.read().await.is_empty());
    }

    /// Lets a test hold one compile job at the point where its worker has
    /// started and taken the compile slot. `hold` reports that point, then
    /// waits to be released.
    pub(super) struct WorkerGate {
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl WorkerGate {
        pub(super) fn hold(self) {
            let _ = self.started.send(());
            let _ = self.release.recv();
        }
    }

    /// A compile job whose caller was cancelled while its worker was already
    /// compiling keeps the slot until that worker ends: a later load waits,
    /// and gets its own queue timeout, instead of compiling beside it. (The
    /// test above gates the job before its worker starts; this one gates it
    /// after, which is the case upstream issue #440 asks for.)
    #[tokio::test(start_paused = true)]
    async fn component_load_keeps_its_slot_while_its_cancelled_worker_is_still_compiling() {
        use std::future::Future;
        use std::task::Poll;
        let provider = Arc::new(ComponentProvider::new());
        let (bytes, manifest) = admitted_fixture();
        let (started, mut worker_started) = tokio::sync::mpsc::unbounded_channel();
        let (release, held) = std::sync::mpsc::channel();
        *provider.worker_gate.lock().unwrap() = Some(WorkerGate {
            started,
            release: held,
        });

        let loading_provider = provider.clone();
        let (first_bytes, first_manifest) = (bytes.clone(), manifest.clone());
        let loading = tokio::spawn(async move {
            loading_provider
                .load_admitted(first_bytes, first_manifest)
                .await
        });
        worker_started.recv().await.expect("the worker starts");
        assert_eq!(
            provider.compile_slot.available_permits(),
            0,
            "the started worker holds the slot"
        );
        loading.abort();
        let cancelled = loading.await.unwrap_err().is_cancelled();

        let result = {
            let next_load = tokio::time::timeout(
                Duration::from_secs(31),
                provider.load_admitted(bytes.clone(), manifest.clone()),
            );
            tokio::pin!(next_load);
            match std::future::poll_fn(|cx| Poll::Ready(next_load.as_mut().poll(cx))).await {
                Poll::Ready(result) => result,
                Poll::Pending => {
                    tokio::time::advance(Duration::from_secs(31)).await;
                    next_load.await
                }
            }
        };

        // Let the held worker finish, then show the slot comes back.
        release.send(()).unwrap();
        tokio::time::resume();
        let handle = provider.load_admitted(bytes, manifest).await.unwrap();
        provider.stop(&handle).await.unwrap();

        assert!(cancelled);
        assert!(
            matches!(result, Ok(Err(ElastosError::Compute(message)))
                if message == "Timed out waiting for the component compiler"),
            "a load must wait for a cancelled caller's compile that is still running"
        );
        assert_eq!(provider.compile_slot.available_permits(), 1);
    }

    /// The fixture's component bytes and manifest, for loads that skip the file read.
    fn admitted_fixture() -> (Vec<u8>, CapsuleManifest) {
        let (path, manifest) = component_fixture();
        (
            std::fs::read(path.join(&manifest.entrypoint)).unwrap(),
            manifest,
        )
    }

    // The next four tests follow the tests of the open upstream change
    // elastos/elastos-runtime #416, on `load_admitted` where they need the
    // first poll to reach the compile slot.

    #[test]
    fn component_load_keeps_async_work_responsive() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (release, waiting) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            let _ = waiting.recv();
        });
        let provider = Arc::new(ComponentProvider::new());
        let (bytes, manifest) = admitted_fixture();

        runtime.block_on(async {
            let (started, observing) = tokio::sync::oneshot::channel();
            let loading_provider = provider.clone();
            let loading = tokio::spawn(async move {
                started.send(()).unwrap();
                loading_provider.load_admitted(bytes, manifest).await
            });
            observing.await.unwrap();
            tokio::task::yield_now().await;
            let yielded_before_loading_finished = !loading.is_finished();

            // Always release the worker before checking the result, including
            // when a regression makes the compile run on the async executor.
            release.send(()).unwrap();
            let handle = loading.await.unwrap().unwrap();
            blocker.await.unwrap();
            assert_eq!(
                provider.status(&handle).await.unwrap(),
                CapsuleStatus::Loading
            );
            provider.stop(&handle).await.unwrap();
            assert!(
                yielded_before_loading_finished,
                "component compilation prevented unrelated async work from running"
            );
        });
    }

    #[tokio::test(start_paused = true)]
    async fn component_load_times_out_waiting_for_compile_slot() {
        assert_eq!(COMPONENT_COMPILE_WAIT_TIMEOUT, Duration::from_secs(30));
        let provider = Arc::new(ComponentProvider::new());
        let held_permit = provider.compile_slot.clone().acquire_owned().await.unwrap();
        let (bytes, manifest) = admitted_fixture();
        let loading_provider = provider.clone();
        let mut loading =
            tokio::spawn(async move { loading_provider.load_admitted(bytes, manifest).await });

        // The outer deadline makes a missing queue limit fail instead of hang.
        // Paused Tokio time avoids relying on compilation or host speed.
        let result = tokio::time::timeout(Duration::from_secs(31), &mut loading).await;
        if result.is_err() {
            loading.abort();
            let _ = loading.await;
        }
        drop(held_permit);

        assert!(
            matches!(result, Ok(Ok(Err(ElastosError::Compute(message))))
                if message == "Timed out waiting for the component compiler"),
            "a queued component load must return its own timeout before the outer deadline"
        );
        assert!(provider.instances.read().await.is_empty());
        assert_eq!(provider.compile_slot.available_permits(), 1);
    }

    #[test]
    fn component_load_retains_compile_slot_after_cancellation() {
        use std::future::Future;
        use std::task::Poll;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let (release, waiting) = std::sync::mpsc::channel();
        let (blocked, observing_blocker) = tokio::sync::oneshot::channel();
        let blocker = runtime.spawn_blocking(move || {
            blocked.send(()).unwrap();
            let _ = waiting.recv();
        });
        let provider = Arc::new(ComponentProvider::new());
        let (bytes, manifest) = admitted_fixture();

        runtime.block_on(async {
            observing_blocker.await.unwrap();
            let (started, observing) = tokio::sync::oneshot::channel();
            let loading_provider = provider.clone();
            let (first_bytes, first_manifest) = (bytes.clone(), manifest.clone());
            let loading = tokio::spawn(async move {
                let mut load =
                    Box::pin(loading_provider.load_admitted(first_bytes, first_manifest));
                // Poll once, so the load takes the slot and queues its compile
                // behind the gated worker, before acknowledging the caller.
                let initial = std::future::poll_fn(|cx| Poll::Ready(load.as_mut().poll(cx))).await;
                started.send(()).unwrap();
                match initial {
                    Poll::Ready(result) => result,
                    Poll::Pending => load.await,
                }
            });
            observing.await.unwrap();
            loading.abort();
            let cancelled = loading.await.unwrap_err().is_cancelled();

            let result = {
                let next_load = tokio::time::timeout(
                    Duration::from_secs(31),
                    provider.load_admitted(bytes.clone(), manifest.clone()),
                );
                tokio::pin!(next_load);
                // Register the queue wait, then advance virtual time while the
                // cancelled caller's compile still owns its slot.
                match std::future::poll_fn(|cx| Poll::Ready(next_load.as_mut().poll(cx))).await {
                    Poll::Ready(result) => result,
                    Poll::Pending => {
                        tokio::time::advance(Duration::from_secs(31)).await;
                        next_load.await
                    }
                }
            };

            // Release and drain the blocking work before asserting, including
            // when an early slot release admitted the second load to the worker.
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::time::resume();
            let handle = provider.load_admitted(bytes, manifest).await.unwrap();
            provider.stop(&handle).await.unwrap();

            assert!(cancelled);
            assert!(
                matches!(result, Ok(Err(ElastosError::Compute(message)))
                    if message == "Timed out waiting for the component compiler"),
                "cancelling a load must keep later loads queued until its blocking compile finishes"
            );
            assert!(provider.instances.read().await.is_empty());
        });
    }

    #[tokio::test]
    async fn component_load_preserves_artifact_errors() {
        let provider = ComponentProvider::new();
        let (_, manifest) = component_fixture();
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            provider.load(directory.path(), manifest.clone()).await,
            Err(ElastosError::CapsuleNotFound(message))
                if message.starts_with("component file not found: ")
        ));
        std::fs::write(directory.path().join(&manifest.entrypoint), b"invalid wasm").unwrap();
        assert!(matches!(
            provider.load(directory.path(), manifest).await,
            Err(ElastosError::Compute(message))
                if message.starts_with("Failed to compile component capsule: ")
        ));
        assert!(provider.instances.read().await.is_empty());
        assert_eq!(provider.compile_slot.available_permits(), 1);
    }

    /// A v1 loading entry is taken away. A running v1 entry is ended by its
    /// stop flag, not by removing it here: its worker removes it when the run
    /// ends (the resident row does that with a real guest). A marked v2
    /// resident entry stays until stop takes it.
    #[tokio::test]
    async fn stop_takes_away_a_loading_entry_and_leaves_a_running_one_to_its_worker() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1");
        let manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(fixture.join("capsule.json")).unwrap()).unwrap();
        let bytes = std::fs::read(fixture.join("bus-v1-conformance.component.wasm")).unwrap();
        let provider = ComponentProvider::new();
        let handle = provider
            .load_admitted_sealed(bytes, manifest)
            .await
            .unwrap();
        let mark = async |status: CapsuleStatus| {
            let mut instances = provider.instances.write().await;
            instances.get_mut(&handle.id).unwrap().status = status;
        };
        // A running v1 entry takes the stop flag and stays for its worker.
        mark(CapsuleStatus::Running).await;
        provider.stop(&handle).await.unwrap();
        let left = provider.instances.read().await;
        let entry = left.get(&handle.id).expect("the running entry stays");
        assert!(entry.sealed);
        assert!(
            entry.stop_requested.load(Ordering::Acquire),
            "stop must set the flag the epoch callback reads"
        );
        drop(left);
        // A loading entry is taken away.
        mark(CapsuleStatus::Loading).await;
        provider.stop(&handle).await.unwrap();
        assert!(!provider.instances.read().await.contains_key(&handle.id));

        // The v2 start now runs guests; this marked entry is already running.
        let (bytes, manifest) = admitted_fixture();
        let mut v2_handle = provider
            .load_admitted_sealed(bytes, manifest)
            .await
            .unwrap();
        v2_handle.manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        v2_handle.manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        v2_handle.manifest.validate().unwrap();
        {
            let mut instances = provider.instances.write().await;
            let entry = instances.get_mut(&v2_handle.id).unwrap();
            entry.manifest = v2_handle.manifest.clone();
            entry.status = CapsuleStatus::Running;
        }
        let refused = provider.start(&v2_handle).await.unwrap_err().to_string();
        assert_eq!(refused, "Compute error: v2 component is already running");
        assert_eq!(
            provider.status(&v2_handle).await.unwrap(),
            CapsuleStatus::Running
        );
        provider.stop(&v2_handle).await.unwrap();
        assert!(!provider.instances.read().await.contains_key(&v2_handle.id));
    }

    /// A sealed activation has no bridge. Its call is refused by the provider
    /// with the seal's words, and no handler sees it: not one installed
    /// before the load, and not one that replaces it before the start. The
    /// control is the same component loaded the ordinary way: its call
    /// reaches the handler.
    #[tokio::test]
    async fn a_sealed_activation_reaches_no_bridge_handler() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1");
        let manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(fixture.join("capsule.json")).unwrap()).unwrap();
        let bytes = std::fs::read(fixture.join("bus-v1-conformance.component.wasm")).unwrap();
        let provider = ComponentProvider::new();
        let reached = Arc::new(Mutex::new(Vec::new()));
        let install = |name: &'static str| {
            let reached = reached.clone();
            provider.set_bus_hostcall(Arc::new(move |_line, _capsule, _principal| {
                reached.lock().unwrap().push(name);
                Err("the test's handler was reached".to_string())
            }));
        };
        for sealed in [true, false] {
            install("installed before the load");
            let loaded = if sealed {
                provider
                    .load_admitted_sealed(bytes.clone(), manifest.clone())
                    .await
            } else {
                provider
                    .load_admitted(bytes.clone(), manifest.clone())
                    .await
            };
            let handle = loaded.unwrap();
            install("installed after the load");
            // The fixture goes on to its bridge call only for this person.
            let person = Some("person:local:bus-conformance".to_string());
            provider.set_bridge_principal(&handle.id, person).await;
            let error = provider.start(&handle).await.unwrap_err().to_string();
            let reached: Vec<&str> = std::mem::take(&mut *reached.lock().unwrap());
            if sealed {
                assert!(error.contains(SEALED_BRIDGE), "{error}");
                assert!(error.contains("BusError::Denied"), "{error}");
                assert_eq!(reached, Vec::<&str>::new());
            } else {
                assert!(error.contains("the test's handler was reached"), "{error}");
                assert_eq!(reached, ["installed after the load"]);
            }
        }
    }

    /// A resident start returns while the guest still runs: the conformance
    /// guest is held in its first bridge call, the start has already returned,
    /// and no outcome is published until the call is released.
    #[tokio::test]
    async fn resident_start_returns_while_the_guest_runs() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1");
        let manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(fixture.join("capsule.json")).unwrap()).unwrap();
        let bytes = std::fs::read(fixture.join("bus-v1-conformance.component.wasm")).unwrap();
        let provider = ComponentProvider::new();
        let (entered, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let released = Arc::new(Mutex::new(released));
        let first = Arc::new(AtomicBool::new(true));
        provider.set_bus_hostcall(Arc::new(move |line, _capsule, _principal| {
            if first.swap(false, Ordering::SeqCst) {
                let _ = entered.send(());
                let _ = released.lock().unwrap().recv();
            }
            let request: serde_json::Value = json_line(line);
            match request["request"]["type"].as_str() {
                Some("request_capability") => Ok(serde_json::json!({
                    "id": 1,
                    "response": { "type": "capability_token", "token": "grant-token" }
                })
                .to_string()),
                Some("resource_invoke") => Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": { "status": "ok", "data": { "probe": true } },
                        "audit": "runtime-audit-1"
                    }
                })
                .to_string()),
                other => Err(format!("unexpected bridge request: {other:?}")),
            }
        }));
        let handle = provider
            .load_admitted(bytes, manifest)
            .await
            .expect("the conformance guest loads");
        provider
            .set_bridge_principal(&handle.id, Some("person:local:bus-conformance".into()))
            .await;

        let started =
            tokio::time::timeout(Duration::from_secs(2), provider.start_resident(&handle)).await;
        let mut resident = match started {
            Ok(start) => start.expect("the resident activation starts"),
            Err(_) => {
                // The plant made start wait for the guest: let it end so the
                // runtime can shut down, then fail here.
                let _ = release.send(());
                panic!("start returned before the guest ended");
            }
        };
        tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
            .await
            .expect("the guest is inside its first bridge call")
            .expect("the guest signal");
        assert!(
            resident.outcome().is_none(),
            "start returned before the guest ended, so no outcome is published yet"
        );

        let _ = release.send(());
        let outcome = tokio::time::timeout(Duration::from_secs(5), resident.ended())
            .await
            .expect("the released guest returns");
        assert_eq!(outcome, ActivationOutcome::Returned);
        assert!(
            provider.instances.read().await.get(&handle.id).is_none(),
            "the worker takes the activation entry away when the run ends"
        );
    }

    /// A stop request is read in the epoch callback and traps the guest as
    /// `stopped`, well before its own-code deadline would.
    #[tokio::test]
    async fn resident_stop_flag_ends_the_guest_as_stopped() {
        let provider = ComponentProvider::new();
        let (_, mut manifest) = component_fixture();
        manifest.entrypoint = "spin.component.wasm".into();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(&manifest.entrypoint),
            lifecycle_component_bytes(true, false),
        )
        .unwrap();
        let handle = provider.load(dir.path(), manifest).await.unwrap();
        // Only the stop may end this spin: the deadline is far off and the
        // fuel is not exhausted.
        {
            let mut instances = provider.instances.write().await;
            let entry = instances.get_mut(&handle.id).unwrap();
            entry.fuel = u64::MAX;
            entry.run_deadline = Duration::from_secs(3);
        }

        let mut resident = provider
            .start_resident(&handle)
            .await
            .expect("the spinning guest starts");
        provider.stop(&handle).await.expect("stop sets the flag");
        let stopped_at = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(5), resident.ended())
            .await
            .expect("the stop ends the guest, not its deadline");
        assert_eq!(
            outcome,
            ActivationOutcome::Stopped,
            "a stop request traps the guest as stopped"
        );
        assert!(
            stopped_at.elapsed() < Duration::from_millis(500),
            "the stop must be seen within a few epoch ticks, not at the deadline"
        );
        assert!(
            provider.instances.read().await.get(&handle.id).is_none(),
            "the worker takes the activation entry away when the run ends"
        );
    }

    #[tokio::test]
    async fn resident_stop_during_instantiation_reports_stopped_before_run() {
        let provider = Arc::new(ComponentProvider::new());
        let (_, mut manifest) = component_fixture();
        manifest.entrypoint = "spin-start.component.wasm".into();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(&manifest.entrypoint),
            lifecycle_component_bytes(true, true),
        )
        .unwrap();
        let handle = provider.load(dir.path(), manifest).await.unwrap();
        {
            let mut instances = provider.instances.write().await;
            let entry = instances.get_mut(&handle.id).unwrap();
            entry.fuel = u64::MAX;
            entry.run_deadline = Duration::from_secs(3);
        }
        let start = tokio::spawn({
            let provider = provider.clone();
            let handle = handle.clone();
            async move { provider.start_resident(&handle).await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if provider.status(&handle).await.unwrap() == CapsuleStatus::Running {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("start marks the activation running");
        provider.stop(&handle).await.expect("stop sets the flag");
        let result = tokio::time::timeout(Duration::from_secs(2), start)
            .await
            .expect("the stopped start completes")
            .unwrap();
        let error = match result {
            Ok(_) => panic!("a stopped start returned a resident handle"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("component was stopped before its run began"),
            "{error}"
        );
        assert!(provider.instances.read().await.get(&handle.id).is_none());
    }

    #[test]
    fn stop_during_start_function_publishes_stopped_outcome() {
        let engine = ComponentProvider::engine().unwrap();
        let component = Component::new(&engine, lifecycle_component_bytes(true, true)).unwrap();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let state = ComponentState {
            fuel: u64::MAX,
            run_deadline: Duration::from_secs(3),
            stop_requested: stop_requested.clone(),
            ..ComponentState::new(None, "spin-start".into(), None)
        };
        let (done, ended) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(ComponentProvider::instantiate_component(
                &engine, &component, state, None,
            ));
        });
        std::thread::sleep(Duration::from_millis(30));
        stop_requested.store(true, Ordering::Release);
        let outcome = ended
            .recv_timeout(Duration::from_secs(2))
            .expect("stop ends the start function");
        assert_eq!(outcome, Err(ActivationOutcome::Stopped));
    }

    #[tokio::test]
    async fn resident_start_waits_for_failed_instantiation() {
        let provider = ComponentProvider::new();
        let (_, mut manifest) = component_fixture();
        manifest.entrypoint = "failing-start.component.wasm".into();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(&manifest.entrypoint),
            lifecycle_component_bytes(true, true),
        )
        .unwrap();
        let handle = provider.load(dir.path(), manifest).await.unwrap();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .fuel = 1;
        let error = match provider.start_resident(&handle).await {
            Ok(_) => panic!("a failed start function returned a resident handle"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("Failed to instantiate component capsule"),
            "{error}"
        );
        assert!(provider.instances.read().await.get(&handle.id).is_none());
    }

    fn state_with_deadline(run_deadline: Duration) -> ComponentState {
        ComponentState {
            fuel: u64::MAX,
            run_deadline,
            ..ComponentState::new(None, "capsule-1".into(), None)
        }
    }

    /// Runs the production activation on its own thread and gives up after
    /// 20 s, so a run that no deadline stops fails here instead of hanging.
    fn run_to_its_end(
        component: Component,
        state: ComponentState,
    ) -> (std::result::Result<(), ActivationOutcome>, Duration) {
        let engine = ComponentProvider::engine().expect("component engine");
        let (done, ended) = std::sync::mpsc::channel();
        let began = Instant::now();
        std::thread::spawn(move || {
            let result = ComponentProvider::instantiate_component(&engine, &component, state, None);
            let _ = done.send(result);
        });
        let result = ended
            .recv_timeout(Duration::from_secs(20))
            .expect("the run was still going after 20 s: no deadline stopped it");
        (result, began.elapsed())
    }

    fn assert_ended_by_the_deadline(result: std::result::Result<(), ActivationOutcome>) {
        let err = result.expect_err("a loop that never ends must not finish");
        let text = err.to_string();
        let first_line = text.lines().next().unwrap_or_default();
        assert!(
            first_line.ends_with(": wasm trap: interrupt (ending: epoch-deadline)"),
            "the first line must end with the cause and the named deadline ending, was: {text}"
        );
    }

    #[test]
    fn a_quick_run_finishes_under_its_deadline() {
        let component = lifecycle_component(false, false);
        let (result, _) = run_to_its_end(component, state_with_deadline(Duration::from_secs(5)));
        result.expect("a run that returns at once is not ended by the deadline");
    }

    #[test]
    fn a_runaway_run_ends_by_the_deadline() {
        let component = lifecycle_component(true, false);
        let (result, lasted) =
            run_to_its_end(component, state_with_deadline(Duration::from_millis(200)));
        assert_ended_by_the_deadline(result);
        assert!(
            lasted < Duration::from_secs(2),
            "a 200 ms limit ended the run only after {lasted:?}"
        );
    }

    #[test]
    fn a_runaway_start_function_ends_by_the_deadline() {
        let component = lifecycle_component(true, true);
        let (result, lasted) =
            run_to_its_end(component, state_with_deadline(Duration::from_millis(200)));
        assert_ended_by_the_deadline(result);
        assert!(
            lasted < Duration::from_secs(2),
            "a 200 ms limit ended the start function only after {lasted:?}"
        );
    }

    /// A v1 component whose core `run` executes `body` before returning 0, so a
    /// test can fault the guest where a native fault is what raises the trap.
    fn trap_component_bytes(body: &str) -> Vec<u8> {
        let text = format!(
            r#"(component
              (import "elastos:bus/types@1.0.0" (instance $types
                (type $error (variant
                  (case "denied" string) (case "not-found" string) (case "invalid" string)
                  (case "unavailable" string) (case "timeout" string) (case "internal" string)))
                (export "bus-error" (type (eq $error)))))
              (alias export $types "bus-error" (type $bus-error))
              (core module $m
                (memory (export "memory") 1)
                (func (export "run") (result i32) {body} (i32.const 0)))
              (core instance $i (instantiate $m))
              (func $run (result (result (error $bus-error)))
                (canon lift (core func $i "run") (memory $i "memory")))
              (instance $lifecycle (export "run" (func $run)))
              (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#
        );
        wat::parse_str(text).expect("component text")
    }

    /// The trap a guest body ends with, named as Wasmtime names it, on the one
    /// engine the provider runs it on.
    fn trap_named_by(run: &str) -> String {
        let engine = ComponentProvider::engine().expect("component engine");
        let component = Component::new(&engine, trap_component_bytes(run)).expect("compiles");
        let (result, _) = run_to_its_end(component, state_with_deadline(Duration::from_secs(5)));
        let text = result.expect_err("the guest body must trap").to_string();
        text.lines().next().unwrap_or_default().to_string()
    }

    /// The first byte past a one-page memory is a guard page: the load faults in
    /// native code and only the installed trap handler turns that into a trap.
    /// On macOS this is the SIGBUS the signal handler receives; a Mach-port
    /// engine would take the fault down the other path entirely.
    #[test]
    fn a_guest_out_of_bounds_load_traps_as_a_named_trap() {
        assert_eq!(
            trap_named_by("(drop (i32.load (i32.const 0x1_0000)))"),
            "Compute error: Component lifecycle run failed: \
             wasm trap: out of bounds memory access"
        );
    }

    /// `unreachable` is a native illegal instruction, so the trap again comes
    /// from the handler rather than from a check the compiler emits.
    #[test]
    fn a_guest_unreachable_traps_as_a_named_trap() {
        assert_eq!(
            trap_named_by("unreachable"),
            "Compute error: Component lifecycle run failed: \
             wasm trap: wasm `unreachable` instruction executed"
        );
    }

    /// Wasmtime has no getter for `macos_use_mach_ports` (the field is
    /// crate-private and `Config` exposes no accessor, unlike
    /// `get_signals_based_traps`), so the two call sites are pinned in the
    /// source: the setting is process-global, chosen by the first Engine in the
    /// process, and a second Engine with the other value panics.
    #[test]
    fn both_engines_are_built_for_signal_traps_not_mach_ports() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/providers/component.rs"
        ))
        .expect("the compute source");
        // The rows themselves name the setting, and a `#[cfg(test)]` item sits
        // inside the production engine code, so cut at the test module's own
        // header rather than at the first `#[cfg(test)]`.
        let production = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("the test module")
            .0;
        let (v1, v2) = production
            .split_once("pub(crate) fn v2_engine()")
            .expect("the v2 engine initializer");
        for (name, half) in [("v1", v1), ("v2", v2)] {
            assert_eq!(
                half.matches("macos_use_mach_ports(false)").count(),
                1,
                "the {name} engine initializer must set macos_use_mach_ports(false) exactly once"
            );
            let set = half
                .find("config.macos_use_mach_ports")
                .expect("the setting");
            let built = half.find("Engine::new(&config)").expect("Engine::new");
            assert!(
                set < built,
                "the {name} setting must precede its Engine::new"
            );
        }
    }

    #[test]
    fn time_inside_bus_calls_is_not_counted_as_running() {
        // One second already spent inside Bus calls: the 200 ms of own running
        // time is only used up once the run has lasted longer than that second.
        let mut state = state_with_deadline(Duration::from_millis(200));
        state.in_bus = Duration::from_secs(1);
        let (result, lasted) = run_to_its_end(lifecycle_component(true, false), state);
        assert_ended_by_the_deadline(result);
        assert!(
            lasted >= Duration::from_secs(1),
            "the run was ended after {lasted:?}, before its Bus time was used up"
        );
        // And not much later: Bus time is taken off once, not more than once.
        assert!(
            lasted < Duration::from_secs(3),
            "the run went on for {lasted:?} with 1.2 s allowed"
        );
    }

    #[test]
    fn a_bus_call_adds_its_time_to_the_time_inside_the_bus() {
        let mut state = ComponentState {
            hostcall: Some(Arc::new(|_line, _capsule, _principal| {
                std::thread::sleep(Duration::from_millis(50));
                Ok(serde_json::json!({
                    "id": 1,
                    "response": { "type": "capability_token", "token": "grant-token" }
                })
                .to_string())
            })),
            ..ComponentState::new(None, "capsule-1".into(), None)
        };
        assert_eq!(state.in_bus, Duration::ZERO);
        let asked = Instant::now();
        elastos::bus::capabilities::Host::request(
            &mut state,
            elastos::bus::types::CapabilityRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                actions: vec!["read".into()],
                reason: "test".into(),
            },
        )
        .expect("the grant");
        let wall = asked.elapsed();
        assert!(
            state.in_bus >= Duration::from_millis(50) && state.in_bus <= wall,
            "the 50 ms Bus call took {wall:?} and was counted as {:?}",
            state.in_bus
        );
    }

    #[test]
    fn a_new_activation_has_ten_seconds_of_its_own_running_time() {
        let state = ComponentState::new(None, "capsule-1".into(), None);
        assert_eq!(state.run_deadline, Duration::from_secs(10));
        assert_eq!(state.in_bus, Duration::ZERO);
        assert_eq!(state.fuel, 100_000_000);
    }

    #[test]
    fn a_runaway_run_with_the_shipped_limits_ends_by_fuel_with_its_cause_and_name() {
        // The shipped fuel and time limit: an ordinary loop uses up 100M fuel long before 10 s.
        let state = ComponentState::new(None, "capsule-1".into(), None);
        let (result, _) = run_to_its_end(lifecycle_component(true, false), state);
        let err = result
            .expect_err("a loop that never ends must not finish")
            .to_string();
        assert_eq!(
            err.lines().next(),
            Some(
                "Compute error: Component lifecycle run failed: \
                 wasm trap: all fuel consumed by WebAssembly (ending: fuel-exhausted)"
            )
        );
        assert!(
            err.contains("\nerror while executing at wasm backtrace"),
            "the backtrace stays, after the cause: {err}"
        );
    }

    /// The same through the provider's own load and start, as a launch does it.
    /// Follows the photo line's test of the same name.
    #[tokio::test]
    async fn fuel_exhaustion_reaches_the_caller_with_its_cause() {
        let (_, mut manifest) = component_fixture();
        manifest.entrypoint = "spin.component.wasm".into();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(&manifest.entrypoint),
            lifecycle_component_bytes(true, false),
        )
        .unwrap();
        let provider = ComponentProvider::new();
        let handle = provider.load(dir.path(), manifest).await.unwrap();

        let err = provider.start(&handle).await.unwrap_err().to_string();

        let first_line = err.lines().next().unwrap_or_default();
        assert!(
            first_line.contains("Component lifecycle run failed: ")
                && first_line.contains("all fuel consumed"),
            "the cause must lead the message: {err}"
        );
        assert!(err.contains("wasm backtrace"), "the backtrace stays: {err}");
    }

    #[test]
    fn a_failure_that_is_no_limit_keeps_its_cause_and_gets_no_ending() {
        let err = ActivationOutcome::Trapped(run_ending(
            "Component lifecycle run failed",
            wasmtime::Error::from(Trap::UnreachableCodeReached).context("outer"),
            false,
        ))
        .to_string();
        assert_eq!(
            err,
            "Compute error: Component lifecycle run failed: \
             wasm trap: wasm `unreachable` instruction executed\nouter"
        );
    }

    #[test]
    fn component_provider_supports_only_wasm_type() {
        let provider = ComponentProvider::new();
        assert!(provider.supports(&CapsuleType::Wasm));
        assert!(!provider.supports(&CapsuleType::MicroVM));
        assert!(!provider.supports(&CapsuleType::WebProjection));
        assert!(!provider.supports(&CapsuleType::NativeProvider));
        assert!(!provider.supports(&CapsuleType::NativeHost));
    }

    #[test]
    fn provider_invoke_uses_runtime_bridge() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_host = captured.clone();
        let mut state = ComponentState {
            hostcall: Some(Arc::new(move |line, _capsule, _principal| {
                captured_host.lock().unwrap().push(line.to_string());
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": { "status": "ok", "data": { "ok": true } },
                        "audit": "runtime-audit-1"
                    }
                })
                .to_string())
            })),
            capsule_id: "capsule-1".into(),
            principal_id: Some("person:local:test".into()),
            ..ComponentState::new(None, String::new(), None)
        };

        let result = elastos::bus::providers::Host::invoke(
            &mut state,
            elastos::bus::types::InvokeRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                operation: "read".into(),
                body: b"{}".to_vec(),
                grant: Some("grant-token".into()),
            },
        )
        .unwrap();

        assert_eq!(result.status, "ok");
        assert_eq!(result.audit.as_deref(), Some("runtime-audit-1"));
        let line = captured.lock().unwrap().pop().unwrap();
        let expected = guest_bus::bridge_envelope_json(
            1,
            guest_bus::invoke_request(guest_bus::InvokeRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                operation: "read".into(),
                body: serde_json::json!({}),
                grant: Some("grant-token".into()),
            }),
        )
        .unwrap();
        assert_eq!(json_line(&line), json_line(&expected));
    }

    #[test]
    fn provider_invoke_maps_runtime_denial_without_altering_request_shape() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_host = captured.clone();
        let mut state = ComponentState {
            hostcall: Some(Arc::new(move |line, _capsule, _principal| {
                captured_host.lock().unwrap().push(line.to_string());
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "error",
                        "code": "capability_denied",
                        "message": "Capability validation failed"
                    }
                })
                .to_string())
            })),
            capsule_id: "capsule-1".into(),
            principal_id: Some("person:local:test".into()),
            ..ComponentState::new(None, String::new(), None)
        };

        let err = elastos::bus::providers::Host::invoke(
            &mut state,
            elastos::bus::types::InvokeRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                operation: "read".into(),
                body: b"{}".to_vec(),
                grant: Some("wrong-action-token".into()),
            },
        )
        .unwrap_err();

        assert!(matches!(err, elastos::bus::types::BusError::Denied(_)));
        let line = captured.lock().unwrap().pop().unwrap();
        let expected = guest_bus::bridge_envelope_json(
            1,
            guest_bus::provider_invoke(
                "localhost://Users/self/Documents/test.json",
                "read",
                serde_json::json!({}),
                Some("wrong-action-token".into()),
            ),
        )
        .unwrap();
        assert_eq!(json_line(&line), json_line(&expected));
    }

    #[test]
    fn bridge_refusals_made_before_storage_are_invalid() {
        let invoke_with = |code: &'static str| {
            let mut state = ComponentState {
                hostcall: Some(Arc::new(move |_line, _capsule, _principal| {
                    Ok(serde_json::json!({
                        "id": 1,
                        "response": { "type": "error", "code": code, "message": "refused" }
                    })
                    .to_string())
                })),
                capsule_id: "capsule-1".into(),
                principal_id: Some("person:local:test".into()),
                ..ComponentState::new(None, String::new(), None)
            };
            elastos::bus::providers::Host::invoke(
                &mut state,
                elastos::bus::types::InvokeRequest {
                    resource: "localhost://Users/self/.AppData/Agents/demo/tasks/t/journal".into(),
                    operation: "write".into(),
                    body: br#"{"content":[1]}"#.to_vec(),
                    grant: Some("grant-token".into()),
                },
            )
            .unwrap_err()
        };
        for code in [
            "revision_required",
            "revision_conflict",
            "principal_root_protection_required",
            "invalid_localhost_path",
            "append_not_allowed",
            "operation_not_allowed",
            "invalid_content",
        ] {
            assert!(
                matches!(invoke_with(code), elastos::bus::types::BusError::Invalid(_)),
                "{code}"
            );
        }
        // A failure that may come after storage stays Internal, and a token
        // refusal stays Denied.
        for code in [
            "write_failed",
            "read_failed",
            "provider_error",
            "something_new",
        ] {
            assert!(
                matches!(
                    invoke_with(code),
                    elastos::bus::types::BusError::Internal(_)
                ),
                "{code}"
            );
        }
        assert!(matches!(
            invoke_with("capability_denied"),
            elastos::bus::types::BusError::Denied(_)
        ));
        assert!(
            matches!(
                invoke_with("principal_context_required"),
                elastos::bus::types::BusError::Internal(message) if message == "refused"
            ),
            "a v1 read keeps principal_context_required as Internal"
        );
    }

    #[test]
    fn provider_invoke_without_a_grant_is_denied_before_the_bridge() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_host = captured.clone();
        let mut state = ComponentState {
            hostcall: Some(Arc::new(move |line, _capsule, _principal| {
                captured_host.lock().unwrap().push(line.to_string());
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": { "status": "ok" }
                    }
                })
                .to_string())
            })),
            capsule_id: "capsule-1".into(),
            principal_id: Some("person:local:test".into()),
            ..ComponentState::new(None, String::new(), None)
        };

        for grant in [None, Some(String::new())] {
            let err = elastos::bus::providers::Host::invoke(
                &mut state,
                elastos::bus::types::InvokeRequest {
                    resource: "localhost://Users/self/Documents/note.txt".into(),
                    operation: "read".into(),
                    body: b"{}".to_vec(),
                    grant,
                },
            )
            .unwrap_err();
            assert!(matches!(err, elastos::bus::types::BusError::Denied(_)));
        }
        assert!(
            captured.lock().unwrap().is_empty(),
            "a read with no grant must not reach the bridge"
        );
    }

    #[test]
    fn capability_request_preserves_requested_resource() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_host = captured.clone();
        let mut state = ComponentState {
            hostcall: Some(Arc::new(move |line, _capsule, _principal| {
                captured_host.lock().unwrap().push(line.to_string());
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "capability_token",
                        "token": "grant-token"
                    }
                })
                .to_string())
            })),
            capsule_id: "capsule-1".into(),
            principal_id: None,
            ..ComponentState::new(None, String::new(), None)
        };

        let grant = elastos::bus::capabilities::Host::request(
            &mut state,
            elastos::bus::types::CapabilityRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                actions: vec!["read".into()],
                reason: "test".into(),
            },
        )
        .unwrap();

        assert_eq!(grant.id, "grant-token");
        assert_eq!(grant.resource, "localhost://Users/self/Documents/test.json");
        assert_eq!(grant.actions, vec!["read"]);
        let line = captured.lock().unwrap().pop().unwrap();
        let expected = guest_bus::bridge_envelope_json(
            1,
            guest_bus::capability_request(guest_bus::CapabilityRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                actions: vec!["read".into()],
                reason: "test".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json_line(&line), json_line(&expected));
    }

    /// Loads the local agent-host guest in this process. It does not start
    /// `elastos serve` and it does not open the Home data directory.
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-local.sh"]
    async fn agent_host_example_keeps_the_head_across_a_compaction() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/agent-host");
        let manifest: CapsuleManifest = serde_json::from_str(
            &std::fs::read_to_string(root.join("capsule.json")).expect("agent-host capsule.json"),
        )
        .expect("agent-host manifest");
        let engine = ComponentProvider::engine().expect("component engine");
        let component = Component::from_file(&engine, root.join("agent-host.component.wasm"))
            .expect("compile agent-host component");
        let ty = component.component_type();
        let mut imports: Vec<String> = ty
            .imports(&engine)
            .map(|(name, _item)| name.to_string())
            .collect();
        imports.sort();
        // `capabilities` asks for the two journal grants; `providers` writes
        // and reads the guest's own task journal with them.
        let mut expected = vec![
            "elastos:bus/capabilities@1.0.0".to_string(),
            "elastos:bus/identity@1.0.0".to_string(),
            "elastos:bus/providers@1.0.0".to_string(),
            "elastos:bus/runtime@1.0.0".to_string(),
            "elastos:bus/types@1.0.0".to_string(),
        ];
        expected.sort();
        assert_eq!(
            imports, expected,
            "agent-host may import only the Bus calls it uses"
        );
        let exports: Vec<String> = ty
            .exports(&engine)
            .map(|(name, _item)| name.to_string())
            .collect();
        assert!(
            exports
                .iter()
                .any(|name| name.starts_with("elastos:bus/") && name.contains("lifecycle")),
            "agent-host exports were {exports:?}"
        );

        let provider = ComponentProvider::new();
        let bridge_lines = Arc::new(Mutex::new(Vec::new()));
        let bridge_seen = bridge_lines.clone();
        provider.set_bus_hostcall(Arc::new(move |line, _capsule, _principal| {
            bridge_seen.lock().unwrap().push(line.to_string());
            Err("this test gives the guest no bridge".to_string())
        }));
        let parent = provider
            .load(&root, manifest.clone())
            .await
            .expect("load agent-host component");
        let child = provider
            .load(&root, manifest)
            .await
            .expect("load a second agent-host component");
        assert_ne!(
            parent.id, child.id,
            "two loads must not share one component id"
        );
        provider
            .start(&parent)
            .await
            .expect("agent-host lifecycle run");
        provider
            .start(&child)
            .await
            .expect("the second component lifecycle run");
        // With no Runtime to answer, each guest asks for exactly two grants on
        // its own journal and, refused, sends no resource call.
        let lines: Vec<serde_json::Value> = bridge_lines
            .lock()
            .unwrap()
            .iter()
            .map(|line| json_line(line))
            .collect();
        let journal = "localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal";
        let asked: Vec<(String, String)> = lines
            .iter()
            .map(|line| {
                assert_eq!(line["request"]["type"], "request_capability", "{line}");
                assert_eq!(line["request"]["resource"], journal, "{line}");
                (
                    line["request"]["resource"].as_str().unwrap().to_string(),
                    line["request"]["action"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let pair = [
            (journal.to_string(), "write".to_string()),
            (journal.to_string(), "read".to_string()),
        ];
        assert_eq!(asked, [pair.clone(), pair].concat());
    }

    /// A12-R at the compute provider's own tables: the end of an activation
    /// takes its entry away, so the provider can neither run it nor let it
    /// ask again, and takes the principal it ran for away with it. The
    /// Runtime's `end_instance` is the one caller (`runtime.rs::release`).
    #[tokio::test]
    async fn forgetting_an_instance_takes_its_entry_and_principal_away() {
        let provider = ComponentProvider::new();
        let (path, manifest) = component_fixture();
        let bytes = std::fs::read(path.join("bus-v1-conformance.component.wasm"))
            .expect("the conformance component is readable");
        let handle = provider
            .load_admitted(bytes, manifest)
            .await
            .expect("the conformance component loads");
        provider
            .set_bridge_principal(&handle.id, Some("person:local:ended".to_string()))
            .await;
        assert!(
            provider.instances.read().await.contains_key(&handle.id),
            "the load holds an activation entry"
        );
        assert_eq!(
            provider.bridge_principals.read().await.get(&handle.id),
            Some(&Some("person:local:ended".to_string())),
            "the start's principal is held for the activation"
        );

        provider.forget_instance(&handle.id).await;

        assert!(
            !provider.instances.read().await.contains_key(&handle.id),
            "the end leaves no activation entry"
        );
        assert!(
            provider
                .bridge_principals
                .read()
                .await
                .get(&handle.id)
                .is_none(),
            "the end leaves no principal"
        );
        assert_eq!(
            provider.status(&handle).await.unwrap_err().to_string(),
            format!("Capsule not found: {}", handle.id.0),
            "the provider cannot run the ended activation"
        );
    }

    #[test]
    fn hold_refuses_a_revoked_id_and_a_closed_book() {
        let mut book = crate::providers::bus2_ui::GrantBook::default();
        book.revoke("grant-token");
        assert!(!book.hold(
            "grant-token",
            "localhost://Users/self/Documents/note.bin",
            "read"
        ));
        book.clear();
        assert!(!book.hold(
            "fresh-grant",
            "localhost://Users/self/Documents/note.bin",
            "read"
        ));
        assert!(book.blocks_read("fresh-grant"));
    }

    /// The host is inside the read. Revoke runs, then the bytes come back.
    /// The bytes are not given to the guest, and the revoke stays.
    #[test]
    fn a_revoke_during_a_read_is_not_undone() {
        let gate = TestGate::new();
        let host_gate = gate.clone();
        let mut state = ComponentState::new(
            Some(Arc::new(move |_line, _capsule, _principal| {
                host_gate.wait();
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": {
                            "status": "ok",
                            "data": { "content": "hello", "size": 5 }
                        }
                    }
                })
                .to_string())
            })),
            "capsule-1".into(),
            None,
        );
        hold_note_grant(&state.grants);
        let book = state.grants.clone();
        let revoker_gate = gate.clone();
        let revoker = std::thread::spawn(move || {
            revoker_gate.entered();
            book.lock().expect("grant book").revoke("grant-token");
            revoker_gate.open();
        });
        let err = state
            .windowed_read(&read_request(64), false)
            .expect_err("a revoked read returns no bytes");
        revoker.join().expect("revoker");
        assert!(
            matches!(err, V2BusError::Denied(ref message) if message.contains("closed")),
            "{err:?}"
        );
        let mut book = state.grants.lock().expect("grant book");
        assert!(book.blocks_read("grant-token"));
        assert!(!book.hold(
            "grant-token",
            "localhost://Users/self/Documents/note.bin",
            "read"
        ));
    }

    /// Present holds the book until the frame is stored. The revoke waits,
    /// then drops the frame. The frame does not outlive the revoke.
    #[test]
    fn a_revoke_during_present_does_not_leave_the_frame() {
        let gate = TestGate::new();
        let mut state = ComponentState::new(Some(use_spent_host()), "capsule-1".into(), None);
        state.present_gate = Some(gate.clone());
        hold_note_grant(&state.grants);
        let book = state.grants.clone();
        let frames = state.frames.clone();
        let id = state.capsule_id.clone();
        let revoker_gate = gate.clone();
        let revoker = std::thread::spawn(move || {
            revoker_gate.entered();
            let mut book = book.lock().expect("grant book");
            book.revoke("grant-token");
            drop_frame_naming(&frames, &id, "grant-token");
        });
        let waiter = gate.clone();
        let opener = std::thread::spawn(move || {
            waiter.entered();
            std::thread::sleep(Duration::from_millis(40));
            waiter.open();
        });
        state
            .present_document(
                crate::providers::bus2_ui::UI_MEDIA_TYPE,
                br#"{"frame":[{"image":{"grant":"grant-token"}}]}"#,
            )
            .expect("present stores under the lock");
        opener.join().expect("opener");
        revoker.join().expect("revoker");
        assert!(
            state.frames.lock().expect("frames").is_empty(),
            "the frame of a grant revoked during present is gone"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoke_during_a_request_is_not_undone() {
        let gate = TestGate::new();
        let host_gate = gate.clone();
        let host: BridgeHostcallAsync = Arc::new(move |_line, _capsule, _principal| {
            let host_gate = host_gate.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || host_gate.wait())
                    .await
                    .expect("gate");
                Ok(serde_json::json!({
                    "id": 1,
                    "response": { "type": "capability_token", "token": "late-token" }
                })
                .to_string())
            })
        });
        let mut state = ComponentState::new(None, "capsule-1".into(), None);
        state.async_hostcall = Some(host);
        let pending = state
            .begin_grant(elastos::bus::types::CapabilityRequest {
                resource: "localhost://Users/self/Documents/note.bin".into(),
                actions: vec!["read".into()],
                reason: "to read".into(),
            })
            .expect("the request can start");
        let bridge = pending.bridge.clone();
        let calling =
            tokio::spawn(async move { await_v2_bridge(&bridge, V2_APPROVAL_DEADLINE).await });
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        state.grants.lock().expect("grant book").revoke_all_held();
        gate.open();
        let raw = calling.await.expect("call");
        let err = state
            .finish_grant(pending, raw)
            .expect_err("the token is not recorded");
        assert!(
            matches!(err, elastos::bus::types::BusError::Denied(_)),
            "{err:?}"
        );
        assert!(state
            .grants
            .lock()
            .expect("grant book")
            .blocks_read("late-token"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_all_includes_a_grant_recorded_while_it_waits() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(
                &handle.id,
                "kept",
                "localhost://Users/self/Documents/note.bin",
                "read",
            )
            .await;
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![crate::providers::bus2_ui::FrameNode::Text("one".into())],
        );
        let gate = TestGate::new();
        *provider.revoke_gate.lock().expect("revoke gate") = Some(gate.clone());
        let sweeping = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.deliver_revoke_all().await })
        };
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        provider
            .testing_hold_grant(
                &handle.id,
                "late",
                "localhost://Users/self/Documents/note.bin",
                "read",
            )
            .await;
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![crate::providers::bus2_ui::FrameNode::Text("two".into())],
        );
        gate.open();
        sweeping.await.expect("sweep");
        let book = provider.instances.read().await[&handle.id].grants.clone();
        let mut book = book.lock().expect("grant book");
        assert!(book.blocks_read("kept"));
        assert!(book.blocks_read("late"));
        assert!(!book.hold("late", "localhost://Users/self/Documents/note.bin", "read"));
        drop(book);
        assert!(provider
            .frames
            .lock()
            .expect("frames")
            .get(handle.id.as_str())
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unawaited_read_does_not_park_a_burn() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "i32.const -1 i32.eq\n        if\n          global.get $events global.get $set call $join",
            "i32.const -1 i32.eq\n        if\n          i32.const 0 i32.const 0 i32.const 65536 memory.fill\n          (loop $burn br $burn)\n          global.get $events global.get $set call $join",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.expect("the burner starts");
        v2_pending_read(&provider, &handle).await;
        let ending = tokio::time::timeout(Duration::from_secs(1), v2_ending(&provider, &handle))
            .await
            .expect("the burn must reach the tick cap");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "an unawaited read left the burn running: {ending}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unawaited_read_plus_a_burn_plus_an_event_each_15ms_is_ended() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "i32.const -1 i32.eq\n        if\n          global.get $events global.get $set call $join",
            "i32.const -1 i32.eq\n        if\n          i32.const 0 i32.const 0 i32.const 65536 memory.fill\n          (loop $burn br $burn)\n          global.get $events global.get $set call $join",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 6;
        provider.start(&handle).await.expect("the burner starts");
        v2_pending_read(&provider, &handle).await;
        let sender = provider.instances.read().await[&handle.id]
            .events
            .clone()
            .expect("events");
        let source = tokio::spawn(async move {
            while sender
                .send(v2::elastos::bus::types::Event::Message(Vec::new()))
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });
        let ending = tokio::time::timeout(Duration::from_secs(1), v2_ending(&provider, &handle))
            .await
            .expect("events every 15 ms must not keep the burn alive");
        source.abort();
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "an event during the burn kept it alive: {ending}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resident_that_sleeps_and_wakes_2000_times_lives() {
        let provider = ComponentProvider::new();
        let source = include_str!("../../../../tests/fixtures/components/v2-sleep.wat")
            .replace(
                "(global $phase (mut i32) (i32.const 0))",
                "(global $phase (mut i32) (i32.const 0))\n    (global $left (mut i32) (i32.const 2000))",
            )
            .replace(
                "(func $begin (result i32)\n      (local $code i32)\n      ;; 400 ms on this guest's clock. The test's tick cap is shorter.\n      i64.const 400 call $sleep local.set $code\n      local.get $code i32.const 15 i32.and i32.const 2 i32.eq\n      if call $after-sleep return end\n      i32.const 0 global.set $phase\n      local.get $code i32.const 4 i32.shr_u call $park)",
                "(func $one-sleep (result i32)\n      (local $code i32)\n      (loop $again\n        global.get $left i32.eqz\n        if call $after-sleep return end\n        global.get $left i32.const 1 i32.sub global.set $left\n        i32.const 2000 global.get $left i32.sub i64.extend_i32_u call $sleep local.set $code\n        local.get $code i32.const 15 i32.and i32.const 2 i32.eq\n        br_if $again)\n      i32.const 0 global.set $phase\n      local.get $code i32.const 4 i32.shr_u call $park)\n    (func $begin (result i32)\n      call $one-sleep)",
            )
            .replace(
                "local.get $result i32.const 15 i32.and i32.const 2 i32.ne\n        if unreachable end\n        call $after-sleep",
                "local.get $result i32.const 15 i32.and i32.const 2 i32.ne\n        if unreachable end\n        call $one-sleep",
            );
        assert!(
            source.contains("i32.const 2000"),
            "the sleep loop was not patched"
        );
        let handle = load_v2_fixture(&provider, wat::parse_str(source).unwrap()).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            // A 1 ms sleep ends inside one tick, so it does not clear the window.
            .test_max_ticks = 500;
        provider.start(&handle).await.expect("the sleeper starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("2000 sleeps did not finish");
        assert_eq!(ending, "returned", "{ending}");
        assert!(
            started.elapsed() >= Duration::from_millis(1_500),
            "2000 one-millisecond sleeps returned in {:?}",
            started.elapsed()
        );
    }

    /// Present's bridge wait is a host wait. Ten slow presents stay inside a
    /// four-tick cap, and the events read is still pending when they finish.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ten_slow_presents_do_not_spend_the_tick_window() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(Arc::new(move |_line, _capsule, _principal| {
            let seen = seen.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(12)).await;
                seen.fetch_add(1, Ordering::Release);
                Ok(serde_json::json!({
                    "id": 1,
                    "response": {
                        "type": "resource_result",
                        "result": {"status": "ok"},
                        "use_spent": true
                    }
                })
                .to_string())
            })
        }));
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-present-loop.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(&handle.id, "g", "localhost://Local/note.txt", "read")
            .await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 4;
        let pending = provider.instances.read().await[&handle.id]
            .pending_read
            .clone();
        provider.start(&handle).await.expect("the presenter starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("ten presents did not finish");
        let elapsed = started.elapsed();
        assert_eq!(ending, "returned", "{ending} after {elapsed:?}");
        assert_eq!(
            calls.load(Ordering::Acquire),
            20,
            "check and count for each present"
        );
        assert!(
            pending.load(Ordering::Acquire),
            "the events read must still be pending"
        );
        assert!(
            elapsed >= Duration::from_millis(200),
            "ten presents of two 12 ms waits finished in {elapsed:?}"
        );
    }

    /// Host work after the deadline arm (scheduler delay on a slow machine)
    /// is not guest time: a short tick budget still lives beside a pending
    /// events read and several slow invokes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_tail_after_deadline_arm_does_not_cut_a_pending_guest() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(Arc::new(move |_line, _capsule, _principal| {
            let seen = seen.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                seen.fetch_add(1, Ordering::Release);
                Ok("{}".to_string())
            })
        }));
        let bytes = wat::parse_str(
            include_str!("../../../../tests/fixtures/components/v2-invoke-loop.wat")
                .replace("(i32.const 2000)", "(i32.const 6)"),
        )
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(&handle.id, "g", "localhost://Local/note.txt", "read")
            .await;
        let pending = {
            let mut entries = provider.instances.write().await;
            let guest = entries.get_mut(&handle.id).unwrap();
            guest.test_max_ticks = 3;
            guest.host_deadline_tail_ms.store(40, Ordering::Release);
            guest.pending_read.clone()
        };
        provider.start(&handle).await.expect("the invoker starts");
        let ending = tokio::time::timeout(Duration::from_secs(8), v2_ending(&provider, &handle))
            .await
            .expect("six invokes with a host tail did not finish");
        assert_eq!(ending, "returned", "{ending}");
        assert_eq!(calls.load(Ordering::Acquire), 6, "host calls");
        assert!(
            pending.load(Ordering::Acquire),
            "the events read must still be pending"
        );
    }

    /// A positive sleep parks for at least [`V2_SLEEP_FLOOR`] (1 ms). A loop
    /// of that length yields the core and stays inside the tick budget.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_events_read_beside_two_thousand_slow_invokes_lives() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(Arc::new(move |_line, _capsule, _principal| {
            let seen = seen.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(12)).await;
                seen.fetch_add(1, Ordering::Release);
                Ok("{}".to_string())
            })
        }));
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-invoke-loop.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(&handle.id, "g", "localhost://Local/note.txt", "read")
            .await;
        let pending = provider.instances.read().await[&handle.id]
            .pending_read
            .clone();
        provider.start(&handle).await.expect("the invoker starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(50), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("2000 invokes did not finish");
        let elapsed = started.elapsed();
        assert_eq!(ending, "returned", "{ending}");
        assert_eq!(calls.load(Ordering::Acquire), 2000, "host calls");
        assert!(
            pending.load(Ordering::Acquire),
            "the events read must still be pending"
        );
        assert!(
            elapsed >= Duration::from_secs(20),
            "2000 invokes of at least 10 ms finished in {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_guest_that_spins_between_invokes_is_cut() {
        let provider = ComponentProvider::new();
        let source = include_str!("../../../../tests/fixtures/components/v2-invoke-loop.wat")
            .replace("(i32.const 2000)", "(i32.const 6)")
            .replace("(i64.const 0)", "(i64.const 50)");
        let handle = load_v2_fixture(&provider, wat::parse_str(source).unwrap()).await;
        {
            let mut entries = provider.instances.write().await;
            let guest = entries.get_mut(&handle.id).unwrap();
            guest.test_max_ticks = 20;
            guest.test_wall_clock = true;
        }
        provider.start(&handle).await.expect("the spinner starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(3), v2_ending(&provider, &handle))
            .await
            .expect("the spin between invokes did not end");
        let elapsed = started.elapsed();
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "spin between invokes ended {ending} after {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "one 50 ms spin must not be enough; elapsed {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sleep_until_zero_loop_is_cut_like_a_spin() {
        let provider = ComponentProvider::new();
        let spin = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
        )]);
        let spin_handle = load_v2_fixture(&provider, spin).await;
        provider.start(&spin_handle).await.expect("spin starts");
        let spin_started = Instant::now();
        let spin_ending =
            tokio::time::timeout(Duration::from_secs(2), v2_ending(&provider, &spin_handle))
                .await
                .expect("the spin did not end");
        let spin_elapsed = spin_started.elapsed();
        assert!(
            spin_ending.contains(ENDING_EPOCH_DEADLINE),
            "spin ending {spin_ending}"
        );

        let source = include_str!("../../../../tests/fixtures/components/v2-sleep.wat").replace(
            "(func $begin (result i32)\n      (local $code i32)\n      ;; 400 ms on this guest's clock. The test's tick cap is shorter.\n      i64.const 400 call $sleep local.set $code\n      local.get $code i32.const 15 i32.and i32.const 2 i32.eq\n      if call $after-sleep return end\n      i32.const 0 global.set $phase\n      local.get $code i32.const 4 i32.shr_u call $park)",
            "(func $begin (result i32)\n      (local $code i32)\n      (loop $again\n        i64.const 0 call $sleep local.set $code\n        local.get $code i32.const 15 i32.and i32.const 2 i32.eq\n        br_if $again)\n      i32.const 0 global.set $phase\n      local.get $code i32.const 4 i32.shr_u call $park)",
        );
        let handle = load_v2_fixture(&provider, wat::parse_str(source).unwrap()).await;
        provider.start(&handle).await.expect("sleep 0 starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(2), v2_ending(&provider, &handle))
            .await
            .expect("sleep 0 did not end");
        let elapsed = started.elapsed();
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "sleep(0) ending {ending} after {elapsed:?}; spin was {spin_elapsed:?}"
        );
        assert!(elapsed > Duration::from_millis(50) && elapsed < Duration::from_secs(2));
        assert!(spin_elapsed > Duration::from_millis(50) && spin_elapsed < Duration::from_secs(2));
    }

    async fn grant_event_guest(provider: &ComponentProvider) -> CapsuleHandle {
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-grant-event.wat"
        ))
        .unwrap();
        load_v2_fixture(provider, bytes).await
    }

    fn grant_gate_host(gate: Arc<TestGate>, token: &'static str) -> super::BridgeHostcallAsync {
        Arc::new(move |_line, _capsule, _principal| {
            let gate = gate.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || gate.wait())
                    .await
                    .expect("gate");
                Ok(token_line(token, ""))
            })
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repeated_grant_revoked_event_keeps_the_next_grant() {
        let gate = TestGate::new();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(grant_gate_host(gate.clone(), "g2"));
        let handle = grant_event_guest(&provider).await;
        let book = provider.instances.read().await[&handle.id].grants.clone();
        book.lock().expect("grant book").revoke("g1");
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![crate::providers::bus2_ui::FrameNode::Image {
                grant: "g1".into(),
                resource: "localhost://Local/a".into(),
            }],
        );
        provider.start(&handle).await.expect("the guest starts");
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        let sender = provider.instances.read().await[&handle.id]
            .events
            .clone()
            .expect("events");
        sender
            .send(v2::elastos::bus::types::Event::GrantRevoked("g1".into()))
            .expect("deliver");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let gone = provider
                    .frames
                    .lock()
                    .expect("frames")
                    .get(handle.id.as_str())
                    .is_none();
                if gone {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the grant-revoked event was not delivered");
        gate.open();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let held = {
                    let book = book.lock().expect("grant book");
                    !book.closed && book.epoch() == 1 && !book.blocks_read("g2")
                };
                if held {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("g2 was not held");
        provider.stop(&handle).await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_real_revoke_during_a_request_refuses_the_new_grant() {
        let gate = TestGate::new();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(grant_gate_host(gate.clone(), "g2"));
        let handle = grant_event_guest(&provider).await;
        provider
            .testing_hold_grant(&handle.id, "kept", "localhost://Local/a", "read")
            .await;
        let book = provider.instances.read().await[&handle.id].grants.clone();
        provider.start(&handle).await.expect("the guest starts");
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        book.lock().expect("grant book").revoke("kept");
        gate.open();
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let book = book.lock().expect("grant book");
            assert!(!book.closed, "the guest must still be running");
            assert!(book.blocks_read("kept"), "the real revoke removed kept");
            assert!(book.blocks_read("g2"), "the in-flight grant is refused");
        }
        provider.stop(&handle).await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resident_woken_every_5ms_lives() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 30;
        provider.start(&handle).await.expect("the resident starts");
        for _ in 0..400 {
            let sender = provider
                .instances
                .read()
                .await
                .get(&handle.id)
                .and_then(|instance| instance.events.clone());
            let Some(sender) = sender else {
                panic!(
                    "a 5 ms wake ended the resident: {:?}",
                    provider.endings.read().await.get(&handle.id)
                );
            };
            let _ = sender.send(v2::elastos::bus::types::Event::Message(Vec::new()));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            provider.endings.read().await.get(&handle.id).is_none(),
            "5 ms wakes ended the resident: {:?}",
            provider.endings.read().await.get(&handle.id)
        );
        provider.stop(&handle).await.expect("stop");
        assert_eq!(v2_ending(&provider, &handle).await, "stopped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resident_lives_through_2000_short_wakes() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 30;
        provider.start(&handle).await.expect("the resident starts");
        for _ in 0..2_000 {
            let sender = provider
                .instances
                .read()
                .await
                .get(&handle.id)
                .and_then(|instance| instance.events.clone());
            let Some(sender) = sender else {
                panic!(
                    "the resident ended during the short wakes: {:?}",
                    provider.endings.read().await.get(&handle.id)
                );
            };
            let _ = sender.send(v2::elastos::bus::types::Event::Message(Vec::new()));
            tokio::time::sleep(Duration::from_millis(12)).await;
        }
        assert!(
            provider.endings.read().await.get(&handle.id).is_none(),
            "2000 short wakes ended the resident: {:?}",
            provider.endings.read().await.get(&handle.id)
        );
        provider.stop(&handle).await.expect("stop");
        assert_eq!(v2_ending(&provider, &handle).await, "stopped");
    }

    #[test]
    fn read_cap_bounds_a_large_object_before_the_scan() {
        let mut big = Vec::new();
        big.extend_from_slice(br#"{"max_bytes":1,"#);
        big.resize(2 * 1024 * 1024, b'x');
        let started = Instant::now();
        let err = crate::providers::bus2_stream::read_cap(&big).expect_err("over the param cap");
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a {} byte object took {:?}",
            big.len(),
            started.elapsed()
        );
        assert!(err.contains("over 256"), "{err}");
        let duplicate = br#"{"max_bytes":1,"max_bytes":2}"#;
        let err = crate::providers::bus2_stream::read_cap(duplicate).expect_err("duplicate key");
        assert!(err.contains("duplicate"), "{err}");
        let broken = br#"{"max_bytes":1,}"#;
        let err = crate::providers::bus2_stream::read_cap(broken).expect_err("malformed");
        assert!(!err.contains("over 256"), "{err}");
    }

    #[tokio::test]
    async fn bridge_calls_add_no_thread_across_timeouts() {
        fn threads() -> usize {
            if let Some(count) = task_threads(std::path::Path::new("/proc/self/task")) {
                return count;
            }
            let output = std::process::Command::new("ps")
                .args(["-M", &std::process::id().to_string()])
                .output()
                .expect("ps");
            String::from_utf8_lossy(&output.stdout).lines().count()
        }
        let before = threads();
        assert!(before > 0, "this process has a thread");
        let ready: BridgeHostcallAsync =
            Arc::new(|_line, _capsule, _principal| Box::pin(async { Ok("{}".to_string()) }));
        for _ in 0..200 {
            test_bridge(Some(ready.clone()), None, V2_HOST_DEADLINE)
                .await
                .expect("call");
        }
        let slow: BridgeHostcallAsync = Arc::new(|_line, _capsule, _principal| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(String::new())
            })
        });
        for _ in 0..50 {
            let err = test_bridge(Some(slow.clone()), None, Duration::from_millis(20))
                .await
                .expect_err("timeout");
            assert!(err.contains("timeout"), "{err}");
        }
        let after = threads();
        assert!(after > 0, "this process has a thread");
        // Eight other tests run in this process and own threads. One thread
        // per call would add 200. One thread per timeout would add 50, and
        // each of those still sleeps for 30s when this count is taken.
        const SIBLING_THREADS: usize = 24;
        const _: () = assert!(SIBLING_THREADS < 50);
        assert!(
            after <= before + SIBLING_THREADS,
            "thread count moved from {before} to {after}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_approval_answered_after_10_seconds_succeeds() {
        let host: BridgeHostcallAsync = Arc::new(|_line, _capsule, _principal| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(serde_json::json!({
                    "id": 1,
                    "response": { "type": "capability_token", "token": "late-grant" }
                })
                .to_string())
            })
        });
        let mut state = ComponentState::new(None, "capsule-1".into(), None);
        state.async_hostcall = Some(host);
        let pending = state
            .begin_grant(elastos::bus::types::CapabilityRequest {
                resource: "localhost://Users/self/Documents/note.bin".into(),
                actions: vec!["read".into()],
                reason: "to read".into(),
            })
            .expect("begin");
        let raw = await_v2_bridge(&pending.bridge, V2_APPROVAL_DEADLINE)
            .await
            .expect("an answer inside 30s succeeds");
        let grant = state.finish_grant(pending, Ok(raw)).expect("recorded");
        assert_eq!(grant.id, "late-grant");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_task_is_in_hand_before_the_worker_is_published() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let gate = TestGate::new();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .publish_gate = Some(gate.clone());
        let provider = Arc::new(provider);
        let starting = {
            let provider = provider.clone();
            let handle = handle.clone();
            tokio::spawn(async move { provider.start(&handle).await })
        };
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        {
            let instances = provider.instances.read().await;
            let instance = &instances[&handle.id];
            assert!(instance.task.is_none());
            assert!(instance.worker.is_none());
            assert!(instance.starting);
            assert!(instance.join.is_some());
        }
        gate.open();
        starting.await.expect("start task").expect("start");
        {
            let instances = provider.instances.read().await;
            let instance = &instances[&handle.id];
            assert!(instance.task.is_some());
            assert!(instance.worker.is_none());
            assert!(!instance.starting);
            assert!(instance.join.is_some());
            assert_eq!(instance.status, CapsuleStatus::Running);
        }
        provider.stop(&handle).await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unawaited_sleep_until_max_plus_a_burn_is_ended() {
        let provider = ComponentProvider::new();
        let source = include_str!("../../../../tests/fixtures/components/v2-sleep.wat").replace(
            "(func $begin (result i32)\n      (local $code i32)\n      ;; 400 ms on this guest's clock. The test's tick cap is shorter.\n      i64.const 400 call $sleep local.set $code\n      local.get $code i32.const 15 i32.and i32.const 2 i32.eq\n      if call $after-sleep return end\n      i32.const 0 global.set $phase\n      local.get $code i32.const 4 i32.shr_u call $park)",
            "(func $begin (result i32)\n      i64.const -1 call $sleep drop\n      i32.const 0 i32.const 0 i32.const 65536 memory.fill\n      (loop $burn br $burn)\n      i32.const 0)",
        );
        assert!(
            source.contains("i64.const -1 call $sleep drop"),
            "the sleep-until u64::MAX was not patched"
        );
        assert!(source.contains("loop $burn"), "the burn was not patched");
        let handle = load_v2_fixture(&provider, wat::parse_str(source).unwrap()).await;
        provider.start(&handle).await.expect("the burner starts");
        let ending = tokio::time::timeout(Duration::from_secs(1), v2_ending(&provider, &handle))
            .await
            .expect("the burn must reach the tick cap");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "an unawaited sleep left the burn running: {ending}"
        );
    }

    async fn burn_sleep_guest(cancel: bool) -> (ComponentProvider, CapsuleHandle) {
        let provider = ComponentProvider::new();
        let source = include_str!("../../../../tests/fixtures/components/v2-tick-burn.wat");
        let source = if cancel {
            source.replacen(
                "(i32.const 0)) ;; park-mode",
                "(i32.const 1)) ;; park-mode",
                1,
            )
        } else {
            source.to_string()
        };
        assert!(
            source.contains(if cancel {
                "(i32.const 1)) ;; park-mode"
            } else {
                "(i32.const 0)) ;; park-mode"
            }),
            "the park mode was not patched"
        );
        let handle = load_v2_fixture(&provider, wat::parse_str(&source).unwrap()).await;
        {
            let mut entries = provider.instances.write().await;
            let guest = entries.get_mut(&handle.id).unwrap();
            guest.test_max_ticks = 10;
            guest.test_wall_clock = true;
        }
        (provider, handle)
    }

    /// Cheap burn, then cancel and drop a sleep, on every pass. The sleep never
    /// parks, so the tick window reaches the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burn_and_a_cancelled_sleep_ends_at_the_tick_bound() {
        let (provider, handle) = burn_sleep_guest(true).await;
        provider.start(&handle).await.expect("the burner starts");
        let ending = tokio::time::timeout(Duration::from_secs(3), v2_ending(&provider, &handle))
            .await
            .expect("a cancelled sleep must not keep the burn alive");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "a cancelled sleep left the burn running: {ending}"
        );
    }

    /// Cheap burn, then sleep for one guest millisecond, on every pass. That
    /// wait ends inside one tick, so the window reaches the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burn_and_a_one_millisecond_sleep_ends_at_the_tick_bound() {
        let (provider, handle) = burn_sleep_guest(false).await;
        provider.start(&handle).await.expect("the burner starts");
        let ending = tokio::time::timeout(Duration::from_secs(3), v2_ending(&provider, &handle))
            .await
            .expect("a 1 ms sleep must not keep the burn alive");
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "a 1 ms sleep left the burn running: {ending}"
        );
    }

    /// A 40 ms burn and an invoke, then a real one-second sleep, four times.
    /// The sleep is a park, so the tick window starts again and the guest returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_one_second_sleep_between_invokes_keeps_the_guest() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let provider = ComponentProvider::new();
        provider.set_bus_hostcall_async(Arc::new(move |_line, _capsule, _principal| {
            let seen = seen.clone();
            Box::pin(async move {
                seen.fetch_add(1, Ordering::Release);
                Ok("{}".to_string())
            })
        }));
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-sleep-between-invokes.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .testing_hold_grant(&handle.id, "g", "localhost://Local/note.txt", "read")
            .await;
        {
            let mut entries = provider.instances.write().await;
            let guest = entries.get_mut(&handle.id).unwrap();
            guest.test_max_ticks = 10;
            guest.test_wall_clock = true;
        }
        provider.start(&handle).await.expect("the sleeper starts");
        let started = Instant::now();
        let ending = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(ending) = provider.endings.read().await.get(&handle.id).cloned() {
                    return ending;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("four one-second sleeps did not finish");
        let elapsed = started.elapsed();
        assert_eq!(ending, "returned", "{ending} after {elapsed:?}");
        assert_eq!(
            calls.load(Ordering::Acquire),
            4,
            "one invoke before each sleep"
        );
        assert!(
            elapsed >= Duration::from_millis(3_500),
            "four 1 s sleeps finished in {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_starts_on_one_handle_the_second_is_refused() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let gate = TestGate::new();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .publish_gate = Some(gate.clone());
        let starting = {
            let provider = provider.clone();
            let handle = handle.clone();
            tokio::spawn(async move { provider.start(&handle).await })
        };
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        let err = provider
            .start(&handle)
            .await
            .expect_err("second start")
            .to_string();
        assert!(err.contains("already running"), "{err}");
        gate.open();
        starting.await.expect("start task").expect("first start");
        assert_eq!(provider.threads_live.load(Ordering::Acquire), 1);
        provider.stop(&handle).await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_held_at_the_gate_counts_toward_the_cap() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let first = load_v2_fixture(&provider, bytes.clone()).await;
        provider.start(&first).await.expect("first");
        let gate = TestGate::new();
        let second = load_v2_fixture(&provider, bytes.clone()).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&second.id)
            .unwrap()
            .publish_gate = Some(gate.clone());
        let starting = {
            let provider = provider.clone();
            let second = second.clone();
            tokio::spawn(async move { provider.start(&second).await })
        };
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        let third = load_v2_fixture(&provider, bytes).await;
        let err = provider
            .start(&third)
            .await
            .expect_err("over the cap")
            .to_string();
        assert!(err.contains("v2 resident cap"), "{err}");
        gate.open();
        starting.await.expect("start task").expect("second");
        provider.stop(&first).await.expect("stop");
        provider.stop(&second).await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_in_the_publish_gap_joins_the_worker() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let gate = TestGate::new();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .publish_gate = Some(gate.clone());
        let starting = {
            let provider = provider.clone();
            let handle = handle.clone();
            tokio::spawn(async move { provider.start(&handle).await })
        };
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        assert!(provider.threads_live.load(Ordering::Acquire) >= 1);
        assert!(provider.instances.read().await[&handle.id].starting);
        provider.stop(&handle).await.expect("stop");
        assert_eq!(provider.threads_live.load(Ordering::Acquire), 0);
        assert!(!provider.instances.read().await.contains_key(&handle.id));
        gate.open();
        let err = starting
            .await
            .expect("start task")
            .expect_err("stopped")
            .to_string();
        assert!(
            err.contains("stopped before it was published")
                || err.contains("removed before its thread was stored"),
            "{err}"
        );
    }

    /// A fuel end clears the stored frame, text included, on the same exit
    /// path a trap uses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fuel_end_clears_the_stored_frame() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .v2_fuel = 1_000;
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![crate::providers::bus2_ui::FrameNode::Text("kept".into())],
        );
        provider.start(&handle).await.unwrap();
        let ending = tokio::time::timeout(Duration::from_secs(5), v2_ending(&provider, &handle))
            .await
            .expect("the fuel end finishes");
        assert!(ending.contains(ENDING_EXECUTION_BOUND), "{ending}");
        assert!(provider
            .frames
            .lock()
            .expect("frames")
            .get(&handle.id.0)
            .is_none());
        assert!(provider
            .read_v2_frame(None, handle.id.as_str())
            .await
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_natural_exit_joins_the_worker_before_the_slot_is_freed() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done\n      i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        let gate = TestGate::new();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .exit_gate = Some(gate.clone());
        provider.start(&handle).await.expect("start");
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        assert!(
            provider.instances.read().await.contains_key(&handle.id),
            "the slot is freed before the worker is joined"
        );
        assert!(provider.threads_live.load(Ordering::Acquire) >= 1);
        gate.open();
        assert_eq!(v2_ending(&provider, &handle).await, "returned");
        assert!(provider.instances.read().await.is_empty());
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.threads_live.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker is joined");
    }

    /// The frame, text included, is gone while the slot is still held for the join.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_natural_end_clears_the_frame_before_the_join() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done\n      i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.testing_store_v2_frame(
            handle.id.as_str(),
            None,
            vec![
                crate::providers::bus2_ui::FrameNode::Text("kept".into()),
                crate::providers::bus2_ui::FrameNode::Image {
                    grant: "pic".into(),
                    resource: "localhost://photo".into(),
                },
            ],
        );
        let gate = TestGate::new();
        // A failed poll still releases the worker, so the harness can exit.
        struct Release(Arc<TestGate>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.open();
            }
        }
        let _release = Release(gate.clone());
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .exit_gate = Some(gate.clone());
        provider.start(&handle).await.expect("start");
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let gone = provider
                    .frames
                    .lock()
                    .expect("frames")
                    .get(&handle.id.0)
                    .is_none()
                    && provider
                        .read_v2_frame(None, handle.id.as_str())
                        .await
                        .is_none();
                let slot = provider.instances.read().await.contains_key(&handle.id);
                if gone && slot {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the frame stays until the worker is joined");
        gate.open();
        assert_eq!(v2_ending(&provider, &handle).await, "returned");
    }

    /// Stop arrives after the natural-exit task has taken the worker. Both
    /// wait on the one join, so the slot stays until that worker is joined.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_during_natural_exit_waits_for_the_same_join() {
        let provider = Arc::new(ComponentProvider::new());
        let bytes = v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done\n      i32.const 0)",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        let gate = TestGate::new();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .exit_gate = Some(gate.clone());
        provider.start(&handle).await.expect("start");
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("entered");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let published = provider
                    .instances
                    .read()
                    .await
                    .get(&handle.id)
                    .is_some_and(|instance| instance.join.is_some());
                if published {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the exit did not publish the join");
        let stop = tokio::spawn({
            let provider = provider.clone();
            let handle = handle.clone();
            async move { provider.stop(&handle).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !stop.is_finished(),
            "stop returned while the worker was still inside the exit gate"
        );
        assert!(
            provider.instances.read().await.contains_key(&handle.id),
            "the slot was freed before the worker joined"
        );
        assert!(provider.threads_live.load(Ordering::Acquire) >= 1);
        gate.open();
        stop.await.expect("stop task").expect("stop");
        assert!(provider.instances.read().await.is_empty());
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.threads_live.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker is joined");
    }

    #[tokio::test]
    async fn drop_closes_guest_events() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        let (sender, mut receiver) = mpsc::unbounded_channel::<v2::elastos::bus::types::Event>();
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .events = Some(sender);
        drop(provider);
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_joins_while_a_reader_holds_the_instance_lock() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.expect("start");
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.threads_live.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker is live");
        let instances = provider.instances.clone();
        let live = provider.threads_live.clone();
        let gate = TestGate::new();
        let reader_gate = gate.clone();
        let reader = std::thread::spawn(move || {
            let _lock = instances.blocking_read();
            reader_gate.wait();
        });
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("the reader holds the lock");
        assert!(live.load(Ordering::Acquire) >= 1);
        let dropping = std::thread::spawn(move || drop(provider));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !dropping.is_finished(),
            "drop returned while the instance lock was held"
        );
        assert!(live.load(Ordering::Acquire) >= 1);
        gate.open();
        reader.join().expect("reader");
        dropping.join().expect("drop");
        let deadline = Instant::now() + Duration::from_secs(2);
        while live.load(Ordering::Acquire) != 0 {
            if Instant::now() > deadline {
                panic!("the worker was not joined");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_past_the_deadline_keeps_the_map_while_the_lock_is_held() {
        let provider = ComponentProvider::new();
        let bytes = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/v2-resident.wat"
        ))
        .unwrap();
        let handle = load_v2_fixture(&provider, bytes).await;
        provider.start(&handle).await.expect("start");
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.threads_live.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker is live");
        let instances = provider.instances.clone();
        let live = provider.threads_live.clone();
        let gate = TestGate::new();
        let reader_gate = gate.clone();
        let reader = std::thread::spawn(move || {
            let _lock = instances.blocking_read();
            reader_gate.wait();
        });
        tokio::task::spawn_blocking({
            let gate = gate.clone();
            move || gate.entered()
        })
        .await
        .expect("the reader holds the lock");
        let dropping = std::thread::spawn(move || drop(provider));
        std::thread::sleep(V2_HOST_DEADLINE + Duration::from_millis(400));
        assert!(
            dropping.is_finished(),
            "drop must return once the deadline passes"
        );
        assert!(
            live.load(Ordering::Acquire) >= 1,
            "the worker stays while the forgotten map holds it"
        );
        dropping.join().expect("drop");
        gate.open();
        reader.join().expect("reader");
    }

    fn spin_guest() -> Vec<u8> {
        v2_variant(&[(
            "call $new global.set $set\n      call $next)",
            "call $new global.set $set\n      (loop $spin br $spin) i32.const 0)",
        )])
    }

    async fn a_late_attach_ends_with(forget: bool) {
        let provider = Arc::new(ComponentProvider::new());
        let handle = load_v2_fixture(&provider, spin_guest()).await;
        let gate = TestGate::new();
        {
            let mut entries = provider.instances.write().await;
            let instance = entries.get_mut(&handle.id).unwrap();
            instance.attach_gate = Some(gate.clone());
            instance.test_max_ticks = 500;
        }
        let running = Arc::clone(&provider);
        let starting_handle = handle.clone();
        let starting = tokio::spawn(async move { running.start(&starting_handle).await });
        let entered = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || entered.entered())
            .await
            .unwrap();
        let began = Instant::now();
        let ending = Arc::clone(&provider);
        let ending_handle = handle.clone();
        let finished = tokio::spawn(async move {
            if forget {
                ending.forget_instance(&ending_handle.id).await;
            } else {
                ending.stop(&ending_handle).await.expect("stop");
            }
        });
        let watched = provider
            .instances
            .read()
            .await
            .get(&handle.id)
            .expect("the slot is held at the race")
            .join
            .clone()
            .expect("join");
        let release = gate;
        tokio::task::spawn_blocking(move || {
            while !watched.is_aborted() {
                std::thread::sleep(Duration::from_millis(1));
            }
            release.open();
        })
        .await
        .unwrap();
        finished.await.expect("end task");
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the guest was still up after {:?}",
            began.elapsed()
        );
        assert!(
            provider.instances.read().await.get(&handle.id).is_none(),
            "the slot stayed"
        );
        let started = starting.await.expect("start task");
        let message = format!("{started:?}");
        assert!(
            message.contains("stopped before it was published")
                || message.contains("removed before its thread was stored"),
            "{message}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_attached_after_stop_took_the_slot_is_aborted() {
        a_late_attach_ends_with(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_attached_after_forget_took_the_slot_is_aborted() {
        a_late_attach_ends_with(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_attached_after_drop_took_the_slot_is_aborted() {
        let provider = ComponentProvider::new();
        let handle = load_v2_fixture(&provider, spin_guest()).await;
        let gate = TestGate::new();
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        let watch = abort.clone();
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            while !watch.is_finished() && started.elapsed() < Duration::from_secs(3) {
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let join = V2Join::prepare(
            None,
            Some(worker),
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::Notify::new()),
            false,
            Some(Arc::clone(&gate)),
        );
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .join = Some(Arc::clone(&join));
        let passed = abort.clone();
        let attacher = std::thread::spawn(move || join.attach_task(passed));
        gate.entered();
        let watched = provider
            .instances
            .read()
            .await
            .get(&handle.id)
            .unwrap()
            .join
            .clone()
            .unwrap();
        let release = Arc::clone(&gate);
        let opener = std::thread::spawn(move || {
            while !watched.is_aborted() {
                std::thread::sleep(Duration::from_millis(1));
            }
            release.open();
        });
        let began = Instant::now();
        tokio::task::spawn_blocking(move || drop(provider))
            .await
            .unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "drop left the worker up for {:?}",
            began.elapsed()
        );
        opener.join().expect("opener");
        attacher.join().expect("attacher");
        assert!(abort.is_finished(), "the late task was not aborted");
    }

    #[test]
    fn owns_thread_is_true_only_when_a_thread_was_spawned() {
        let wake = Arc::new(tokio::sync::Notify::new());
        let inline = V2Join::prepare(
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            wake.clone(),
            true,
            None,
        );
        inline.start();
        assert!(inline.started.load(Ordering::Acquire));
        assert!(!inline.owns_thread());
        let threaded = V2Join::prepare(
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            wake,
            false,
            None,
        );
        threaded.start();
        assert!(threaded.owns_thread());
    }
}
