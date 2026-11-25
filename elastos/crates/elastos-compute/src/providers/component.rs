//! WASM Component Model provider for the ElastOS component ABI.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
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

use crate::{CapsuleHandle, CapsuleInfo, ComputeProvider};

use super::BridgeHostcall;

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
/// Every blocking bridge call and the invoke trailer. The guest thread waits
/// this long, then the call is named a timeout. A stop joins within this too.
#[cfg(not(test))]
const V2_HOST_DEADLINE: Duration = Duration::from_secs(2);
#[cfg(test)]
const V2_HOST_DEADLINE: Duration = Duration::from_secs(2);
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
    /// How long a stop waits for that join before it answers "still running".
    join_bound: Duration,
    #[cfg(test)]
    test_max_ticks: u64,
    #[cfg(test)]
    pending_read: Arc<AtomicBool>,
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
}

/// What a sealed component gets for any call to the bridge.
pub const SEALED_BRIDGE: &str = "this capsule was started with no authority: it has no bridge";

/// The start error of an activation whose stop interrupted its start function.
pub const STOPPED_BEFORE_RUN: &str = "component was stopped before its run began";

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
    /// The v2 token bucket. v1 has none.
    fuel_bucket: Option<Arc<Mutex<super::fuel_bucket::FuelBucket>>>,
    /// v2's own limiter. v1 keeps [`ComponentState::limits`].
    guest_memory: super::fuel_bucket::GuestMemory,
    grants: Arc<Mutex<crate::providers::bus2_ui::GrantBook>>,
    /// The one presented frame, keyed by capsule id, with the principal who
    /// presented it. A second present replaces it.
    frames: Arc<Mutex<HashMap<String, StoredFrame>>>,
    /// This guest's provider budget. Guests of one provider share it.
    reads: Arc<super::bus2_stream::ReadBudget>,
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
    bridge_principals: Arc<RwLock<HashMap<CapsuleId, Option<String>>>>,
    frames: Arc<Mutex<HashMap<String, StoredFrame>>>,
    read_budget: Arc<super::bus2_stream::ReadBudget>,
    compile_slot: Arc<Semaphore>,
    /// Test only: holds the next compile job just after its worker has taken
    /// the compile slot, so a test can act while a compile is in progress.
    #[cfg(test)]
    worker_gate: std::sync::Mutex<Option<tests::WorkerGate>>,
    #[cfg(test)]
    panic_next_v2: AtomicBool,
    /// v2 guest threads that have entered their run and not left it.
    #[cfg(test)]
    threads_live: Arc<AtomicUsize>,
}

impl ComponentProvider {
    pub fn new() -> Self {
        Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(test)]
            endings: Arc::new(RwLock::new(HashMap::new())),
            bus_hostcall: std::sync::RwLock::new(None),
            bridge_principals: Arc::new(RwLock::new(HashMap::new())),
            frames: Arc::new(Mutex::new(HashMap::new())),
            read_budget: super::bus2_stream::ReadBudget::new(),
            // One compile at a time: a burst of loads queues instead of
            // starting competing compiler jobs.
            compile_slot: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            worker_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            panic_next_v2: AtomicBool::new(false),
            #[cfg(test)]
            threads_live: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn set_bus_hostcall(&self, hostcall: BridgeHostcall) {
        *self.bus_hostcall.write().unwrap() = Some(hostcall);
    }

    /// The frame stored for `id` when `caller` is the principal who presented
    /// it. A different person or app gets nothing. `None` matches a guest that
    /// ran with no principal.
    pub fn read_v2_frame(
        &self,
        caller: Option<&str>,
        id: &str,
    ) -> Option<crate::providers::bus2_ui::Frame> {
        let frames = self.frames.lock().expect("frames");
        let stored = frames.get(id)?;
        if stored.principal.as_deref() != caller {
            return None;
        }
        Some(stored.frame.clone())
    }

    /// Stores one frame so a same-process Home test can read it back.
    /// A guest present is the production writer.
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
            instance.grants.lock().expect("grant book").clear();
            instance.stop_requested.store(true, Ordering::Release);
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

    /// Sets the fuel a v2 resident starts with. A caller does this before start.
    pub async fn set_v2_fuel(&self, id: &CapsuleId, fuel: u64) -> Result<()> {
        let mut instances = self.instances.write().await;
        let instance = instances
            .get_mut(id)
            .ok_or_else(|| ElastosError::CapsuleNotFound(id.0.clone()))?;
        instance.v2_fuel = fuel;
        Ok(())
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
                join_bound: V2_HOST_DEADLINE,
                #[cfg(test)]
                test_max_ticks: V2_TEST_EPOCH_TICKS,
                #[cfg(test)]
                pending_read: Arc::new(AtomicBool::new(false)),
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
        if instance.status != CapsuleStatus::Loading {
            return Err(ElastosError::Compute(
                "v2 component is already running".into(),
            ));
        }
        let reads = self.read_budget.clone();
        let state = ComponentState {
            sealed: instance.sealed,
            grants: instance.grants.clone(),
            frames,
            reads,
            stop_requested: instance.stop_requested.clone(),
            cancel_requested: instance.cancel_requested.clone(),
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
        };
        let ending_cancel = control.cancel_requested.clone();
        #[cfg(test)]
        let panic_now = self.panic_next_v2.swap(false, Ordering::AcqRel);
        #[cfg(not(test))]
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
                    #[cfg(test)]
                    if panic_now {
                        panic!("injected v2 task panic");
                    }
                    #[cfg(not(test))]
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
        {
            let Some(instance) = entries.get_mut(&handle.id) else {
                drop(entries);
                drop(sender);
                let _ = worker.join();
                return Err(ElastosError::Compute(
                    "v2 guest was removed before its thread was stored".into(),
                ));
            };
            instance.status = CapsuleStatus::Running;
            instance.events = Some(sender);
            instance.worker = Some(worker);
        }
        drop(entries);

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
            if let Some(instance) = instances.write().await.remove(&id_for_end) {
                instance.grants.lock().expect("grant book").clear();
            }
            frames_for_end.lock().expect("frames").remove(&id_for_end.0);
            #[cfg(test)]
            endings.write().await.insert(id_for_end, ending);
        });

        let abort = match abort_rx.await {
            Ok(abort) => abort,
            Err(_) => {
                self.instances.write().await.remove(&handle.id);
                return Err(ElastosError::Compute(
                    "v2 guest thread ended before it started".into(),
                ));
            }
        };
        {
            let mut entries = self.instances.write().await;
            if let Some(instance) = entries.get_mut(&handle.id) {
                instance.task = Some(abort);
            } else {
                abort.abort();
            }
        }
        match ready_rx.await {
            Ok(result) => result?,
            Err(_) => {
                return Err(ElastosError::Compute(
                    "v2 resident task ended during start".into(),
                ));
            }
        }
        Ok(ResidentActivation {
            handle: handle.clone(),
            outcome: outcome_rx,
        })
    }

    /// Starts a loaded activation and returns once the guest is ready. A v1
    /// guest runs on a blocking thread. A v2 guest runs on its own thread, so
    /// a request worker is not the one inside the guest. Dropping the handle
    /// does not end the guest. The worker publishes the outcome and removes
    /// the activation entry when the run ends.
    pub async fn start_resident(&self, handle: &CapsuleHandle) -> Result<ResidentActivation> {
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
        let bucket = Arc::new(Mutex::new(super::fuel_bucket::FuelBucket::full(
            control.fuel,
            Instant::now(),
        )));
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
        let deadline_ticks = Arc::new(AtomicU64::new(0));
        let cancel_requested = control.cancel_requested.clone();
        let max_ticks = control.max_ticks;
        store.epoch_deadline_callback(move |context| {
            if cancel_requested.load(Ordering::Acquire) {
                return Ok(UpdateDeadline::Interrupt);
            }
            let parked = context
                .data()
                .fuel_bucket
                .as_ref()
                .is_some_and(|bucket| bucket.lock().expect("fuel").open);
            if parked {
                return Ok(UpdateDeadline::Continue(1));
            }
            Ok(
                if deadline_ticks.fetch_add(1, Ordering::AcqRel) + 1 >= max_ticks {
                    UpdateDeadline::Interrupt
                } else {
                    UpdateDeadline::Continue(1)
                },
            )
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
        ran.map_err(|err| {
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
    Arc<Mutex<super::fuel_bucket::FuelBucket>>,
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
        let _opened = charge_bucket(&self.4, &mut store);
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                release_bucket(&self.4);
                // Epochs that passed while the guest was parked are not ticks.
                store.set_epoch_deadline(1);
                note_delivered_event(&self.1, &self.2, &self.3, &event);
                destination.set_buffer(Some(event));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => {
                release_bucket(&self.4);
                store.set_epoch_deadline(1);
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Poll::Pending if finish => {
                release_bucket(&self.4);
                store.set_epoch_deadline(1);
                Poll::Ready(Ok(StreamResult::Cancelled))
            }
            Poll::Pending => {
                #[cfg(test)]
                self.5.store(true, Ordering::Release);
                Poll::Pending
            }
        }
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

/// One owner of a v2 worker. Later stops wait on this completion. The slot
/// stays until `wait` reports the worker has ended.
struct V2Join {
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
    cancel: Arc<AtomicBool>,
    done: Mutex<bool>,
    cv: Condvar,
    started: AtomicBool,
}

impl V2Join {
    fn prepare(
        task: Option<tokio::task::AbortHandle>,
        worker: Option<std::thread::JoinHandle<()>>,
        cancel: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            worker: Mutex::new(worker),
            task: Mutex::new(task),
            cancel,
            done: Mutex::new(false),
            cv: Condvar::new(),
            started: AtomicBool::new(false),
        })
    }

    /// Starts the single owner thread. A second call does nothing.
    fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let join = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("component-v2-join".into())
            .spawn(move || join.own());
        if spawned.is_err() {
            self.started.store(false, Ordering::Release);
        }
    }

    fn own(&self) {
        std::thread::sleep(V2_STOP_GRACE);
        if let Some(task) = self.task.lock().expect("join").take() {
            if !task.is_finished() {
                self.cancel.store(true, Ordering::Release);
                task.abort();
            }
        }
        if let Some(worker) = self.worker.lock().expect("join").take() {
            let _ = worker.join();
        }
        *self.done.lock().expect("join") = true;
        self.cv.notify_all();
    }

    fn wait(&self, bound: Duration) -> bool {
        let guard = self.done.lock().expect("join");
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, bound, |done| !*done)
            .expect("join");
        *guard
    }

    fn owns_thread(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }
}

/// Moves this guest's worker into the one join, or returns the join a stop
/// already owns. `None` means there is no worker to join.
fn begin_v2_join(instance: &mut ComponentActivation) -> Option<Arc<V2Join>> {
    if let Some(join) = instance.join.clone() {
        return Some(join);
    }
    let task = instance.task.take();
    let worker = instance.worker.take();
    if task.is_none() && worker.is_none() {
        return None;
    }
    let join = V2Join::prepare(task, worker, instance.cancel_requested.clone());
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

/// Charges the loan once. A bucket that is already parked is left unread.
fn charge_bucket(
    bucket: &Mutex<super::fuel_bucket::FuelBucket>,
    store: &mut impl wasmtime::AsContextMut,
) -> bool {
    let mut bucket = bucket.lock().expect("fuel");
    if bucket.open {
        return false;
    }
    let remaining = store.as_context().get_fuel().unwrap_or(0);
    let lend = bucket.settle(remaining, Instant::now()).unwrap_or(0);
    drop(bucket);
    let _ = store.as_context_mut().set_fuel(lend);
    true
}

fn release_bucket(bucket: &Mutex<super::fuel_bucket::FuelBucket>) {
    bucket.lock().expect("fuel").resume();
}

fn charge_access(access: &mut impl wasmtime::AsContextMut<Data = ComponentState>) -> bool {
    let Some(bucket) = access.as_context().data().fuel_bucket.clone() else {
        return false;
    };
    charge_bucket(&bucket, access)
}

fn release_access(access: &mut impl wasmtime::AsContextMut<Data = ComponentState>) {
    if let Some(bucket) = access.as_context().data().fuel_bucket.clone() {
        release_bucket(&bucket);
    }
    // The host call's wall time is not guest execution.
    access.as_context_mut().set_epoch_deadline(1);
}

/// Runs a v2 bridge on another thread. The guest waits at most `deadline`.
/// A panic is named `panicked`. Only a timeout is named `deadline`.
fn bounded_hostcall(
    hostcall: &BridgeHostcall,
    line: &str,
    capsule_id: &str,
    principal: Option<&str>,
    deadline: Duration,
) -> std::result::Result<String, String> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let hostcall = hostcall.clone();
    let line = line.to_string();
    let capsule_id = capsule_id.to_string();
    let principal = principal.map(str::to_string);
    std::thread::Builder::new()
        .name("component-bridge".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hostcall(&line, &capsule_id, principal.as_deref())
            }));
            let result = match result {
                Ok(value) => value,
                Err(_) => Err("panicked".into()),
            };
            let _ = done_tx.send(result);
        })
        .map_err(|err| err.to_string())?;
    match done_rx.recv_timeout(deadline) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err("panicked".into()),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err("deadline".into()),
    }
}

/// A v2 guest that is running, stopping, or still has a worker that has not
/// joined. A stop/start loop cannot pass the cap by leaving the thread up.
fn v2_slot(item: &ComponentActivation) -> bool {
    item.manifest.bus_contract.as_deref() == Some(ELASTOS_BUS_V2_CONTRACT)
        && (matches!(
            item.status,
            CapsuleStatus::Running | CapsuleStatus::Stopping
        ) || item.worker.is_some()
            || item.task.is_some())
}

impl Drop for ComponentProvider {
    fn drop(&mut self) {
        let Ok(mut instances) = self.instances.try_write() else {
            tracing::error!("instance lock busy; a guest thread may still be running");
            return;
        };
        let mut joins = Vec::new();
        for (id, instance) in instances.iter_mut() {
            instance.cancel_requested.store(true, Ordering::Release);
            instance.stop_requested.store(true, Ordering::Release);
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
            instance.stop_requested.store(true, Ordering::Release);
            return Ok(());
        }
        if !v2 {
            instances.remove(&id);
            drop(instances);
            self.frames.lock().expect("frames").remove(&id.0);
            return Ok(());
        }
        instance.stop_requested.store(true, Ordering::Release);
        instance.grants.lock().expect("grant book").clear();
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
        self.instances
            .read()
            .await
            .get(&handle.id)
            .map(|instance| instance.status)
            .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))
    }

    async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
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
    let Some(items) = content.as_array() else {
        return Err(V2BusError::Invalid("read content is not bytes".into()));
    };
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| V2BusError::Invalid("read content is not bytes".into()))
        })
        .collect()
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
            ended_by_stop: false,
            fuel_bucket: None,
            guest_memory: super::fuel_bucket::GuestMemory::default(),
            grants: Arc::new(Mutex::new(crate::providers::bus2_ui::GrantBook::default())),
            frames: Arc::new(Mutex::new(HashMap::new())),
            reads: super::bus2_stream::ReadBudget::new(),
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

    /// `bounded` is the v2 path: one bridge thread and the host deadline.
    /// v1 passes false and stays on this thread with no cap.
    fn call_bridge(
        &mut self,
        request: RuntimeRequest,
        bounded: bool,
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
        let raw = if bounded {
            bounded_hostcall(
                &hostcall,
                &line,
                &self.capsule_id,
                self.principal_id.as_deref(),
                V2_HOST_DEADLINE,
            )
        } else {
            hostcall(&line, &self.capsule_id, self.principal_id.as_deref())
        };
        self.in_bus += asked.elapsed();
        let raw = raw.map_err(|err| bus_error("internal", err))?;
        let envelope: ResponseEnvelope =
            serde_json::from_str(&raw).map_err(|err| bus_error("internal", err.to_string()))?;
        if matches!(&envelope.response, RuntimeResponse::Error { .. }) {
            return Err(response_error(&envelope.response));
        }
        Ok(envelope.response)
    }

    /// A v2 read through the sync bridge. The seal is the first decision.
    /// One call asks for `cap + 1` bytes on the bridge the v1 invoke already
    /// uses. Over the cap, this returns before any guest chunk exists.
    fn windowed_read(
        &mut self,
        request: &v2::elastos::bus::types::InvokeRequest,
        had_body: bool,
    ) -> V2Result<super::bus2_stream::PreparedRead> {
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
        if self.grants.lock().expect("grant book").blocks_read(&grant) {
            return Err(V2BusError::Denied("the grant is closed".into()));
        }
        let mut hold = super::bus2_stream::ReadHold::try_reserve(&self.reads, cap)
            .ok_or_else(|| V2BusError::Unavailable("the host read cap is already in use".into()))?;
        let resource = request.resource.clone();
        let (bytes, audit) = self.bridge_window(&resource, &grant, 0, cap as u64 + 1)?;
        if bytes.len() > cap {
            return Err(V2BusError::Invalid(format!(
                "object is {} bytes, over the cap of {cap}",
                bytes.len()
            )));
        }
        hold.shrink(bytes.len());
        self.grants
            .lock()
            .expect("grant book")
            .hold(&grant, &resource, "read");
        Ok(super::bus2_stream::PreparedRead { bytes, audit, hold })
    }

    /// Checker first, then a grant this guest already holds. One frame, replaced.
    fn present_document(&mut self, media: &str, document: &[u8]) -> V2Result<()> {
        if self.sealed {
            return Err(V2BusError::Denied(SEALED_BRIDGE.into()));
        }
        let frame = {
            let book = self.grants.lock().expect("grant book");
            crate::providers::bus2_ui::present_frame(media, document, &book)
                .map_err(present_error)?
        };
        self.frames.lock().expect("frames").insert(
            self.capsule_id.clone(),
            StoredFrame {
                principal: self.principal_id.clone(),
                frame,
            },
        );
        Ok(())
    }

    fn bridge_window(
        &mut self,
        resource: &str,
        grant: &str,
        offset: u64,
        length: u64,
    ) -> V2Result<(Vec<u8>, Option<String>)> {
        let response = self
            .call_bridge(
                guest_bus::invoke_request(guest_bus::InvokeRequest {
                    resource: resource.to_string(),
                    operation: "read".into(),
                    body: serde_json::json!({
                        "path": resource,
                        "offset": offset,
                        "length": length,
                        "check_revision": true,
                    }),
                    grant: Some(grant.to_string()),
                }),
                true,
            )
            .map_err(v2_error)?;
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
        Ok((window_bytes(data)?, audit))
    }
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
    /// `bounded` is true for a v2 call. v1 passes false: same thread, no cap.
    fn capability_request(
        &mut self,
        request: elastos::bus::types::CapabilityRequest,
        bounded: bool,
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
            bounded,
        )?;
        let token = match response {
            RuntimeResponse::CapabilityToken { token } => token,
            response => return Err(response_error(&response)),
        };
        self.grants
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
        self.capability_request(request, false)
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
        let response = self.call_bridge(
            guest_bus::invoke_request(guest_bus::InvokeRequest {
                resource: request.resource,
                operation: request.operation,
                body,
                grant: Some(grant),
            }),
            false,
        )?;
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
        self.fuel_bucket
            .as_ref()
            .map(|bucket| bucket.lock().expect("fuel").now_ms())
            .unwrap_or(0)
    }
}

impl v2::elastos::bus::clock::HostWithStore<ComponentState> for HasSelf<ComponentState> {
    async fn sleep_until_ms(
        accessor: &wasmtime::component::Accessor<ComponentState, Self>,
        deadline_ms: u64,
    ) {
        let (wait, cancel, stop) = accessor.with(|mut access| {
            let _opened = charge_access(&mut access);
            let left = {
                let state = access.get();
                state
                    .run_deadline
                    .saturating_sub(state.run_started.elapsed().saturating_sub(state.in_bus))
            };
            let wait = access
                .get()
                .fuel_bucket
                .clone()
                .map(|bucket| bucket.lock().expect("fuel").sleep_for(deadline_ms, left))
                .unwrap_or(Duration::ZERO);
            let state = access.get();
            (
                wait,
                state.cancel_requested.clone(),
                state.stop_requested.clone(),
            )
        });
        let mut left = wait;
        while !left.is_zero() {
            if cancel.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
                break;
            }
            let slice = DEADLINE_TICK.min(left);
            tokio::time::sleep(slice).await;
            left = left.saturating_sub(slice);
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
        let decided = accessor.with(|mut access| {
            let opened = charge_access(&mut access);
            let result = access.get().capability_request(
                elastos::bus::types::CapabilityRequest {
                    resource,
                    actions,
                    reason,
                },
                true,
            );
            if opened {
                release_access(&mut access);
            }
            result
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
        let super::bus2_stream::PreparedRead { bytes, audit, hold } =
            accessor.with(|mut access| {
                let opened = charge_access(&mut access);
                let result = access.get().windowed_read(&request, had_body);
                if opened {
                    release_access(&mut access);
                }
                result
            })?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        accessor
            .with(|mut access| {
                let stream = StreamReader::new(
                    &mut access,
                    super::bus2_stream::WindowRead::new(bytes, tx, hold),
                )?;
                let trailer = wasmtime::component::FutureReader::new(&mut access, async move {
                    let ended = match tokio::time::timeout(V2_HOST_DEADLINE, rx).await {
                        Ok(Ok(value)) => value,
                        Ok(Err(_)) => Err("the provider ended without a result".into()),
                        Err(_) => Err("deadline".into()),
                    };
                    Ok::<_, wasmtime::Error>(ended.map_err(V2BusError::Invalid))
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
        accessor.with(|mut access| access.get().present_document(&media_type, &document))
    }
}

fn present_error(err: crate::providers::bus2_ui::PresentError) -> V2BusError {
    match err {
        crate::providers::bus2_ui::PresentError::Invalid(message) => V2BusError::Invalid(message),
        crate::providers::bus2_ui::PresentError::Denied(message) => V2BusError::Denied(message),
    }
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
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .join_bound = Duration::from_millis(40);
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

    /// The shipped busy loop. Prints the burn rate and checks B and R against it.
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
        eprintln!("calibration fuel_per_second={rate:.0} bucket_seconds={seconds:.3} refill_per_second={refill}");
        assert!(
            (1.5..3.0).contains(&seconds),
            "B should be about two seconds of this burn, got {seconds:.3}s at {rate:.0}/s"
        );
        assert!(
            refill > 10_000,
            "R must sit above a resident's per-wake burn"
        );
        assert!(
            (refill as f64) < rate / 4.0,
            "R must sit below a full burn ({rate:.0}/s)"
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
        let slow: BridgeHostcall = Arc::new(|_, _, _| {
            std::thread::sleep(Duration::from_secs(2));
            Ok(String::new())
        });
        let err = bounded_hostcall(&slow, "", "capsule", None, Duration::from_millis(40))
            .expect_err("the guest must unblock");
        assert!(err.contains("deadline"), "{err}");
    }

    #[test]
    fn a_panicking_bridge_is_named_panicked() {
        let boom: BridgeHostcall = Arc::new(|_, _, _| panic!("bridge"));
        let err = bounded_hostcall(&boom, "", "capsule", None, Duration::from_secs(2))
            .expect_err("a panic must not look like success");
        assert!(err.contains("panicked"), "{err}");
        assert!(!err.contains("deadline"), "{err}");
    }

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
                        "result": { "status": "ok", "data": { "content": [7], "size": 1 } },
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

    /// The guest reads an event and then burns fuel, while a source keeps
    /// sending. A delivered event leaves the tick count as it is, so the
    /// guest still ends on the tick bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v2_a_delivered_event_does_not_clear_the_tick_bound() {
        let provider = ComponentProvider::new();
        let bytes = v2_variant(&[(
            "(func (export \"callback\") (param $event i32) (param $handle i32) (param $result i32) (result i32)\n      local.get $event i32.const 2 i32.eq",
            "(func (export \"callback\") (param $event i32) (param $handle i32) (param $result i32) (result i32)\n      i32.const 0 i32.const 0 i32.const 65536 memory.fill\n      local.get $event i32.const 2 i32.eq",
        )]);
        let handle = load_v2_fixture(&provider, bytes).await;
        provider
            .instances
            .write()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .test_max_ticks = 6;
        provider.start(&handle).await.unwrap();
        let sender = provider
            .instances
            .read()
            .await
            .get(&handle.id)
            .and_then(|instance| instance.events.clone())
            .expect("the guest is reading events");
        let source = tokio::spawn(async move {
            while sender
                .send(v2::elastos::bus::types::Event::Message(Vec::new()))
                .is_ok()
            {
                tokio::task::yield_now().await;
            }
        });
        let ending = v2_ending(&provider, &handle).await;
        source.abort();
        assert!(
            ending.contains(ENDING_EPOCH_DEADLINE),
            "a stream of events must still end on the tick bound, got {ending}"
        );
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
        assert!(provider.read_v2_frame(None, &handle.id.0).is_some());
        provider.stop(&handle).await.unwrap();
        assert!(book.lock().unwrap().is_empty());
        assert!(provider.read_v2_frame(None, &handle.id.0).is_none());
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
                if provider.read_v2_frame(None, &handle.id.0).is_none() {
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

    /// The bridge answers one window. `calls` records each `length`.
    /// Each call has its own budget. Guests of one provider use [`state_on`].
    fn state_for(object: Vec<u8>, calls: Arc<Mutex<Vec<u64>>>) -> ComponentState {
        state_on(
            &crate::providers::bus2_stream::ReadBudget::new(),
            object,
            calls,
        )
    }

    /// Printable bytes travel as one JSON string. A number per byte of a
    /// 16 MiB window blows the v2 host deadline.
    fn content_value(bytes: &[u8]) -> serde_json::Value {
        let printable = bytes
            .iter()
            .all(|byte| (0x20..0x7f).contains(byte) && *byte != b'"' && *byte != b'\\');
        if printable {
            serde_json::Value::String(String::from_utf8(bytes.to_vec()).expect("printable"))
        } else {
            serde_json::json!(bytes)
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
            matches!(err, V2BusError::Invalid(ref message) if message.contains("are not JSON")),
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
            3,
            "present does not call the bridge"
        );
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
}
