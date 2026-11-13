//! WASM Component Model provider for the ElastOS component ABI.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use wasmtime::component::{bindgen, Component, HasSelf, Linker};
use wasmtime::{
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline, WasmFeatures,
};

use elastos_common::{
    CapsuleId, CapsuleManifest, CapsuleRuntimeAbi, CapsuleStatus, CapsuleType, ElastosError, Result,
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

const COMPONENT_FUEL: u64 = 100_000_000;
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
/// The named ending of a run that the deadline stopped.
const ENDING_EPOCH_DEADLINE: &str = "epoch-deadline";
/// The named ending of a run that used up its fuel.
const ENDING_FUEL_EXHAUSTED: &str = "fuel-exhausted";

struct ComponentActivation {
    engine: Engine,
    component: Component,
    status: CapsuleStatus,
    manifest: CapsuleManifest,
    /// Loaded with no bridge: see [`ComponentProvider::load_admitted_sealed`].
    sealed: bool,
}

/// What a sealed component gets for any call to the bridge.
pub const SEALED_BRIDGE: &str = "this capsule was started with no authority: it has no bridge";

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
}

/// Component compute provider.
///
/// This runner exposes no WASI, environment, filesystem preopen, FIFO, raw
/// socket, or gateway authority. Every guest effect goes through the Bus
/// hostcall configured by Runtime.
pub struct ComponentProvider {
    instances: Arc<RwLock<HashMap<CapsuleId, ComponentActivation>>>,
    bus_hostcall: std::sync::RwLock<Option<BridgeHostcall>>,
    bridge_principals: Arc<RwLock<HashMap<CapsuleId, Option<String>>>>,
    compile_slot: Arc<Semaphore>,
    /// Test only: holds the next compile job just after its worker has taken
    /// the compile slot, so a test can act while a compile is in progress.
    #[cfg(test)]
    worker_gate: std::sync::Mutex<Option<tests::WorkerGate>>,
}

impl ComponentProvider {
    pub fn new() -> Self {
        Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            bus_hostcall: std::sync::RwLock::new(None),
            bridge_principals: Arc::new(RwLock::new(HashMap::new())),
            // One compile at a time: a burst of loads queues instead of
            // starting competing compiler jobs.
            compile_slot: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            worker_gate: std::sync::Mutex::new(None),
        }
    }

    pub fn set_bus_hostcall(&self, hostcall: BridgeHostcall) {
        *self.bus_hostcall.write().unwrap() = Some(hostcall);
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

    /// The one engine every component in this process compiles and runs on.
    /// The v1 ABI uses none of these proposals, so they are off here as well as
    /// compiled out of the build (`threads`, `gc`, `stack-switching` in Cargo.toml).
    fn engine() -> Result<Engine> {
        static ENGINE: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();
        ENGINE
            .get_or_init(|| {
                let mut config = Config::new();
                config.wasm_component_model(true);
                config.consume_fuel(true);
                config.epoch_interruption(true);
                config.wasm_features(
                    WasmFeatures::THREADS
                        | WasmFeatures::SHARED_EVERYTHING_THREADS
                        | WasmFeatures::GC
                        | WasmFeatures::STACK_SWITCHING,
                    false,
                );
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
    /// another capsule. The entry is taken away when the start returns. A
    /// start that is cancelled before it returns leaves its entry behind,
    /// still sealed. If the start had not yet marked it running it is still
    /// marked loading, and `stop` takes it away; once it is marked running
    /// `stop` refuses it, and it stays.
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
        let (engine, component) =
            tokio::task::spawn_blocking(move || -> Result<(Engine, Component)> {
                let _compile_permit = compile_permit;
                #[cfg(test)]
                if let Some(gate) = worker_gate {
                    gate.hold();
                }
                let engine = Self::engine()?;
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
            },
        );

        Ok(CapsuleHandle {
            id,
            manifest,
            args: Vec::new(),
        })
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
    ) -> Result<()> {
        // The deadline is armed before instantiation: a start function is guest code.
        state.run_started = Instant::now();
        let (fuel, first_ticks) = (state.fuel, deadline_ticks(state.run_deadline));
        let mut store = Store::new(engine, state);
        store.limiter(|state| &mut state.limits);
        // With the callback below the limit holds without this line too (an
        // unset deadline calls the callback at the first tick check); setting
        // it spares that first call.
        store.set_epoch_deadline(first_ticks);
        store.epoch_deadline_callback(|context| Ok(context.data().deadline_update()));
        store
            .set_fuel(fuel)
            .map_err(|err| ElastosError::Compute(format!("Failed to set component fuel: {err}")))?;

        let mut linker = Linker::new(engine);
        ProductCapsuleV1::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|err| ElastosError::Compute(format!("Failed to link bus imports: {err}")))?;
        let bindings = ProductCapsuleV1::instantiate(&mut store, component, &linker)
            .map_err(|err| run_error("Failed to instantiate component capsule", err))?;
        bindings
            .elastos_bus_lifecycle()
            .call_run(&mut store)
            .map_err(|err| run_error("Component lifecycle run failed", err))?
            .map_err(|err| ElastosError::Compute(format!("Component capsule denied: {err:?}")))?;

        Ok(())
    }
}

/// Whole ticks in `time`, and never zero: zero would trap before any guest code.
fn deadline_ticks(time: Duration) -> u64 {
    ((time.as_millis() / DEADLINE_TICK.as_millis()) as u64).max(1)
}

/// Leads with the cause Wasmtime gave (the root of its error chain: the outer
/// error alone only says "error while executing"), names the ending of a run
/// that a limit stopped, and keeps the outer text, the wasm backtrace, after it.
fn run_error(stage: &str, err: wasmtime::Error) -> ElastosError {
    let ending = match err.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => format!(" (ending: {ENDING_EPOCH_DEADLINE})"),
        Some(Trap::OutOfFuel) => format!(" (ending: {ENDING_FUEL_EXHAUSTED})"),
        _ => String::new(),
    };
    let mut chain: Vec<String> = err.chain().map(|link| link.to_string()).collect();
    let cause = chain.pop().unwrap_or_default();
    let context: String = chain.iter().map(|outer| format!("\n{outer}")).collect();
    ElastosError::Compute(format!("{stage}: {cause}{ending}{context}"))
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

    async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
        let (engine, component, sealed) = {
            let instances = self.instances.read().await;
            let instance = instances
                .get(&handle.id)
                .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?;
            (
                instance.engine.clone(),
                instance.component.clone(),
                instance.sealed,
            )
        };

        {
            let mut instances = self.instances.write().await;
            if let Some(instance) = instances.get_mut(&handle.id) {
                instance.status = CapsuleStatus::Running;
            }
        }

        let hostcall = self.bus_hostcall.read().unwrap().clone();
        let principal_id = self
            .bridge_principals
            .read()
            .await
            .get(&handle.id)
            .cloned()
            .flatten();
        let capsule_id = handle.id.0.clone();
        let state = ComponentState {
            sealed,
            ..ComponentState::new(hostcall, capsule_id, principal_id)
        };
        let result = tokio::task::spawn_blocking(move || {
            Self::instantiate_component(&engine, &component, state)
        })
        .await;

        // Drop the activation entry when the start returns, also after a
        // failed or panicked host call. A start whose future is dropped
        // before this line does not reach it, and its entry stays.
        self.instances.write().await.remove(&handle.id);

        result.map_err(|err| ElastosError::Compute(format!("Component task join error: {err}")))?
    }

    async fn stop(&self, handle: &CapsuleHandle) -> Result<()> {
        // One lock for the look and the removal: a start cannot mark the
        // entry running between the two.
        let mut instances = self.instances.write().await;
        let running = |instance: &ComponentActivation| instance.status == CapsuleStatus::Running;
        if instances.get(&handle.id).is_some_and(running) {
            return Err(ElastosError::Compute(
                "component/v1 is a bounded activation contract and has no resident stop operation"
                    .to_string(),
            ));
        }
        instances.remove(&handle.id);
        Ok(())
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
        }
    }

    /// Called when the deadline is reached: go on for the time still left, or stop.
    /// Time this run spent inside Bus calls does not count as its own running.
    fn deadline_update(&self) -> UpdateDeadline {
        let ran = self.run_started.elapsed().saturating_sub(self.in_bus);
        match self.run_deadline.checked_sub(ran) {
            Some(left) if left >= DEADLINE_TICK => UpdateDeadline::Continue(deadline_ticks(left)),
            _ => UpdateDeadline::Interrupt,
        }
    }

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

impl elastos::bus::capabilities::Host for ComponentState {
    fn request(
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
            RuntimeResponse::CapabilityToken { token } => token,
            response => return Err(response_error(&response)),
        };
        Ok(elastos::bus::types::CapabilityGrant {
            id: token,
            resource,
            actions: vec![action],
            expires_at_ms: None,
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

    /// What `stop` does with an entry a cancelled start left behind: one
    /// still marked loading is taken away; one already marked running is
    /// refused and stays, sealed as it was.
    #[tokio::test]
    async fn stop_takes_away_a_loading_entry_and_refuses_a_running_one() {
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
        // As a start leaves it when it is cancelled after its first step.
        mark(CapsuleStatus::Running).await;
        let refused = provider.stop(&handle).await.unwrap_err().to_string();
        assert!(refused.contains("no resident stop operation"), "{refused}");
        let left = provider.instances.read().await;
        let entry = left.get(&handle.id).expect("the running entry stays");
        assert!(entry.sealed);
        drop(left);
        // As a start leaves it when it is cancelled before that step.
        mark(CapsuleStatus::Loading).await;
        provider.stop(&handle).await.unwrap();
        assert!(!provider.instances.read().await.contains_key(&handle.id));
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

    fn state_with_deadline(run_deadline: Duration) -> ComponentState {
        ComponentState {
            fuel: u64::MAX,
            run_deadline,
            ..ComponentState::new(None, "capsule-1".into(), None)
        }
    }

    /// Runs the production activation on its own thread and gives up after
    /// 20 s, so a run that no deadline stops fails here instead of hanging.
    fn run_to_its_end(component: Component, state: ComponentState) -> (Result<()>, Duration) {
        let engine = ComponentProvider::engine().expect("component engine");
        let (done, ended) = std::sync::mpsc::channel();
        let began = Instant::now();
        std::thread::spawn(move || {
            let result = ComponentProvider::instantiate_component(&engine, &component, state);
            let _ = done.send(result);
        });
        let result = ended
            .recv_timeout(Duration::from_secs(20))
            .expect("the run was still going after 20 s: no deadline stopped it");
        (result, began.elapsed())
    }

    fn assert_ended_by_the_deadline(result: Result<()>) {
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
        let err = run_error(
            "Component lifecycle run failed",
            wasmtime::Error::from(Trap::UnreachableCodeReached).context("outer"),
        )
        .to_string();
        assert_eq!(
            err,
            "Compute error: Component lifecycle run failed: \
             wasm trap: wasm `unreachable` instruction executed\nouter"
        );
    }

    #[test]
    fn deadline_ticks_are_whole_ten_millisecond_ticks_and_never_zero() {
        assert_eq!(deadline_ticks(Duration::from_secs(10)), 1000);
        assert_eq!(deadline_ticks(Duration::from_millis(200)), 20);
        assert_eq!(deadline_ticks(Duration::from_millis(19)), 1);
        assert_eq!(deadline_ticks(Duration::from_millis(1)), 1);
        assert_eq!(deadline_ticks(Duration::ZERO), 1);
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
}
