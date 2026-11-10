//! WASM Component Model provider for the ElastOS component ABI.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
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
/// One deadline tick. Wasmtime calls this the engine "epoch"; this code says
/// "tick", because "epoch" already names the capability revocation epoch.
const DEADLINE_TICK: Duration = Duration::from_millis(10);
/// How long one activation's own code may run. Time inside Bus calls is not
/// counted, so a run that waits on the Runtime is not ended for waiting.
/// Fuel counts instructions, and how long an instruction takes depends on the
/// instruction and the machine; this bounds the time itself.
const COMPONENT_RUN_DEADLINE: Duration = Duration::from_secs(10);
/// The named ending of a run that the deadline stopped.
const ENDING_EPOCH_DEADLINE: &str = "epoch-deadline";

struct ComponentActivation {
    engine: Engine,
    component: Component,
    status: CapsuleStatus,
    manifest: CapsuleManifest,
}

struct ComponentState {
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
}

impl ComponentProvider {
    pub fn new() -> Self {
        Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            bus_hostcall: std::sync::RwLock::new(None),
            bridge_principals: Arc::new(RwLock::new(HashMap::new())),
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

/// A run the deadline stopped gets its named ending; any other failure keeps its text.
fn run_error(stage: &str, err: wasmtime::Error) -> ElastosError {
    if err.downcast_ref::<Trap>() == Some(&Trap::Interrupt) {
        return ElastosError::Compute(format!(
            "Component run ended: {ENDING_EPOCH_DEADLINE} (its own code ran past its time limit)"
        ));
    }
    ElastosError::Compute(format!("{stage}: {err}"))
}

impl Default for ComponentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ComputeProvider for ComponentProvider {
    async fn load(&self, path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
        if manifest.validate().is_err() || !Self::is_component_manifest(&manifest) {
            return Err(ElastosError::Compute(
                "ComponentProvider only accepts elastos.component/v1 manifests".into(),
            ));
        }

        let component_path = path.join(&manifest.entrypoint);
        if !component_path.exists() {
            return Err(ElastosError::CapsuleNotFound(format!(
                "component file not found: {}",
                component_path.display()
            )));
        }

        let engine = Self::engine()?;
        let component = Component::from_file(&engine, &component_path).map_err(|err| {
            ElastosError::Compute(format!("Failed to compile component capsule: {err}"))
        })?;
        let id = CapsuleId::new(format!("component-{}", uuid::Uuid::new_v4()));

        self.instances.write().await.insert(
            id.clone(),
            ComponentActivation {
                engine,
                component,
                status: CapsuleStatus::Loading,
                manifest: manifest.clone(),
            },
        );

        Ok(CapsuleHandle {
            id,
            manifest,
            args: Vec::new(),
        })
    }

    async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
        let (engine, component) = {
            let instances = self.instances.read().await;
            let instance = instances
                .get(&handle.id)
                .ok_or_else(|| ElastosError::CapsuleNotFound(handle.id.0.clone()))?;
            (instance.engine.clone(), instance.component.clone())
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
        let state = ComponentState::new(hostcall, capsule_id, principal_id);
        let result = tokio::task::spawn_blocking(move || {
            Self::instantiate_component(&engine, &component, state)
        })
        .await;

        // Drop the activation entry when it finishes, including a failed or panicked host call.
        self.instances.write().await.remove(&handle.id);

        result.map_err(|err| ElastosError::Compute(format!("Component task join error: {err}")))?
    }

    async fn stop(&self, handle: &CapsuleHandle) -> Result<()> {
        if self
            .instances
            .read()
            .await
            .get(&handle.id)
            .is_some_and(|instance| instance.status == CapsuleStatus::Running)
        {
            return Err(ElastosError::Compute(
                "component/v1 is a bounded activation contract and has no resident stop operation"
                    .to_string(),
            ));
        }
        self.instances.write().await.remove(&handle.id);
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
        let engine = ComponentProvider::engine().expect("component engine");
        Component::new(&engine, wat::parse_str(text).expect("component text")).expect("compiles")
    }

    /// An activation with the given time limit and fuel that never runs out,
    /// so that only the deadline can end a loop.
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
        assert!(
            err.to_string()
                .contains("Component run ended: epoch-deadline"),
            "the ending must be the named deadline ending, was: {err}"
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
        let (result, _) =
            run_to_its_end(component, state_with_deadline(Duration::from_millis(200)));
        assert_ended_by_the_deadline(result);
    }

    #[test]
    fn a_runaway_start_function_ends_by_the_deadline() {
        let component = lifecycle_component(true, true);
        let (result, _) =
            run_to_its_end(component, state_with_deadline(Duration::from_millis(200)));
        assert_ended_by_the_deadline(result);
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
        elastos::bus::capabilities::Host::request(
            &mut state,
            elastos::bus::types::CapabilityRequest {
                resource: "localhost://Users/self/Documents/test.json".into(),
                actions: vec!["read".into()],
                reason: "test".into(),
            },
        )
        .expect("the grant");
        assert!(
            state.in_bus >= Duration::from_millis(50),
            "the 50 ms Bus call was counted as {:?}",
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
