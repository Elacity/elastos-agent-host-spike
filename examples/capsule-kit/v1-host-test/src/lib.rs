//! The host-test harness every Bus v1 component capsule of the capsule kit
//! shares (kit item A2): a fake Runtime bridge behind the Bus hostcall, a run
//! of the built component in the Runtime's own `ComponentProvider`, a copy of
//! the Runtime's admission import check, and a fuel runner.
//!
//! Moved here from `examples/photo-viewer/host-test/tests/component.rs`. Each
//! capsule's own `host-test/tests/component.rs` keeps its fixtures and tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use elastos_common::CapsuleManifest;
use elastos_compute::providers::ComponentProvider;
use elastos_compute::ComputeProvider;
use serde_json::{json, Value};

/// The imports `elastos-server/src/component.rs:6-12` allows.
pub const ALLOWED_BUS_IMPORTS: &[&str] = &[
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

// --- fake Runtime bridge ---------------------------------------------------------

#[derive(Default)]
pub struct Bridge {
    pub objects: BTreeMap<String, Vec<u8>>,
    pub allowed: BTreeSet<(String, String)>,
    pub issued: BTreeMap<String, (String, String)>,
    pub written: BTreeMap<String, String>,
    pub lines: Vec<Value>,
    pub bytes_served: BTreeMap<String, usize>,
    pub provider_errors: BTreeMap<String, String>,
}

impl Bridge {
    /// A bridge holding a list object at `list`
    /// (`{"schema": schema, "items": [{"uri": ...}, ...]}` for `objects`),
    /// each object, a read grant on the list and on each object, and a write
    /// grant on `output`.
    pub fn with_list<S: AsRef<str>>(
        list: &str,
        schema: &str,
        output: &str,
        objects: &[(S, Vec<u8>)],
    ) -> Self {
        let items: Vec<Value> = objects
            .iter()
            .map(|(uri, _)| json!({ "uri": uri.as_ref() }))
            .collect();
        let mut bridge = Bridge::default();
        bridge.put(
            list,
            serde_json::to_vec(&json!({ "schema": schema, "items": items })).unwrap(),
        );
        bridge.allow(list, "read");
        bridge.allow(output, "write");
        for (uri, bytes) in objects {
            bridge.put(uri.as_ref(), bytes.clone());
            bridge.allow(uri.as_ref(), "read");
        }
        bridge
    }

    pub fn put(&mut self, uri: &str, bytes: Vec<u8>) {
        self.objects.insert(uri.to_string(), bytes);
    }

    pub fn allow(&mut self, uri: &str, action: &str) {
        self.allowed.insert((uri.to_string(), action.to_string()));
    }

    pub fn deny(&mut self, uri: &str, action: &str) {
        self.allowed.remove(&(uri.to_string(), action.to_string()));
    }

    pub fn invokes_on(&self, uri: &str) -> usize {
        self.lines
            .iter()
            .filter(|line| {
                line["request"]["type"] == "resource_invoke" && line["request"]["uri"] == uri
            })
            .count()
    }

    pub fn answer(&mut self, line: &str) -> Value {
        let envelope: Value = serde_json::from_str(line).expect("bridge line is JSON");
        self.lines.push(envelope.clone());
        let id = envelope["id"].clone();
        let request = &envelope["request"];
        let response = match request["type"].as_str() {
            Some("request_capability") => self.capability(request),
            Some("resource_invoke") => self.invoke(request),
            other => error("invalid", &format!("unexpected request type {other:?}")),
        };
        json!({ "id": id, "response": response })
    }

    pub fn capability(&mut self, request: &Value) -> Value {
        let resource = request["resource"].as_str().unwrap_or_default().to_string();
        let action = request["action"].as_str().unwrap_or_default().to_string();
        if !self.allowed.contains(&(resource.clone(), action.clone())) {
            return error("denied", &format!("no {action} grant for {resource}"));
        }
        let token = format!("token-{}", self.issued.len() + 1);
        self.issued.insert(token.clone(), (resource, action));
        json!({ "type": "capability_token", "token": token })
    }

    pub fn invoke(&mut self, request: &Value) -> Value {
        let uri = request["uri"].as_str().unwrap_or_default().to_string();
        let operation = request["operation"].as_str().unwrap_or_default();
        let body = &request["body"];
        let token = request["token"].as_str().unwrap_or_default();
        if token.is_empty() {
            return error(
                "missing_token",
                "resource_invoke requires a capability token",
            );
        }
        let action = match operation {
            "read" => "read",
            "write" => "write",
            _ => return error("invalid_resource_invoke", "unsupported operation"),
        };
        match self.issued.get(token) {
            Some((resource, granted)) if *resource == uri && granted == action => {}
            _ => return error("capability_denied", "Capability validation failed"),
        }
        if body["path"].as_str() != Some(uri.as_str()) {
            return error("invalid_resource_invoke", "path must equal the resource");
        }
        let result = if let Some(problem) = provider_body_problem(action, body) {
            json!({ "status": "error", "code": "invalid_request", "message": problem })
        } else if let Some(message) = self.provider_errors.get(&uri) {
            json!({ "status": "error", "code": "read_failed", "message": message })
        } else if action == "read" {
            match self.objects.get(&uri) {
                None => json!({ "status": "error", "code": "read_failed", "message": "not found" }),
                Some(bytes) => {
                    // resource_bridge.rs:594-604
                    let start = body["offset"].as_u64().unwrap_or(0) as usize;
                    let window: Vec<u8> = if start >= bytes.len() {
                        Vec::new()
                    } else {
                        let length = body["length"].as_u64().unwrap() as usize;
                        let end = start.saturating_add(length).min(bytes.len());
                        bytes[start..end].to_vec()
                    };
                    *self.bytes_served.entry(uri.clone()).or_default() += window.len();
                    json!({ "status": "ok", "data": { "content": window, "size": window.len() } })
                }
            }
        } else {
            let content: Vec<u8> = serde_json::from_value(body["content"].clone()).unwrap();
            let written = content.len();
            self.written
                .insert(uri.clone(), String::from_utf8(content).unwrap());
            json!({ "status": "ok", "data": { "bytes_written": written } })
        };
        json!({ "type": "resource_result", "result": result, "audit": "component-invoke:test" })
    }
}

/// What the localhost provider would refuse in this body
/// (`elastos/capsules/localhost-provider/src/main.rs:25-48`, unknown fields
/// refused; `length` required here because the provider underflows without it).
pub fn provider_body_problem(action: &str, body: &Value) -> Option<String> {
    let allowed: &[&str] = match action {
        "read" => &["path", "offset", "length", "encoding"],
        _ => &["path", "content", "append"],
    };
    let object = body.as_object()?;
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Some(format!("unknown field `{key}`"));
    }
    if action == "read" {
        return (!body["length"].is_u64()).then(|| "read must name a length".into());
    }
    if serde_json::from_value::<Vec<u8>>(body["content"].clone()).is_err() {
        return Some("write content must be a byte array".into());
    }
    (!body["append"].is_boolean()).then(|| "write must say append".into())
}

pub fn error(code: &str, message: &str) -> Value {
    json!({ "type": "error", "code": code, "message": message })
}

/// Loads and starts the capsule in `capsule_dir` once in `ComponentProvider`.
/// Returns the Runtime's result and the bridge after the run.
pub async fn run(
    capsule_dir: &Path,
    manifest: CapsuleManifest,
    bridge: Bridge,
) -> (Result<(), String>, Bridge) {
    let bridge = Arc::new(Mutex::new(bridge));
    let provider = ComponentProvider::new();
    let host = bridge.clone();
    provider.set_bus_hostcall(Arc::new(move |line, _capsule, _principal| {
        let response = host.lock().unwrap().answer(line);
        Ok(response.to_string())
    }));
    let handle = provider
        .load(capsule_dir, manifest)
        .await
        .expect("ComponentProvider loads the capsule");
    provider
        .set_bridge_principal(&handle.id, Some("person:local:test".into()))
        .await;
    let result = provider.start(&handle).await.map_err(|err| err.to_string());
    // The provider keeps the hostcall, so take the state out through the lock.
    let bridge = std::mem::take(&mut *bridge.lock().unwrap());
    (result, bridge)
}

/// The component's import and export names, as Wasmtime reads them.
pub fn imports_and_exports(component: &Path) -> (Vec<String>, Vec<String>) {
    let engine = wasmtime::Engine::new(wasmtime::Config::new().wasm_component_model(true)).unwrap();
    let component = wasmtime::component::Component::from_file(&engine, component).unwrap();
    let ty = component.component_type();
    let imports = ty
        .imports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    let exports = ty
        .exports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    (imports, exports)
}

// --- the Runtime's admission import check -----------------------------------------

// Copied from `elastos-server/src/component.rs:14-136` (private there), so the
// artifact passes the same import check Runtime runs before launch
// (`elastos-server/src/runtime.rs:283`).
pub mod admission {
    use super::ALLOWED_BUS_IMPORTS;
    use wasmparser::{ComponentTypeRef, Encoding, Parser, Payload};

    const FORBIDDEN_AUTHORITY_MARKERS: &[&str] = &[
        "wasi",
        "env",
        "preopen",
        "socket",
        "sock",
        "fifo",
        "fd_",
        "path_",
        "http",
        "tcp",
        "udp",
        "ELASTOS_API",
        "ELASTOS_TOKEN",
        "ELASTOS_CARRIER_FIFOS",
        "_carrier",
    ];

    pub fn validate_component_imports(bytes: &[u8]) -> Result<(), String> {
        let mut saw_root_header = false;
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.map_err(|err| format!("failed to parse component entrypoint: {err}"))? {
                Payload::Version { encoding, .. } if !saw_root_header => {
                    saw_root_header = true;
                    if encoding != Encoding::Component {
                        return Err("component entrypoint must be a WebAssembly component".into());
                    }
                }
                Payload::ComponentImportSection(section) => {
                    for import in section {
                        let import = import.map_err(|err| err.to_string())?;
                        let name = import.name.0;
                        if name.starts_with("import-type-") {
                            if !matches!(import.ty, ComponentTypeRef::Type(_)) {
                                return Err(format!("generated type import {name} must be a type"));
                            }
                            continue;
                        }
                        if name == "import-func-run" {
                            if !matches!(import.ty, ComponentTypeRef::Func(_)) {
                                return Err("generated run import must be a function".into());
                            }
                            continue;
                        }
                        if !ALLOWED_BUS_IMPORTS.contains(&name) {
                            return Err(format!("component import {name:?} is not allowed"));
                        }
                        if !matches!(import.ty, ComponentTypeRef::Instance(_)) {
                            return Err(format!("component import {name:?} must be an instance"));
                        }
                    }
                }
                Payload::ImportSection(section) => {
                    for import in section {
                        let import = import.map_err(|err| err.to_string())?;
                        validate_core_import(import.module, import.name)?;
                    }
                }
                _ => {}
            }
        }
        if !saw_root_header {
            return Err("component entrypoint is empty".into());
        }
        Ok(())
    }

    fn validate_core_import(module: &str, name: &str) -> Result<(), String> {
        let lower = format!("{module}::{name}").to_ascii_lowercase();
        if FORBIDDEN_AUTHORITY_MARKERS
            .iter()
            .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
        {
            return Err(format!("core import \"{module}::{name}\" is forbidden"));
        }
        if ALLOWED_BUS_IMPORTS.contains(&module) {
            return Ok(());
        }
        if module.is_empty()
            && (name == "$imports" || name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Ok(());
        }
        Err(format!("core import \"{module}::{name}\" is not allowed"))
    }
}

// --- fuel measurement ---------------------------------------------------------------
//
// ComponentProvider fixes fuel at 100_000_000 (`component.rs:28`) and reports a
// trap without its cause (`component.rs:134` formats only the outer context).
// This runner uses the same world, engine config and store limits, but its own
// Store, so it can read how much fuel a run used.

pub mod measure {
    use std::path::Path;

    use super::Bridge;
    use serde_json::{json, Value};
    use wasmtime::component::{bindgen, Component, HasSelf, Linker};
    use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

    bindgen!({
        path: "../../../elastos/wit",
        world: "product-capsule-v1",
    });

    use elastos::bus::types::{
        BusError, CapabilityGrant, CapabilityRequest, IdentityContext, InvokeRequest,
        InvokeResponse, RuntimeInfo,
    };

    pub const RUNTIME_FUEL: u64 = 100_000_000;

    struct State {
        bridge: Bridge,
        capsule: String,
        limits: StoreLimits,
    }

    fn bus_error(response: &Value) -> BusError {
        let message = response["message"].as_str().unwrap_or_default().to_string();
        match response["code"].as_str().unwrap_or_default() {
            "denied" | "capability_denied" | "missing_token" | "invalid_token" => {
                BusError::Denied(message)
            }
            _ => BusError::Invalid(message),
        }
    }

    impl elastos::bus::types::Host for State {}

    impl elastos::bus::runtime::Host for State {
        fn info(&mut self) -> RuntimeInfo {
            RuntimeInfo {
                abi: "elastos.component/v1".into(),
                runtime_version: "host-test".into(),
            }
        }
    }

    impl elastos::bus::identity::Host for State {
        fn context(&mut self) -> IdentityContext {
            IdentityContext {
                principal: Some("person:local:test".into()),
                capsule: self.capsule.clone(),
                session: self.capsule.clone(),
                device: None,
            }
        }
    }

    impl elastos::bus::capabilities::Host for State {
        fn request(&mut self, request: CapabilityRequest) -> Result<CapabilityGrant, BusError> {
            let response = self.bridge.capability(&json!({
                "resource": request.resource,
                "action": request.actions[0],
            }));
            match response["token"].as_str() {
                Some(token) => Ok(CapabilityGrant {
                    id: token.into(),
                    resource: request.resource,
                    actions: request.actions,
                    expires_at_ms: None,
                }),
                None => Err(bus_error(&response)),
            }
        }
    }

    impl elastos::bus::providers::Host for State {
        fn invoke(&mut self, request: InvokeRequest) -> Result<InvokeResponse, BusError> {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let response = self.bridge.invoke(&json!({
                "uri": request.resource,
                "operation": request.operation,
                "body": body,
                "token": request.grant.unwrap_or_default(),
            }));
            if response["type"] != "resource_result" {
                return Err(bus_error(&response));
            }
            let result = &response["result"];
            Ok(InvokeResponse {
                status: result["status"].as_str().unwrap_or("ok").into(),
                body: serde_json::to_vec(result).unwrap(),
                audit: None,
            })
        }
    }

    /// Runs `component` (as capsule `capsule`) once with `fuel`. Returns the
    /// outcome and the fuel used.
    pub fn run(
        bridge: Bridge,
        component: &Path,
        capsule: &str,
        fuel: u64,
    ) -> (Result<(), String>, u64) {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();
        let component = Component::from_file(&engine, component).unwrap();
        let limits = StoreLimitsBuilder::new()
            .memory_size(128 * 1024 * 1024)
            .instances(16)
            .tables(32)
            .memories(4)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &engine,
            State {
                bridge,
                capsule: capsule.to_string(),
                limits,
            },
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(fuel).unwrap();
        let mut linker = Linker::new(&engine);
        ProductCapsuleV1::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).unwrap();
        let bindings = ProductCapsuleV1::instantiate(&mut store, &component, &linker).unwrap();
        let outcome = match bindings.elastos_bus_lifecycle().call_run(&mut store) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(format!("{err:?}")),
            Err(trap) => Err(format!("{:?}", trap.root_cause())),
        };
        let used = fuel - store.get_fuel().unwrap();
        (outcome, used)
    }
}
