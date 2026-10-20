//! Runs the built `photo-viewer.component.wasm` in `ComponentProvider`, the
//! Runtime's own Component runner (`elastos-compute/src/providers/component.rs`),
//! with a fake Runtime bridge behind the Bus hostcall.
//!
//! Build the component first: `../build.sh`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use elastos_common::CapsuleManifest;
use elastos_compute::providers::ComponentProvider;
use elastos_compute::ComputeProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ALBUM: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
const PLAYLIST: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";
const A: &str = "localhost://Users/self/Pictures/a.png";
const B: &str = "localhost://Users/self/Pictures/b.jpg";
const C: &str = "localhost://Users/self/Pictures/c.webp";
const MAX_OBJECT_BYTES: usize = 128 * 1024;
const MAX_ALBUM_BODY_BYTES: usize = 128 * 1024;
const MAX_ALBUM_ITEMS: usize = 64;

/// The imports `elastos-server/src/component.rs:6-12` allows.
const ALLOWED_BUS_IMPORTS: &[&str] = &[
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

fn capsule_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn component_path() -> PathBuf {
    let path = capsule_dir().join("photo-viewer.component.wasm");
    assert!(
        path.is_file(),
        "{} is missing; run examples/photo-viewer/build.sh first",
        path.display()
    );
    path
}

fn manifest() -> CapsuleManifest {
    let text = std::fs::read_to_string(capsule_dir().join("capsule.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

// --- fake Runtime bridge ---------------------------------------------------------

#[derive(Default)]
struct Bridge {
    objects: BTreeMap<String, Vec<u8>>,
    allowed: BTreeSet<(String, String)>,
    issued: BTreeMap<String, (String, String)>,
    written: BTreeMap<String, String>,
    lines: Vec<Value>,
    bytes_served: BTreeMap<String, usize>,
}

impl Bridge {
    fn with<S: AsRef<str>>(objects: &[(S, Vec<u8>)]) -> Self {
        let items: Vec<Value> = objects
            .iter()
            .map(|(uri, _)| json!({ "uri": uri.as_ref() }))
            .collect();
        let mut bridge = Bridge::default();
        bridge.put(
            ALBUM,
            serde_json::to_vec(
                &json!({ "schema": "elastos.photo-viewer.album/v1", "items": items }),
            )
            .unwrap(),
        );
        bridge.allow(ALBUM, "read");
        bridge.allow(PLAYLIST, "write");
        for (uri, bytes) in objects {
            bridge.put(uri.as_ref(), bytes.clone());
            bridge.allow(uri.as_ref(), "read");
        }
        bridge
    }

    fn put(&mut self, uri: &str, bytes: Vec<u8>) {
        self.objects.insert(uri.to_string(), bytes);
    }

    fn allow(&mut self, uri: &str, action: &str) {
        self.allowed.insert((uri.to_string(), action.to_string()));
    }

    fn deny(&mut self, uri: &str, action: &str) {
        self.allowed.remove(&(uri.to_string(), action.to_string()));
    }

    fn invokes_on(&self, uri: &str) -> usize {
        self.lines
            .iter()
            .filter(|line| {
                line["request"]["type"] == "resource_invoke" && line["request"]["uri"] == uri
            })
            .count()
    }

    fn answer(&mut self, line: &str) -> Value {
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

    fn capability(&mut self, request: &Value) -> Value {
        let resource = request["resource"].as_str().unwrap_or_default().to_string();
        let action = request["action"].as_str().unwrap_or_default().to_string();
        if !self.allowed.contains(&(resource.clone(), action.clone())) {
            return error("denied", &format!("no {action} grant for {resource}"));
        }
        let token = format!("token-{}", self.issued.len() + 1);
        self.issued.insert(token.clone(), (resource, action));
        json!({ "type": "capability_token", "token": token })
    }

    fn invoke(&mut self, request: &Value) -> Value {
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
        let result = if action == "read" {
            match self.objects.get(&uri) {
                None => json!({ "status": "error", "code": "read_failed", "message": "not found" }),
                Some(bytes) => {
                    // resource_bridge.rs:594-604
                    let start = body["offset"].as_u64().unwrap_or(0) as usize;
                    let window: Vec<u8> = if start >= bytes.len() {
                        Vec::new()
                    } else {
                        let end = body["length"].as_u64().map_or(bytes.len(), |length| {
                            start.saturating_add(length as usize).min(bytes.len())
                        });
                        bytes[start..end].to_vec()
                    };
                    *self.bytes_served.entry(uri.clone()).or_default() += window.len();
                    json!({ "status": "ok", "data": { "content": window, "size": window.len() } })
                }
            }
        } else {
            let content = body["content"].as_str().unwrap_or_default().to_string();
            let written = content.len();
            self.written.insert(uri.clone(), content);
            json!({ "status": "ok", "data": { "bytes_written": written } })
        };
        json!({ "type": "resource_result", "result": result, "audit": "component-invoke:test" })
    }
}

fn error(code: &str, message: &str) -> Value {
    json!({ "type": "error", "code": code, "message": message })
}

/// Loads and starts the component once. Returns the Runtime's result and the
/// bridge after the run.
async fn run(bridge: Bridge) -> (Result<(), String>, Bridge) {
    let bridge = Arc::new(Mutex::new(bridge));
    let provider = ComponentProvider::new();
    let host = bridge.clone();
    provider.set_bus_hostcall(Arc::new(move |line, _capsule, _principal| {
        let response = host.lock().unwrap().answer(line);
        Ok(response.to_string())
    }));
    let _ = component_path();
    let handle = provider
        .load(&capsule_dir(), manifest())
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

// --- fixtures ----------------------------------------------------------------------

fn png(width: u32, height: u32, total: usize) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes.resize(total.max(bytes.len()), 0x5a);
    bytes
}

fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08];
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1, 0xff, 0xd9]);
    bytes
}

fn webp_vp8l(width: u32, height: u32) -> Vec<u8> {
    let bits = (width - 1) | (height - 1) << 14;
    let mut bytes = b"RIFF\x11\x00\x00\x00WEBPVP8L\x05\x00\x00\x00\x2f".to_vec();
    bytes.extend_from_slice(&bits.to_le_bytes());
    bytes
}

// --- artifact ---------------------------------------------------------------------

#[test]
fn component_imports_only_the_elastos_bus() {
    let engine = wasmtime::Engine::new(wasmtime::Config::new().wasm_component_model(true)).unwrap();
    let component = wasmtime::component::Component::from_file(&engine, component_path()).unwrap();
    let ty = component.component_type();
    let imports: Vec<String> = ty
        .imports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    let exports: Vec<String> = ty
        .exports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    println!("imports: {imports:?}");
    println!("exports: {exports:?}");
    assert!(!imports.is_empty());
    for import in &imports {
        assert!(
            ALLOWED_BUS_IMPORTS.contains(&import.as_str()),
            "import {import} is outside elastos:bus@v1"
        );
        assert!(!import.to_ascii_lowercase().contains("wasi"));
    }
    assert_eq!(exports, vec!["elastos:bus/lifecycle@1.0.0".to_string()]);
}

// Copied from `elastos-server/src/component.rs:14-136` (private there), so the
// artifact passes the same import check Runtime runs before launch
// (`elastos-server/src/runtime.rs:283`).
mod admission {
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

#[test]
fn component_passes_the_runtime_admission_import_check() {
    let bytes = std::fs::read(component_path()).unwrap();
    admission::validate_component_imports(&bytes).expect("Runtime would admit these imports");
}

#[test]
fn the_copied_admission_check_refuses_a_core_module() {
    // A plain core module (version 1, no component layer) is not admissible.
    let err = admission::validate_component_imports(b"\0asm\x01\0\0\0").unwrap_err();
    assert!(err.contains("must be a WebAssembly component"), "{err}");
}

#[test]
fn manifest_is_a_valid_component_capsule_with_narrow_storage_bounds() {
    let manifest = manifest();
    manifest.validate().expect("manifest validates");
    assert!(manifest.is_component_capsule());
    assert_eq!(manifest.entrypoint, "photo-viewer.component.wasm");
    assert_eq!(
        manifest.resource_authority_bounds(),
        vec![
            "localhost://Users/self/.AppData/App/photo-viewer/*".to_string(),
            "localhost://Users/self/Pictures/*".to_string(),
        ]
    );
}

// --- runs in the Runtime's ComponentProvider ------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn album_plays_and_the_playlist_is_written() {
    let objects = [
        (A, png(640, 480, 2048)),
        (B, jpeg(1920, 1080)),
        (C, webp_vp8l(300, 200)),
    ];
    let (result, bridge) = run(Bridge::with(&objects)).await;
    result.expect("component run succeeds");
    let playlist: Value = serde_json::from_str(&bridge.written[PLAYLIST]).unwrap();
    println!("playlist: {playlist}");
    let items = playlist["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    for (item, (uri, bytes)) in items.iter().zip(objects.iter()) {
        assert_eq!(item["uri"], *uri);
        let sha: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(item["sha256"], sha);
    }
    assert_eq!(
        (
            items[0]["mime"].clone(),
            items[0]["width"].clone(),
            items[0]["height"].clone()
        ),
        (json!("image/png"), json!(640), json!(480))
    );
    assert_eq!(items[1]["mime"], "image/jpeg");
    assert_eq!(items[2]["mime"], "image/webp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_is_denied_through_the_runtime() {
    let mut bridge = Bridge::with(&[(A, png(1, 1, 64))]);
    bridge.deny(A, "read");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Denied("),
        "{err}"
    );
    assert!(err.contains(A), "{err}");
    assert_eq!(bridge.invokes_on(A), 0);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_type_is_refused_through_the_runtime() {
    let (result, bridge) = run(Bridge::with(&[(A, b"GIF89a....".to_vec())])).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Invalid(")
            && err.contains("is not PNG, JPEG or WebP"),
        "{err}"
    );
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_is_refused_through_the_runtime_without_reading_the_body() {
    let (result, bridge) = run(Bridge::with(&[(A, png(1, 1, MAX_OBJECT_BYTES + 1))])).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Invalid(")
            && err.contains("is larger than"),
        "{err}"
    );
    assert_eq!(bridge.bytes_served[A], 32 + 1);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_header_is_refused_through_the_runtime() {
    let (result, bridge) = run(Bridge::with(&[(A, b"\x89PNG\r\n\x1a\n\x00\x00".to_vec())])).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Invalid(")
            && err.contains("ends before its image header"),
        "{err}"
    );
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_without_grant_is_denied_through_the_runtime() {
    let mut bridge = Bridge::with(&[(A, png(1, 1, 64))]);
    bridge.deny(PLAYLIST, "write");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(
        err.contains("Component capsule denied: BusError::Denied(") && err.contains(PLAYLIST),
        "{err}"
    );
    assert_eq!(bridge.invokes_on(PLAYLIST), 0);
}

/// The two albums that cost the most fuel within the guest's own limits.
fn worst_case_albums() -> Vec<(&'static str, Bridge)> {
    let many: Vec<(String, Vec<u8>)> = (0..MAX_ALBUM_ITEMS)
        .map(|index| {
            (
                format!("localhost://Users/self/Pictures/{index}.png"),
                png(10, 10, MAX_ALBUM_BODY_BYTES / MAX_ALBUM_ITEMS),
            )
        })
        .collect();
    vec![
        (
            "one image at the object limit",
            Bridge::with(&[(A, png(10, 10, MAX_OBJECT_BYTES))]),
        ),
        ("64 images filling the body budget", Bridge::with(&many)),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worst_case_albums_play_in_the_runtime_component_provider() {
    for (name, bridge) in worst_case_albums() {
        let (result, bridge) = run(bridge).await;
        result.unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(bridge.written.contains_key(PLAYLIST), "{name}");
    }
}

#[test]
fn worst_case_albums_stay_under_80_percent_of_the_runtime_fuel() {
    for (name, bridge) in worst_case_albums() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        outcome.unwrap_or_else(|err| panic!("{name}: {err}"));
        let percent = used as f64 * 100.0 / measure::RUNTIME_FUEL as f64;
        println!("{name}: {used} fuel ({percent:.1}% of the Runtime budget)");
        assert!(percent <= 80.0, "{name} uses {percent:.1}% of the fuel");
    }
}

// --- fuel measurement ---------------------------------------------------------------
//
// ComponentProvider fixes fuel at 100_000_000 (`component.rs:28`) and reports a
// trap without its cause (`component.rs:134` formats only the outer context).
// This runner uses the same world, engine config and store limits, but its own
// Store, so it can read how much fuel a run used.

mod measure {
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
                capsule: "photo-viewer".into(),
                session: "photo-viewer".into(),
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

    /// Runs once with `fuel`. Returns the outcome and the fuel used.
    pub fn run(bridge: Bridge, fuel: u64) -> (Result<(), String>, u64) {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();
        let component = Component::from_file(&engine, super::component_path()).unwrap();
        let limits = StoreLimitsBuilder::new()
            .memory_size(128 * 1024 * 1024)
            .instances(16)
            .tables(32)
            .memories(4)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&engine, State { bridge, limits });
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

/// Measurement, not a gate: fuel used per object size, against the
/// Runtime's fixed budget. Run with
/// `cargo test --locked -- --ignored --nocapture fuel_probe`.
#[test]
#[ignore]
fn fuel_probe() {
    for kib in [1, 64, 256, 512, 1024, 2048, 4096] {
        let bridge = Bridge::with(&[(A, png(10, 10, kib * 1024))]);
        let (outcome, used) = measure::run(bridge, u64::MAX / 2);
        println!(
            "fuel_probe {kib:>5} KiB: {used:>12} fuel ({:>5.1}% of the Runtime budget), {}",
            used as f64 * 100.0 / measure::RUNTIME_FUEL as f64,
            if outcome.is_ok() {
                "plays".to_string()
            } else {
                format!("{outcome:?}")
            }
        );
    }
}
