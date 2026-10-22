//! Runs the built `docs-viewer.component.wasm` in `ComponentProvider`, the
//! Runtime's own Component runner (`elastos-compute/src/providers/component.rs`),
//! with a fake Runtime bridge behind the Bus hostcall.
//!
//! Build the component first: `../build.sh`.
//!
//! The bridge, the admission check and the fuel runner are copied from
//! `examples/photo-viewer/host-test/tests/component.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use elastos_common::CapsuleManifest;
use elastos_compute::providers::ComponentProvider;
use elastos_compute::ComputeProvider;
use serde_json::{json, Value};

const SHELF: &str = "localhost://Users/self/.AppData/App/docs-viewer/shelf.json";
const PAGES: &str = "localhost://Users/self/.AppData/App/docs-viewer/pages.json";
const A: &str = "localhost://Users/self/Documents/notes.md";
const B: &str = "localhost://Users/self/Documents/todo.txt";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
const MAX_SHELF_BYTES: usize = 4 * 1024;
const MAX_SHELF_ITEMS: usize = 8;

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
    let path = capsule_dir().join("docs-viewer.component.wasm");
    assert!(
        path.is_file(),
        "{} is missing; run examples/docs-viewer/build.sh first",
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
    provider_errors: BTreeMap<String, String>,
}

impl Bridge {
    fn with<S: AsRef<str>>(objects: &[(S, Vec<u8>)]) -> Self {
        let items: Vec<Value> = objects
            .iter()
            .map(|(uri, _)| json!({ "uri": uri.as_ref() }))
            .collect();
        let mut bridge = Bridge::default();
        bridge.put(
            SHELF,
            serde_json::to_vec(
                &json!({ "schema": "elastos.docs-viewer.shelf/v1", "items": items }),
            )
            .unwrap(),
        );
        bridge.allow(SHELF, "read");
        bridge.allow(PAGES, "write");
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
fn provider_body_problem(action: &str, body: &Value) -> Option<String> {
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

/// `size` bytes of ordinary markdown: headings, paragraphs with some
/// emphasis and code, and lists.
fn markdown(size: usize) -> Vec<u8> {
    let unit =
        "## A section\n\nSome *words* here, a `name` there and **a few** more words to read.\n\
                It goes on for a line or two, as notes do.\n\n- one item\n- another item\n\n";
    repeat_to(unit, size)
}

/// `size` bytes of markdown with the most spans a block may hold, which
/// renders past what a shelf may show and is skipped.
fn worst_markdown(size: usize) -> Vec<u8> {
    repeat_to(&format!("{}\n\n", "`a` ".repeat(127)), size)
}

/// Markdown that renders to nearly all a shelf may show (64 KiB) from about
/// 4 KiB: nine paragraphs of 120 one-character code spans.
fn shown_to_the_cap() -> Vec<u8> {
    format!("{}\n\n", "`a` ".repeat(120)).repeat(9).into_bytes()
}

/// `size` bytes that are read in full and then skipped: too many spans.
fn too_long_markdown(size: usize) -> Vec<u8> {
    repeat_to(&format!("{}\n\n", "`a` ".repeat(300)), size)
}

/// `size` bytes of openers that never close.
fn never_closed(size: usize) -> Vec<u8> {
    repeat_to("[a](*b <c:", size)
}

/// `size` bytes of backtick runs that never close: each run has a length no
/// other run has (Codex's probe).
fn distinct_backticks(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size + 256);
    let mut run = 1;
    while bytes.len() < size {
        bytes.extend_from_slice(&vec![b'`'; run]);
        bytes.extend_from_slice(b"a ");
        run += 1;
    }
    bytes.truncate(size);
    bytes
}

fn repeat_to(unit: &str, size: usize) -> Vec<u8> {
    let mut bytes = unit.repeat(size / unit.len() + 1).into_bytes();
    bytes.truncate(size);
    bytes
}

fn doc(n: usize) -> String {
    format!("localhost://Users/self/Documents/{n}.md")
}

// --- manifest -----------------------------------------------------------------------

#[test]
fn manifest_is_a_valid_component_capsule_with_narrow_storage_bounds() {
    let manifest = manifest();
    manifest.validate().expect("manifest validates");
    assert!(manifest.is_component_capsule());
    assert_eq!(manifest.entrypoint, "docs-viewer.component.wasm");
    assert_eq!(
        manifest.resource_authority_bounds(),
        vec![
            "localhost://Users/self/.AppData/App/docs-viewer/*".to_string(),
            "localhost://Users/self/Documents/*".to_string(),
        ]
    );
}

// --- runs in the Runtime's ComponentProvider ------------------------------------------

fn pages(bridge: &Bridge) -> Value {
    serde_json::from_str(&bridge.written[PAGES]).expect("pages written")
}

fn denied(err: &str) -> bool {
    err.contains("Component capsule denied: BusError::Denied(")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shelf_is_shown_and_its_pages_are_written() {
    let objects = [
        (A, b"# Trip\n\n- tent\n- `stove`\n".to_vec()),
        (B, b"milk\nbread".to_vec()),
    ];
    let (result, bridge) = run(Bridge::with(&objects)).await;
    result.unwrap();
    let pages = pages(&bridge);
    assert_eq!(pages["schema"], "elastos.docs-viewer.pages/v1");
    assert_eq!(pages["documents"][0]["title"], "Trip");
    assert_eq!(
        pages["documents"][0]["blocks"][1],
        json!({ "kind": "list", "ordered": false, "items": [
            [{ "style": "plain", "text": "tent" }],
            [{ "style": "code", "text": "stove" }],
        ] })
    );
    assert_eq!(pages["documents"][1]["mime"], "text/plain");
    assert_eq!(pages["skipped"], json!([]));
    // Each object through its own token, in order.
    let uris: Vec<&str> = bridge
        .lines
        .iter()
        .filter(|line| line["request"]["type"] == "request_capability")
        .map(|line| line["request"]["resource"].as_str().unwrap())
        .collect();
    assert_eq!(uris, [SHELF, A, B, PAGES]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_failures_are_skipped_and_listed_through_the_runtime() {
    let objects = [
        (
            "localhost://Users/self/Documents/a.pdf".to_string(),
            b"%PDF-1.7".to_vec(),
        ),
        (
            "localhost://Users/self/Documents/b.md".to_string(),
            b"\0\x01\x02".to_vec(),
        ),
        (
            "localhost://Users/self/Documents/c.md".to_string(),
            markdown(MAX_DOCUMENT_BYTES + 1),
        ),
        (A.to_string(), b"kept".to_vec()),
    ];
    let (result, bridge) = run(Bridge::with(&objects)).await;
    result.unwrap();
    let pages = pages(&bridge);
    let reasons: Vec<&str> = pages["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skip| skip["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["wrong_kind", "not_text", "oversize"]);
    assert_eq!(pages["documents"][0]["order"], 3);
    assert!(bridge.bytes_served["localhost://Users/self/Documents/c.md"] <= 512 + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_grant_stops_the_run_through_the_runtime() {
    let mut bridge = Bridge::with(&[(A, b"# a".to_vec()), (B, b"b".to_vec())]);
    bridge.deny(A, "read");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err), "{err}");
    assert!(err.contains(A), "{err}");
    assert_eq!(bridge.invokes_on(A), 0, "no read without a grant");
    assert_eq!(bridge.invokes_on(B), 0);
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_error_stops_the_run_through_the_runtime() {
    let mut bridge = Bridge::with(&[(A, b"# a".to_vec())]);
    bridge
        .provider_errors
        .insert(A.to_string(), "disk gone".to_string());
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(err.contains("disk gone"), "{err}");
    assert!(bridge.written.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_without_grant_is_denied_through_the_runtime() {
    let mut bridge = Bridge::with(&[(A, b"# a".to_vec())]);
    bridge.deny(PAGES, "write");
    let (result, bridge) = run(bridge).await;
    let err = result.unwrap_err();
    assert!(denied(&err), "{err}");
    assert!(bridge.written.is_empty());
}

/// The shelves that cost the most fuel within the caps.
fn worst_case_shelves() -> Vec<(&'static str, Bridge)> {
    let shelf_of = |make: fn(usize) -> Vec<u8>| -> Bridge {
        let docs: Vec<(String, Vec<u8>)> = (0..MAX_SHELF_ITEMS)
            .map(|n| (doc(n), make(MAX_DOCUMENT_BYTES)))
            .collect();
        Bridge::with(&docs)
    };
    // The shelf itself at its cap: the longest names that fit.
    let name = "n".repeat(
        (MAX_SHELF_BYTES - 60) / MAX_SHELF_ITEMS - "localhost://Users/self/Documents/".len() - 20,
    );
    let named: Vec<(String, Vec<u8>)> = (0..MAX_SHELF_ITEMS)
        .map(|n| {
            (
                format!("localhost://Users/self/Documents/{name}{n}.md"),
                worst_markdown(MAX_DOCUMENT_BYTES),
            )
        })
        .collect();
    vec![
        ("8 full documents", shelf_of(markdown)),
        (
            "8 full documents of the most spans",
            shelf_of(worst_markdown),
        ),
        (
            "8 full documents skipped after reading",
            shelf_of(too_long_markdown),
        ),
        (
            "8 full documents of openers that never close",
            shelf_of(never_closed),
        ),
        (
            "8 full documents of brackets that never close",
            shelf_of(|size| repeat_to("[", size)),
        ),
        (
            "8 full documents of backtick runs of distinct lengths",
            shelf_of(distinct_backticks),
        ),
        ("the longest shelf of the most spans", Bridge::with(&named)),
        ("shown to the cap, then read to the cap", {
            let mut docs = vec![(doc(0), shown_to_the_cap())];
            docs.extend(
                (1..MAX_SHELF_ITEMS).map(|n| (doc(n), too_long_markdown(MAX_DOCUMENT_BYTES))),
            );
            Bridge::with(&docs)
        }),
    ]
}

#[test]
fn the_worst_case_shelf_object_is_near_its_cap() {
    let (_, bridge) = worst_case_shelves()
        .into_iter()
        .find(|(name, _)| *name == "the longest shelf of the most spans")
        .unwrap();
    let size = bridge.objects[SHELF].len();
    println!("worst shelf object: {size} bytes");
    assert!(size <= MAX_SHELF_BYTES, "{size}");
    assert!(size > MAX_SHELF_BYTES * 3 / 4, "{size}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worst_case_shelves_run_in_the_runtime_component_provider() {
    for (name, bridge) in worst_case_shelves() {
        let (result, bridge) = run(bridge).await;
        result.unwrap_or_else(|err| panic!("{name}: {err}"));
        // Written whole, each byte as a number of up to four characters: far
        // under the 1 MiB bridge frame (`resource_bridge.rs:32`).
        let size = bridge.written[PAGES].len();
        println!("{name}: {size} bytes of pages");
        assert!(size <= 96 * 1024, "{name}: {size}");
    }
}

#[test]
fn worst_case_shelves_stay_under_80_percent_of_the_runtime_fuel() {
    for (name, bridge) in worst_case_shelves() {
        let (outcome, used) = measure::run(bridge, measure::RUNTIME_FUEL);
        outcome.unwrap_or_else(|err| panic!("{name}: {err}"));
        let percent = used as f64 * 100.0 / measure::RUNTIME_FUEL as f64;
        println!("{name}: {used} fuel ({percent:.1}% of the Runtime budget)");
        assert!(percent <= 80.0, "{name} uses {percent:.1}% of the fuel");
    }
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
                capsule: "docs-viewer".into(),
                session: "docs-viewer".into(),
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

/// Named objects for one shelf.
type Objects = Vec<(String, Vec<u8>)>;

/// Measurement, not a gate: fuel per shelf shape. Run with
/// `cargo test --locked -- --ignored --nocapture fuel_probe`.
#[test]
#[ignore]
fn fuel_probe() {
    let shapes: Vec<(String, Objects)> = vec![
        ("1 small".into(), vec![(A.to_string(), markdown(100))]),
        (
            "1 of 16 KiB".into(),
            vec![(A.to_string(), markdown(16 << 10))],
        ),
        (
            "1 of 16 KiB, most spans".into(),
            vec![(A.to_string(), worst_markdown(16 << 10))],
        ),
        (
            "2 of 16 KiB, most spans".into(),
            (0..2).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "8 of 16 KiB, most spans".into(),
            (0..8).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "8 small".into(),
            (0..8).map(|n| (doc(n), markdown(100))).collect(),
        ),
        (
            "3 of 16 KiB, most spans".into(),
            (0..3).map(|n| (doc(n), worst_markdown(16 << 10))).collect(),
        ),
        (
            "1 of 16 KiB, unclosed emphasis".into(),
            vec![(
                A.to_string(),
                "*a ".repeat(6000).into_bytes()[..16 << 10].to_vec(),
            )],
        ),
        (
            "1 of 16 KiB, never closed".into(),
            vec![(A.to_string(), never_closed(16 << 10))],
        ),
        (
            "1 of 16 KiB, backtick runs".into(),
            vec![(
                A.to_string(),
                "`a ``b ".repeat(3000).into_bytes()[..16 << 10].to_vec(),
            )],
        ),
        (
            "1 of 16 KiB, plain words".into(),
            vec![(
                A.to_string(),
                "word ".repeat(4000).into_bytes()[..16 << 10].to_vec(),
            )],
        ),
    ];
    for (name, objects) in shapes {
        let (outcome, used) = measure::run(Bridge::with(&objects), u64::MAX / 2);
        println!(
            "fuel_probe {name}: {used} fuel ({:.1}% of the Runtime budget), {}",
            used as f64 * 100.0 / measure::RUNTIME_FUEL as f64,
            if outcome.is_ok() {
                "ok".to_string()
            } else {
                format!("{outcome:?}")
            }
        );
    }
}
