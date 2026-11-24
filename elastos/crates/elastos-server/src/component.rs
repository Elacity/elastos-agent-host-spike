use std::path::Path;

use elastos_common::{
    CapsuleManifest, ElastosError, Result, ELASTOS_BUS_V1_CONTRACT, ELASTOS_BUS_V2_CONTRACT,
};
use wasmparser::{ComponentTypeRef, Encoding, Parser, Payload};

/// The component imports this Runtime admits. Exported so the capsule kit's
/// host tests read this table instead of keeping a copy (kit item A2).
pub const ALLOWED_BUS_IMPORTS: &[&str] = &[
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

const ALLOWED_BUS_V2_IMPORTS: &[&str] = &[
    "elastos:bus/types@2.0.0",
    "elastos:bus/runtime@2.0.0",
    "elastos:bus/identity@2.0.0",
    "elastos:bus/capabilities@2.0.0",
    "elastos:bus/providers@2.0.0",
    "elastos:bus/clock@2.0.0",
    "elastos:bus/random@2.0.0",
    "elastos:bus/ui@2.0.0",
    "elastos:bus/credentials@2.0.0",
];

/// Exact core builtins for the generated Bus v2 async guest, by module and name.
/// wit-component 0.254.2 `src/dummy.rs:423-438` supplies the root names;
/// wit-bindgen 0.60 `src/interface.rs:732-745` supplies the lifecycle stream
/// names. wit-component `src/dummy.rs:262-274` defers synchronous stream
/// read/write. Unit-stream imports require wit-bindgen's inter-task-wakeup
/// feature, which this guest does not enable.
const ALLOWED_V2_CORE_BUILTINS: &[(&str, &str)] = &[
    ("$root", "[backpressure-inc]"),
    ("$root", "[backpressure-dec]"),
    ("$root", "[waitable-set-new]"),
    ("$root", "[waitable-set-wait]"),
    ("$root", "[waitable-set-poll]"),
    ("$root", "[waitable-set-drop]"),
    ("$root", "[waitable-join]"),
    ("$root", "[thread-yield]"),
    ("$root", "[subtask-drop]"),
    ("$root", "[subtask-cancel]"),
    ("$root", "[context-get-0]"),
    ("$root", "[context-set-0]"),
    ("[export]$root", "[task-cancel]"),
    ("[export]elastos:bus/lifecycle@2.0.0", "[task-return]run"),
    ("[export]elastos:bus/lifecycle@2.0.0", "[stream-new-0]run"),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[stream-cancel-read-0]run",
    ),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[stream-cancel-write-0]run",
    ),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[stream-drop-readable-0]run",
    ),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[stream-drop-writable-0]run",
    ),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[async-lower][stream-read-0]run",
    ),
    (
        "[export]elastos:bus/lifecycle@2.0.0",
        "[async-lower][stream-write-0]run",
    ),
];

/// Parse caps: bounds on the work the compiler is asked to do, checked in the
/// same pass as the imports. The largest component in this repository
/// (agent-host) has 896 functions and a largest body of 88,523 bytes.
const MAX_COMPONENT_FUNCTIONS: u32 = 20_000;
const MAX_FUNCTION_BODY_BYTES: usize = 512 * 1024;
/// The same component's largest function declares 35 locals, and it has 5
/// canonical functions (the lifts and lowers between the component and its
/// core module, each of which the engine compiles a trampoline for). The
/// generated Bus v2 async shape has 36.
const MAX_FUNCTION_LOCALS: u32 = 1_000;
const MAX_CANONICAL_FUNCTIONS: u32 = 64;

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

/// Reads a component capsule's entrypoint once, under the size cap. The
/// signature check, the import check and the compiler all use these bytes.
pub(crate) async fn read_admitted_entrypoint(
    capsule_dir: &Path,
    manifest: &CapsuleManifest,
) -> Result<Vec<u8>> {
    let entrypoint = capsule_dir.join(&manifest.entrypoint);
    let bytes = elastos_compute::providers::ComponentProvider::read_component(&entrypoint)
        .await
        .map_err(|err| {
            ElastosError::InvalidManifest(format!(
                "failed to read component entrypoint {}: {}",
                manifest.entrypoint, err
            ))
        })?;
    #[cfg(test)]
    AFTER_ENTRYPOINT_READ.with(|hook| hook.borrow().iter().for_each(|hook| hook(&entrypoint)));
    Ok(bytes)
}

#[cfg(test)]
type EntrypointHook = Option<Box<dyn Fn(&Path)>>;

#[cfg(test)]
thread_local! {
    /// Test hook: runs right after the one read of a component entrypoint, so a
    /// test can replace the file and show that nothing reads it again.
    pub(crate) static AFTER_ENTRYPOINT_READ: std::cell::RefCell<EntrypointHook> =
        const { std::cell::RefCell::new(None) };
}

/// The shell's read of the one frame a v2 guest presented. Home gets nodes,
/// grant ids, and resource names. This read mints nothing and it is not a
/// gateway path.
pub fn read_v2_frame_for_home(
    provider: &elastos_compute::providers::ComponentProvider,
    id: &str,
) -> Option<Vec<elastos_compute::providers::bus2_ui::FrameNode>> {
    provider.read_v2_frame(id).map(|frame| frame.nodes)
}

/// The public v1 component admission check for capsule kit host tests (kit
/// item A2). Capsule and bundle starts use the manifest-aware check below.
pub fn validate_component_imports(bytes: &[u8]) -> std::result::Result<(), String> {
    validate_component_imports_for_contract(bytes, ELASTOS_BUS_V1_CONTRACT)
}

pub(crate) fn validate_component_imports_for_manifest(
    bytes: &[u8],
    manifest: &CapsuleManifest,
) -> std::result::Result<(), String> {
    let contract = manifest
        .bus_contract
        .as_deref()
        .unwrap_or(ELASTOS_BUS_V1_CONTRACT);
    validate_component_imports_for_contract(bytes, contract)
}

pub(crate) fn validate_component_imports_for_contract(
    bytes: &[u8],
    contract: &str,
) -> std::result::Result<(), String> {
    let allowed = match contract {
        ELASTOS_BUS_V1_CONTRACT => ALLOWED_BUS_IMPORTS,
        ELASTOS_BUS_V2_CONTRACT => ALLOWED_BUS_V2_IMPORTS,
        _ => return Err(format!("unsupported component bus contract {contract:?}")),
    };
    let (mut v1, mut v2) = (false, false);
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::ComponentImportSection(section)) = payload {
            for import in section.into_iter().flatten() {
                let name = import.name.name;
                if name.starts_with("elastos:bus/") {
                    v1 |= name.ends_with("@1.0.0");
                    v2 |= name.ends_with("@2.0.0");
                }
            }
        }
    }
    if v1 && v2 {
        return Err("component mixes Bus v1 and Bus v2 imports".to_string());
    }

    let mut saw_root_header = false;
    let mut functions: u32 = 0;
    let mut canonical_functions: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|err| format!("failed to parse component entrypoint: {err}"))? {
            Payload::Version { encoding, .. } if !saw_root_header => {
                saw_root_header = true;
                if encoding != Encoding::Component {
                    return Err("component entrypoint must be a WebAssembly component".to_string());
                }
            }
            Payload::ComponentImportSection(section) => {
                for import in section {
                    let import = import.map_err(|err| {
                        format!("failed to parse component import section: {err}")
                    })?;
                    let name = import.name.name;
                    let generated =
                        contract == ELASTOS_BUS_V1_CONTRACT || contract == ELASTOS_BUS_V2_CONTRACT;
                    if generated && name.starts_with("import-type-") {
                        if !matches!(import.ty, ComponentTypeRef::Type(_)) {
                            return Err(format!(
                                "component generated type import \"{}\" must be a type import",
                                name
                            ));
                        }
                        continue;
                    }
                    if generated && name == "import-func-run" {
                        if !matches!(import.ty, ComponentTypeRef::Func(_)) {
                            return Err("component generated run import must be a function import"
                                .to_string());
                        }
                        continue;
                    }
                    if !allowed.contains(&name) {
                        return Err(format!(
                            "component import \"{}\" is not allowed; allowed imports: {}",
                            name,
                            allowed.join(", ")
                        ));
                    }
                    if !matches!(import.ty, ComponentTypeRef::Instance(_)) {
                        return Err(format!(
                            "component import \"{}\" must be an interface instance import",
                            name
                        ));
                    }
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                functions = functions.saturating_add(count);
                if functions > MAX_COMPONENT_FUNCTIONS {
                    return Err(format!(
                        "component has more than {MAX_COMPONENT_FUNCTIONS} functions"
                    ));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let len = body.range().len();
                if len > MAX_FUNCTION_BODY_BYTES {
                    return Err(format!(
                        "component function body of {len} bytes is over the {MAX_FUNCTION_BODY_BYTES} byte limit"
                    ));
                }
                let mut locals: u32 = 0;
                let declared = body
                    .get_locals_reader()
                    .map_err(|err| format!("failed to parse component function locals: {err}"))?;
                for local in declared {
                    let (count, _) = local.map_err(|err| {
                        format!("failed to parse component function locals: {err}")
                    })?;
                    locals = locals.saturating_add(count);
                }
                if locals > MAX_FUNCTION_LOCALS {
                    return Err(format!(
                        "component function declares {locals} locals, over the {MAX_FUNCTION_LOCALS} limit"
                    ));
                }
            }
            Payload::ComponentCanonicalSection(section) => {
                canonical_functions = canonical_functions.saturating_add(section.count());
                if canonical_functions > MAX_CANONICAL_FUNCTIONS {
                    return Err(format!(
                        "component has more than {MAX_CANONICAL_FUNCTIONS} canonical functions"
                    ));
                }
            }
            Payload::ImportSection(section) => {
                // Flattens wasmparser's grouped (compact) imports into one per item.
                for import in section.into_imports() {
                    let import = import.map_err(|err| {
                        format!("failed to parse component core import section: {err}")
                    })?;
                    let builtins: &[(&str, &str)] = if contract == ELASTOS_BUS_V2_CONTRACT {
                        ALLOWED_V2_CORE_BUILTINS
                    } else {
                        &[]
                    };
                    validate_core_import(import.module, import.name, allowed, builtins)?;
                }
            }
            _ => {}
        }
    }

    if !saw_root_header {
        return Err("component entrypoint is empty".to_string());
    }

    Ok(())
}

fn validate_core_import(
    module: &str,
    name: &str,
    allowed: &[&str],
    builtins: &[(&str, &str)],
) -> std::result::Result<(), String> {
    let lower = format!("{module}::{name}").to_ascii_lowercase();
    if FORBIDDEN_AUTHORITY_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        return Err(format!(
            "component core module import \"{module}::{name}\" is forbidden"
        ));
    }

    if builtins
        .iter()
        .any(|(builtin_module, builtin_name)| *builtin_module == module && *builtin_name == name)
    {
        return Ok(());
    }
    if allowed.contains(&module) {
        return Ok(());
    }
    if module.is_empty() && (name == "$imports" || name.bytes().all(|byte| byte.is_ascii_digit())) {
        return Ok(());
    }

    Err(format!(
        "component core module import \"{module}::{name}\" is not allowed; use elastos:bus component imports only"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{
        Component, ComponentImportSection, ComponentTypeRef as EncodedComponentTypeRef,
        ComponentTypeSection, InstanceType, PrimitiveValType,
    };

    #[test]
    fn v2_frame_read_returns_nodes_and_grant_ids() {
        use elastos_compute::providers::bus2_ui::{FrameNode, GrantBook, UI_MEDIA_TYPE};
        use elastos_compute::providers::ComponentProvider;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let provider = ComponentProvider::new();
        let calls = Arc::new(AtomicU64::new(0));
        let seen = calls.clone();
        provider.set_bus_hostcall(Arc::new(move |_, _, _| {
            seen.fetch_add(1, Ordering::Relaxed);
            Err("the frame read must not call the bridge".into())
        }));
        let mut book = GrantBook::default();
        let photo = "localhost://Users/self/Pictures/a.png";
        book.hold("g1", photo, "read");
        provider
            .present_held_frame(
                "cap",
                UI_MEDIA_TYPE,
                br#"{"frame":[{"text":"one"}]}"#,
                &book,
            )
            .unwrap();
        provider
            .present_held_frame(
                "cap",
                UI_MEDIA_TYPE,
                br#"{"frame":[{"text":"two"},{"image":{"grant":"g1"}}]}"#,
                &book,
            )
            .unwrap();
        let nodes = super::read_v2_frame_for_home(&provider, "cap").expect("the frame");
        assert_eq!(
            nodes,
            vec![
                FrameNode::Text("two".into()),
                FrameNode::Image {
                    grant: "g1".into(),
                    resource: photo.into(),
                },
            ]
        );
        assert_eq!(
            format!("{nodes:?}"),
            format!(
                "[Text({:?}), Image {{ grant: {:?}, resource: {:?} }}]",
                "two", "g1", photo
            )
        );
        assert!(super::read_v2_frame_for_home(&provider, "other").is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    /// A guest reads an object it holds and calls ui.present. Home's frame
    /// read returns that frame. A second guest's frame stays its own.
    #[tokio::test]
    async fn v2_guest_present_reaches_the_home_frame_read() {
        use elastos_compute::providers::bus2_ui::FrameNode;
        use elastos_compute::providers::ComponentProvider;
        use elastos_compute::ComputeProvider;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let object_a = br#"{"frame":[{"text":"A"}]}"#.to_vec();
        let object_b = br#"{"frame":[{"text":"B"}]}"#.to_vec();
        let docs = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
        let lines = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let provider = ComponentProvider::new();
        let docs_for_call = docs.clone();
        let lines_for_call = lines.clone();
        provider.set_bus_hostcall(Arc::new(move |line, capsule, _principal| {
            lines_for_call
                .lock()
                .expect("lines")
                .push((capsule.to_string(), line.to_string()));
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| err.to_string())?;
            let body = &value["request"]["body"];
            let offset = body["offset"].as_u64().ok_or("offset")? as usize;
            let length = body["length"].as_u64().ok_or("length")? as usize;
            let doc = docs_for_call
                .lock()
                .expect("docs")
                .get(capsule)
                .cloned()
                .ok_or_else(|| format!("no object for {capsule}"))?;
            let start = offset.min(doc.len());
            let end = start.saturating_add(length).min(doc.len());
            let window = doc[start..end].to_vec();
            Ok(serde_json::json!({
                "id": 1,
                "response": {
                    "type": "resource_result",
                    "result": {
                        "status": "ok",
                        "data": { "content": window, "size": window.len() }
                    },
                    "audit": "read-1"
                }
            })
            .to_string())
        }));

        let bytes = wat::parse_str(include_str!(
            "../../../tests/fixtures/components/v2-present.wat"
        ))
        .expect("v2-present.wat parses");
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1/capsule.json");
        let mut manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        let first = provider
            .load_admitted(bytes.clone(), manifest.clone())
            .await
            .expect("first guest loads");
        let second = provider
            .load_admitted(bytes, manifest)
            .await
            .expect("second guest loads");
        docs.lock()
            .expect("docs")
            .insert(first.id.as_str().to_string(), object_a);
        docs.lock()
            .expect("docs")
            .insert(second.id.as_str().to_string(), object_b);

        provider.start(&first).await.expect("first guest starts");
        provider.start(&second).await.expect("second guest starts");

        let frame_of = |id: &str| {
            let provider = &provider;
            let id = id.to_string();
            async move {
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if let Some(nodes) = read_v2_frame_for_home(provider, &id) {
                            return nodes;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("home frame read stayed empty for {id}"))
            }
        };
        let nodes_a = frame_of(first.id.as_str()).await;
        let nodes_b = frame_of(second.id.as_str()).await;
        assert_eq!(nodes_a, vec![FrameNode::Text("A".into())]);
        assert_eq!(nodes_b, vec![FrameNode::Text("B".into())]);
        assert_eq!(
            read_v2_frame_for_home(&provider, first.id.as_str()),
            Some(vec![FrameNode::Text("A".into())]),
            "the second guest does not replace the first frame"
        );
        assert!(read_v2_frame_for_home(&provider, "other-guest").is_none());

        let seen = lines.lock().expect("lines").clone();
        assert_eq!(seen.len(), 2, "each guest reads its object once: {seen:?}");
        for (capsule, line) in &seen {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            let request = &value["request"];
            assert_eq!(request["type"], "resource_invoke");
            assert_eq!(request["operation"], "read");
            assert_eq!(request["token"], "grant-token");
            assert_eq!(request["uri"], "localhost://Users/self/Documents/note.bin");
            assert!(
                capsule == first.id.as_str() || capsule == second.id.as_str(),
                "{capsule}"
            );
        }
        let mut callers: Vec<&str> = seen.iter().map(|(capsule, _)| capsule.as_str()).collect();
        callers.sort();
        let mut ids = vec![first.id.as_str(), second.id.as_str()];
        ids.sort();
        assert_eq!(callers, ids);

        provider.stop(&first).await.unwrap();
        provider.stop(&second).await.unwrap();
    }

    /// A v2 guest asks on the real bridge. The owner grants that pending
    /// request. The guest's read carries the token from that grant. A token
    /// the bridge did not sign is refused, and a denial keeps the owner's text.
    #[tokio::test(flavor = "multi_thread")]
    async fn v2_guest_obtains_a_grant_and_reads_with_that_token() {
        use crate::resource_bridge::{handle_component_resource_request, BridgeContext};
        use elastos_common::AuthorityBound;
        use elastos_compute::providers::{ActivationOutcome, ComponentProvider};
        use elastos_compute::ComputeProvider;
        use elastos_runtime::capability::pending::PendingRequestStore;
        use elastos_runtime::capability::{
            Action, CapabilityManager, CapabilityStore, GrantDuration, RequestStatus, Settler,
            TokenConstraints,
        };
        use elastos_runtime::primitives::audit::AuditLog;
        use elastos_runtime::primitives::metrics::MetricsManager;
        use elastos_runtime::provider::{
            Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
        };
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        const RESOURCE: &str = "localhost://Local/SharedByLocalUsersAndBots/Home/note.txt";

        struct NoteProvider {
            calls: Arc<Mutex<Vec<serde_json::Value>>>,
            note: Vec<u8>,
        }

        #[async_trait::async_trait]
        impl Provider for NoteProvider {
            async fn handle(
                &self,
                _: ResourceRequest,
            ) -> std::result::Result<ResourceResponse, ProviderError> {
                Err(ProviderError::Provider("raw only".into()))
            }

            fn schemes(&self) -> Vec<&'static str> {
                vec!["localhost"]
            }

            fn name(&self) -> &'static str {
                "note"
            }

            async fn send_raw(
                &self,
                request: &serde_json::Value,
            ) -> std::result::Result<serde_json::Value, ProviderError> {
                self.calls.lock().expect("calls").push(request.clone());
                let offset = request["offset"].as_u64().unwrap_or(0) as usize;
                let length = request["length"].as_u64().unwrap_or(0) as usize;
                let start = offset.min(self.note.len());
                let end = start.saturating_add(length).min(self.note.len());
                Ok(serde_json::json!({
                    "status": "ok",
                    "data": { "content": self.note[start..end] }
                }))
            }
        }

        let audit = Arc::new(AuditLog::new());
        let manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending = Arc::new(PendingRequestStore::new(audit));
        let registry = Arc::new(ProviderRegistry::new());
        let calls = Arc::new(Mutex::new(Vec::new()));
        registry
            .register(Arc::new(NoteProvider {
                calls: calls.clone(),
                note: b"note".to_vec(),
            }))
            .await;
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let host = tokio::runtime::Handle::current();
        let provider = ComponentProvider::new();
        {
            let registry = registry.clone();
            let manager = manager.clone();
            let pending = pending.clone();
            let lines = lines.clone();
            provider.set_bus_hostcall(Arc::new(move |line, capsule, principal| {
                lines.lock().expect("lines").push(line.to_string());
                let ctx = BridgeContext {
                    provider_registry: registry.clone(),
                    capability_manager: manager.clone(),
                    pending_store: pending.clone(),
                    capsule_id: capsule.to_string(),
                    session_id: capsule.to_string(),
                    principal_id: principal.map(str::to_string),
                    manifest_capabilities: vec![AuthorityBound::from(
                        "localhost://Local/SharedByLocalUsersAndBots/Home/*".to_string(),
                    )],
                    data_dir: None,
                    launch: None,
                    model_token_ceiling: None,
                    model_budget: None,
                    stop: None,
                };
                let response = crate::runtime::Runtime::block_on_component_bridge(
                    &host,
                    handle_component_resource_request(line, ctx),
                )
                .map_err(|err| err.to_string())?;
                serde_json::to_string(&response).map_err(|err| err.to_string())
            }));
        }

        let bytes = wat::parse_str(include_str!(
            "../../../tests/fixtures/components/v2-grant.wat"
        ))
        .expect("v2-grant.wat parses");
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1/capsule.json");
        let mut manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        manifest.bus_contract = Some(ELASTOS_BUS_V2_CONTRACT.into());
        manifest.wit_world_sha256 = Some(elastos_common::elastos_bus_v2_wit_sha256());
        let handle = provider
            .load_admitted(bytes, manifest)
            .await
            .expect("grant guest loads");
        let mut resident = provider
            .start_resident(&handle)
            .await
            .expect("grant guest starts");

        let started = Instant::now();
        let request = loop {
            if let Some(request) = pending.list_pending().await.into_iter().next() {
                break request;
            }
            if let Some(outcome) = resident.outcome() {
                panic!("guest ended before a pending request: {outcome:?}");
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!(
                    "no pending request; lines: {:?}",
                    lines.lock().expect("lines")
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(request.resource.as_str(), RESOURCE);
        assert_eq!(request.reason, "to read");
        assert_eq!(request.action, Action::Read);
        assert!(matches!(request.status, RequestStatus::Pending));
        let token = manager.grant(
            request.session_id.as_str(),
            request.resource.clone(),
            request.action,
            TokenConstraints::default(),
            None,
        );
        let encoded = token.to_base64().expect("token encodes");
        pending
            .grant_request(request.id.as_str(), token, GrantDuration::Session)
            .await
            .expect("owner grants");

        let outcome = tokio::time::timeout(Duration::from_secs(10), resident.ended())
            .await
            .expect("guest timed out");
        assert_eq!(outcome, ActivationOutcome::Returned, "guest ending");
        let seen = lines.lock().expect("lines").clone();
        let reads: Vec<serde_json::Value> = seen
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| value["request"]["type"] == "resource_invoke")
            .collect();
        assert_eq!(reads.len(), 1, "one read: {seen:?}");
        assert_eq!(reads[0]["request"]["token"], encoded);
        assert_eq!(reads[0]["request"]["uri"], RESOURCE);
        let dispatched = calls.lock().expect("calls").clone();
        assert_eq!(
            dispatched.len(),
            1,
            "the bridge dispatched the granted read"
        );
        assert_eq!(dispatched[0]["op"], "read");
        assert_eq!(dispatched[0]["path"], RESOURCE);

        let bad = handle_component_resource_request(
            &serde_json::json!({
                "id": 2,
                "request": {
                    "type": "resource_invoke",
                    "uri": RESOURCE,
                    "operation": "read",
                    "body": { "path": RESOURCE, "offset": 0, "length": 8 },
                    "token": "grant-token"
                }
            })
            .to_string(),
            BridgeContext {
                provider_registry: registry.clone(),
                capability_manager: manager.clone(),
                pending_store: pending.clone(),
                capsule_id: handle.id.0.clone(),
                session_id: handle.id.0.clone(),
                principal_id: None,
                manifest_capabilities: vec![AuthorityBound::from(
                    "localhost://Local/SharedByLocalUsersAndBots/Home/*".to_string(),
                )],
                data_dir: None,
                launch: None,
                model_token_ceiling: None,
                model_budget: None,
                stop: None,
            },
        )
        .await
        .expect("bad token call");
        assert_eq!(bad["response"]["code"], "invalid_token");
        assert_eq!(
            calls.lock().expect("calls").len(),
            1,
            "an ungranted token never reaches the provider"
        );

        let deny_line = serde_json::json!({
            "id": 3,
            "request": {
                "type": "request_capability",
                "resource": RESOURCE,
                "action": "read",
                "reason": "because"
            }
        })
        .to_string();
        let deny_ctx = BridgeContext {
            provider_registry: registry,
            capability_manager: manager,
            pending_store: pending.clone(),
            capsule_id: handle.id.0.clone(),
            session_id: handle.id.0.clone(),
            principal_id: None,
            manifest_capabilities: vec![AuthorityBound::from(
                "localhost://Local/SharedByLocalUsersAndBots/Home/*".to_string(),
            )],
            data_dir: None,
            launch: None,
            model_token_ceiling: None,
            model_budget: None,
            stop: None,
        };
        let deny_pending = pending.clone();
        let waiting = tokio::spawn(async move {
            handle_component_resource_request(&deny_line, deny_ctx)
                .await
                .expect("denial call")
        });
        let started = Instant::now();
        let denied = loop {
            if let Some(request) = deny_pending.list_pending().await.into_iter().next() {
                break request;
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!("denial left no pending request");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        deny_pending
            .deny_request_by(denied.id.as_str(), "not now", Settler::Shell)
            .await
            .expect("owner denies");
        let denied = waiting.await.expect("denial task");
        assert_eq!(denied["response"]["code"], "denied");
        assert_eq!(denied["response"]["message"], "not now");

        provider.stop(&handle).await.unwrap();
    }

    fn wat_imports(names: &[&str]) -> Vec<u8> {
        let imports = names
            .iter()
            .map(|name| format!("(import \"{name}\" (instance))"))
            .collect::<Vec<_>>()
            .join(" ");
        wat::parse_str(format!("(component {imports})")).unwrap()
    }

    #[test]
    fn v2_refuses_a_mix_with_v1() {
        let v2_imports = &[
            "elastos:bus/types@2.0.0",
            "elastos:bus/runtime@2.0.0",
            "elastos:bus/identity@2.0.0",
            "elastos:bus/capabilities@2.0.0",
            "elastos:bus/providers@2.0.0",
            "elastos:bus/clock@2.0.0",
            "elastos:bus/random@2.0.0",
            "elastos:bus/ui@2.0.0",
            "elastos:bus/credentials@2.0.0",
        ];
        assert_eq!(ALLOWED_BUS_V2_IMPORTS, v2_imports);
        validate_component_imports_for_contract(&wat_imports(v2_imports), ELASTOS_BUS_V2_CONTRACT)
            .unwrap();
        let err = validate_component_imports_for_contract(
            &wat_imports(&["elastos:bus/runtime@1.0.0", "elastos:bus/ui@2.0.0"]),
            ELASTOS_BUS_V2_CONTRACT,
        )
        .unwrap_err();
        assert_eq!(err, "component mixes Bus v1 and Bus v2 imports");
        let err = validate_component_imports_for_contract(
            &wat_imports(&["elastos:bus/runtime@1.0.0"]),
            ELASTOS_BUS_V2_CONTRACT,
        )
        .unwrap_err();
        assert!(err.contains("runtime@1.0.0"), "{err}");
    }

    /// Interface-instance and fixup imports observed in the generated guest.
    /// The exact builtin list is independently pinned in the test below.
    const V2_GENERATED_OTHER_CORE_IMPORTS: &[(&str, &str)] = &[
        ("elastos:bus/providers@2.0.0", "[async-lower]invoke"),
        (
            "elastos:bus/providers@2.0.0",
            "[stream-drop-readable-0]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[async-lower][future-write-2]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[async-lower][future-read-2]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[future-cancel-write-2]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[future-cancel-read-2]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[future-drop-writable-2]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[future-drop-readable-2]invoke",
        ),
        ("elastos:bus/providers@2.0.0", "[future-new-2]invoke"),
        (
            "elastos:bus/providers@2.0.0",
            "[async-lower][stream-write-0]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[async-lower][stream-read-0]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[stream-cancel-write-0]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[stream-cancel-read-0]invoke",
        ),
        (
            "elastos:bus/providers@2.0.0",
            "[stream-drop-writable-0]invoke",
        ),
        ("elastos:bus/providers@2.0.0", "[stream-new-0]invoke"),
        ("elastos:bus/capabilities@2.0.0", "[async-lower]request"),
        ("elastos:bus/ui@2.0.0", "[async-lower]present"),
        ("elastos:bus/credentials@2.0.0", "presented"),
        ("", "0"),
        ("", "1"),
        ("", "2"),
        ("", "3"),
        ("", "4"),
        ("", "5"),
        ("", "6"),
        ("", "7"),
        ("", "8"),
        ("", "9"),
        ("", "10"),
        ("", "11"),
        ("", "$imports"),
    ];

    /// The generated shape as a WAT component: the bus instances, the nested
    /// generated `import-type-*` / `import-func-run` imports, the core builtins
    /// and `canonical` canonical functions.
    fn v2_generated_shape(canonical: usize, extra_core: &[(&str, &str)]) -> Vec<u8> {
        let mut wat = String::from("(component\n  (type $inst (instance))\n");
        for name in [
            "elastos:bus/types@2.0.0",
            "elastos:bus/capabilities@2.0.0",
            "elastos:bus/providers@2.0.0",
            "elastos:bus/ui@2.0.0",
            "elastos:bus/credentials@2.0.0",
        ] {
            wat.push_str(&format!("  (import \"{name}\" (instance))\n"));
        }
        for name in [
            "import-type-grant-id",
            "import-type-event",
            "import-type-bus-error",
            "import-type-event0",
            "import-type-bus-error0",
        ] {
            wat.push_str(&format!("  (import \"{name}\" (type (eq $inst)))\n"));
        }
        wat.push_str("  (import \"import-func-run\" (func))\n");
        wat.push_str("  (core module $guest\n");
        for (module, name) in ALLOWED_V2_CORE_BUILTINS
            .iter()
            .chain(V2_GENERATED_OTHER_CORE_IMPORTS)
            .chain(extra_core)
        {
            wat.push_str(&format!("    (import \"{module}\" \"{name}\" (func))\n"));
        }
        wat.push_str("    (func (export \"run\")))\n");
        for index in 0..canonical {
            wat.push_str(&format!(
                "  (core func $f{index} (canon waitable-set.new))\n"
            ));
        }
        wat.push(')');
        wat::parse_str(&wat).unwrap()
    }

    #[test]
    fn v2_admits_generated_imports_with_kind_checks() {
        // The names are admitted for v2 now, but the kind checks stay: a type
        // import must be a type and the run import must be a function.
        let type_import = component_with_imports(&[(
            "import-type-event",
            EncodedComponentTypeRef::Type(wasm_encoder::TypeBounds::Eq(0)),
        )]);
        validate_component_imports_for_contract(&type_import, ELASTOS_BUS_V2_CONTRACT).unwrap();

        let wrong_kind =
            component_with_imports(&[("import-type-event", EncodedComponentTypeRef::Func(0))]);
        let err = validate_component_imports_for_contract(&wrong_kind, ELASTOS_BUS_V2_CONTRACT)
            .unwrap_err();
        assert!(err.contains("must be a type import"), "{err}");

        let run_import =
            component_with_imports(&[("import-func-run", EncodedComponentTypeRef::Func(0))]);
        validate_component_imports_for_contract(&run_import, ELASTOS_BUS_V2_CONTRACT).unwrap();
        let wrong_run = component_with_imports(&[(
            "import-func-run",
            EncodedComponentTypeRef::Type(wasm_encoder::TypeBounds::Eq(0)),
        )]);
        for contract in [ELASTOS_BUS_V1_CONTRACT, ELASTOS_BUS_V2_CONTRACT] {
            let err = validate_component_imports_for_contract(&wrong_run, contract).unwrap_err();
            assert_eq!(
                err,
                "component generated run import must be a function import"
            );
        }
    }

    #[test]
    fn v2_builtin_pairs_are_exactly_the_toolchain_set() {
        assert_eq!(
            ALLOWED_V2_CORE_BUILTINS,
            &[
                ("$root", "[backpressure-inc]"),
                ("$root", "[backpressure-dec]"),
                ("$root", "[waitable-set-new]"),
                ("$root", "[waitable-set-wait]"),
                ("$root", "[waitable-set-poll]"),
                ("$root", "[waitable-set-drop]"),
                ("$root", "[waitable-join]"),
                ("$root", "[thread-yield]"),
                ("$root", "[subtask-drop]"),
                ("$root", "[subtask-cancel]"),
                ("$root", "[context-get-0]"),
                ("$root", "[context-set-0]"),
                ("[export]$root", "[task-cancel]"),
                ("[export]elastos:bus/lifecycle@2.0.0", "[task-return]run"),
                ("[export]elastos:bus/lifecycle@2.0.0", "[stream-new-0]run"),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[stream-cancel-read-0]run"
                ),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[stream-cancel-write-0]run"
                ),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[stream-drop-readable-0]run"
                ),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[stream-drop-writable-0]run"
                ),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[async-lower][stream-read-0]run"
                ),
                (
                    "[export]elastos:bus/lifecycle@2.0.0",
                    "[async-lower][stream-write-0]run"
                ),
            ]
        );
    }

    #[test]
    fn v2_admits_the_generated_async_shape_and_nothing_more() {
        let shape = v2_generated_shape(36, &[]);
        validate_component_imports_for_contract(&shape, ELASTOS_BUS_V2_CONTRACT).unwrap();

        for (module, name) in [
            ("$root", "[not-a-builtin]"),
            ("[export]$root", "[not-a-builtin]"),
            ("[export]elastos:bus/lifecycle@2.0.0", "[not-a-builtin]"),
            ("[export]elastos:bus/lifecycle@2.0.0", "[stream-read-0]run"),
            ("[export]elastos:bus/lifecycle@2.0.0", "[stream-write-0]run"),
            ("evil", "[waitable-set-new]"),
            ("[export]elastos:bus/lifecycle@2.0.1", "[task-return]run"),
        ] {
            let err = validate_component_imports_for_contract(
                &v2_generated_shape(36, &[(module, name)]),
                ELASTOS_BUS_V2_CONTRACT,
            )
            .unwrap_err();
            assert!(err.contains(&format!("{module}::{name}")), "{err}");
            assert!(err.contains("not allowed"), "{err}");
        }

        // The generated shape's 36 canonical functions fit; 65 do not.
        let err = validate_component_imports_for_contract(
            &v2_generated_shape(65, &[]),
            ELASTOS_BUS_V2_CONTRACT,
        )
        .unwrap_err();
        assert_eq!(err, "component has more than 64 canonical functions");
    }

    #[test]
    fn v1_refuses_ui_v2() {
        let err = validate_component_imports(&wat_imports(&["elastos:bus/ui@2.0.0"])).unwrap_err();
        assert!(err.contains("not allowed"), "{err}");
        assert!(err.contains("elastos:bus/ui@2.0.0"), "{err}");
    }

    #[test]
    fn v1_refuses_v2_root_builtin() {
        // A single v2 builtin checks the v1 contract without mixed bus imports.
        let component = wat::parse_str(
            "(component (core module (import \"$root\" \"[waitable-set-new]\" (func))))",
        )
        .unwrap();
        let err = validate_component_imports(&component).unwrap_err();
        assert!(err.contains("$root::[waitable-set-new]"), "{err}");
        assert!(err.contains("not allowed"), "{err}");
    }

    fn component_with_imports(imports: &[(&str, EncodedComponentTypeRef)]) -> Vec<u8> {
        let mut types = ComponentTypeSection::new();
        types.instance(&InstanceType::new());

        let mut import_section = ComponentImportSection::new();
        for (name, ty) in imports {
            import_section.import(*name, *ty);
        }

        let mut component = Component::new();
        component.section(&types);
        component.section(&import_section);
        component.finish()
    }

    #[test]
    fn accepts_allowed_component_imports() {
        let bytes = component_with_imports(&[
            (
                "elastos:bus/runtime@1.0.0",
                EncodedComponentTypeRef::Instance(0),
            ),
            (
                "elastos:bus/providers@1.0.0",
                EncodedComponentTypeRef::Instance(0),
            ),
        ]);

        validate_component_imports(&bytes).unwrap();
    }

    #[test]
    fn rejects_core_wasm_module() {
        let err = validate_component_imports(b"\0asm\x01\0\0\0").unwrap_err();
        assert!(err.contains("must be a WebAssembly component"));
    }

    #[test]
    fn rejects_extra_component_import() {
        let bytes = component_with_imports(&[(
            "wasi:filesystem/types@0.2.0",
            EncodedComponentTypeRef::Instance(0),
        )]);

        let err = validate_component_imports(&bytes).unwrap_err();
        assert!(err.contains("not allowed"));
        assert!(err.contains("elastos:bus/runtime@1.0.0"));
    }

    #[test]
    fn rejects_unimplemented_bus_import() {
        let bytes = component_with_imports(&[(
            "elastos:bus/streams@1.0.0",
            EncodedComponentTypeRef::Instance(0),
        )]);

        let err = validate_component_imports(&bytes).unwrap_err();
        assert!(err.contains("not allowed"));
        assert!(err.contains("elastos:bus/streams@1.0.0"));
    }

    #[test]
    fn rejects_nested_core_module_imports() {
        let mut module = wasm_encoder::Module::new();
        let mut types = wasm_encoder::TypeSection::new();
        types.ty().function([], []);
        module.section(&types);
        let mut imports = wasm_encoder::ImportSection::new();
        imports.import(
            "wasi_snapshot_preview1",
            "fd_write",
            wasm_encoder::EntityType::Function(0),
        );
        module.section(&imports);

        let mut component = Component::new();
        component.section(&wasm_encoder::ModuleSection(&module));

        let err = validate_component_imports(&component.finish()).unwrap_err();
        assert!(err.contains("core module import"));
        assert!(err.contains("wasi_snapshot_preview1::fd_write"));
    }

    /// A component holding core modules, one per entry of `modules`; each
    /// module has that many functions, each a body of `body_len` bytes.
    fn component_with_functions(modules: &[u32], body_len: usize) -> Vec<u8> {
        let mut component = Component::new();
        for count in modules {
            let mut module = wasm_encoder::Module::new();
            let mut types = wasm_encoder::TypeSection::new();
            types.ty().function([], []);
            module.section(&types);
            let mut functions = wasm_encoder::FunctionSection::new();
            let mut code = wasm_encoder::CodeSection::new();
            // A body is its locals count (one byte), its instructions, and `end`.
            let mut body = wasm_encoder::Function::new([]);
            for _ in 0..body_len - 2 {
                body.instruction(&wasm_encoder::Instruction::Nop);
            }
            body.instruction(&wasm_encoder::Instruction::End);
            for _ in 0..*count {
                functions.function(0);
                code.function(&body);
            }
            module.section(&functions);
            module.section(&code);
            component.section(&wasm_encoder::ModuleSection(&module));
        }
        component.finish()
    }

    #[test]
    fn a_component_may_hold_twenty_thousand_functions_and_no_more() {
        // The count is over every core module of the component together.
        validate_component_imports(&component_with_functions(&[12_000, 8_000], 2)).unwrap();
        let err =
            validate_component_imports(&component_with_functions(&[12_000, 8_001], 2)).unwrap_err();
        assert_eq!(err, "component has more than 20000 functions");
    }

    #[test]
    fn a_function_body_may_be_512_kib_and_no_more() {
        validate_component_imports(&component_with_functions(&[1], 512 * 1024)).unwrap();
        let err = validate_component_imports(&component_with_functions(&[1], 512 * 1024 + 1))
            .unwrap_err();
        assert_eq!(
            err,
            "component function body of 524289 bytes is over the 524288 byte limit"
        );
    }

    /// A component with one core module of one function that declares its
    /// locals in the given groups.
    fn component_with_locals(groups: &[u32]) -> Vec<u8> {
        let mut module = wasm_encoder::Module::new();
        let mut types = wasm_encoder::TypeSection::new();
        types.ty().function([], []);
        module.section(&types);
        let mut functions = wasm_encoder::FunctionSection::new();
        functions.function(0);
        module.section(&functions);
        let mut body =
            wasm_encoder::Function::new(groups.iter().map(|n| (*n, wasm_encoder::ValType::I32)));
        body.instruction(&wasm_encoder::Instruction::End);
        let mut code = wasm_encoder::CodeSection::new();
        code.function(&body);
        module.section(&code);
        let mut component = Component::new();
        component.section(&wasm_encoder::ModuleSection(&module));
        component.finish()
    }

    #[test]
    fn a_function_may_declare_a_thousand_locals_and_no_more() {
        // The count is over all of a function's local groups together.
        validate_component_imports(&component_with_locals(&[600, 400])).unwrap();
        let err = validate_component_imports(&component_with_locals(&[600, 401])).unwrap_err();
        assert_eq!(
            err,
            "component function declares 1001 locals, over the 1000 limit"
        );
    }

    /// A component with canonical-function sections of the given sizes.
    fn component_with_canonical_functions(sections: &[u32]) -> Vec<u8> {
        let mut component = Component::new();
        for count in sections {
            let mut canonical = wasm_encoder::CanonicalFunctionSection::new();
            for index in 0..*count {
                canonical.lower(index, []);
            }
            component.section(&canonical);
        }
        component.finish()
    }

    #[test]
    fn a_component_may_hold_sixty_four_canonical_functions_and_no_more() {
        // The count is over every canonical section of the component together.
        validate_component_imports(&component_with_canonical_functions(&[40, 24])).unwrap();
        let err =
            validate_component_imports(&component_with_canonical_functions(&[40, 25])).unwrap_err();
        assert_eq!(err, "component has more than 64 canonical functions");
    }

    #[test]
    fn the_repository_fixture_is_far_under_the_parse_caps() {
        let bytes = include_bytes!(
            "../../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"
        );
        validate_component_imports(bytes).unwrap();
    }

    #[test]
    fn rejects_a_forbidden_import_inside_a_nested_component() {
        // The walk must reach a component nested inside the one being checked.
        let inner = component_with_imports(&[(
            "wasi:filesystem/types@0.2.0",
            EncodedComponentTypeRef::Instance(0),
        )]);
        let mut outer = Component::new();
        outer.section(&wasm_encoder::RawSection {
            id: wasm_encoder::ComponentSectionId::Component.into(),
            data: &inner,
        });
        let err = validate_component_imports(&outer.finish()).unwrap_err();
        assert!(err.contains("not allowed"), "{err}");
        assert!(err.contains("wasi:filesystem/types@0.2.0"), "{err}");
    }

    #[test]
    fn rejects_allowed_name_with_wrong_import_kind() {
        let mut types = ComponentTypeSection::new();
        types
            .function()
            .params(std::iter::empty::<(&str, PrimitiveValType)>())
            .result(None);

        let mut imports = ComponentImportSection::new();
        imports.import(
            "elastos:bus/runtime@1.0.0",
            EncodedComponentTypeRef::Func(0),
        );

        let mut component = Component::new();
        component.section(&types);
        component.section(&imports);

        let err = validate_component_imports(&component.finish()).unwrap_err();
        assert!(err.contains("must be an interface instance import"));
    }
}
