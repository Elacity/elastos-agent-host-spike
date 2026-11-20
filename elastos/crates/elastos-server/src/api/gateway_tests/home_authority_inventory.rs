//! Home authority inventory. Inclusion rule: scan compiled, non-test API source for
//! direct calls to `require_home_token` or `require_home_token_context`, and calls
//! to a `require_home_launch_token*` or internal-shell `*_for_any_*` gate whose
//! argument names `HOME_CAPSULE_ID` or whose local allowed list contains it.
//! Catalog affordance calls are included because their requested capsule can
//! resolve to Home and is passed as the one allowed actor. The proxy's local
//! allowlist is inspected, so adding Home there creates a missing row.
//! Gate-to-gate forwarding inside `gateway_home_token.rs` is excluded: the
//! table follows each route entry, not the verifier implementation. App-only
//! lists and launch-bound page tokens are covered by the behavior rows below.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::start_census_tests as source;

#[derive(Clone, Debug)]
struct AuthorityRow {
    file: &'static str,
    function: &'static str,
    gate: &'static str,
    count: usize,
    authority: &'static str,
}

fn rows() -> Vec<AuthorityRow> {
    const AUTH: &str = "elastos-server/src/api/auth_gateway.rs";
    const CATALOG: &str = "elastos-server/src/api/gateway_capsule_catalog.rs";
    const EXTERNAL: &str = "elastos-server/src/api/gateway_home_external_link.rs";
    const HOME_RUNTIME: &str = "elastos-server/src/api/gateway_home_runtime.rs";
    const SHARED: &str = "elastos-server/src/api/gateway_home_shared_content.rs";
    const HOME_SYSTEM: &str = "elastos-server/src/api/gateway_home_system.rs";
    const STEP_UP: &str = "elastos-server/src/api/gateway_passkey_step_up.rs";
    const ROOM: &str = "elastos-server/src/api/gateway_room.rs";
    const ROUTES: &str = "elastos-server/src/api/routes.rs";
    const VIEWER: &str = "elastos-server/src/api/viewer_gateway.rs";
    let row = |file, function, gate, count, authority| AuthorityRow {
        file,
        function,
        gate,
        count,
        authority,
    };
    vec![
        row(
            AUTH,
            "require_passkey_add_launch",
            "require_home_token_context",
            1,
            "runtime-admin:require_hosted_step_up_launch+is_admin",
        ),
        row(
            AUTH,
            "sign_out_session_inner",
            "require_home_token_context",
            1,
            "home-own",
        ),
        row(
            AUTH,
            "full_recovery_bundle_export_inner",
            "require_home_launch_token_binding",
            1,
            "runtime-admin:require_active_passkey_principal_for_context+runtime_wallet_authority",
        ),
        row(
            AUTH,
            "full_recovery_bundle_import_inner",
            "require_home_launch_token_binding",
            1,
            "runtime-admin:require_active_passkey_principal_for_context+runtime_wallet_authority",
        ),
        row(
            AUTH,
            "refresh_session_inner",
            "require_home_token_context",
            1,
            "home-own",
        ),
        row(
            AUTH,
            "require_auth_home_or_system_context",
            "require_home_launch_token_for_any_context",
            1,
            "runtime-admin:require_active_principal_for_context+is_admin at callers",
        ),
        row(
            CATALOG,
            "capsule_interface_invoke",
            "require_home_launch_token_for_any_app_context",
            2,
            "home-own",
        ),
        row(
            CATALOG,
            "dispatch_capsule_affordance",
            "require_home_launch_token_for_any_app_context",
            1,
            "home-own",
        ),
        row(
            CATALOG,
            "require_capsule_catalog_token",
            "require_home_launch_token_for_any_context",
            1,
            "home-own",
        ),
        row(
            EXTERNAL,
            "home_external_link_app",
            "require_home_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_RUNTIME,
            "home_launch",
            "require_home_launch_token_context",
            1,
            "app-grant:OPEN P2-4 follow-up",
        ),
        row(
            SHARED,
            "home_shared_content_check",
            "require_home_token_context",
            1,
            "delegates:ipfs via home_external_link_app+ProviderRegistry::send_raw",
        ),
        row(
            SHARED,
            "home_shared_content_get",
            "require_home_token_context",
            1,
            "delegates:ipfs+content via redeem_check+ProviderRegistry::send_raw/invoke_provider",
        ),
        row(
            HOME_SYSTEM,
            "home_background_image",
            "require_home_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "home_runtime_ensure",
            "require_home_token",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "require_home_active_shell_token_context",
            "require_home_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "require_home_active_shell_update_token_context",
            "require_home_launch_token_for_any_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "require_home_shell_state_token_context",
            "require_home_launch_token_for_any_context",
            1,
            "home-own",
        ),
        row(
            STEP_UP,
            "passkey_step_up_begin_inner",
            "require_home_token_context",
            1,
            "runtime-admin:require_hosted_step_up_launch+passkey_for_launch",
        ),
        row(
            STEP_UP,
            "passkey_step_up_cancel_inner",
            "require_home_token_context",
            1,
            "runtime-admin:claim_pending",
        ),
        row(
            STEP_UP,
            "passkey_step_up_complete_inner",
            "require_home_token_context",
            1,
            "runtime-admin:claim_pending+complete_authentication",
        ),
        row(
            ROOM,
            "chat_room_summary",
            "require_home_token",
            1,
            "app-grant:OPEN P2-4 follow-up",
        ),
        row(
            ROUTES,
            "open_launch",
            "require_internal_shell_launch_grant_for_any_context",
            1,
            "app-grant:OPEN P2-4 follow-up",
        ),
        row(
            VIEWER,
            "home_launch_content",
            "require_home_token_context",
            1,
            "app-grant:OPEN P2-4 follow-up",
        ),
    ]
}

fn call_end(text: &str, open: usize) -> usize {
    let mut depth = 0;
    for (at, byte) in text.bytes().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unclosed call at {open}");
}

fn found() -> BTreeMap<(String, String, String), usize> {
    let mut result = BTreeMap::new();
    for (file, raw) in source::production_sources() {
        if !file.starts_with("elastos-server/src/api/") || file.contains("/gateway_tests/") {
            continue;
        }
        let code = source::code_only(&raw);
        let prefix = ["require", "_"].concat();
        let launch_prefix = ["require_home", "_launch_token"].concat();
        let internal_shell = ["require_internal_shell_launch_grant", "_for_any_context"].concat();
        let home_actor = ["HOME_", "CAPSULE_ID"].concat();
        let proxy_allowlist = ["let allowed", "_apps"].concat();
        for (at, _) in code.match_indices(&prefix) {
            let end_name = code[at..]
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .map(|length| at + length)
                .unwrap_or(code.len());
            if code.as_bytes().get(end_name) != Some(&b'(') {
                continue;
            }
            let gate = &code[at..end_name];
            if gate != "require_home_token"
                && gate != "require_home_token_context"
                && !gate.starts_with(&launch_prefix)
                && gate != internal_shell
            {
                continue;
            }
            let prefix = code[..at].rsplit('\n').next().unwrap_or("");
            if prefix.trim_end().ends_with("fn") {
                continue;
            }
            let function = source::enclosing_fn(&code, at);
            if file.ends_with("/gateway_home_token.rs") {
                continue;
            }
            let end = call_end(&code, end_name);
            let call = &code[at..end];
            let directly_home =
                gate == "require_home_token" || gate == "require_home_token_context";
            let local_list = (gate == "require_home_launch_token_for_any_context"
                && matches!(
                    function.as_str(),
                    "require_home_active_shell_update_token_context"
                        | "require_capsule_catalog_token"
                ))
                || (gate == "require_home_launch_token_for_any_app_context"
                    && file.ends_with("/gateway_capsule_catalog.rs")
                    && matches!(
                        function.as_str(),
                        "capsule_interface_invoke" | "dispatch_capsule_affordance"
                    ));
            let proxy_list = gate == "require_home_launch_token_binding"
                && file.ends_with("/gateway_provider_proxy.rs")
                && function == "gateway_provider_proxy"
                && code[..at]
                    .rfind(&proxy_allowlist)
                    .is_some_and(|start| code[start..at].contains(&home_actor));
            if !directly_home && !call.contains(&home_actor) && !local_list && !proxy_list {
                continue;
            }
            *result
                .entry((file.clone(), function, gate.to_string()))
                .or_default() += 1;
        }
    }
    result
}

#[test]
fn every_home_admitting_route_has_an_authority_row() {
    let found = found();
    let mut listed = BTreeSet::new();
    let mut classes = BTreeMap::new();
    for row in rows() {
        let key = (
            row.file.to_string(),
            row.function.to_string(),
            row.gate.to_string(),
        );
        assert!(
            listed.insert(key.clone()),
            "duplicate authority row: {key:?}"
        );
        assert_eq!(
            found.get(&key).copied().unwrap_or(0),
            row.count,
            "stale authority row: {key:?}"
        );
        let class = row.authority.split(':').next().unwrap();
        assert!(matches!(
            class,
            "home-own" | "runtime-admin" | "delegates" | "app-grant"
        ));
        *classes.entry(class).or_insert(0usize) += 1;
    }
    let missing: Vec<_> = found
        .iter()
        .filter(|(key, _)| !listed.contains(*key))
        .collect();
    assert!(
        missing.is_empty(),
        "unlisted Home authority routes: {missing:#?}"
    );
    println!("Home authority: {} rows; {:?}", listed.len(), classes);
}

#[test]
fn existing_documents_home_token_refusal_remains_present() {
    let name = [
        "test_library_home_token_",
        "cannot_mutate_documents_provider",
    ]
    .concat();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/gateway_tests/documents.rs");
    let text = fs::read_to_string(path).unwrap();
    assert!(text.contains(&["async fn ", name.as_str(), "("].concat()));
}

#[tokio::test]
async fn home_session_cannot_open_a_launch_bound_viewer_page() {
    let dir = tempfile::tempdir().unwrap();
    let token = issue_home_launch_token(dir.path(), HOME_CAPSULE_ID).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    headers.insert(HOST, "localhost:61180".parse().unwrap());
    headers.insert("origin", "null".parse().unwrap());
    let Err(error) = require_launch_bound_token(dir.path(), &headers, "image-viewer", false) else {
        panic!("Home session passed the viewer launch gate");
    };
    assert!(
        error.to_string().contains("not bound to a content launch"),
        "{error}"
    );
}

#[tokio::test]
async fn home_session_cannot_pass_an_app_only_gate() {
    let dir = tempfile::tempdir().unwrap();
    let token = issue_home_launch_token(dir.path(), HOME_CAPSULE_ID).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    headers.insert(HOST, "localhost:61180".parse().unwrap());
    headers.insert("origin", "http://localhost:61180".parse().unwrap());
    let result = require_home_launch_token_for_any_app_context(
        dir.path(),
        &headers,
        &[DOCUMENTS_CAPSULE_ID],
    );
    let Err(error) = result else {
        panic!("Home session passed an app-only gate");
    };
    assert!(error.to_string().contains("not authorized"), "{error}");
}

#[derive(Default)]
struct CountedDocumentsProvider(AtomicUsize);

#[async_trait::async_trait]
impl Provider for CountedDocumentsProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw requests only".into()))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec!["documents"]
    }
    fn name(&self) -> &'static str {
        "counted-documents-fixture"
    }
    async fn send_raw(&self, _request: &Value) -> Result<Value, ProviderError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"status": "ok"}))
    }
}

#[tokio::test]
async fn home_session_cannot_invoke_an_app_only_documents_operation() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state(dir.path());
    let registry = Arc::new(ProviderRegistry::new());
    let provider = Arc::new(CountedDocumentsProvider::default());
    registry.register(provider.clone()).await;
    state.provider_registry = Some(registry);
    let app = gateway_router(state);
    let token = issue_home_launch_token(dir.path(), HOME_CAPSULE_ID).unwrap();
    let response = app
        .oneshot(
            test_browser_request("localhost:61180", "http://localhost:61180")
                .method("POST")
                .uri("/api/provider/documents/create")
                .header("x-elastos-home-token", token)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"title":"Denied"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        provider.0.load(Ordering::SeqCst),
        0,
        "provider received a denied call"
    );
}

fn protected_names() -> Vec<(String, &'static str)> {
    vec![
        (["NodeLocal", "StoredShareV1"].concat(), "custody"),
        (["NodeLocalShare", "ReceiptV1"].concat(), "custody"),
        (["NodeLocalShare", "StoreV1"].concat(), "custody"),
        (["ProvisionedNodeLocal", "ShareV1"].concat(), "custody"),
        (["PqHybridSealed", "ShareV1"].concat(), "contracts"),
        (["RecipientSealed", "ContributionV1"].concat(), "contracts"),
        (["NodeCustody", "SecretKeyV1"].concat(), "custody"),
        (["ContentEncryption", "KeyV1"].concat(), "custody"),
        (["DecryptSession", "SecretKeyV1"].concat(), "custody"),
        (["Recipient", "SecretKeyV1"].concat(), "custody"),
        (
            ["reconstruct_content_key_into_", "decrypt_session"].concat(),
            "custody",
        ),
        (
            ["unwrap_content_key_in_", "decrypt_session"].concat(),
            "custody",
        ),
        (["mint_decrypt_session_", "from_seed"].concat(), "custody"),
        (
            [
                "decrypt_payload_to_staging_writer_",
                "from_authenticated_operation_v1",
            ]
            .concat(),
            "custody",
        ),
        (["KeyRelease", "RequestV1"].concat(), "contracts"),
        (["VerifiedKeyRelease", "RequestV1"].concat(), "contracts"),
        (["KeyRelease", "OutcomeV1"].concat(), "contracts"),
        (
            ["SignedRuntimeRelease", "OperationV1"].concat(),
            "contracts",
        ),
        (
            ["AuthenticatedRuntimeRelease", "OperationV1"].concat(),
            "contracts",
        ),
        (["RuntimeRelease", "Coordinator"].concat(), "runtime"),
        (
            ["CustodyProvider", "RequestV1"].concat(),
            "provider-contracts",
        ),
        (
            ["DecryptProvider", "RequestV1"].concat(),
            "provider-contracts",
        ),
    ]
}

fn walk_home_source(root: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root).expect("Home source directory") {
        let path = entry.expect("Home source entry").path();
        let name = path.file_name().unwrap().to_string_lossy();
        if matches!(name.as_ref(), "target" | "target-build" | ".git") {
            continue;
        }
        if path.is_dir() {
            walk_home_source(&path, out);
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some(
                "rs" | "js" | "mjs" | "ts" | "html" | "css" | "json" | "webmanifest" | "svg" | "md"
            )
        ) {
            out.push(path);
        }
    }
}

#[test]
fn home_sources_name_only_the_listed_protected_key_and_share_symbols() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest.ancestors().nth(3).unwrap();
    for (name, crate_suffix) in protected_names() {
        let path = repo.join(format!(
            "elastos/crates/elastos-protected-content-{crate_suffix}/src/lib.rs"
        ));
        let lib = fs::read_to_string(&path).unwrap();
        assert!(lib.contains(&name), "public source name moved: {name}");
    }
    let mut files = BTreeMap::new();
    for (file, text) in source::production_sources() {
        if file == "elastos-server/src/api/gateway.rs"
            || file == "elastos-server/src/api/viewer_gateway.rs"
            || file == "elastos-server/src/api/gateway_provider_proxy.rs"
            || file.starts_with("elastos-server/src/api/gateway_home_")
        {
            files.insert(file, text);
        }
    }
    let home_root = repo.join("capsules/home");
    let mut paths = Vec::new();
    walk_home_source(&home_root, &mut paths);
    for path in paths {
        let file = path
            .strip_prefix(repo)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        files.insert(file, fs::read_to_string(path).unwrap());
    }
    let mut hits = BTreeMap::new();
    for (file, text) in &files {
        for (name, _) in protected_names() {
            let count = text.match_indices(&name).count();
            if count > 0 {
                hits.insert((file.clone(), name), count);
            }
        }
    }
    let open: BTreeMap<(String, String), usize> = BTreeMap::new();
    assert_eq!(
        hits, open,
        "new Home key/share symbol; record an OPEN row for P2-4 follow-up"
    );
    println!("Home custody/key source rows: {} OPEN", open.len());
}
