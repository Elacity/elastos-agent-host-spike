//! Home authority inventory. The scan covers production sources under
//! elastos-server/src/api/ only. Its call census does not see callers outside
//! api/, aliased or function-pointer calls, macro-generated calls, or calls to
//! gates defined outside gateway_home_token.rs. The counted gate table covers every production
//! `require_*` function in gateway_home_token.rs. A call is counted when its
//! actor is Home, can resolve to Home, or has an unresolved local actor list.
//! Calls within the verifier module are forwarding, so route entries start in
//! other compiled API files. A new gate or unresolved call requires a row.

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

// Every production require_* definition in gateway_home_token.rs has one
// decision here. This is deliberately a counted table: a new definition must
// be reviewed before the call-site scan can pass.
fn gate_decisions() -> BTreeMap<&'static str, (bool, &'static str)> {
    BTreeMap::from([
        ("require_home_launch_token", (true, "")),
        ("require_home_launch_token_context", (true, "")),
        ("require_home_launch_grant", (true, "")),
        ("require_home_launch_token_for_any_context", (true, "")),
        ("require_home_launch_token_for_any_app_context", (true, "")),
        ("require_home_projection_launch_token_context", (true, "")),
        ("require_home_viewer_launch_token_context", (true, "")),
        (
            "require_internal_shell_launch_grant_for_any_context",
            (true, ""),
        ),
        ("require_internal_shell_launch_grant_principal", (true, "")),
        ("require_internal_shell_projection_context", (true, "")),
        ("require_launch_bound_token", (true, "")),
        ("require_home_token", (true, "")),
        ("require_home_token_context", (true, "")),
        (
            "require_signed_browser_launch",
            (false, "Browser-only actor list"),
        ),
        ("require_gateway_launch_for", (true, "")),
        ("require_gateway_launch", (true, "")),
        ("require_runtime_wallet_authority", (true, "")),
        (
            "require_internal_shell_runtime_wallet_authority",
            (true, ""),
        ),
        ("require_home_runtime_wallet_authority", (true, "")),
        ("require_home_launch_token_binding", (true, "")),
        ("require_home_launch_token_for_any_from", (true, "")),
        (
            "require_home_launch_token_for_any_from_with_origin",
            (true, ""),
        ),
        (
            "require_home_launch_token_for_any_from_expected_did",
            (true, ""),
        ),
        ("require_carried_home_launch_token", (true, "")),
        (
            "require_home_launch_token_value_from_expected_did",
            (true, ""),
        ),
        (
            "require_launch_token_schema",
            (false, "Payload schema check only"),
        ),
        (
            "require_capsule_browser_origin",
            (false, "Opaque origin check only"),
        ),
        (
            "require_exact_home_browser_origin",
            (false, "Same-origin check only"),
        ),
        (
            "require_internal_shell_origin",
            (false, "Browser provenance check only"),
        ),
    ])
}

// A wrapper is counted when a direct or already-counted wrapper call admits
// Home. Guarded connector and fixed documents-viewer wrappers remain listed
// as non-admitting decisions, so a new wrapper needs an explicit decision.
fn wrapper_decisions() -> BTreeMap<&'static str, (bool, &'static str)> {
    BTreeMap::from([
        ("require_auth_home_or_system_context", (true, "")),
        ("require_capsule_catalog_token", (true, "")),
        ("require_home_active_shell_wallet_authority", (true, "")),
        ("require_home_active_shell_token_context", (true, "")),
        ("require_home_active_shell_update_token_context", (true, "")),
        ("require_home_shell_state_token_context", (true, "")),
        ("require_home_wallet_connector_authority", (true, "")),
        ("require_passkey_add_launch", (true, "")),
        ("require_library_object_viewer_context", (true, "")),
        ("require_viewer_library_launch_context", (true, "")),
        ("require_viewer_bound_launch_token_context", (true, "")),
        (
            "require_documents_viewer_context",
            (false, "Documents viewer pin"),
        ),
        (
            "require_wallet_connector_launch_authority",
            (false, "Connector ID guard"),
        ),
        (
            "require_wallet_connector_launch_context",
            (false, "Connector ID guard"),
        ),
    ])
}

fn counted_gate_total() -> usize {
    gate_decisions()
        .values()
        .filter(|(admit, _)| *admit)
        .count()
        + wrapper_decisions()
            .values()
            .filter(|(admit, _)| *admit)
            .count()
}

fn source_gate_names(code: &str) -> BTreeSet<String> {
    code.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let after = line
                .strip_prefix("fn ")
                .or_else(|| line.find(" fn ").map(|at| &line[at + 4..]))?;
            let name = after.split_once('(')?.0;
            name.starts_with("require_").then(|| name.to_string())
        })
        .collect()
}

// These HeaderMap gates have fixed non-Home actors and do not enter the Home
// call census. A new API HeaderMap gate needs a decision in one of the tables.
fn other_api_header_gate_decisions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("require_wallet_link_context", "WalletConnect actor only"),
        ("require_wallet_app_launch_authority", "Wallet actor only"),
        ("require_system_admin", "System actor and admin passkey"),
    ])
}

#[test]
fn every_api_header_gate_has_a_decision() {
    let decided: BTreeSet<_> = gate_decisions()
        .keys()
        .chain(wrapper_decisions().keys())
        .chain(other_api_header_gate_decisions().keys())
        .map(|name| (*name).to_string())
        .collect();
    let mut unreviewed = BTreeSet::new();
    for (file, raw) in source::production_sources() {
        if !file.starts_with("elastos-server/src/api/") || file.contains("/gateway_tests/") {
            continue;
        }
        let code = source::code_only(&raw);
        for name in source_gate_names(&code) {
            let open = code
                .find(&format!("fn {name}("))
                .expect("gate definition has a parameter list")
                + "fn ".len()
                + name.len();
            let signature = &code[open..call_end(&code, open)];
            if signature.contains("HeaderMap") && !decided.contains(&name) {
                unreviewed.insert(format!("{file}::{name}"));
            }
        }
    }
    assert!(
        unreviewed.is_empty(),
        "API HeaderMap gates need a decision: {unreviewed:?}"
    );
}

#[test]
fn every_home_token_gate_has_a_counted_decision() {
    let sources = source::production_sources();
    let raw = &sources["elastos-server/src/api/gateway_home_token.rs"];
    let definitions = source_gate_names(&source::code_only(raw));
    let decisions = gate_decisions();
    assert_eq!(
        definitions,
        decisions.keys().map(|name| (*name).to_string()).collect(),
        "gateway_home_token.rs gate definitions changed"
    );
    assert!(decisions.values().filter(|(admit, _)| *admit).count() > 0);
    assert!(decisions
        .values()
        .all(|(admit, reason)| *admit || !reason.is_empty()));
}

fn rows() -> Vec<AuthorityRow> {
    const AUTH: &str = "elastos-server/src/api/auth_gateway.rs";
    const CATALOG: &str = "elastos-server/src/api/gateway_capsule_catalog.rs";
    const EXTERNAL: &str = "elastos-server/src/api/gateway_home_external_link.rs";
    const HOME_RUNTIME: &str = "elastos-server/src/api/gateway_home_runtime.rs";
    const FRONTDOOR: &str = "elastos-server/src/api/gateway_frontdoor.rs";
    const SUPERVISOR: &str = "elastos-server/src/api/handlers/supervisor_api.rs";
    const SHARED: &str = "elastos-server/src/api/gateway_home_shared_content.rs";
    const HOME_SYSTEM: &str = "elastos-server/src/api/gateway_home_system.rs";
    const STEP_UP: &str = "elastos-server/src/api/gateway_passkey_step_up.rs";
    const ROOM: &str = "elastos-server/src/api/gateway_room.rs";
    const ROUTES: &str = "elastos-server/src/api/routes.rs";
    const VIEWER: &str = "elastos-server/src/api/viewer_gateway.rs";
    const SITE: &str = "elastos-server/src/api/gateway_site.rs";
    const CONNECTORS: &str = "elastos-server/src/api/gateway_wallet_connectors.rs";
    const HOME_CONNECTOR: &str = "elastos-server/src/api/gateway_home_wallet_connector.rs";
    const MARKETPLACE: &str = "elastos-server/src/api/gateway_marketplace.rs";
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
            "runtime-admin:require_active_passkey_principal_for_context+runtime_wallet_authority; conditional did via recovery_kit_import_inner -> verify_did_recovery_import_proof",
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
            "runtime-admin:active principal or passkey checks at callers",
        ),
        row(
            AUTH,
            "replacement_wallet_authority",
            "require_runtime_wallet_authority",
            1,
            "delegates:wallet via replacement shell token and verified actor binding",
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
            "app-grant:OPEN P2-4 follow-up; conditional model+peer via Inbox services sync",
        ),
        row(
            FRONTDOOR,
            "gateway_admission",
            "require_home_active_shell_wallet_authority",
            1,
            "delegates:wallet via /api/apps/home/* front door",
        ),
        row(
            SHARED,
            "home_shared_content_check",
            "require_home_token_context",
            1,
            "delegates:ipfs via content_pinned_here -> local_cid_pinned -> registry.send_raw",
        ),
        row(
            SHARED,
            "home_shared_content_get",
            "require_home_token_context",
            1,
            "delegates:ipfs+content via content_pinned_here -> local_cid_pinned -> registry.send_raw and invoke_provider",
        ),
        row(
            HOME_SYSTEM,
            "home_events",
            "require_home_runtime_wallet_authority",
            1,
            "delegates:wallet+object via home_realtime_snapshot -> home_desktop_events_signature -> registry.send_raw(object/events)",
        ),
        row(
            HOME_SYSTEM,
            "home_events_stream",
            "require_home_runtime_wallet_authority",
            1,
            "delegates:wallet+object via home_realtime_snapshot -> home_desktop_events_signature -> registry.send_raw(object/events)",
        ),
        row(
            HOME_SYSTEM,
            "home_summary",
            "require_home_active_shell_wallet_authority",
            1,
            "delegates:wallet+object via home_desktop_objects_summary -> registry.send_raw(object/list) -> home_trash_desktop_object -> registry.send_raw(object/roots)",
        ),
        row(
            HOME_SYSTEM,
            "require_home_active_shell_wallet_authority",
            "require_home_runtime_wallet_authority",
            1,
            "delegates:wallet via Home token",
        ),
        row(
            HOME_SYSTEM,
            "require_home_active_shell_wallet_authority",
            "require_runtime_wallet_authority",
            1,
            "delegates:wallet via local Home and shell actor list",
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
            "principal_from_capsule_name",
            "require_internal_shell_launch_grant_principal",
            1,
            "app-grant:OPEN; conditional: admits Home when the name resolves to home",
        ),
        row(
            ROUTES,
            "kept_launch_reader",
            "require_internal_shell_projection_context",
            1,
            "app-grant:launch-bound page token; Home actor only when the kept page resolves to home",
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
            "require_viewer_library_launch_context",
            "require_home_viewer_launch_token_context",
            1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule",
        ),
        row(
            VIEWER,
            "require_viewer_bound_launch_token_context",
            "require_home_projection_launch_token_context",
            1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule",
        ),
        row(
            SUPERVISOR,
            "supervisor_launch_principal_from_input",
            "require_internal_shell_launch_grant_principal",
            1,
            "app-grant:OPEN; conditional: admits Home when the name resolves to home",
        ),
        row(
            VIEWER,
            "home_launch_content",
            "require_home_token_context",
            1,
            "app-grant:OPEN P2-4 follow-up",
        ),
        row(
            FRONTDOOR,
            "gateway_admission",
            "require_gateway_launch_for",
            1,
            "home-own:front door admission before route checks",
        ),
        row(
            EXTERNAL,
            "home_external_link_app",
            "require_carried_home_launch_token",
            1,
            "app-grant:list not resolved: counted; checked against Home launch targets",
        ),
        row(
            HOME_RUNTIME,
            "home_launch",
            "require_carried_home_launch_token",
            1,
            "app-grant:list not resolved: counted; target grant verified; conditional model+peer via Inbox services sync",
        ),
        row(
            HOME_SYSTEM,
            "home_active_shell_get",
            "require_home_active_shell_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "home_active_shell_update",
            "require_home_active_shell_update_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "home_appearance_preferences_update",
            "require_home_active_shell_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "home_browser_state_get",
            "require_home_shell_state_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "home_browser_state_update",
            "require_home_shell_state_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_SYSTEM,
            "require_home_active_shell_token_context",
            "require_home_active_shell_update_token_context",
            1,
            "home-own",
        ),
        row(
            HOME_CONNECTOR,
            "require_home_wallet_connector_authority",
            "require_home_runtime_wallet_authority",
            1,
            "delegates:wallet via Home connector authority",
        ),
        row(
            HOME_CONNECTOR,
            "require_home_wallet_connector_authority",
            "require_carried_home_launch_token",
            1,
            "delegates:wallet via connector launch binding; list not resolved: counted",
        ),
        row(
            ROOM,
            "gateway_carrier_bootstrap",
            "require_gateway_launch",
            1,
            "delegates:peer via managed_runtime_carrier_bootstrap or gateway_provider_carrier_bootstrap -> registry.send_raw(peer/get_ticket)",
        ),
        row(
            SITE,
            "cid_route_admitted",
            "require_gateway_launch",
            1,
            "delegates:content via CID serving",
        ),
        row(
            CONNECTORS,
            "require_wallet_connector_launch_authority",
            "require_runtime_wallet_authority",
            1,
            "delegates:wallet via connector actor validation; list not resolved: counted",
        ),
        row(
            CONNECTORS,
            "require_wallet_connector_launch_context",
            "require_home_launch_token_context",
            1,
            "app-grant:list not resolved: counted; connector actor validation",
        ),
        row(
            VIEWER,
            "viewer_launch_read",
            "require_launch_bound_token",
            1,
            "app-grant:OPEN; conditional: admits Home when the viewer resolves to home",
        ),
        row(AUTH, "passkey_add_begin_inner", "require_passkey_add_launch", 1,
            "runtime-admin:require_hosted_step_up_launch+active admin passkey"),
        row(AUTH, "passkey_add_complete_inner", "require_passkey_add_launch", 1,
            "runtime-admin:require_hosted_step_up_launch+active admin passkey"),
        row(AUTH, "passkey_demote_guest_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:active principal+is_admin"),
        row(AUTH, "passkey_list_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:active principal+self or admin filter"),
        row(AUTH, "passkey_promote_admin_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:active principal+is_admin"),
        row(AUTH, "passkey_revoke_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:revoke_passkey_for_actor"),
        row(AUTH, "recovery_kit_import_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:active passkey principal+request binding; conditional did via verify_did_recovery_import_proof"),
        row(AUTH, "recovery_status_inner", "require_auth_home_or_system_context", 1,
            "runtime-admin:active passkey principal"),
        row(AUTH, "revoke_session", "require_auth_home_or_system_context", 1,
            "runtime-admin:active principal+self or admin"),
        row(CATALOG, "capsule_catalog", "require_capsule_catalog_token", 2,
            "home-own:catalog read"),
        row(CATALOG, "capsule_interfaces", "require_capsule_catalog_token", 1,
            "home-own:interface read"),
        row(MARKETPLACE, "marketplace_catalog", "require_capsule_catalog_token", 1,
            "app-grant:OPEN; catalog read"),
        row(HOME_CONNECTOR, "home_wallet_connector_evm_link_challenge", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority"),
        row(HOME_CONNECTOR, "home_wallet_connector_evm_link_verify", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority; conditional chain via erc1271_is_valid_signature"),
        row(HOME_CONNECTOR, "home_wallet_connector_bitcoin_link_challenge", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority"),
        row(HOME_CONNECTOR, "home_wallet_connector_bitcoin_link_verify", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority"),
        row(HOME_CONNECTOR, "home_wallet_connector_approval_handoff", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority"),
        row(HOME_CONNECTOR, "home_wallet_connector_approval_complete", "require_home_wallet_connector_authority", 1,
            "delegates:wallet via connector authority"),
        row(VIEWER, "require_documents_viewer_context", "require_viewer_library_launch_context", 1,
            "app-grant:list not resolved: counted; documents viewer guard"),
        row(VIEWER, "require_library_object_viewer_context", "require_viewer_library_launch_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "require_viewer_bound_launch_token_context", "require_viewer_library_launch_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_content", "require_viewer_bound_launch_token_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_library_summary", "require_viewer_library_launch_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_storage_target", "require_viewer_bound_launch_token_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_library_object_get", "require_library_object_viewer_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_library_object_post", "require_library_object_viewer_context", 1,
            "app-own: actor equals URL viewer; Home refused by is_viewer_capsule"),
        row(VIEWER, "viewer_library_roots_get", "require_library_object_viewer_context", 1,
            "app-grant:list not resolved: counted; archive-manager guard"),
    ]
}

// This is a bounded source check, not a proof that a conditional branch runs.
// Keep the names in the needles assembled at run time, so this test's own text
// cannot supply a production call to the source scan.
struct ProviderFunction {
    file: String,
    name: String,
    code: String,
    raw: String,
}

fn provider_functions() -> (Vec<ProviderFunction>, BTreeMap<String, Vec<usize>>) {
    let mut functions = Vec::new();
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (file, raw) in source::production_sources() {
        if !file.starts_with("elastos-server/src/") {
            continue;
        }
        let code = source::code_only(&raw);
        for (at, _) in code.match_indices(&["f", "n "].concat()) {
            if at > 0
                && (code.as_bytes()[at - 1].is_ascii_alphanumeric()
                    || code.as_bytes()[at - 1] == b'_')
            {
                continue;
            }
            let start = at + 3;
            let end = start
                + code[start..]
                    .bytes()
                    .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    .count();
            if end == start || !matches!(code.as_bytes().get(end), Some(b'(' | b'<')) {
                continue;
            }
            let Some(open) = code[end..].find(['{', ';']).map(|offset| end + offset) else {
                continue;
            };
            if code.as_bytes()[open] != b'{' {
                continue;
            }
            let mut depth = 0;
            let mut close = None;
            for (offset, byte) in code.as_bytes()[open..].iter().enumerate() {
                match byte {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else { continue };
            let name = code[start..end].to_string();
            let index = functions.len();
            functions.push(ProviderFunction {
                file: file.clone(),
                name: name.clone(),
                code: code[open..close].to_string(),
                raw: raw[open..close].to_string(),
            });
            by_name.entry(name).or_default().push(index);
        }
    }
    (functions, by_name)
}

#[test]
fn viewer_route_rows_pin_capsule_check_before_token() {
    let (functions, _) = provider_functions();
    let viewer_file = ["elastos-server/src/api/", "viewer_gateway.rs"].concat();
    let check = ["is_", "viewer_capsule"].concat();
    let sites = [
        (
            ["viewer_", "library_summary"].concat(),
            ["require_viewer_", "library_launch_context"].concat(),
        ),
        (
            ["viewer_", "content"].concat(),
            ["require_viewer_", "bound_launch_token_context"].concat(),
        ),
        (
            ["viewer_", "storage_target"].concat(),
            ["require_viewer_", "bound_launch_token_context"].concat(),
        ),
        (
            ["require_library_", "object_viewer_context"].concat(),
            ["require_viewer_", "library_launch_context"].concat(),
        ),
    ];
    for (name, token) in sites {
        let function = functions
            .iter()
            .find(|function| function.file == viewer_file && function.name == name)
            .unwrap_or_else(|| panic!("missing viewer gate {name}"));
        let check_at = function
            .code
            .find(&format!("{check}("))
            .unwrap_or_else(|| panic!("{name} lost {check}"));
        let token_at = function
            .code
            .find(&format!("{token}("))
            .unwrap_or_else(|| panic!("{name} lost {token}"));
        assert!(
            check_at < token_at,
            "{name} checks token before viewer capsule"
        );
    }
}

fn provider_literal(argument: &str) -> Option<String> {
    let literal = argument.trim().strip_prefix('"')?;
    let value = literal.split_once('"')?.0;
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    .then(|| value.to_string())
}

fn provider_calls(function: &ProviderFunction) -> (Vec<String>, BTreeSet<String>) {
    let mut schemes = Vec::new();
    let mut callees = BTreeSet::new();
    let bytes = function.code.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if !(bytes[at].is_ascii_alphabetic() || bytes[at] == b'_') {
            at += 1;
            continue;
        }
        let start = at;
        at += 1;
        while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
            at += 1;
        }
        let name = &function.code[start..at];
        let open = at
            + bytes[at..]
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let send = ["send", "_raw"].concat();
        let data = ["provider", "_data"].concat();
        let invoke = ["invoke", "_provider"].concat();
        if name == send || name == invoke || name == data || name.ends_with(&format!("_{data}")) {
            let end = call_end(&function.code, open);
            let raw_call = &function.raw[start..end];
            let args = call_arguments(raw_call);
            let scheme = if name == send {
                args.first().and_then(|arg| provider_literal(arg))
            } else if name == invoke {
                let code_call = &function.code[start..end];
                code_call
                    .find("target:")
                    .and_then(|offset| provider_literal(&raw_call[offset + "target:".len()..]))
            } else {
                args.get(1).and_then(|arg| provider_literal(arg))
            };
            if let Some(scheme) = scheme {
                schemes.push(scheme);
            }
        }
        callees.insert(name.to_string());
    }
    (schemes, callees)
}

fn walk_provider_reach(
    functions: &[ProviderFunction],
    by_name: &BTreeMap<String, Vec<usize>>,
    index: usize,
    depth: usize,
    path: &mut Vec<usize>,
    found: &mut BTreeMap<String, String>,
) {
    if path.contains(&index) {
        return;
    }
    path.push(index);
    let function = &functions[index];
    let (schemes, callees) = provider_calls(function);
    for scheme in schemes {
        let chain = path
            .iter()
            .map(|at| functions[*at].name.as_str())
            .collect::<Vec<_>>()
            .join(" -> ");
        found
            .entry(scheme)
            .or_insert_with(|| format!("{chain} ({})", function.file));
    }
    if depth < 4 {
        for name in callees {
            let Some(candidates) = by_name.get(&name) else {
                continue;
            };
            let local: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|at| functions[*at].file == function.file)
                .collect();
            let next = if local.len() == 1 {
                Some(local[0])
            } else if local.is_empty() && candidates.len() == 1 {
                Some(candidates[0])
            } else {
                None
            };
            if let Some(next) = next {
                walk_provider_reach(functions, by_name, next, depth + 1, path, found);
            }
        }
    }
    path.pop();
}

fn provider_reach_exceptions(
) -> BTreeMap<(&'static str, &'static str, &'static str), (&'static str, &'static str)> {
    // Each entry is (row key, scheme, "not reached because ...").
    BTreeMap::from([(
        (
            "elastos-server/src/api/viewer_gateway.rs",
            "viewer_library_roots_get",
            "require_library_object_viewer_context",
        ),
        (
            "content",
            "not reached because this route fixes op to roots; the shared Library handler reaches content only for Repair",
        ),
    )])
}

#[test]
fn every_home_authority_row_names_mechanical_provider_reach() {
    let (functions, by_name) = provider_functions();
    let exceptions = provider_reach_exceptions();
    let mut checked = 0;
    let mut used_exceptions = 0;
    let mut missing = Vec::new();
    let rows = rows();
    for row in &rows {
        let candidates = by_name
            .get(row.function)
            .expect("row function in production source");
        let index = *candidates
            .iter()
            .find(|at| functions[**at].file == row.file)
            .unwrap_or_else(|| {
                panic!("missing production function {}::{}", row.file, row.function)
            });
        let mut found = BTreeMap::new();
        walk_provider_reach(&functions, &by_name, index, 0, &mut Vec::new(), &mut found);
        for (scheme, chain) in found {
            checked += 1;
            if row
                .authority
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
                .any(|word| word == scheme)
            {
                continue;
            }
            match exceptions.get(&(row.file, row.function, row.gate)) {
                Some((excepted, reason))
                    if *excepted == scheme && reason.starts_with("not reached because ") =>
                {
                    used_exceptions += 1;
                }
                _ => missing.push(format!(
                    "{}::{} [{}] omits {scheme}: {chain}",
                    row.file, row.function, row.gate
                )),
            }
        }
    }
    assert_eq!(
        used_exceptions,
        exceptions.len(),
        "stale provider reach exception"
    );
    println!(
        "Home provider reach: {} rows, {} schemes found mechanically, {} exceptions",
        rows.len(),
        checked,
        used_exceptions
    );
    assert!(
        missing.is_empty(),
        "authority labels omit provider schemes:\n{}",
        missing.join("\n")
    );
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

fn call_arguments(call: &str) -> Vec<&str> {
    let body = &call[call.find('(').unwrap() + 1..call.len() - 1];
    let mut args = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    for (at, byte) in body.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                args.push(body[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    if !body[start..].trim().is_empty() {
        args.push(body[start..].trim());
    }
    args
}

fn actor_can_be_home(code: &str, at: usize, function: &str, gate: &str, call: &str) -> bool {
    if wrapper_decisions()
        .get(gate)
        .is_some_and(|(admit, _)| *admit)
    {
        return true;
    }
    if matches!(
        gate,
        "require_home_token"
            | "require_home_token_context"
            | "require_home_runtime_wallet_authority"
            | "require_gateway_launch"
            | "require_gateway_launch_for"
    ) {
        return true;
    }
    let args = call_arguments(call);
    let actor = if gate == "require_launch_bound_token" {
        args.get(2).copied()
    } else if gate == "require_home_projection_launch_token_context"
        || gate == "require_internal_shell_projection_context"
    {
        args.get(3).copied()
    } else {
        args.last().copied()
    }
    .unwrap_or("");
    if actor.contains("HOME_CAPSULE_ID") {
        return true;
    }
    let named_actor = actor.trim_start_matches('&').trim();
    if named_actor.starts_with('"') && named_actor.ends_with('"') {
        return named_actor == "\"home\"";
    }
    if named_actor.rsplit("::").next().is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
    }) {
        return false;
    }
    // A literal list of other named actors is resolved. A variable list must
    // be traced to its local declaration. Unresolved lists stay counted.
    if actor.starts_with("&[") && actor.ends_with(']') {
        let entries = &actor[2..actor.len() - 1];
        if entries.split(',').all(|entry| {
            let entry = entry.trim();
            entry.is_empty()
                || (entry.starts_with('"') && entry.ends_with('"') && entry != "\"home\"")
                || entry.rsplit("::").next().is_some_and(|name| {
                    !name.is_empty()
                        && name.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit()
                        })
                })
        }) {
            return false;
        }
        return true;
    }
    let start = code[..at].rfind(&format!("fn {function}")).unwrap_or(0);
    let scope = &code[start..at];
    let var = actor.trim_start_matches('&').trim();
    if var.is_empty() || !var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return true;
    }
    let declaration = scope
        .rfind(&format!("let {var}"))
        .or_else(|| scope.rfind(&format!("let mut {var}")));
    let Some(declaration) = declaration else {
        return true; // parameter or unresolved local list
    };
    let value = &scope[declaration..];
    if value.contains("HOME_CAPSULE_ID") {
        return true;
    }
    // A local list built from a static match is resolved when every arm
    // names only fixed capsule constants. This covers the provider proxy.
    if value.contains("match ") && value.contains("CAPSULE_ID") && !value.contains("collect::<") {
        return false;
    }
    true
}

fn found() -> BTreeMap<(String, String, String), usize> {
    let mut result = BTreeMap::new();
    let gates = gate_decisions();
    let wrappers = wrapper_decisions();
    for (file, raw) in source::production_sources() {
        if !file.starts_with("elastos-server/src/api/") || file.contains("/gateway_tests/") {
            continue;
        }
        let code = source::code_only(&raw);
        let prefix = ["require", "_"].concat();
        for (at, _) in code.match_indices(&prefix) {
            if at > 0
                && (code.as_bytes()[at - 1].is_ascii_alphanumeric()
                    || code.as_bytes()[at - 1] == b'_')
            {
                continue;
            }
            let end_name = code[at..]
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .map(|length| at + length)
                .unwrap_or(code.len());
            let open = end_name
                + code[end_name..]
                    .bytes()
                    .take_while(u8::is_ascii_whitespace)
                    .count();
            if code.as_bytes().get(open) != Some(&b'(') {
                continue;
            }
            let gate = &code[at..end_name];
            if !gates.get(gate).is_some_and(|(admit, _)| *admit)
                && !wrappers.get(gate).is_some_and(|(admit, _)| *admit)
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
            let end = call_end(&code, open);
            let call = &raw[at..end];
            if !actor_can_be_home(&code, at, &function, gate, call) {
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
    let decisions = wrapper_decisions();
    let discovered: BTreeSet<_> = found
        .keys()
        .filter(|(_, function, _)| function.starts_with("require_"))
        .map(|(_, function, _)| function.as_str())
        .collect();
    assert_eq!(
        discovered,
        decisions.keys().copied().collect(),
        "API wrapper decisions changed"
    );
    assert!(decisions
        .values()
        .all(|(admit, reason)| *admit || !reason.is_empty()));
    let mut listed = BTreeSet::new();
    let mut classes = BTreeMap::new();
    let mut open = Vec::new();
    let mut calls = 0;
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
            "home-own" | "runtime-admin" | "delegates" | "app-grant" | "app-own"
        ));
        *classes.entry(class).or_insert(0usize) += 1;
        calls += row.count;
        if row.authority.contains("OPEN") {
            open.push(format!("{}::{} [{}]", row.file, row.function, row.gate));
        }
    }
    let missing: Vec<_> = found
        .iter()
        .filter(|(key, _)| !listed.contains(*key))
        .collect();
    assert!(
        missing.is_empty(),
        "unlisted Home authority routes: {missing:#?}"
    );
    println!(
        "Home authority (production elastos-server/src/api/ only; call census misses outside-api callers, aliased/function-pointer calls, macro-generated calls, and calls to gates outside gateway_home_token.rs): {} gates, {} rows, {} calls; {:?}; OPEN rows: {:?}",
        counted_gate_total(),
        listed.len(),
        calls,
        classes,
        open
    );
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

fn protected_names(repo: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for suffix in ["custody", "contracts", "runtime", "provider-contracts"] {
        // The crate name is joined at run time so the generic Runtime product
        // inventory does not count this test as a product reference.
        let crate_name = ["elastos", "protected", "content", suffix].join("-");
        let path = repo.join(format!("elastos/crates/{crate_name}/src/lib.rs"));
        let lib = fs::read_to_string(path).unwrap();
        let mut export = String::new();
        for line in lib.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("pub use ") {
                export.push_str(rest);
            } else if !export.is_empty() {
                export.push_str(trimmed);
            }
            if !export.is_empty() && export.contains(';') {
                let items = export.split_once('{').map_or_else(
                    || export.split_once("::").map(|(_, item)| item).unwrap_or(""),
                    |(_, items)| items.split_once('}').map(|(body, _)| body).unwrap_or(""),
                );
                for item in items.split(',') {
                    let name = item.trim().trim_end_matches(';').trim();
                    if protected_symbol_name(name)
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        names.insert(name.to_string());
                    }
                }
                export.clear();
            }
            if let Some(rest) = trimmed
                .strip_prefix("pub struct ")
                .or_else(|| trimmed.strip_prefix("pub enum "))
                .or_else(|| trimmed.strip_prefix("pub type "))
                .or_else(|| trimmed.strip_prefix("pub trait "))
                .or_else(|| trimmed.strip_prefix("pub fn "))
            {
                let name = rest
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .next()
                    .unwrap();
                if protected_symbol_name(name) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    assert!(!names.is_empty(), "protected public-item scan is empty");
    for known in [
        "NodeLocalStoredShareV1",
        "DecryptSessionSecretKeyV1",
        "RuntimeReleaseCoordinator",
    ] {
        assert!(names.contains(known), "missing known public item: {known}");
    }
    names
}

fn protected_symbol_name(name: &str) -> bool {
    [
        "Custody",
        "Decrypt",
        "decrypt",
        "Share",
        "SecretKey",
        "ContentEncryption",
        "KeyRelease",
        "RuntimeRelease",
        "SealedContribution",
        "content_key",
    ]
    .iter()
    .any(|part| name.contains(part))
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
    let names = protected_names(repo);
    let mut files = BTreeMap::new();
    for (file, text) in source::production_sources() {
        if file == "elastos-server/src/api/gateway.rs"
            || file == "elastos-server/src/api/auth_gateway.rs"
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
        for name in &names {
            let count = text.match_indices(name.as_str()).count();
            if count > 0 {
                hits.insert((file.clone(), name.clone()), count);
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
