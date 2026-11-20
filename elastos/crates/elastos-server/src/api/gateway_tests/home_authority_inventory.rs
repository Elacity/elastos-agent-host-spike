//! Home authority inventory. The counted gate table covers every production
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
fn gate_decisions() -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        ("require_home_launch_token", true),
        ("require_home_launch_token_context", true),
        ("require_home_launch_grant", true),
        ("require_home_launch_token_for_any_context", true),
        ("require_home_launch_token_for_any_app_context", true),
        ("require_home_projection_launch_token_context", true),
        ("require_home_viewer_launch_token_context", true),
        ("require_internal_shell_launch_grant_for_any_context", true),
        ("require_internal_shell_launch_grant_principal", true),
        ("require_internal_shell_projection_context", true),
        ("require_launch_bound_token", true),
        ("require_home_token", true),
        ("require_home_token_context", true),
        ("require_signed_browser_launch", false),
        ("require_gateway_launch_for", true),
        ("require_gateway_launch", true),
        ("require_runtime_wallet_authority", true),
        ("require_internal_shell_runtime_wallet_authority", true),
        ("require_home_runtime_wallet_authority", true),
        ("require_home_launch_token_binding", true),
        ("require_home_launch_token_for_any_from", true),
        ("require_home_launch_token_for_any_from_with_origin", true),
        ("require_home_launch_token_for_any_from_expected_did", true),
        ("require_carried_home_launch_token", true),
        ("require_home_launch_token_value_from_expected_did", true),
        ("require_launch_token_schema", false),
        ("require_capsule_browser_origin", false),
        ("require_exact_home_browser_origin", false),
        ("require_internal_shell_origin", false),
    ])
}

// A wrapper is counted when a direct or already-counted wrapper call admits
// Home. Guarded connector and fixed documents-viewer wrappers remain listed
// as non-admitting decisions, so a new wrapper needs an explicit decision.
fn wrapper_decisions() -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        ("require_auth_home_or_system_context", true),
        ("require_capsule_catalog_token", true),
        ("require_home_active_shell_wallet_authority", true),
        ("require_home_active_shell_token_context", true),
        ("require_home_active_shell_update_token_context", true),
        ("require_home_shell_state_token_context", true),
        ("require_home_wallet_connector_authority", true),
        ("require_passkey_add_launch", true),
        ("require_library_object_viewer_context", true),
        ("require_viewer_library_launch_context", true),
        ("require_viewer_bound_launch_token_context", true),
        ("require_documents_viewer_context", false),
        ("require_wallet_connector_launch_authority", false),
        ("require_wallet_connector_launch_context", false),
    ])
}

fn counted_gate_total() -> usize {
    gate_decisions().values().filter(|admit| **admit).count()
        + wrapper_decisions().values().filter(|admit| **admit).count()
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
    assert!(decisions.values().filter(|admit| **admit).count() > 0);
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
            "app-grant:OPEN P2-4 follow-up",
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
            "delegates:wallet via Home events authority",
        ),
        row(
            HOME_SYSTEM,
            "home_events_stream",
            "require_home_runtime_wallet_authority",
            1,
            "delegates:wallet via Home events stream authority",
        ),
        row(
            HOME_SYSTEM,
            "home_summary",
            "require_home_active_shell_wallet_authority",
            1,
            "delegates:wallet via Home summary authority",
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
            "app-grant:OPEN; conditional: admits Home when the name resolves to home",
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
            "app-grant:OPEN; conditional: admits Home when the name resolves to home",
        ),
        row(
            VIEWER,
            "require_viewer_bound_launch_token_context",
            "require_home_projection_launch_token_context",
            1,
            "app-grant:OPEN; conditional: admits Home when the name resolves to home",
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
            "app-grant:list not resolved: counted; target grant verified",
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
            "delegates:carrier via managed_runtime_carrier_bootstrap or gateway_provider_carrier_bootstrap",
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
            "runtime-admin:active passkey principal+request binding"),
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
            "delegates:wallet via connector authority"),
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
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "require_viewer_bound_launch_token_context", "require_viewer_library_launch_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_content", "require_viewer_bound_launch_token_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_library_summary", "require_viewer_library_launch_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_storage_target", "require_viewer_bound_launch_token_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_library_object_get", "require_library_object_viewer_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_library_object_post", "require_library_object_viewer_context", 1,
            "app-grant:OPEN; conditional: admits Home when viewer resolves to home"),
        row(VIEWER, "viewer_library_roots_get", "require_library_object_viewer_context", 1,
            "app-grant:list not resolved: counted; archive-manager guard"),
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
    if wrapper_decisions().get(gate).copied().unwrap_or(false) {
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
            if !gates.get(gate).copied().unwrap_or(false)
                && !wrappers.get(gate).copied().unwrap_or(false)
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
            "home-own" | "runtime-admin" | "delegates" | "app-grant"
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
        "Home authority: {} gates, {} rows, {} calls; {:?}; OPEN rows: {:?}",
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
        let path = repo.join(format!(
            "elastos/crates/elastos-protected-content-{suffix}/src/lib.rs"
        ));
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
