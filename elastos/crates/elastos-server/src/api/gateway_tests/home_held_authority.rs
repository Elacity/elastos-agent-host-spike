//! Home-held authority inventory.
//!
//! One scan lists every production site where Home mints, forwards, or holds
//! another actor's authority. Each site has one row: the file, the function,
//! the mechanism, how many times it occurs, and a decision with a one-line
//! reason. A new site without a row, or a row whose site disappears, fails
//! this test.
//!
//! The sources are the closure `start_census_tests::production_sources`
//! already uses: `elastos-server` and `elastos-runtime` crate roots, with
//! every `#[cfg(test)]` item removed. This file is reached only from the test
//! module. Needles are joined at run time, so this file does not count itself.
//!
//! The row key is the file, the function name, and the mechanism. Two
//! functions with the same name in one file are one row, and their calls add.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::home_authority_inventory::{protected_names, protected_symbol_name};
use crate::start_census_tests as source;

struct HeldRow {
    file: &'static str,
    function: &'static str,
    mechanism: &'static str,
    count: usize,
    status: &'static str,
    authority: &'static str,
    behalf: &'static str,
    reason: &'static str,
}

struct Mark {
    status: &'static str,
    authority: &'static str,
    behalf: &'static str,
    reason: &'static str,
}

fn mark(
    status: &'static str,
    authority: &'static str,
    behalf: &'static str,
    reason: &'static str,
) -> Mark {
    Mark {
        status,
        authority,
        behalf,
        reason,
    }
}

fn row(
    file: &'static str,
    function: &'static str,
    mechanism: &'static str,
    count: usize,
    mark: Mark,
) -> HeldRow {
    HeldRow {
        file,
        function,
        mechanism,
        count,
        status: mark.status,
        authority: mark.authority,
        behalf: mark.behalf,
        reason: mark.reason,
    }
}

/// Reviewed open sites. A row may be `open` only when it is also named here,
/// so a new open site cannot land by editing only the row's status.
const OPEN_ROWS: &[(&str, &str, &str)] = &[
    (
        "elastos-server/src/api/gateway_home_token.rs",
        "local_home_launch_token_context",
        "HomeLaunchTokenContext::resolved",
    ),
    (
        "elastos-server/src/api/gateway_home_token.rs",
        "local_home_launch_token_context",
        "load_or_create_did",
    ),
    (
        "elastos-server/src/server_infra.rs",
        "register_chain_provider_plane",
        "load_or_create_device_key",
    ),
    (
        "elastos-server/src/localhost_file_migration.rs",
        "localhost_provider_bridge_config",
        "encryption_key: device_key_hex",
    ),
];

fn rows() -> Vec<HeldRow> {
    vec![
    row(
        "elastos-runtime/src/bootstrap/runtime_builder.rs",
        "build",
        "CapabilityManager::load_or_generate",
        1,
        mark("runtime-own", "capability signer", "Runtime", "Runtime startup loads its capability signer"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "rotate_signing_key",
        "SigningKey::generate",
        1,
        mark("runtime-own", "capability signing key", "Runtime", "Runtime rotates its capability signing key"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "delegate",
        "capability_manager.grant",
        1,
        mark("runtime-own", "child capability", "child capsule", "Runtime grants a non-delegatable child token from a parent capability"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "generate_and_persist_key",
        "SigningKey::generate",
        1,
        mark("runtime-own", "capability signing key", "Runtime", "Runtime persists a new capability signing key"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "load_or_generate",
        "SigningKey::generate",
        4,
        mark("runtime-own", "capability signing key", "Runtime", "Runtime loads or generates its capability signing key"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "new",
        "SigningKey::generate",
        1,
        mark("runtime-own", "capability signing key", "Runtime", "A new capability manager generates its signing key"),
    ),
    row(
        "elastos-runtime/src/capability/manager.rs",
        "read_signing_key_file",
        "SigningKey::from_bytes",
        1,
        mark("runtime-own", "capability signing key", "Runtime", "Runtime reads its stored capability signing key"),
    ),
    row(
        "elastos-runtime/src/handler/request_handler.rs",
        "handle_grant_capability",
        "capability_manager.grant",
        1,
        mark("runtime-own", "capsule capability", "capsule", "The request handler grants a capsule capability"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "btc_verify_for_wallet_link",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "wallet-link context", "person", "A Bitcoin wallet link rebuilds the person's launch context"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "btc_verify_for_wallet_link",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("delegated", "app token after wallet link", "person", "A Bitcoin wallet link mints the app token the grant names"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "evm_verify_for_wallet_link",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "wallet-link context", "person", "An EVM wallet link rebuilds the person's launch context"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "evm_verify_for_wallet_link",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("delegated", "app token after wallet link", "person", "An EVM wallet link mints the app token the grant names"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "passkey_response_for_grant",
        "issue_home_launch_token_for_auth_grant",
        2,
        mark("delegated", "Home and System tokens", "person", "Sign-in mints Home and System tokens for the apps the grant names"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "recovery_kit_import_inner",
        "issue_home_launch_token_for_verified_grant",
        2,
        mark("delegated", "Home and System tokens", "recovered person", "Recovery mints Home and System tokens for the verified grant"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "refresh_session_inner",
        "issue_home_launch_token_for_auth_grant",
        2,
        mark("delegated", "Home and System tokens", "person", "A refreshed session mints Home and System tokens for the apps the grant names"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "replacement_wallet_authority",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "replacement wallet token", "person", "A wallet replacement requires the caller's launch token"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "require_passkey_add_launch",
        "require_carried_home_launch_token",
        1,
        mark("delegated", "passkey-add token", "person", "Adding a passkey requires the carried launch token"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "require_wallet_link_context",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "wallet-link token", "person", "A wallet link requires the caller's launch token"),
    ),
    row(
        "elastos-server/src/api/auth_gateway.rs",
        "restore_people_identity_inner",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "recovered person", "Recovery signs the restored profile with this device"),
    ),
    row(
        "elastos-server/src/api/browser_sessions.rs",
        "browser_session_request",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "A browser session names this device"),
    ),
    row(
        "elastos-server/src/api/gateway.rs",
        "home_launch_token_context_from_parts",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "checked session grant", "the grant's person", "The gateway-owned environment route reaches this call only when a proof binding is set and the live grant matches"),
    ),
    row(
        "elastos-server/src/api/gateway.rs",
        "issue_gateway_owned_home_cli_launch_token",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("delegated", "projection under the checked grant", "the grant's person", "This mints the named app only after the env context's live grant has been checked, and that grant names home"),
    ),
    row(
        "elastos-server/src/api/gateway.rs",
        "issue_local_runtime_home_launch_token",
        "issue_local_runtime_home_launch_token",
        1,
        mark("narrowed", "public device mint", "home and home-cli", "The public wrapper forwards to the device mint, which accepts only home and home-cli"),
    ),
    row(
        "elastos-server/src/api/gateway.rs",
        "load_existing_gateway_runtime_did",
        "load_existing_did",
        1,
        mark("home-own", "device DID", "Home", "The gateway reads this device's DID when no trusted signer DID is set"),
    ),
    row(
        "elastos-server/src/api/gateway_agents.rs",
        "start_agent",
        "issue_home_agent_launch_token_with_context",
        1,
        mark("delegated", "agent start grant", "owner", "An agent start mints the short agent grant after passkey step-up"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_open",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Opening a Browser app requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_open_status",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Browser open status requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_close",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Closing a Browser page requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_diagnostics",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Browser page diagnostics require the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_heartbeat",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser page heartbeat requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_input",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Browser page input requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_status",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Browser page status requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_page_webrtc",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Browser page media requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_app_summary",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "The Browser summary requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser.rs",
        "browser_page_inspection",
        "require_runtime_wallet_authority",
        3,
        mark("delegated", "browser launch token", "browser", "Browser page inspection requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_internet.rs",
        "answer",
        "capability_manager.grant",
        1,
        mark("delegated", "internet execute capability", "browser", "A Browser internet answer mints an execute capability after passkey step-up"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_internet.rs",
        "summary",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser or inbox launch token", "browser", "The internet summary requires a Browser or Inbox launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator.rs",
        "approve_admission",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Admission approval requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator.rs",
        "approve_admission",
        "capability_manager.grant",
        1,
        mark("delegated", "operator write capability", "browser operator", "Approving an operator admission mints a bounded write capability"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator.rs",
        "owner_live",
        "require_carried_home_launch_token",
        1,
        mark("delegated", "browser launch token", "browser", "The live owner check requires the carried Browser token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator.rs",
        "pending_admissions",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Listing admissions requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator.rs",
        "revoke_admission",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "Revoking an admission requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_operator_client.rs",
        "grant_inspection",
        "capability_manager.grant",
        1,
        mark("delegated", "operator inspect capability", "browser operator", "Inspection mints a bounded read capability when the admission includes it"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_approval_status",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser wallet approval requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_bridge",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "The Browser wallet bridge requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_broadcast_transaction",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser wallet broadcast requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_read",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser wallet read requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_request_accounts",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser account request requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_request_signature",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser signature request requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_browser_wallet.rs",
        "browser_app_wallet_request_transaction",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "browser launch token", "browser", "A Browser transaction request requires the Browser launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_cli_mint.rs",
        "claim_request",
        "issue_home_launch_token_at",
        1,
        mark("delegated", "passkey-approved 5-min grant", "CLI", "The CLI claim signs a five-minute grant after passkey approval"),
    ),
    row(
        "elastos-server/src/api/gateway_home_cli_mint.rs",
        "signing_context",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "passkey-approved context", "CLI", "The CLI claim rebuilds the approved signing context"),
    ),
    row(
        "elastos-server/src/api/gateway_home_external_link.rs",
        "home_external_link_app",
        "require_carried_home_launch_token",
        1,
        mark("delegated", "target app token", "calling app", "An external link requires the target app's carried token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_runtime.rs",
        "append_home_launch_token",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("home-own", "route-bound launch", "Home page", "Home appends a projection token to a route on its page"),
    ),
    row(
        "elastos-server/src/api/gateway_home_runtime.rs",
        "home_launch",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("home-own", "target app launch", "Home page", "The Home page mints the target app's projection token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_runtime.rs",
        "home_launch",
        "require_carried_home_launch_token",
        1,
        mark("home-own", "freshly minted launch token", "Home page", "The Home page checks the launch token it just minted"),
    ),
    row(
        "elastos-server/src/api/gateway_home_runtime.rs",
        "launch_runtime_capsule",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("home-own", "runtime capsule launch", "Home page", "The Home page sends a projection grant to the Runtime"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "home_events",
        "require_home_runtime_wallet_authority",
        1,
        mark("delegated", "Home wallet token", "Home", "Home events require the Home launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "home_events_stream",
        "require_home_runtime_wallet_authority",
        1,
        mark("delegated", "Home wallet token", "Home", "The Home event stream requires the Home launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "home_services_local_device_did",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "Home services show this device's DID"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "local_model_offer_is_shared",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("home-own", "local model offer", "Home", "Home reads whether its local model offer is shared"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "require_home_active_shell_wallet_authority",
        "require_home_runtime_wallet_authority",
        1,
        mark("delegated", "Home shell token", "Home", "The active shell wallet path accepts the Home token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "require_home_active_shell_wallet_authority",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "shell app token", "shell", "The active shell wallet path accepts a shell app token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "stored_passkey_principal_context",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("home-own", "passkey principal", "person", "A passkey authorize check rebuilds the stored principal"),
    ),
    row(
        "elastos-server/src/api/gateway_home_system.rs",
        "system_summary",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "System launch token", "system", "The System summary requires the System launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "home_launch_context",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "verified wallet context", "checked app", "A verified wallet authority copies its launch context"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_agent_launch_token_with_context",
        "issue_home_launch_token_at",
        1,
        mark("delegated", "short agent grant", "owner", "The agent issuer signs a grant of at most 60 seconds"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_launch_token_at",
        "load_or_create_did",
        1,
        mark("home-own", "single device signer", "Home", "Every launch token is signed by this device key"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_launch_token_for_auth_grant",
        "issue_home_launch_token_for_verified_grant",
        1,
        mark("delegated", "grant.apps-gated mint", "person", "The auth-grant issuer checks the grant before it signs"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_launch_token_for_verified_grant",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "grant context", "person", "The verified-grant issuer binds the token to the grant"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_launch_token_for_verified_grant",
        "issue_home_launch_token_at",
        1,
        mark("delegated", "grant.apps-gated mint", "person", "The verified-grant issuer signs only an app the grant names"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_launch_token_with_context",
        "issue_home_launch_token_at",
        1,
        mark("open-latent", "caller-named app token", "caller-named app", "This issuer has no grant.apps check; its only production caller restricts the app to home and home-cli"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_home_projection_launch_token_with_context",
        "issue_home_launch_token_at",
        1,
        mark("home-own", "home-authority projection", "app executor", "Home signs a projection whose authorizing actor is home"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_launch_page_token",
        "issue_home_launch_token_at",
        1,
        mark("delegated", "launch-bound page token", "content page", "A page token is bound to one launch, one content item, and one binding"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_local_runtime_home_launch_token",
        "issue_home_launch_token_with_context",
        1,
        mark("narrowed", "home and home-cli token", "device", "The device mint signs a token only for home and home-cli"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "issue_local_runtime_home_launch_token",
        "local_home_launch_token_context",
        1,
        mark("narrowed", "device launch context", "home and home-cli", "The device mint loads a device context only after the app is home or home-cli"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "local_home_launch_token_context",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("open", "device launch context", "Home device", "The device context is built with no grant, passkey, or page origin"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "local_home_launch_token_context",
        "load_or_create_did",
        1,
        mark("open", "device DID root", "Home device", "The device DID is the principal root of the device context; its only production caller uses that context for home and home-cli"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "resolved",
        "HomeLaunchTokenContext {",
        1,
        mark("delegated", "resolved launch context", "caller", "The constructor stores the root its caller already resolved"),
    ),
    row(
        "elastos-server/src/api/gateway_home_token.rs",
        "verify_home_launch_token_value",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "verified token context", "token principal", "Verification rebuilds the context the token already carries"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_approval_complete",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "Completing a connector approval requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_approval_handoff",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "A connector handoff requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_bitcoin_link_challenge",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "A Bitcoin connector challenge requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_bitcoin_link_verify",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "A Bitcoin connector verify requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_evm_link_challenge",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "An EVM connector challenge requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "home_wallet_connector_evm_link_verify",
        "require_home_wallet_connector_authority",
        1,
        mark("delegated", "connector token", "person", "An EVM connector verify requires the person's connector authority"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "require_home_wallet_connector_authority",
        "require_carried_home_launch_token",
        1,
        mark("delegated", "connector app token", "connector", "The connector checks the carried token of the connector app"),
    ),
    row(
        "elastos-server/src/api/gateway_home_wallet_connector.rs",
        "require_home_wallet_connector_authority",
        "require_home_runtime_wallet_authority",
        1,
        mark("delegated", "Home wallet token", "Home", "The connector checks the Home launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_inbox.rs",
        "inbox_summary",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "Inbox launch token", "inbox", "The Inbox summary requires the Inbox launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_model_service.rs",
        "remote_context",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "remote caller context", "calling principal", "A remote model call rebuilds the caller's context"),
    ),
    row(
        "elastos-server/src/api/gateway_passkey_step_up.rs",
        "complete_step_up",
        "issue_step_up_token",
        1,
        mark("home-own", "admin step-up", "admin", "Completing step-up mints a non-delegatable admin token"),
    ),
    row(
        "elastos-server/src/api/gateway_passkey_step_up.rs",
        "issue_step_up_token",
        "load_or_create_did",
        1,
        mark("home-own", "device signer", "admin", "The step-up token is signed by this device and cannot be delegated"),
    ),
    row(
        "elastos-server/src/api/gateway_passkey_step_up.rs",
        "passkey_step_up_begin_inner",
        "require_carried_home_launch_token",
        1,
        mark("delegated", "carried launch token", "admin", "Beginning step-up requires the carried launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_provider_proxy.rs",
        "bus_model_provider_request",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "caller grant", "calling app", "The Bus model request resolves the caller's launch context"),
    ),
    row(
        "elastos-server/src/api/gateway_provider_proxy.rs",
        "normalize_model_provider_request",
        "RuntimeAccessBinding {",
        2,
        mark("delegated", "caller grant", "calling app", "The model proxy builds an access binding from the caller's grant"),
    ),
    row(
        "elastos-server/src/api/gateway_provider_proxy.rs",
        "normalize_model_provider_request",
        "RuntimeCreateBinding {",
        1,
        mark("delegated", "caller grant", "calling app", "The model proxy builds a create binding from the caller's grant"),
    ),
    row(
        "elastos-server/src/api/gateway_transaction_effects.rs",
        "transaction_chain_data",
        "HomeLaunchTokenContext::resolved",
        1,
        mark("delegated", "browser launch context", "browser", "A browser chain read keeps the browser launch that requested it"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_accounts.rs",
        "system_wallet_default_update",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "System launch token", "system", "A system wallet change requires the System launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_accounts.rs",
        "system_wallet_managed_create",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "System launch token", "system", "Creating a managed wallet requires the System launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_approvals.rs",
        "system_wallet_approval_reject",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "System launch token", "system", "Rejecting a wallet approval requires the System launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_approvals.rs",
        "system_wallet_approvals",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "System launch token", "system", "Listing wallet approvals requires the System launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_connectors.rs",
        "require_wallet_app_launch_authority",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "wallet app token", "wallet", "A wallet app route requires the Wallet launch token"),
    ),
    row(
        "elastos-server/src/api/gateway_wallet_connectors.rs",
        "require_wallet_connector_launch_authority",
        "require_runtime_wallet_authority",
        1,
        mark("delegated", "connector token", "connector", "A connector route requires that connector's launch token"),
    ),
    row(
        "elastos-server/src/api/handlers/capability.rs",
        "grant_request",
        "capability_manager.grant",
        1,
        mark("runtime-own", "capsule capability", "capsule", "The capability route grants a capsule token"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "delete_hosted_secret",
        "hosted_secret_path",
        1,
        mark("home-own", "hosted key file", "model provider", "Home deletes a hosted model key it keeps"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "hosted_key_for_save",
        "read_hosted_secret",
        1,
        mark("home-own", "hosted key", "model provider", "Home reads a hosted key while saving an offer"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "read_hosted_secret",
        "hosted_secret_path",
        1,
        mark("home-own", "hosted key file", "model provider", "Home locates the hosted key file it keeps"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "save_hosted_offer",
        "write_hosted_secret",
        1,
        mark("home-own", "hosted key custody", "model provider", "Home stores the key for a hosted offer"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "store_operator_offer_secret",
        "write_hosted_secret",
        1,
        mark("home-own", "hosted key custody", "model provider", "Home stores an operator offer key"),
    ),
    row(
        "elastos-server/src/api/model_provider_config.rs",
        "write_hosted_secret",
        "hosted_secret_path",
        1,
        mark("home-own", "hosted key file", "model provider", "Home writes the hosted key file it keeps"),
    ),
    row(
        "elastos-server/src/api/model_provider_egress.rs",
        "fetch_validation_inner",
        "bearer_auth",
        1,
        mark("home-own", "validation credential", "model provider", "Home adds the hosted credential while it checks an offer"),
    ),
    row(
        "elastos-server/src/api/model_provider_egress.rs",
        "forward",
        "bearer_auth",
        1,
        mark("home-own", "upstream credential", "model provider", "Home adds the hosted credential on upstream egress"),
    ),
    row(
        "elastos-server/src/api/model_provider_egress.rs",
        "resolve_effect",
        "read_hosted_secret",
        1,
        mark("home-own", "egress credential", "model provider", "Home reads the hosted credential for egress"),
    ),
    row(
        "elastos-server/src/api/model_provider_egress.rs",
        "saved_connection_state",
        "read_hosted_secret",
        1,
        mark("home-own", "egress credential", "model provider", "Home reads the hosted credential for a saved connection"),
    ),
    row(
        "elastos-server/src/api/routes.rs",
        "kept_launch_content",
        "read_kept_launch",
        1,
        mark("delegated", "kept launch content", "page owner", "The page route serves kept launch content to the page owner"),
    ),
    row(
        "elastos-server/src/api/routes.rs",
        "kept_launch_output",
        "read_kept_launch",
        1,
        mark("delegated", "kept launch output", "page owner", "The page route serves kept launch output to the page owner"),
    ),
    row(
        "elastos-server/src/api/routes.rs",
        "kept_launch_page_file",
        "read_kept_page_file",
        1,
        mark("delegated", "kept page file", "page owner", "The page route serves a kept page file to the page owner"),
    ),
    row(
        "elastos-server/src/api/viewer_gateway.rs",
        "home_launch_content",
        "issue_launch_page_token",
        1,
        mark("delegated", "content page token", "page", "Home mints a page token bound to the opened content"),
    ),
    row(
        "elastos-server/src/api/viewer_gateway.rs",
        "open_at_runtime",
        "issue_home_projection_launch_token_with_context",
        1,
        mark("delegated", "home and home-shell grant", "Home page", "Content open asks the Runtime with a home-shell projection of a proof-bound context"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "arm_owner_enrollment",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home owner", "Owner enrollment is signed by this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "begin_owner_enrollment_with_intent",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home owner", "Owner enrollment is signed by this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "check_owner_claim",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home owner", "An owner claim is checked against this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "commit_recovered_root_reassignment",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "recovered person", "A recovered root is signed by this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "load_audit_chain_activation_unlocked",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain", "Home", "Home reads its audit chain with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "observe_runtime_device_key_file_identity",
        "device_key_path",
        1,
        mark("home-own", "device key file", "Home", "Home watches the device key file so a changed key drops the cached auth state"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "persist_audit_chain_activation_unlocked",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain", "Home", "Home writes its audit chain with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "sign_audit_chain_anchor",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain signature", "Home", "Home signs an audit-chain anchor with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "sign_audit_chain_link",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain signature", "Home", "Home signs an audit-chain link with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "sign_audit_chain_state",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain signature", "Home", "Home signs audit-chain state with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "sign_audit_event",
        "load_or_create_did",
        1,
        mark("home-own", "audit event signature", "Home", "Home signs an audit event with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "verify_audit_chain_from",
        "load_or_create_did",
        1,
        mark("home-own", "audit chain check", "Home", "Home checks its audit chain with this device"),
    ),
    row(
        "elastos-server/src/auth.rs",
        "verify_signed_full_recovery_outcome_audit_event",
        "load_or_create_did",
        1,
        mark("home-own", "recovery audit check", "Home", "Home checks a recovery audit event with this device"),
    ),
    row(
        "elastos-server/src/carrier_exit.rs",
        "sign_service_message",
        "load_existing_device_signing_key",
        1,
        mark("home-own", "Home network identity", "Home", "Carrier exit signs with this device"),
    ),
    row(
        "elastos-server/src/collaboration_presence_grant.rs",
        "set_presence_grant",
        "capability_manager.grant",
        1,
        mark("delegated", "presence capability", "person", "A presence answer mints a capability for that person"),
    ),
    row(
        "elastos-server/src/collaboration_profile_authority.rs",
        "load_existing_device_did",
        "load_existing_device_signing_key",
        1,
        mark("home-own", "profile DID", "Home", "The profile authority reads this device's signing key"),
    ),
    row(
        "elastos-server/src/content.rs",
        "attach_signed_fetch_receipt_set",
        "load_or_create_did",
        1,
        mark("home-own", "content fetch receipt", "Home", "Home signs a content fetch receipt with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "attach_signed_rows",
        "load_or_create_did",
        1,
        mark("home-own", "content receipt rows", "Home", "Home signs content receipt rows with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "effective_publisher_did",
        "load_or_create_did",
        1,
        mark("home-own", "publisher DID", "Home", "Home names itself as publisher with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "settle_distinct_holder_success",
        "load_or_create_did",
        1,
        mark("home-own", "holder settlement receipt", "Home", "Home signs a holder settlement with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "sign_admission_receipt",
        "load_or_create_did",
        1,
        mark("home-own", "admission receipt", "Home", "Home signs an admission receipt with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "sign_federated_abuse_control_exchange_request",
        "load_or_create_did",
        1,
        mark("home-own", "federated abuse exchange", "Home", "Home signs a federated abuse exchange with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "sign_federated_quota_ledger_exchange_request",
        "load_or_create_did",
        1,
        mark("home-own", "federated quota exchange", "Home", "Home signs a federated quota exchange with this device"),
    ),
    row(
        "elastos-server/src/content.rs",
        "write_receipt",
        "load_or_create_did",
        1,
        mark("home-own", "content receipt", "Home", "Home signs a content receipt with this device"),
    ),
    row(
        "elastos-server/src/documents.rs",
        "documents_create_local",
        "load_or_create_did",
        1,
        mark("home-own", "record owner DID", "Documents", "Documents stamps a new record with this device's DID"),
    ),
    row(
        "elastos-server/src/documents.rs",
        "documents_import_chat_attachment_local",
        "load_or_create_did",
        1,
        mark("home-own", "record owner DID", "Documents", "Documents stamps an imported attachment with this device's DID"),
    ),
    row(
        "elastos-server/src/documents.rs",
        "documents_save_as_local",
        "load_or_create_did",
        1,
        mark("home-own", "record owner DID", "Documents", "Documents stamps a saved record with this device's DID"),
    ),
    row(
        "elastos-server/src/home_cmd.rs",
        "gather_snapshot_from_parts",
        "load_existing_did",
        1,
        mark("home-own", "device DID", "Home CLI", "The CLI snapshot reads this device's DID when no projection names one"),
    ),
    row(
        "elastos-server/src/home_cmd.rs",
        "home_cli_invoke_principal",
        "load_or_create_did",
        1,
        mark("home-own", "device principal", "Home CLI", "A standalone CLI invoke names this device as its principal"),
    ),
    row(
        "elastos-server/src/home_cmd.rs",
        "issue_capsule_launch_token",
        "issue_gateway_owned_home_cli_launch_token",
        1,
        mark("delegated", "gateway-owned env token", "the grant's person", "The CLI tries the gateway-owned env path first, and that path mints only after a live grant is checked"),
    ),
    row(
        "elastos-server/src/home_cmd.rs",
        "issue_capsule_launch_token",
        "issue_local_runtime_home_launch_token",
        1,
        mark("narrowed", "standalone device fallback", "home and home-cli", "Without the gateway-owned grant the CLI mints a device token only for home and home-cli"),
    ),
    row(
        "elastos-server/src/home_cmd.rs",
        "load_existing_did",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "The CLI summary reads this device's DID"),
    ),
    row(
        "elastos-server/src/identity_cmd.rs",
        "load_identity_profile",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "The identity command reads this device's DID"),
    ),
    row(
        "elastos-server/src/operator_control.rs",
        "approve_local_room_request",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "Operator approval signs as this device"),
    ),
    row(
        "elastos-server/src/operator_control.rs",
        "deny_local_room_request",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "Operator denial signs as this device"),
    ),
    row(
        "elastos-server/src/operator_control.rs",
        "gather_local_node_status",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "Operator status reads this device's DID"),
    ),
    row(
        "elastos-server/src/operator_control.rs",
        "handle_operator_stream",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "The operator stream signs as this device"),
    ),
    row(
        "elastos-server/src/operator_control.rs",
        "request_remote_typed_with_args",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "A remote operator request signs as this device"),
    ),
    row(
        "elastos-server/src/page_launch.rs",
        "open_for_page",
        "take_place",
        1,
        mark("delegated", "kept capsule handle", "page owner", "Home takes a bounded place for the page owner"),
    ),
    row(
        "elastos-server/src/protected_content_config.rs",
        "provision_custody_node_with_installed_provider",
        "require_isolated_provider",
        1,
        mark("dkm", "custody isolation", "custody provider", "Provisioning a custody node asks for an isolated provider"),
    ),
    row(
        "elastos-server/src/protected_content_config.rs",
        "run_protected_content_config_command_with_writer",
        "device_key_path",
        1,
        mark("dkm", "device key file", "custody", "Showing the Runtime issuer locates this device key file"),
    ),
    row(
        "elastos-server/src/protected_content_config.rs",
        "run_protected_content_config_command_with_writer",
        "load_or_create_device_key",
        1,
        mark("dkm", "runtime issuer", "custody", "Showing the Runtime issuer reads this device key"),
    ),
    row(
        "elastos-server/src/protected_content_config.rs",
        "run_protected_content_config_command_with_writer",
        "read_policy_authority_key",
        1,
        mark("dkm", "custody policy key", "custody nodes", "Custody composition reads the policy authority key"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "assemble_protected_content_runtime_release_operation",
        "load_existing_device_signing_key",
        1,
        mark("dkm", "release signer", "viewer", "A protected-content release is signed by this device key"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "cancel_prepared_recipient",
        "invoke_decrypt_provider",
        1,
        mark("dkm", "decrypt call", "viewer", "The viewer cancels a prepared recipient through the decrypt provider"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "close_viewer_session",
        "invoke_decrypt_provider",
        1,
        mark("dkm", "decrypt call", "viewer", "The viewer closes a session through the decrypt provider"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "load_existing_device_signing_key",
        1,
        mark("dkm", "open signer", "viewer", "Opening the custody viewer is signed by this device key"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "open_viewer_session",
        "invoke_decrypt_provider",
        1,
        mark("dkm", "decrypt call", "viewer", "The viewer opens a session through the decrypt provider"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "prepare_recipient",
        "invoke_decrypt_provider",
        1,
        mark("dkm", "decrypt call", "viewer", "The viewer prepares a recipient through the decrypt provider"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "publish_runtime_custody_library_object",
        "load_existing_device_signing_key",
        1,
        mark("dkm", "publish signer", "protected content", "Publishing protected content is signed by this device key"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "read_viewer_media_part",
        "invoke_decrypt_provider",
        1,
        mark("dkm", "decrypt call", "viewer", "The viewer reads media through the decrypt provider"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "register_inactive_custody_provider",
        "require_isolated_provider",
        1,
        mark("dkm", "custody spawn", "custody provider", "The custody provider is spawned through the generic bridge"),
    ),
    row(
        "elastos-server/src/protected_content_runtime.rs",
        "register_protected_content_decrypt_provider",
        "require_isolated_provider",
        1,
        mark("dkm", "decrypt spawn", "decrypt provider", "The decrypt provider is spawned through the generic bridge"),
    ),
    row(
        "elastos-server/src/provider_host.rs",
        "compose",
        "load_or_create_device_key",
        1,
        mark("home-own", "provider-host DID", "provider host", "this is the host's Carrier identity, the same `derive_did` the Home server already owns. The raw key is not copied into a child config."),
    ),
    row(
        "elastos-server/src/resource_bridge.rs",
        "dispatch_agent_plan_step",
        "capability_manager.grant",
        1,
        mark("runtime-own", "plan-step capability", "capsule", "The bridge grants the approved plan step"),
    ),
    row(
        "elastos-server/src/resource_bridge.rs",
        "dispatch_agent_plan_step",
        "encode_bridge_capability_token",
        1,
        mark("runtime-own", "bridge capability", "capsule", "The bridge encodes the plan-step capability"),
    ),
    row(
        "elastos-server/src/resource_bridge.rs",
        "handle_request",
        "capability_manager.grant",
        1,
        mark("runtime-own", "launch capability", "capsule", "The bridge grants a launch-bound capability"),
    ),
    row(
        "elastos-server/src/resource_bridge.rs",
        "handle_request",
        "encode_bridge_capability_token",
        2,
        mark("runtime-own", "bridge capability", "capsule", "The bridge encodes launch-bound capabilities"),
    ),
    row(
        "elastos-server/src/resource_bridge.rs",
        "reserve_model_create",
        "RuntimeCreateBinding {",
        1,
        mark("delegated", "caller capability", "calling capsule", "A model run binding is built from the caller's capability token"),
    ),
    row(
        "elastos-server/src/room_service.rs",
        "load_local_room_signing_authority",
        "load_existing_device_signing_key",
        1,
        mark("home-own", "room signing key", "Home", "Room service signs with this device"),
    ),
    row(
        "elastos-server/src/runtime.rs",
        "start_by_bundle",
        "LaunchHeld::new",
        1,
        mark("delegated", "launch handle", "launching app", "Home holds the launch handle until the start ends"),
    ),
    row(
        "elastos-server/src/runtime_control.rs",
        "ensure_managed_runtime",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "A managed runtime uses this device's DID"),
    ),
    row(
        "elastos-server/src/security_cmd.rs",
        "run_emergency",
        "CapabilityManager::load_or_generate",
        1,
        mark("runtime-own", "capability signer", "Runtime", "Emergency control loads the Runtime capability signer"),
    ),
    row(
        "elastos-server/src/localhost_file_migration.rs",
        "localhost_provider_bridge_config",
        "encryption_key: device_key_hex",
        1,
        mark("open", "device private key", "localhost provider", "On Unix the encryption field is the HKDF file key `elastos-localhost-file-v1`, not the raw device key. On Windows the field is still the device key, because this slice does not rewrite files there. The object config no longer carries the device key. The localhost child is unconfined and `base_path` is the data directory, so it can open `identity/device.key`. The object process has that same file-read. The row stays open until slice C."),
    ),
    row(
        "elastos-server/src/server_infra.rs",
        "register_chain_provider_plane",
        "load_or_create_device_key",
        1,
        mark("open", "device private key", "chain provider", "The child config now carries only the Ed25519 verifying key of `derive_did(device_key)`, which `RuntimeOperationIssuerKeyV1` accepts only as a public key. The row stays open: the child is an unconfined same-user process and the data directory is a fixed default, so it can still open `identity/device.key`, as the object provider can. It closes when slice C confines it."),
    ),
    row(
        "elastos-server/src/server_infra.rs",
        "setup_server_infrastructure_impl",
        "CapabilityManager::load_or_generate",
        1,
        mark("runtime-own", "capability signer", "Runtime", "Home startup loads the Runtime capability signer"),
    ),
    row(
        "elastos-server/src/server_infra.rs",
        "setup_server_infrastructure_impl",
        "load_or_create_device_key",
        1,
        mark("home-own", "Carrier and issuer", "Home", "Home derives its Carrier identity and runtime issuer from the device key"),
    ),
    row(
        "elastos-server/src/server_infra.rs",
        "did_provider_bridge_config",
        "encryption_key: device_key_hex",
        1,
        mark("narrowed", "device private key", "DID provider", "DID provider receives the existing device signing seed and the existing `elastos-did-storage` key. It does not receive the raw device key. It can still sign chat as the device."),
    ),
    row(
        "elastos-server/src/server_infra.rs",
        "wallet_provider_bridge_config",
        "encryption_key: device_key_hex",
        1,
        mark("narrowed", "device private key", "wallet provider", "wallet storage key is the random `wallet-key.hex`; the confined process is not given the device key."),
    ),
    row(
        "elastos-server/src/sources.rs",
        "local_session_owner",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "A local session's owner is this device"),
    ),
    row(
        "elastos-server/src/trust_cmd.rs",
        "run_keys",
        "load_or_create_did",
        1,
        mark("home-own", "device DID", "Home", "The trust command reads this device's DID"),
    ),
    ]
}

fn call(parts: &[&str]) -> (String, String) {
    let label = parts.concat();
    let needle = format!("{label}(");
    (label, needle)
}

fn text(parts: &[&str]) -> (String, String) {
    let label = parts.concat();
    (label.clone(), label)
}

/// Every mechanism the census counts. The pieces are joined only at run time.
fn needles() -> Vec<(String, String)> {
    vec![
        call(&["issue_home_", "launch_token_at"]),
        call(&["issue_home_", "launch_token_with_context"]),
        call(&["issue_home_", "launch_token_for_auth_grant"]),
        call(&["issue_home_", "launch_token_for_verified_grant"]),
        call(&["issue_home_", "projection_launch_token_with_context"]),
        call(&["issue_home_", "agent_launch_token_with_context"]),
        call(&["issue_local_", "runtime_home_launch_token"]),
        call(&["issue_gateway_owned_", "home_cli_launch_token"]),
        call(&["issue_", "launch_page_token"]),
        call(&["issue_", "step_up_token"]),
        call(&["local_home_", "launch_token_context"]),
        call(&["HomeLaunchTokenContext::", "resolved"]),
        text(&["HomeLaunchTokenContext", " {"]),
        text(&["Runtime", "CreateBinding {"]),
        text(&["Runtime", "AccessBinding {"]),
        call(&["require_carried_", "home_launch_token"]),
        call(&["require_", "runtime_wallet_authority"]),
        call(&["require_home_", "runtime_wallet_authority"]),
        call(&["require_home_", "wallet_connector_authority"]),
        text(&["encryption_key: ", "device_key_hex"]),
        call(&["read_", "hosted_secret"]),
        call(&["write_", "hosted_secret"]),
        call(&["hosted_", "secret_path"]),
        call(&["bearer_", "auth"]),
        call(&["read_", "policy_authority_key"]),
        call(&["require_", "isolated_provider"]),
        call(&["invoke_", "decrypt_provider"]),
        call(&["CapabilityManager::", "load_or_generate"]),
        (
            ["capability_manager", ".grant"].concat(),
            [".grant", "("].concat(),
        ),
        call(&["encode_bridge_", "capability_token"]),
        call(&["LaunchHeld::", "new"]),
        call(&["take_", "place"]),
        call(&["read_kept_", "launch"]),
        call(&["read_kept_", "page_file"]),
        call(&["load_or_", "create_did"]),
        call(&["load_existing_", "did"]),
        call(&["load_existing_", "device_signing_key"]),
        call(&["load_or_", "create_device_key"]),
        call(&["device_key_", "path"]),
        (
            ["*", "_with_device_key"].concat(),
            ["_with_device_key", "("].concat(),
        ),
    ]
}

/// `load_or_generate` signs with these literals. They are counted only in the
/// capability manager, because a tree-wide signing-key scan is another inventory.
fn signing_literals() -> Vec<(String, String)> {
    vec![
        call(&["SigningKey::", "from_bytes"]),
        call(&["SigningKey::", "generate"]),
    ]
}

fn sources() -> &'static BTreeMap<String, String> {
    use std::sync::OnceLock;
    static SOURCES: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    SOURCES.get_or_init(source::production_sources)
}

fn device_key_labels() -> BTreeSet<String> {
    [
        ["load_or_", "create_did"].concat(),
        ["load_existing_", "did"].concat(),
        ["load_existing_", "device_signing_key"].concat(),
        ["load_or_", "create_device_key"].concat(),
        ["device_key_", "path"].concat(),
    ]
    .into_iter()
    .collect()
}

fn is_device_key_mechanism(label: &str) -> bool {
    device_key_labels().contains(label) || label.ends_with("_with_device_key")
}

struct FnBody {
    name: String,
    start: usize,
    end: usize,
}

/// The `{` of a function body, or the `;` of a body-less declaration.
/// Parentheses and brackets stay nested, so `[u8; 32]` does not end the signature.
fn body_open(code: &str, from: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    let mut round = 0i32;
    let mut square = 0i32;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => round += 1,
            b')' => round -= 1,
            b'[' => square += 1,
            b']' => square -= 1,
            b'{' if round == 0 && square == 0 => return Some(i),
            b';' if round == 0 && square == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn function_bodies(code: &str) -> Vec<FnBody> {
    let bytes = code.as_bytes();
    let mut bodies = Vec::new();
    let mut at = 0;
    while let Some(rel) = code[at..].find("fn ") {
        let pos = at + rel;
        if pos > 0 {
            let prev = bytes[pos - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                at = pos + 3;
                continue;
            }
        }
        let name_start = pos + 3;
        let name_len = code[name_start..]
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if name_len == 0 {
            at = pos + 3;
            continue;
        }
        let name_end = name_start + name_len;
        if !matches!(bytes.get(name_end), Some(b'(' | b'<')) {
            at = name_end;
            continue;
        }
        // A semicolon inside `[u8; 32]` is not the end of the signature.
        let Some(open) = body_open(code, name_end) else {
            break;
        };
        if bytes[open] != b'{' {
            at = open + 1;
            continue;
        }
        let mut depth = 0usize;
        let mut close = None;
        for (offset, byte) in bytes[open..].iter().enumerate() {
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
        let Some(end) = close else {
            break;
        };
        bodies.push(FnBody {
            name: code[name_start..name_end].to_string(),
            start: open,
            end,
        });
        at = name_end;
    }
    bodies
}

fn enclosing_function(bodies: &[FnBody], at: usize) -> &str {
    bodies
        .iter()
        .filter(|body| body.start < at && at < body.end)
        .min_by_key(|body| body.end - body.start)
        .map(|body| body.name.as_str())
        .unwrap_or("")
}

fn counts_as_site(code: &str, at: usize) -> bool {
    let bytes = code.as_bytes();
    if at > 0 {
        let prev = bytes[at - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return false;
        }
    }
    !(at >= 3 && &code[at - 3..at] == "fn ")
}

fn add_site(
    found: &mut BTreeMap<(String, String, String), usize>,
    file: &str,
    bodies: &[FnBody],
    at: usize,
    label: &str,
) {
    let function = enclosing_function(bodies, at);
    *found
        .entry((file.to_string(), function.to_string(), label.to_string()))
        .or_default() += 1;
}

fn capability_grant_label() -> String {
    ["capability_manager", ".grant"].concat()
}

fn device_key_family_needle() -> String {
    ["_with_device_key", "("].concat()
}

fn context_literal_label() -> String {
    ["HomeLaunchTokenContext", " {"].concat()
}

fn preceded_by_arrow(code: &str, at: usize) -> bool {
    let bytes = code.as_bytes();
    let mut end = at;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end >= 2 && &code[end - 2..end] == "->"
}

/// A capability grant is any `.grant(` with arguments. The receiver may be an
/// identifier or a method call. A line break before the dot does not matter.
/// A zero-argument `.grant()` is a getter, not this grant.
fn record_capability_grants(
    found: &mut BTreeMap<(String, String, String), usize>,
    file: &str,
    code: &str,
    bodies: &[FnBody],
    label: &str,
) {
    let needle = [".grant", "("].concat();
    let mut from = 0;
    while let Some(rel) = code[from..].find(&needle) {
        let dot = from + rel;
        let after = dot + needle.len();
        from = after;
        if source::receiver_before(code, dot).is_empty() && !method_call_receiver(code, dot) {
            continue;
        }
        if code[after..].trim_start().starts_with(')') {
            continue;
        }
        add_site(found, file, bodies, dot, label);
    }
}

/// The character before `dot`, after whitespace, closes a call.
fn method_call_receiver(code: &str, dot: usize) -> bool {
    let bytes = code.as_bytes();
    let mut end = dot;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end > 0 && bytes[end - 1] == b')'
}

/// Every call whose name ends in `_with_device_key`. The mechanism is that
/// full name, so a new function in the family is its own row.
fn record_device_key_family(
    found: &mut BTreeMap<(String, String, String), usize>,
    file: &str,
    code: &str,
    bodies: &[FnBody],
) {
    let marker = device_key_family_needle();
    let suffix_len = ["_with_device_key"].concat().len();
    let bytes = code.as_bytes();
    for (at, _) in code.match_indices(&marker) {
        let mut start = at;
        while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            start -= 1;
        }
        if !counts_as_site(code, start) {
            continue;
        }
        add_site(found, file, bodies, start, &code[start..at + suffix_len]);
    }
}

/// A `HomeLaunchTokenContext { ... }` value, including `Self { ... }` inside
/// `impl HomeLaunchTokenContext`. A struct or impl declaration, and a function
/// whose return type is that name, are not constructions.
fn record_context_literals(
    found: &mut BTreeMap<(String, String, String), usize>,
    file: &str,
    code: &str,
    bodies: &[FnBody],
    label: &str,
) {
    let name = label.trim_end_matches([' ', '{']);
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(rel) = code[from..].find(name) {
        let at = from + rel;
        let after = at + name.len();
        from = after;
        if bytes
            .get(after)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            continue;
        }
        if !counts_as_site(code, at) {
            continue;
        }
        if !code[after..].trim_start().starts_with('{') {
            continue;
        }
        let before = source::receiver_before(code, at);
        if matches!(before, "struct" | "impl" | "enum" | "trait") || preceded_by_arrow(code, at) {
            continue;
        }
        add_site(found, file, bodies, at, label);
    }
    record_context_self_literals(found, file, code, bodies, label);
}

/// `Self { ... }` inside `impl HomeLaunchTokenContext` is that same construction.
fn record_context_self_literals(
    found: &mut BTreeMap<(String, String, String), usize>,
    file: &str,
    code: &str,
    bodies: &[FnBody],
    label: &str,
) {
    let header = ["impl ", "HomeLaunchTokenContext"].concat();
    let mut from = 0;
    while let Some(rel) = code[from..].find(&header) {
        let at = from + rel;
        let after_name = at + header.len();
        from = after_name;
        if !counts_as_site(code, at + 5) {
            continue;
        }
        if code
            .as_bytes()
            .get(after_name)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            continue;
        }
        let Some(open_rel) = code[after_name..].find(|ch: char| !ch.is_ascii_whitespace()) else {
            break;
        };
        let open = after_name + open_rel;
        if code.as_bytes()[open] != b'{' {
            continue;
        }
        let Some(end) = matching_brace_end(code, open) else {
            break;
        };
        from = end;
        let mut inner = open + 1;
        while inner < end {
            let Some(rel) = code[inner..end].find("Self") else {
                break;
            };
            let self_at = inner + rel;
            inner = self_at + 4;
            if !counts_as_site(code, self_at) {
                continue;
            }
            if code
                .as_bytes()
                .get(self_at + 4)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                continue;
            }
            if !code[self_at + 4..end].trim_start().starts_with('{') {
                continue;
            }
            if preceded_by_arrow(code, self_at) {
                continue;
            }
            add_site(found, file, bodies, self_at, label);
        }
    }
}

fn matching_brace_end(code: &str, open: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn sites_in(
    file: &str,
    raw: &str,
    needles: &[(String, String)],
) -> BTreeMap<(String, String, String), usize> {
    let code = source::code_only(raw);
    let bodies = function_bodies(&code);
    let mut found = BTreeMap::new();
    let grant_label = capability_grant_label();
    let family_needle = device_key_family_needle();
    let literal_label = context_literal_label();
    for (label, needle) in needles {
        if label == &grant_label {
            record_capability_grants(&mut found, file, &code, &bodies, label);
            continue;
        }
        if needle == &family_needle {
            record_device_key_family(&mut found, file, &code, &bodies);
            continue;
        }
        if label == &literal_label {
            record_context_literals(&mut found, file, &code, &bodies, label);
            continue;
        }
        for (at, _) in code.match_indices(needle.as_str()) {
            if !counts_as_site(&code, at) {
                continue;
            }
            add_site(&mut found, file, &bodies, at, label);
        }
    }
    found
}

fn found_sites(needles: &[(String, String)]) -> BTreeMap<(String, String, String), usize> {
    let mut found = BTreeMap::new();
    for (file, raw) in sources() {
        for (key, count) in sites_in(file, raw, needles) {
            *found.entry(key).or_default() += count;
        }
    }
    found
}

fn census_sites() -> BTreeMap<(String, String, String), usize> {
    let mut found = found_sites(&needles());
    let manager = "elastos-runtime/src/capability/manager.rs";
    if let Some(raw) = sources().get(manager) {
        for (key, count) in sites_in(manager, raw, &signing_literals()) {
            *found.entry(key).or_default() += count;
        }
    }
    found
}

fn row_map() -> BTreeMap<(String, String, String), usize> {
    let mut listed = BTreeMap::new();
    for row in rows() {
        let key = (
            row.file.to_string(),
            row.function.to_string(),
            row.mechanism.to_string(),
        );
        assert!(
            listed.insert(key.clone(), row.count).is_none(),
            "duplicate held-authority row: {key:?}"
        );
    }
    listed
}

fn dump_lines(found: &BTreeMap<(String, String, String), usize>) -> String {
    let mut lines = Vec::new();
    for ((file, function, mechanism), count) in found {
        lines.push(format!("{count}\t{file}\t{function}\t{mechanism}"));
    }
    lines.join("\n")
}

fn write_dump(found: &BTreeMap<(String, String, String), usize>) {
    let Ok(path) = std::env::var("HOME_HELD_AUTHORITY_DUMP") else {
        return;
    };
    std::fs::write(&path, dump_lines(found)).unwrap_or_else(|err| panic!("dump {path}: {err}"));
}

fn diff_sites(
    found: &BTreeMap<(String, String, String), usize>,
    listed: &BTreeMap<(String, String, String), usize>,
) -> (Vec<String>, Vec<String>) {
    let mut missing = Vec::new();
    let mut stale = Vec::new();
    for (key, count) in found {
        match listed.get(key) {
            Some(expected) if expected == count => {}
            Some(expected) => stale.push(format!("count {key:?}: found {count}, row {expected}")),
            None => missing.push(format!("{count}\t{}\t{}\t{}", key.0, key.1, key.2)),
        }
    }
    for (key, count) in listed {
        if !found.contains_key(key) {
            stale.push(format!("absent {count}\t{}\t{}\t{}", key.0, key.1, key.2));
        }
    }
    (missing, stale)
}

fn summary() -> String {
    let rows = rows();
    let open = rows.iter().filter(|row| row.status == "open").count();
    let dkm = rows.iter().filter(|row| row.status == "dkm").count();
    format!(
        "Home-held authority rows: {}, open: {open}, dkm: {dkm}",
        rows.len()
    )
}

#[test]
fn every_held_authority_site_has_a_row() {
    let found = census_sites();
    write_dump(&found);
    let listed = row_map();
    let (missing, stale) = diff_sites(&found, &listed);
    let line = summary();
    println!("{line}");
    assert!(
        missing.is_empty() && stale.is_empty(),
        "{line}\nmissing sites:\n{}\n\nstale rows:\n{}",
        missing.join("\n"),
        stale.join("\n")
    );
}

#[test]
fn every_device_key_signing_site_names_its_authority() {
    let needles: Vec<_> = needles()
        .into_iter()
        .filter(|(label, _)| is_device_key_mechanism(label))
        .collect();
    let found = found_sites(&needles);
    let mut listed = row_map();
    listed.retain(|key, _| is_device_key_mechanism(&key.2));
    let (missing, stale) = diff_sites(&found, &listed);
    assert!(
        missing.is_empty() && stale.is_empty(),
        "device-key signing sites\nmissing:\n{}\n\nstale:\n{}",
        missing.join("\n"),
        stale.join("\n")
    );
    for row in rows() {
        if is_device_key_mechanism(row.mechanism) {
            assert!(!row.authority.is_empty(), "{}", row.function);
            assert!(!row.behalf.is_empty(), "{}", row.function);
            assert!(!row.reason.is_empty(), "{}", row.function);
        }
    }
}

#[test]
fn open_rows_are_an_explicit_list() {
    let mut from_rows = BTreeSet::new();
    for row in rows() {
        if row.status == "open" {
            assert!(
                from_rows.insert((row.file, row.function, row.mechanism)),
                "duplicate open row {}::{}",
                row.function,
                row.mechanism
            );
        }
    }
    let listed: BTreeSet<_> = OPEN_ROWS.iter().copied().collect();
    assert_eq!(from_rows, listed, "open rows drifted from OPEN_ROWS");
}

#[test]
fn held_rows_name_a_decision() {
    const STATUSES: &[&str] = &[
        "home-own",
        "delegated",
        "runtime-own",
        "open",
        "open-latent",
        "narrowed",
        "dkm",
    ];
    for row in rows() {
        assert!(STATUSES.contains(&row.status), "{}", row.status);
        assert!(!row.authority.is_empty(), "{}", row.function);
        assert!(!row.behalf.is_empty(), "{}", row.function);
        assert!(!row.reason.is_empty(), "{}", row.function);
        assert!(row.count > 0, "{}", row.function);
        assert!(
            row.file.starts_with("elastos-server/src/")
                || row.file.starts_with("elastos-runtime/src/"),
            "{}",
            row.file
        );
    }
}

fn identifiers(code: &str) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut names = Vec::new();
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
        names.push(&code[start..at]);
    }
    names
}

fn function_raw_bodies<'a>(raw: &'a str, function: &str) -> Vec<&'a str> {
    let code = source::code_only(raw);
    debug_assert_eq!(code.len(), raw.len());
    function_bodies(&code)
        .into_iter()
        .filter(|body| body.name == function)
        .map(|body| &raw[body.start..body.end])
        .collect()
}

/// The custody functions already name these public types. A new name fails.
/// An open, open-latent, or narrowed row names none of them.
const DKM_KEY_SYMBOLS: &[(&str, &str, &str)] = &[
    (
        "elastos-server/src/protected_content_runtime.rs",
        "assemble_protected_content_runtime_release_operation",
        "RuntimeReleaseOperationStatementV1",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "assemble_protected_content_runtime_release_operation",
        "SignedRuntimeReleaseOperationV1",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "KeyReleaseRequestV1",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "RuntimeReleaseAuditIdV1",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "RuntimeReleaseCoordinator",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "RuntimeReleaseCoordinatorOutcome",
    ),
    (
        "elastos-server/src/protected_content_runtime.rs",
        "open_runtime_custody_viewer",
        "RuntimeReleaseTerminalResult",
    ),
];

#[test]
fn open_or_dkm_rows_name_no_key_material() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest.ancestors().nth(3).unwrap();
    let names = protected_names(repo);
    assert!(
        names.iter().all(|name| protected_symbol_name(name)),
        "protected name set drifted from its predicate"
    );
    let sources = sources();
    let mut open_hits = Vec::new();
    let mut dkm_hits = BTreeSet::new();
    for row in rows() {
        let watch_open = matches!(row.status, "open" | "open-latent" | "narrowed");
        if !watch_open && row.status != "dkm" {
            continue;
        }
        let Some(raw) = sources.get(row.file) else {
            open_hits.push(format!("missing source {}", row.file));
            continue;
        };
        let bodies = function_raw_bodies(raw, row.function);
        if bodies.is_empty() {
            open_hits.push(format!("missing function {}::{}", row.file, row.function));
            continue;
        }
        for body in bodies {
            let code = source::code_only(body);
            for ident in identifiers(&code) {
                if !names.contains(ident) {
                    continue;
                }
                if watch_open {
                    open_hits.push(format!("{}::{} names {ident}", row.file, row.function));
                } else {
                    dkm_hits.insert((
                        row.file.to_string(),
                        row.function.to_string(),
                        ident.to_string(),
                    ));
                }
            }
        }
    }
    open_hits.sort();
    open_hits.dedup();
    assert!(
        open_hits.is_empty(),
        "open row names protected key material:\n{}",
        open_hits.join("\n")
    );
    let expected: BTreeSet<_> = DKM_KEY_SYMBOLS
        .iter()
        .map(|(file, function, symbol)| {
            (
                (*file).to_string(),
                (*function).to_string(),
                (*symbol).to_string(),
            )
        })
        .collect();
    assert_eq!(
        dkm_hits, expected,
        "dkm key symbols drifted from the reviewed list"
    );
}

#[test]
fn scanner_counts_a_call_and_skips_its_definition() {
    let mint = ["issue_local_", "runtime_home_launch_token"].concat();
    let source = format!(
        "fn outer() {{\n    let brace = \"}}\";\n    fn inner() {{}}\n    {mint}(data);\n}}\nfn {mint}(data: &str) {{}}\n"
    );
    let found = sites_in("elastos-server/src/fixture.rs", &source, &needles());
    let key = (
        "elastos-server/src/fixture.rs".to_string(),
        "outer".to_string(),
        mint,
    );
    assert_eq!(found.get(&key).copied(), Some(1), "{found:?}");
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn scanner_keeps_a_call_inside_an_array_return_type() {
    let mint = ["SigningKey::", "generate"].concat();
    let source = format!("fn rotate(&mut self) -> [u8; 32] {{\n    {mint}(&mut rng);\n}}\n");
    let found = sites_in(
        "elastos-runtime/src/capability/manager.rs",
        &source,
        &signing_literals(),
    );
    let key = (
        "elastos-runtime/src/capability/manager.rs".to_string(),
        "rotate".to_string(),
        mint,
    );
    assert_eq!(found.get(&key).copied(), Some(1), "{found:?}");
}

#[test]
fn scanner_counts_a_capability_grant_with_any_receiver() {
    let source = "fn issue() {\n    manager.grant(a, b, c, d, e);\n    self.capability_manager\n        .grant(a, b, c, d, e);\n}\nfn read() {\n    let _ = held.grant();\n}\n";
    let found = sites_in("elastos-server/src/fixture.rs", source, &needles());
    let grant = capability_grant_label();
    let key = (
        "elastos-server/src/fixture.rs".to_string(),
        "issue".to_string(),
        grant,
    );
    assert_eq!(found.get(&key).copied(), Some(2), "{found:?}");
    assert!(found.keys().all(|key| key.1 != "read"), "{found:?}");
}

#[test]
fn scanner_counts_device_key_calls_and_a_context_literal() {
    let existing = ["load_existing_", "did"].concat();
    let path = ["device_key_", "path"].concat();
    let family = ["save_nickname", "_with_device_key"].concat();
    let literal = context_literal_label();
    let context = ["HomeLaunch", "TokenContext"].concat();
    let resolved = ["HomeLaunchTokenContext::", "resolved"].concat();
    let source = format!(
        "fn use_key(data: &Path) {{\n    {existing}(data);\n    let _ = {path}(data);\n    {family}(data, key, name);\n    let _ = {context} {{ session_id: id }};\n}}\nfn {existing}(data: &Path) {{}}\nfn make() -> {context} {{\n    {resolved}(a, b, c, d)\n}}\nstruct {context} {{ session_id: String }}\nimpl {context} {{ fn id(&self) {{}} }}\n"
    );
    let found = sites_in("elastos-server/src/fixture.rs", &source, &needles());
    let file = "elastos-server/src/fixture.rs";
    let hit = |function: &str, mechanism: &str| {
        (
            file.to_string(),
            function.to_string(),
            mechanism.to_string(),
        )
    };
    assert_eq!(
        found.get(&hit("use_key", &existing)).copied(),
        Some(1),
        "{found:?}"
    );
    assert_eq!(
        found.get(&hit("use_key", &path)).copied(),
        Some(1),
        "{found:?}"
    );
    assert_eq!(
        found.get(&hit("use_key", &family)).copied(),
        Some(1),
        "{found:?}"
    );
    assert_eq!(
        found.get(&hit("use_key", &literal)).copied(),
        Some(1),
        "{found:?}"
    );
    assert_eq!(
        found.get(&hit("make", &resolved)).copied(),
        Some(1),
        "{found:?}"
    );
    assert!(found.keys().all(|key| !key.1.is_empty()), "{found:?}");
    assert_eq!(found.len(), 5, "{found:?}");
}

#[test]
fn scanner_counts_a_grant_on_a_method_call_receiver() {
    let source = "fn issue() {\n    x.capability_manager().grant(a, b, c, d, e);\n}\nfn read() {\n    let _ = holder().grant();\n}\n";
    let found = sites_in("elastos-server/src/fixture.rs", source, &needles());
    let key = (
        "elastos-server/src/fixture.rs".to_string(),
        "issue".to_string(),
        capability_grant_label(),
    );
    assert_eq!(found.get(&key).copied(), Some(1), "{found:?}");
    assert!(found.keys().all(|key| key.1 != "read"), "{found:?}");
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn scanner_counts_self_construction_inside_home_launch_context_impl() {
    let context = ["HomeLaunch", "TokenContext"].concat();
    let literal = context_literal_label();
    let source = format!(
        "impl {context} {{\n    fn resolved() -> Self {{\n        Self {{ session_id: id }}\n    }}\n}}\nimpl Other {{\n    fn make() -> Self {{\n        Self {{}}\n    }}\n}}\n"
    );
    let found = sites_in("elastos-server/src/fixture.rs", &source, &needles());
    let key = (
        "elastos-server/src/fixture.rs".to_string(),
        "resolved".to_string(),
        literal,
    );
    assert_eq!(found.get(&key).copied(), Some(1), "{found:?}");
    assert!(found.keys().all(|key| key.1 != "make"), "{found:?}");
    assert_eq!(found.len(), 1, "{found:?}");
}
