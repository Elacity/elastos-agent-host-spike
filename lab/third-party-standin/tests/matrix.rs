//! Six-hook matrix for the lab stand-in.
//!
//! Each today-row asserts the behaviour this tree has now, so the lab is
//! green. A later slice that builds the hook makes that row fail, and the
//! row is then flipped. `p2_10_matrix_wanted` states the wanted behaviour
//! and is red today.
//!
//! Provider calls go through `ProviderRegistry::route` (`route_with_options`).
//! That is the registry's normal route. It reaches `Provider::handle` only
//! after it has a provider. These tests do not call the raw provider send
//! on a product provider.

mod common;

use std::sync::Arc;

use elastos_common::{AffordanceApprovalMode, AskAction};
use elastos_runtime::provider::{ProviderError, ProviderRegistry, ResourceAction};
use serde_json::Value;

use common::{
    answer, app_name, assert_base58_vectors, item_body, join, load_manifest, scheme, server_file,
    user_approval_method, verify_signed, walk_text_files, MarkerProvider,
};

fn rows_table() -> Value {
    serde_json::from_str(&common::read_text(
        &common::manifest_dir().join("fixtures/rows.json"),
    ))
    .expect("rows table")
}

fn provider_operations() -> Vec<String> {
    let manifest = load_manifest("provider");
    manifest
        .authority
        .expect("provider authority")
        .capabilities
        .into_iter()
        .next()
        .expect("one capability")
        .operations
}

#[test]
fn base58_vectors_match_the_known_answers() {
    assert_base58_vectors();
}

#[test]
fn signed_manifests_verify_with_the_public_test_key() {
    verify_signed("provider", "provider-entry");
    verify_signed("app", "app-entry");
}

#[test]
fn fixtures_declare_the_hook_surfaces() {
    let provider = load_manifest("provider");
    provider.validate().expect("provider manifest");
    assert_eq!(provider.name, common::provider_name());
    assert_eq!(
        provider.provides.as_deref(),
        Some(format!("elastos://{}/*", scheme()).as_str())
    );
    assert_eq!(
        provider_operations(),
        ["quote", "lock", "claim", "refund", "status"]
    );
    let prompt = user_approval_method(&provider);
    assert_eq!(prompt.operation.as_deref(), Some("lock"));
    assert!(
        prompt
            .description
            .as_deref()
            .is_some_and(|text| text.contains("Approve")),
        "the user-approval operation carries prompt text"
    );

    let app = load_manifest("app");
    app.validate().expect("app manifest");
    assert_eq!(app.name, app_name());
    let asked: Vec<&str> = app.asks.iter().map(|ask| ask.resource.as_str()).collect();
    for operation in ["quote", "lock", "claim", "status"] {
        assert!(
            asked
                .iter()
                .any(|resource| resource.ends_with(operation) && resource.contains(&scheme())),
            "app asks for {operation}"
        );
    }
    assert!(
        asked.iter().all(|resource| !resource.ends_with("refund")),
        "app does not ask for refund"
    );
    let wallet: Vec<_> = asked
        .iter()
        .filter(|resource| resource.starts_with("elastos://wallet/"))
        .collect();
    assert_eq!(wallet.len(), 2, "two wallet methods");
    assert!(wallet
        .iter()
        .any(|resource| resource.ends_with("personal_sign")));
    assert!(wallet
        .iter()
        .any(|resource| resource.ends_with("eth_sendTransaction")));
    let chain: Vec<_> = asked
        .iter()
        .filter(|resource| resource.contains("elastos://chain/base/"))
        .copied()
        .collect();
    assert_eq!(chain.len(), 2, "two methods on one named chain");
    assert!(chain.iter().any(|resource| resource.ends_with("eth_call")));
    assert!(chain
        .iter()
        .any(|resource| resource.ends_with("eth_getLogs")));
    let logs = app
        .interfaces
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .find(|method| method.operation.as_deref() == Some("eth_getLogs"))
        .expect("log-range method");
    let schema = logs.input_schema.as_ref().expect("log range schema");
    assert_eq!(schema["properties"]["chain"]["const"], "base");
    assert_eq!(schema["properties"]["from_block"]["const"], 1);
    assert_eq!(schema["properties"]["to_block"]["const"], 100);
    let topic_asks: Vec<_> = app
        .asks
        .iter()
        .filter(|ask| ask.actions == vec![AskAction::Message])
        .collect();
    assert_eq!(topic_asks.len(), 1, "one carrier topic ask");
    assert!(topic_asks[0].resource.contains(&app_name()));
    assert!(topic_asks[0].resource.contains("carrier"));
    let topic = app
        .interfaces
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .find(|method| method.id == "carrier.topic")
        .expect("topic method");
    let topic_schema = topic.input_schema.as_ref().expect("topic schema");
    assert_eq!(
        topic_schema["properties"]["topic_pattern"]["const"],
        format!("{}/swap", app_name())
    );
    assert_eq!(
        topic_schema["properties"]["max_message_bytes"]["const"],
        4096
    );
    let _ = AffordanceApprovalMode::User;
}

/// H1. Provider by scheme. Lane: B3 (declared scheme and operations).
///
/// Wanted: after install and user approval, a request for a declared
/// operation is answered, and an operation outside the declared list is
/// refused. The signature admits the bytes and grants nothing, so approval
/// stays bound to the content id.
///
/// Today: `ProviderRegistry::register` takes a provider, not a manifest.
/// `registry.rs` does not name `CapsuleManifest`. A request for the stand-in
/// URI through `ProviderRegistry::route` is `NoProvider` for scheme `elastos`.
#[tokio::test]
async fn hook1_provider_scheme_from_manifest_is_missing_today() {
    let manifest = load_manifest("provider");
    manifest.validate().expect("provider manifest");
    let registry_src = server_file("elastos/crates/elastos-runtime/src/provider/registry.rs");
    let register_sig = join(&[
        "pub async fn register(&self, provider: Arc<dyn ",
        "Provider>)",
    ]);
    assert!(
        registry_src.contains(&register_sig),
        "register takes a provider value, not a manifest"
    );
    let manifest_type = join(&["Capsule", "Manifest"]);
    assert!(
        !registry_src.contains(&manifest_type),
        "registry.rs does not name the manifest type"
    );

    let registry = ProviderRegistry::new();
    assert!(registry.registrations().await.is_empty());
    let uri = format!("elastos://{}/quote", scheme());
    let error = registry
        .route(&uri, "lab-caller", ResourceAction::Read, None)
        .await
        .expect_err("no provider is registered from the manifest");
    match error {
        ProviderError::NoProvider(found) => assert_eq!(found, "elastos"),
        other => panic!("wanted NoProvider for scheme elastos, got {other:?}"),
    }
}

/// H1b. Duplicate scheme registration. Lane: B3.
///
/// The row is OPEN. `ProviderRegistry::register` replaces a scheme a
/// built-in already holds. The built-in content provider registers the
/// scheme `content` through this function (`server_infra.rs`
/// `register_content_plane`). `register_sub_provider` already refuses a
/// second name. This path is not reachable by a third party today, because
/// no manifest registration path exists. The row is here so that path cannot
/// be added without the refusal.
///
/// Wanted: the second registration is refused and the first provider still
/// answers.
#[tokio::test]
async fn hook1b_duplicate_scheme_registration_replaces_the_first_today() {
    let registry = ProviderRegistry::new();
    let first = Arc::new(MarkerProvider {
        scheme: "content",
        marker: "first-holder",
    });
    let second = Arc::new(MarkerProvider {
        scheme: "content",
        marker: "second-holder",
    });
    registry.register(first).await;
    registry.register(second).await;
    let response = registry
        .route("content://kept", "lab-caller", ResourceAction::Read, None)
        .await
        .expect("the scheme still has a provider");
    assert_eq!(
        answer(response),
        b"second-holder",
        "OPEN: register replaces the first provider"
    );
}

/// H2. Wallet bridge for an app that is not the Browser.
/// Lane: U10 (asks in the signed manifest) and A15-R (the approval record).
/// The fixed capsule id is the gateway allowlist P2-10 slice 4 waits on.
///
/// Wanted: an app that declares wallet methods may use the bridge. The
/// gateway names the app from the launch.
///
/// Today: `browser_app_wallet_bridge` admits the fixed browser capsule id.
#[test]
fn hook2_wallet_bridge_admits_a_fixed_browser_id_today() {
    let source = server_file("elastos/crates/elastos-server/src/api/gateway_browser_wallet.rs");
    let fn_name = join(&["fn browser_app_", "wallet_bridge"]);
    let body = item_body(&source, &fn_name);
    let admit = join(&["require_runtime_", "wallet_authority"]);
    let browser = join(&["BROWSER_", "CAPSULE_", "ID"]);
    assert!(body.contains(&admit), "bridge asks the wallet authority");
    assert!(
        body.contains(&format!("&[{browser}]")),
        "bridge admits the fixed browser capsule id"
    );
    assert!(
        !body.contains(&scheme()),
        "bridge does not read the stand-in app"
    );
}

/// H3. Typed chain reads for declared methods and chains. Lane: U10.
///
/// Wanted: the Runtime answers only the methods and chains the app declares,
/// with a log range cap for every caller, and without the Browser internet
/// consent.
///
/// Today: `browser_wallet_read` requires the Browser internet permission
/// before any read.
#[test]
fn hook3_chain_reads_require_browser_internet_permission_today() {
    let source =
        server_file("elastos/crates/elastos-server/src/api/gateway_browser_wallet_reads.rs");
    let fn_name = join(&["fn browser_", "wallet_read("]);
    let body = item_body(&source, &fn_name);
    let gate = join(&["Browser internet permission", " is required"]);
    assert!(
        body.contains(&gate),
        "chain reads require the browser internet permission"
    );
    assert!(body.contains("eth_getLogs") || source.contains("eth_getLogs"));
    assert!(!source.contains(&scheme()));
}

/// H4. App-owned Carrier topics. Lane: P2-9.
///
/// Wanted: a topic pattern under the app's own name, a message size limit,
/// and a sender id derived from the launch and the topic.
///
/// Today: carrier uses one wire maximum for every caller and does not read
/// a manifest topic pattern.
#[test]
fn hook4_carrier_message_limit_is_one_constant_today() {
    let source = server_file("elastos/crates/elastos-server/src/carrier.rs");
    let constant = join(&[
        "const GOSSIP_WIRE",
        "_MESSAGE_MAX_BYTES: usize = 192 * 1024;",
    ]);
    assert!(
        source.contains(&constant),
        "one wire maximum for every caller"
    );
    let topic_pattern = join(&["topic", "_pattern"]);
    assert!(
        !source.contains(&topic_pattern),
        "carrier.rs has no manifest topic pattern"
    );
    assert!(!source.contains(&scheme()));
}

/// H5. User approval for an operation marked approval: user.
/// Lane: U10 (the prompt in the signed manifest), A15-R (the approval
/// record) and U11 (the grant is remembered and can be revoked).
///
/// Wanted: that operation asks the user with the manifest prompt, and the
/// answer is kept and can be revoked.
///
/// Today: the provider proxy maps an operation through the fixed action map
/// and refuses an unmapped operation with a fixed sentence. It does not read
/// the manifest approval mode.
#[test]
fn hook5_user_approval_is_not_read_from_the_manifest_today() {
    let source = server_file("elastos/crates/elastos-server/src/api/handlers/provider.rs");
    let refusal = join(&["Unsupported provider operation", " action mapping"]);
    let action_map = join(&["provider_", "operation_action"]);
    assert!(
        source.contains(&refusal),
        "unmapped operations use a fixed sentence"
    );
    assert!(
        source.contains(&action_map),
        "the proxy uses the fixed action map"
    );
    let approval_mode = join(&["Affordance", "ApprovalMode"]);
    assert!(!source.contains(&approval_mode));
    assert!(!source.contains(&scheme()));
}

/// H6. Install a signed outside bundle by fingerprint. Lane: P2-2.
/// The row is OPEN.
///
/// What exists: `stage_bundle` in `stage_cmd.rs` writes a signed bundle into
/// the store and starts nothing. `run_bundle` in `run_cmd.rs` starts a bundle
/// the store already holds, by its fingerprint. This crate does not depend
/// on the server, so it cannot call either function. Neither file registers
/// a provider from a manifest `provides` field.
///
/// Wanted: the signed stand-in installs by its fingerprint and its scheme
/// answers, with no Runtime source edit that names the app.
#[test]
fn hook6_stage_bundle_exists_and_starts_nothing_today() {
    let stage = server_file("elastos/crates/elastos-server/src/stage_cmd.rs");
    let run = server_file("elastos/crates/elastos-server/src/run_cmd.rs");
    let starts_nothing = join(&["Staging starts ", "nothing"]);
    let stage_fn = join(&["pub async fn stage_", "bundle("]);
    let run_fn = join(&["pub async fn run_", "bundle("]);
    assert!(stage.contains(&starts_nothing));
    assert!(stage.contains(&stage_fn));
    assert!(run.contains(&run_fn));
    let registry_type = join(&["Provider", "Registry"]);
    assert!(!stage.contains(&registry_type));
    assert!(!run.contains(&scheme()));
    let cargo = common::read_text(&common::manifest_dir().join("Cargo.toml"));
    let server_dep = join(&["elastos-", "server"]);
    assert!(
        !cargo.contains(&server_dep),
        "this crate does not depend on the server"
    );
}

/// Provider network right: named hosts, and loopback. Lane: B3 follow-up
/// rights. The row is WAITING. It waits for Sash's ruling and Rong's answer.
/// This test only checks that the row is in the table.
#[test]
fn hook_network_right_is_waiting() {
    let table = rows_table();
    let present = table["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .any(|row| row["id"] == "network-right");
    assert!(present, "the provider network right row is in the table");
}

/// Tripwire: a Runtime source edit that names the stand-in.
/// The search is `elastos/crates/`. It skips `target`, `target-build` and
/// `.git`. The needle is built at run time.
#[test]
fn runtime_sources_do_not_name_the_stand_in() {
    let needle = scheme();
    let root = common::repo_root().join("elastos/crates");
    let mut hits = Vec::new();
    for (path, text) in walk_text_files(&root) {
        if text.contains(&needle) {
            hits.push(path);
        }
    }
    assert!(
        hits.is_empty(),
        "Runtime sources name the stand-in: {hits:?}"
    );
}

/// Wanted behaviour for every hook. Red today. Ignored so the lab stays
/// green. Run it with `--ignored` and keep the output.
#[tokio::test]
#[ignore]
async fn p2_10_matrix_wanted() {
    let mut red = Vec::new();

    let registry = ProviderRegistry::new();
    let quote = format!("elastos://{}/quote", scheme());
    let sweep = format!("elastos://{}/sweep", scheme());
    let quote_result = registry
        .route(&quote, "lab-caller", ResourceAction::Read, None)
        .await;
    let sweep_result = registry
        .route(&sweep, "lab-caller", ResourceAction::Read, None)
        .await;
    if quote_result.is_err() || sweep_result.is_ok() {
        red.push("H1 provider scheme from the manifest");
    }

    let duplicate = ProviderRegistry::new();
    duplicate
        .register(Arc::new(MarkerProvider {
            scheme: "content",
            marker: "first-holder",
        }))
        .await;
    duplicate
        .register(Arc::new(MarkerProvider {
            scheme: "content",
            marker: "second-holder",
        }))
        .await;
    let who = duplicate
        .route("content://kept", "lab-caller", ResourceAction::Read, None)
        .await
        .map(answer);
    if who.as_deref().ok() != Some(b"first-holder".as_slice()) {
        red.push("H1b duplicate scheme registration");
    }

    let wallet = server_file("elastos/crates/elastos-server/src/api/gateway_browser_wallet.rs");
    let bridge = item_body(&wallet, &join(&["fn browser_app_", "wallet_bridge"]));
    let browser_only = format!("&[{}]", join(&["BROWSER_", "CAPSULE_", "ID"]));
    if bridge.contains(&browser_only) {
        red.push("H2 wallet bridge for an app that is not the browser");
    }

    let reads =
        server_file("elastos/crates/elastos-server/src/api/gateway_browser_wallet_reads.rs");
    let read_fn = item_body(&reads, &join(&["fn browser_", "wallet_read("]));
    if read_fn.contains(&join(&["Browser internet permission", " is required"])) {
        red.push("H3 typed chain reads");
    }

    let carrier = server_file("elastos/crates/elastos-server/src/carrier.rs");
    if !carrier.contains(&join(&["topic", "_pattern"])) {
        red.push("H4 app-owned carrier topics");
    }

    let proxy = server_file("elastos/crates/elastos-server/src/api/handlers/provider.rs");
    if !proxy.contains(&join(&["Affordance", "ApprovalMode"])) {
        red.push("H5 user approval from the manifest");
    }

    let stage = server_file("elastos/crates/elastos-server/src/stage_cmd.rs");
    let installed = !stage.contains(&join(&["Staging starts ", "nothing"]));
    let scheme_answers = registry
        .route(&quote, "lab-caller", ResourceAction::Read, None)
        .await
        .is_ok();
    if !installed || !scheme_answers {
        red.push("H6 install a signed bundle by fingerprint");
    }

    let named = walk_text_files(&common::repo_root().join("elastos/crates"))
        .into_iter()
        .any(|(_, text)| text.contains(&scheme()));
    if named {
        red.push("no-name tripwire");
    }

    let waiting = rows_table()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == "network-right");
    assert!(waiting, "network-right row missing from the table");
    eprintln!("network-right waiting: no behaviour asserted");

    for row in &red {
        eprintln!("RED {row}");
    }
    assert!(
        red.is_empty(),
        "wanted rows red ({}): {}",
        red.len(),
        red.join("; ")
    );
}
