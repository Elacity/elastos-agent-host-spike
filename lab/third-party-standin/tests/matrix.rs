//! Six-hook matrix for the lab stand-in.
//!
//! Each today-row asserts the behaviour this tree has now, so the lab is
//! green. A later slice that builds the hook makes that row fail, and the
//! row is then flipped. `p2_10_matrix_wanted` names the wanted behaviour.
//! Where no API can express that behaviour yet, the row says so and is red.
//!
//! The calls that reach a provider use `ProviderRegistry::route` on
//! `MarkerProvider`, a test double. That route runs no capability check.
//! The lab therefore proves nothing about the server's capability gate.

mod common;

use std::sync::Arc;

use elastos_common::{AffordanceApprovalMode, AskAction};
use elastos_runtime::provider::{ProviderError, ProviderRegistry, ResourceAction};
use serde_json::Value;

use common::{
    action_variant_counts, answer, app_name, assert_base58_vectors, call_inventory,
    call_with_last_arg, const_expression, field_reads, ident_inventory, item_body, join,
    load_manifest, manifest_struct_fields, provides_readers, register_signature_returns_nothing,
    registration_sites, repo_call_inventory, scheme, server_file, sites_json, user_approval_method,
    validate_fns_mention, verify_signed, walk_text_files, MarkerProvider,
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
/// URI through `ProviderRegistry::route` on an empty registry is `NoProvider`
/// for scheme `elastos`. The sites row watches the real registration code.
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

/// H1 sites. A new production registration, or a new production reader of the
/// manifest `provides` field, is the moment this row is flipped with H1.
#[test]
fn hook1_registration_and_provides_sites_are_the_known_set_today() {
    let registrations = registration_sites();
    assert!(
        registrations.iter().any(|site| {
            site.file.ends_with("server_infra.rs")
                && site.function == "register_content_plane"
                && site.label == join(&["reg", "ister"])
                && site.count == 1
        }),
        "register_content_plane still registers one provider"
    );
    let readers = provides_readers();
    assert!(
        readers.iter().any(|site| {
            site.file.ends_with("elastos-common/src/manifest.rs") && site.function == "validate"
        }),
        "CapsuleManifest::validate reads provides"
    );
    expect_sites("registration", sites_json(&registrations));
    expect_sites("provides_readers", sites_json(&readers));
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
    let registry_src = server_file("elastos/crates/elastos-runtime/src/provider/registry.rs");
    assert!(
        register_signature_returns_nothing(&registry_src),
        "register returns nothing, so it cannot refuse a second call"
    );
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
/// Today: every production use of the fixed browser capsule id in the wallet
/// bridge file and the provider-proxy file is the known set. A new use is a
/// new door.
#[test]
fn hook2_wallet_bridge_browser_capsule_uses_are_the_known_set_today() {
    let ident = join(&["BROWSER_", "CAPSULE_", "ID"]);
    let bridge = "elastos/crates/elastos-server/src/api/gateway_browser_wallet.rs";
    let proxy = "elastos/crates/elastos-server/src/api/gateway_provider_proxy.rs";
    let mut uses = ident_inventory(bridge, &ident);
    uses.extend(ident_inventory(proxy, &ident));
    uses.sort();
    assert!(
        uses.iter().any(|site| {
            site.function == join(&["browser_app_", "wallet_bridge"]) && site.count == 1
        }),
        "the bridge admits the fixed browser capsule id once"
    );
    assert!(uses.iter().all(|site| site.label != scheme()));
    expect_sites("h2_browser_capsule_id", sites_json(&uses));
}

/// H3. Typed chain reads for declared methods and chains. Lane: U10.
///
/// Wanted: the Runtime answers only the methods and chains the app declares,
/// with a log range cap for every caller, and without the Browser internet
/// consent.
///
/// Today: `browser_wallet_read` calls the internet gate with `request_missing`
/// false, and the reads file does not read the manifest fields the hook needs.
#[test]
fn hook3_chain_read_internet_gate_is_the_known_call_today() {
    let reads = "elastos/crates/elastos-server/src/api/gateway_browser_wallet_reads.rs";
    let gate = join(&["effect_for_", "authority"]);
    let calls = call_with_last_arg(reads, &gate);
    assert!(
        calls.iter().any(|site| {
            site.function == join(&["browser_", "wallet_read"])
                && site.label.ends_with("(false)")
                && site.count == 1
        }),
        "the read calls the internet gate once and does not request a missing grant"
    );
    let mut manifest_fields = field_reads(reads, "asks");
    manifest_fields.extend(field_reads(reads, &join(&["input_", "schema"])));
    manifest_fields.sort();
    assert!(
        manifest_fields.is_empty(),
        "chain reads do not read manifest asks or input_schema: {manifest_fields:?}"
    );
    expect_sites("h3_internet_gate", sites_json(&calls));
    expect_sites("h3_manifest_fields", sites_json(&manifest_fields));
}

/// H4. App-owned Carrier topics. Lane: P2-9.
///
/// Wanted: a topic pattern under the app's own name, a message size limit,
/// and a sender id derived from the launch and the topic.
///
/// Today: one wire maximum is the value production code uses, and carrier
/// does not read a manifest topic pattern.
#[test]
fn hook4_carrier_wire_limit_uses_are_the_known_set_today() {
    let carrier = "elastos/crates/elastos-server/src/carrier.rs";
    let name = join(&["GOSSIP_WIRE_", "MESSAGE_MAX_BYTES"]);
    let expression = const_expression(carrier, &name);
    assert_eq!(
        expression, "192 * 1024",
        "one wire maximum for every caller"
    );
    let uses = ident_inventory(carrier, &name);
    assert!(
        uses.iter()
            .any(|site| site.function == "serialize_gossip_wire_message"),
        "the serializer enforces the wire maximum"
    );
    let topic = join(&["topic_", "pattern"]);
    let readers = ident_inventory(carrier, &topic);
    assert!(
        readers.is_empty(),
        "carrier has no production reader of a manifest topic pattern"
    );
    expect_sites(
        "h4_wire_limit",
        serde_json::json!({
            "expression": expression,
            "uses": sites_json(&uses),
            "topic_pattern": sites_json(&readers),
        }),
    );
}

/// H5. User approval for an operation marked approval: user.
/// Lane: U10 (the prompt in the signed manifest), A15-R (the approval
/// record) and U11 (the grant is remembered and can be revoked).
///
/// Wanted: that operation asks the user with the manifest prompt, and the
/// answer is kept and can be revoked.
///
/// Today: the operation-to-action map is the known set of actions, and neither
/// the proxy nor the map reads the manifest approval mode.
#[test]
fn hook5_provider_operation_actions_are_the_known_set_today() {
    let map_file = "elastos/crates/elastos-server/src/provider_resource.rs";
    let proxy_file = "elastos/crates/elastos-server/src/api/handlers/provider.rs";
    let map = join(&["provider_", "operation_action"]);
    let actions = action_variant_counts(map_file, &map);
    assert!(actions.get("Read").copied().unwrap_or(0) > 0);
    assert!(actions.get("Write").copied().unwrap_or(0) > 0);
    let callers = repo_call_inventory(&map);
    assert!(
        callers.iter().any(|site| site.function == "provider_proxy"),
        "the proxy decides the action through the map"
    );
    let mode = join(&["Affordance", "ApprovalMode"]);
    let mut approval = ident_inventory(map_file, &mode);
    approval.extend(ident_inventory(proxy_file, &mode));
    approval.extend(field_reads(map_file, "approval"));
    approval.extend(field_reads(proxy_file, "approval"));
    approval.sort();
    assert!(
        approval.is_empty(),
        "the action map does not read the manifest approval mode: {approval:?}"
    );
    expect_sites(
        "h5_actions",
        serde_json::json!({
            "variants": actions,
            "callers": sites_json(&callers),
            "approval_readers": sites_json(&approval),
        }),
    );
}

/// H6. Install a signed outside bundle by fingerprint. Lane: P2-2.
/// The row is OPEN.
///
/// What exists: `stage_bundle_observed` writes the checked bundle into the
/// slot and does not start it. `run_bundle` starts a bundle the store already
/// holds, by its fingerprint. This crate does not depend on the server, so
/// it cannot call either function.
///
/// Wanted: the signed stand-in installs by its fingerprint and its scheme
/// answers, with no Runtime source edit that names the app.
#[test]
fn hook6_stage_writes_the_slot_and_run_starts_by_fingerprint_today() {
    let stage = "elastos/crates/elastos-server/src/stage_cmd.rs";
    let run = "elastos/crates/elastos-server/src/run_cmd.rs";
    let write_slot = join(&["write_", "slot"]);
    let run_by = join(&["run_by_", "bundle"]);
    let mut calls = call_inventory(stage, &write_slot);
    calls.extend(call_inventory(stage, &run_by));
    calls.extend(call_inventory(run, &run_by));
    calls.sort();
    assert!(
        calls.iter().any(|site| {
            site.function == join(&["stage_bundle_", "observed"])
                && site.label == write_slot
                && site.count == 1
        }),
        "staging writes the slot once"
    );
    assert!(
        calls
            .iter()
            .all(|site| site.function != join(&["stage_bundle_", "observed"])
                || site.label != run_by),
        "staging does not start the bundle"
    );
    assert!(
        calls.iter().any(|site| {
            site.function == join(&["run_", "bundle"]) && site.label == run_by && site.count == 1
        }),
        "run starts a stored bundle by its fingerprint"
    );
    let cargo = common::read_text(&common::manifest_dir().join("Cargo.toml"));
    let server_dep = join(&["elastos-", "server"]);
    assert!(
        !cargo.contains(&server_dep),
        "this crate does not depend on the server"
    );
    expect_sites("h6_stage_and_run", sites_json(&calls));
}

/// Declared log range and topic message limit. OPEN. Owner: the P2-10 hook
/// slices. The values live in interface `input_schema`. That schema is
/// discoverability metadata. No manifest field enforces the numbers.
#[test]
fn hook_declared_limits_are_descriptive_today() {
    let table = rows_table();
    let row = table["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["id"] == "declared-limits")
        .expect("declared-limits row");
    assert_eq!(row["state"], "open");
    assert_eq!(row["owner"], "the P2-10 hook slices");

    let manifest_path = common::fixture("app").join("capsule.json");
    let value: Value = serde_json::from_str(&common::read_text(&manifest_path)).expect("app json");
    let keys = limit_keys();
    let mut hits = Vec::new();
    collect_keys(&value, &keys, &mut Vec::new(), &mut hits);
    assert!(!hits.is_empty(), "the fixture declares the limits");
    assert!(
        hits.iter()
            .all(|path| path.split('.').any(|part| part == "input_schema")),
        "limits live under input_schema, found {hits:?}"
    );

    let mut absurd = value.clone();
    set_schema_const(&mut absurd, &keys[0], 9_999_999);
    set_schema_const(&mut absurd, &keys[1], 0);
    set_schema_const(&mut absurd, &keys[3], 99_999_999);
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_value(absurd).expect("absurd limits are still a manifest");
    manifest
        .validate()
        .expect("input_schema limits are not enforced");

    let manifest_rs = "elastos/crates/elastos-common/src/manifest.rs";
    let fields = manifest_struct_fields(manifest_rs);
    assert!(
        fields
            .iter()
            .any(|field| field == "CapsuleManifest.provides"),
        "struct fields were read: {fields:?}"
    );
    for key in &keys {
        assert!(
            !fields
                .iter()
                .any(|field| field.ends_with(&format!(".{key}"))),
            "no manifest field is named {key}"
        );
        let mentions = validate_fns_mention(manifest_rs, key);
        assert!(
            mentions.is_empty(),
            "validate functions do not read {key}: {mentions:?}"
        );
    }
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

/// A following item is not absorbed into the body.
#[test]
fn item_body_stops_before_the_next_item() {
    let source = "\
fn kept() {\n    let value = 1;\n}\n\
pub fn next_fn() {}\n\
pub async fn next_async() {}\n\
impl Next {}\n\
mod next_mod {}\n\
use next::Item;\n\
static NEXT: i32 = 1;\n\
trait NextTrait {}\n";
    let body = item_body(source, "fn kept()");
    assert!(body.contains("let value"));
    for later in [
        "next_fn",
        "next_async",
        "impl Next",
        "next_mod",
        "use next",
        "NEXT",
        "NextTrait",
    ] {
        assert!(!body.contains(later), "body absorbed {later}: {body}");
    }
}

/// Wanted behaviour for every hook. Red today. Ignored so the lab stays
/// green. A row is red with an explicit missing-behaviour message when no
/// API can express it. It does not pass on a weaker stand-in.
#[tokio::test]
#[ignore]
async fn p2_10_matrix_wanted() {
    let mut red = Vec::new();

    // No API registers a provider from a verified manifest after user
    // approval bound to the bundle content id, and none refuses an operation
    // the manifest did not declare.
    red.push("H1 wanted: registered from the verified manifest only after user approval bound to the bundle CID, and an undeclared operation is refused: no API yet");

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
    let registry_src = server_file("elastos/crates/elastos-runtime/src/provider/registry.rs");
    if register_signature_returns_nothing(&registry_src) {
        red.push(
            "H1b wanted: the second registration is refused: no API yet (register returns nothing)",
        );
    } else {
        red.push("H1b wanted: the second registration is refused: register can return a value, so assert that refusal; this row stays red until that assertion is written");
    }

    red.push("H2 wanted: an app that is not the Browser may use the wallet bridge: no API yet");
    red.push("H3 wanted: the Runtime answers only the methods and chains the app declares, with a log range cap, and without the Browser internet consent: no API yet");
    red.push("H4 wanted: a topic pattern under the app name, a message size limit, and a sender id from the launch and the topic: no API yet");
    red.push("H5 wanted: an operation marked approval user asks with the manifest prompt, and the answer is kept and can be revoked: no API yet");
    red.push("H6 wanted: the stand-in bundle is staged by fingerprint and started with no Runtime source edit: no API yet");

    let named = walk_text_files(&common::repo_root().join("elastos/crates"))
        .into_iter()
        .any(|(_, text)| text.contains(&scheme()));
    if named {
        red.push("no-name tripwire: a Runtime source names the stand-in");
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

fn expect_sites(section: &str, live: Value) {
    let path = common::manifest_dir().join("fixtures/production-sites.json");
    let file: Value = serde_json::from_str(&common::read_text(&path))
        .unwrap_or_else(|err| panic!("production site inventory: {err}"));
    let expected = &file[section];
    assert_eq!(
        &live,
        expected,
        "{section} inventory changed\nlive {}\nexpected {}",
        serde_json::to_string_pretty(&live).unwrap_or_default(),
        serde_json::to_string_pretty(expected).unwrap_or_default()
    );
}

fn limit_keys() -> Vec<String> {
    vec![
        join(&["from_", "block"]),
        join(&["to_", "block"]),
        join(&["topic_", "pattern"]),
        join(&["max_message_", "bytes"]),
    ]
}

fn collect_keys(value: &Value, keys: &[String], path: &mut Vec<String>, hits: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                if keys.iter().any(|wanted| wanted == key) {
                    hits.push(path.join("."));
                }
                collect_keys(child, keys, path, hits);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(index.to_string());
                collect_keys(child, keys, path, hits);
                path.pop();
            }
        }
        _ => {}
    }
}

fn set_schema_const(value: &mut Value, key: &str, number: i64) {
    match value {
        Value::Object(map) => {
            if map.contains_key(key) {
                if let Some(slot) = map.get_mut(key).and_then(|child| child.as_object_mut()) {
                    slot.insert("const".to_string(), Value::from(number));
                }
            }
            for child in map.values_mut() {
                set_schema_const(child, key, number);
            }
        }
        Value::Array(items) => {
            for child in items {
                set_schema_const(child, key, number);
            }
        }
        _ => {}
    }
}
