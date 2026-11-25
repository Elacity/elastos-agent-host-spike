#![cfg(feature = "prototype-agents")]
//! Hosted agent rows for one admitted agent.
//!
//! These rows compile only when the crate is built with `prototype-agents`.
//! A Studio receipt of
//! `cargo test --locked -p elastos-server --lib --features prototype-agents`
//! on a Mac runs the seven rows. The default Studio receipt builds the
//! featureless library, so cargo lists `hosted_agent_rows_are_not_compiled`
//! as ignored and the seven rows are absent. CI job `test-elastos`
//! (ubuntu-24.04), step "cargo test with prototype-agents", runs
//! `hosted_agent_rows_stay_in_the_agents_build` and does not contain the
//! seven rows, because each row is `target_os = "macos"`. Job
//! `source-home-macos`, step "B4-R named localhost decision tests", does not
//! select these rows.
//!
//! A row that reaches the egress broker takes its provider identity from
//! `ProviderBridge::spawn_confined_model`. That spawn starts the existing
//! hosted-effect probe as a real child and stores the child's pid and birth.
//! A row that refuses before dispatch does not name a provider process.

#[cfg(target_os = "macos")]
use super::{
    bridge_context, model_input_hash, model_invoke, Action, AgentKey, BridgeContext, ModelBudget,
    ModelDispatchBudget, RunKey, RuntimeCreateBinding, RUNTIME_CREATE_BINDING_SCHEMA,
};
#[cfg(target_os = "macos")]
use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};
#[cfg(target_os = "macos")]
use std::sync::Arc;

#[cfg(target_os = "macos")]
const HOSTED_OFFER: &str = "model:openrouter";
#[cfg(target_os = "macos")]
const HOSTED_CAPSULE: &str = "capsule-agent";
#[cfg(target_os = "macos")]
const HOSTED_INPUT_LIMIT: u64 = 100;
#[cfg(target_os = "macos")]
const HOSTED_INLINE_LIMIT: u64 = 128;
#[cfg(target_os = "macos")]
const HOSTED_SECRET: &str = "fixture-hosted-secret";

#[cfg(target_os = "macos")]
fn hosted_offer_tokens() -> u64 {
    HOSTED_INPUT_LIMIT + 1024 + (HOSTED_INLINE_LIMIT / 4).max(1)
}

#[cfg(target_os = "macos")]
struct BrokerModel {
    data_dir: std::path::PathBuf,
    creates: Arc<std::sync::atomic::AtomicUsize>,
    reply: Arc<std::sync::Mutex<String>>,
}

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl Provider for BrokerModel {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw model fixture".to_string()))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec!["model"]
    }
    fn name(&self) -> &'static str {
        "broker-model"
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        if request["op"] == "offers_list" {
            return Ok(serde_json::json!({
                "status": "ok",
                "data": {
                    "offers": [{
                        "id": HOSTED_OFFER,
                        "policy": {
                            "input_bytes_limit": HOSTED_INPUT_LIMIT,
                            "inline_output_bytes_limit": HOSTED_INLINE_LIMIT,
                        },
                    }],
                    "offer_revisions": {HOSTED_OFFER: "sha256:s8"},
                },
            }));
        }
        if request["op"] != "runs_create" {
            return Ok(serde_json::json!({"status": "error", "code": "unsupported"}));
        }
        self.creates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let binding =
            serde_json::from_value::<RuntimeCreateBinding>(request["runtime_binding"].clone())
                .map_err(|err| ProviderError::Provider(err.to_string()))?;
        let run_id = elastos_model_contract::model_run_id(&binding);
        let forwarded = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crate::api::model_provider_egress::hosted_forward::forward_hosted_text_for_test(
                &self.data_dir,
                request,
                &run_id,
                &binding.request_id,
            ),
        )
        .await
        .map_err(|_| ProviderError::Provider("hosted broker timed out".to_string()))?
        .map_err(|err| ProviderError::Provider(err.to_string()))?;
        *self.reply.lock().unwrap() = forwarded.clone();
        if !forwarded.starts_with("HTTP/1.1 200") {
            return Ok(serde_json::json!({
                "status": "error",
                "code": "broker_refused",
                "message": forwarded,
            }));
        }
        Ok(serde_json::json!({"status": "ok", "data": {"run_id": run_id}}))
    }
}

#[cfg(target_os = "macos")]
struct HostedHome {
    ctx: BridgeContext,
    creates: Arc<std::sync::atomic::AtomicUsize>,
    hits: Arc<std::sync::atomic::AtomicUsize>,
    captured: Arc<std::sync::Mutex<String>>,
    reply: Arc<std::sync::Mutex<String>>,
    owner_id: String,
    owner_proof: String,
    agent_id: String,
    decision_id: String,
    account: Arc<ModelBudget>,
    agent_key: AgentKey,
    sink: tokio::task::JoinHandle<()>,
    _temp: tempfile::TempDir,
}

#[cfg(target_os = "macos")]
fn enroll_hosted_owner(dir: &std::path::Path) -> (String, String) {
    let mut identity = elastos_identity::IdentityManager::new(dir.to_path_buf()).unwrap();
    let secret = crate::auth::random_secret_hex();
    let owner = crate::auth::OwnerAdmission {
        origin: "http://localhost:61971",
        rp_id: "localhost",
        claimant: &secret,
        loopback: true,
    };
    let (_, options) = crate::auth::begin_owner_enrollment(
        dir,
        &mut identity,
        &owner,
        "owner",
        crate::auth::now_ts(),
    )
    .unwrap()
    .unwrap();
    let attestation = crate::auth::owner_attestation_for_test(
        &options.unwrap().public_key.challenge,
        owner.rp_id,
        owner.origin,
    );
    crate::auth::complete_owner_enrollment(
        dir,
        &mut identity,
        &owner,
        "owner",
        Some(&attestation),
        None,
        crate::auth::now_ts(),
    )
    .unwrap()
    .unwrap();
    let principal = crate::auth::active_passkey_principals(dir)
        .unwrap()
        .into_iter()
        .find(crate::auth::is_admin)
        .unwrap();
    crate::auth::store_test_principal_root_protection_for(
        dir,
        &principal.principal_id,
        &principal.localhost_root,
    );
    (principal.principal_id, principal.proof_binding_id)
}

#[cfg(target_os = "macos")]
fn hosted_owner_caller<'a>(owner_id: &'a str, proof: &'a str) -> crate::agents::Caller<'a> {
    crate::agents::Caller {
        principal_id: owner_id,
        proof_binding_id: proof,
        session_id: "s8-session",
    }
}

#[cfg(target_os = "macos")]
fn write_hosted_fixture(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true).mode(0o600);
    options.open(path).unwrap().write_all(bytes).unwrap();
}

#[cfg(target_os = "macos")]
fn hosted_input() -> serde_json::Value {
    serde_json::json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "hi",
    })
}

#[cfg(target_os = "macos")]
fn hosted_run_id(agent_id: &str, request_id: &str) -> String {
    let input = hosted_input();
    let binding = RuntimeCreateBinding {
        schema: RUNTIME_CREATE_BINDING_SCHEMA.to_string(),
        principal_id: agent_id.to_string(),
        session_id: HOSTED_CAPSULE.to_string(),
        capsule_id: HOSTED_CAPSULE.to_string(),
        grant_id: "capability:preview".to_string(),
        request_id: request_id.to_string(),
        offer_id: HOSTED_OFFER.to_string(),
        operation: "text.generate".to_string(),
        input_hash: model_input_hash(&input).unwrap(),
    };
    elastos_model_contract::model_run_id(&binding)
}

#[cfg(target_os = "macos")]
async fn hosted_agent_home(ceiling: u64) -> HostedHome {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    crate::agents::require_build().expect("hosted rows require the agents build");
    let temp = tempfile::tempdir().unwrap();
    let (owner_id, owner_proof) = enroll_hosted_owner(temp.path());
    let now = crate::auth::now_ts();
    let caller = hosted_owner_caller(&owner_id, &owner_proof);
    crate::agents::set_enabled(temp.path(), &caller, true, now).unwrap();
    let agent_id = crate::agents::create(
        temp.path(),
        &caller,
        &crate::agents::CreateRequest {
            display_name: "Hosted".to_string(),
            agent_host: "a5-launch-probe".to_string(),
            request_id: "s8-create".to_string(),
        },
        |host| {
            Ok(
                crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                    host,
                    "bafkreia5probe",
                    "bafkreia5bundle",
                ),
            )
        },
        now,
    )
    .unwrap()
    .agent_id;
    crate::agents::set_active(temp.path(), &caller, &agent_id, true, now).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let chat = format!("http://127.0.0.1:{port}/openrouter/api/v1/chat/completions");
    crate::api::seed_model_provider_operator_offers_for_test(
        temp.path(),
        vec![serde_json::json!({
            "id": HOSTED_OFFER,
            "title": "Fixture",
            "operation": "text.generate",
            "input_modalities": ["text/plain"],
            "output_modalities": ["text/plain"],
            "enabled": true,
            "policy": {
                "input_bytes_limit": HOSTED_INPUT_LIMIT,
                "inline_output_bytes_limit": HOSTED_INLINE_LIMIT,
            },
            "adapter": {
                "kind": "open_ai_compatible_text",
                "api_url": "https://openrouter.ai/api/v1/chat/completions",
                "model": "fixture/model",
                "api_key": HOSTED_SECRET,
                "hosted": {
                    "backend_provider_label": "OpenRouter",
                    "selection_mode": "pinned",
                    "privacy_policy_ref": "fixture:privacy:v1",
                    "terms_ref": "fixture:terms:v1",
                    "upstream_routing_fallback_assertion": "operator_asserted_disabled"
                }
            }
        })],
    )
    .unwrap();
    write_hosted_fixture(
        &temp
            .path()
            .join("providers/model-provider/validate-fixtures.json"),
        serde_json::json!({
            "openrouter_models_url": format!("http://127.0.0.1:{port}/models"),
            "venice_rate_limits_url": format!("http://127.0.0.1:{port}/limits"),
            "venice_models_url": format!("http://127.0.0.1:{port}/venice-models"),
            "openrouter_chat_url": chat,
        })
        .to_string()
        .as_bytes(),
    );
    let request_id = "model-v1:1700000000000:s8";
    let decision_id =
        crate::api::model_provider_egress::hosted_forward::approve_hosted_text_for_test(
            temp.path(),
            HOSTED_OFFER,
            &hosted_run_id(&agent_id, request_id),
            request_id,
            &owner_proof,
        )
        .unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let captured = Arc::new(std::sync::Mutex::new(String::new()));
    let reply = Arc::new(std::sync::Mutex::new(String::new()));
    let hits_task = hits.clone();
    let captured_task = captured.clone();
    let sink = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 2048];
                let Ok(count) = socket.read(&mut chunk).await else {
                    break;
                };
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..count]);
                let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() < end + 4 + length {
                    continue;
                }
                hits_task.fetch_add(1, Ordering::SeqCst);
                *captured_task.lock().unwrap() = String::from_utf8_lossy(&bytes).into_owned();
                let body = b"{}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body).await;
                break;
            }
        }
    });
    let creates = Arc::new(AtomicUsize::new(0));
    let account = Arc::new(ModelBudget::new());
    account.bind_home(temp.path().to_path_buf());
    let agent_key = AgentKey::for_test(&agent_id);
    account.open(&agent_key, ceiling).unwrap();
    let mut ctx = bridge_context();
    ctx.capsule_id = HOSTED_CAPSULE.to_string();
    ctx.principal_id = Some(agent_id.clone());
    ctx.data_dir = Some(temp.path().to_path_buf());
    ctx.manifest_capabilities = vec!["elastos://model/*".into()];
    ctx.model_token_ceiling = Some(ceiling);
    ctx.model_budget = Some(ModelDispatchBudget {
        agent: agent_key.clone(),
        account: account.clone(),
        offers: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let provider = Arc::new(BrokerModel {
        data_dir: temp.path().to_path_buf(),
        creates: creates.clone(),
        reply: reply.clone(),
    });
    ctx.provider_registry
        .register_sub_provider("model", provider)
        .await
        .unwrap();
    HostedHome {
        ctx,
        creates,
        hits,
        captured,
        reply,
        owner_id,
        owner_proof,
        agent_id,
        decision_id,
        account,
        agent_key,
        sink,
        _temp: temp,
    }
}

#[cfg(target_os = "macos")]
async fn hosted_runs_create(ctx: &BridgeContext, request_id: &str) -> serde_json::Value {
    model_invoke(
        ctx,
        "runs_create",
        Action::Execute,
        serde_json::json!({
            "offer_id": HOSTED_OFFER,
            "operation": "text.generate",
            "input": hosted_input(),
            "request_id": request_id,
        }),
    )
    .await
}

#[cfg(target_os = "macos")]
fn demote_hosted_owner(data_dir: &std::path::Path, owner_id: &str) {
    let mut state = crate::auth::load_auth_state(data_dir).unwrap();
    for principal in &mut state.principals {
        if principal.principal_id == owner_id {
            principal.role = crate::auth::RuntimePrincipalRole::Guest;
        }
    }
    crate::auth::save_auth_state(data_dir, &state, None).unwrap();
}

/// An admitted agent reaches the loopback broker once. The fixture stores
/// a hosted secret. The guest result and the broker reply carry no Authorization.
/// This row names the hosted-effect probe, a real child, through
/// `spawn_confined_model`.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn agent_hosted_run_reaches_the_egress_broker_once() {
    let home = hosted_agent_home(hosted_offer_tokens()).await;
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let created = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    assert_eq!(created["response"]["result"]["status"], "ok", "{created}");
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    let secret = HOSTED_SECRET.to_ascii_lowercase();
    let captured = home.captured.lock().unwrap().to_ascii_lowercase();
    assert!(
        captured.contains("authorization") && captured.contains(&secret),
        "the fixture secret did not reach the upstream request: {captured}"
    );
    let guest = created.to_string().to_ascii_lowercase();
    assert!(
        !guest.contains("authorization") && !guest.contains(&secret),
        "the guest result carried the hosted credential: {guest}"
    );
    let reply = home.reply.lock().unwrap().to_ascii_lowercase();
    assert!(
        !reply.contains("authorization") && !reply.contains(&secret),
        "the broker reply carried the hosted credential: {reply}"
    );
    assert_eq!(
        home.account.held_for_test(&home.agent_key),
        hosted_offer_tokens()
    );
    let (_owner, spent) =
        crate::agents::model_spend(home.ctx.data_dir.as_deref().unwrap(), &home.agent_id).unwrap();
    assert_eq!(spent, hosted_offer_tokens());
    let caller = hosted_owner_caller(&home.owner_id, &home.owner_proof);
    crate::agents::set_active(
        home.ctx.data_dir.as_deref().unwrap(),
        &caller,
        &home.agent_id,
        false,
        crate::auth::now_ts(),
    )
    .unwrap();
    let inactive = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8b").await;
    assert_eq!(
        inactive["response"]["code"], "hosted_run_admin_only",
        "{inactive}"
    );
    crate::agents::set_active(
        home.ctx.data_dir.as_deref().unwrap(),
        &caller,
        &home.agent_id,
        true,
        crate::auth::now_ts(),
    )
    .unwrap();
    crate::api::model_provider_egress::hosted_forward::end_hosted_decision_for_test(
        home.ctx.data_dir.as_deref().unwrap(),
        &home.decision_id,
        &home.owner_proof,
    )
    .unwrap();
    let ended = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8c").await;
    assert_eq!(
        ended["response"]["code"], "hosted_run_admin_only",
        "{ended}"
    );
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        home.account.held_for_test(&home.agent_key),
        hosted_offer_tokens()
    );
    home.sink.abort();
}

/// An agent whose stored owner is not an admin keeps the hosted refusal.
/// This row does not name a provider process. The refusal is before dispatch.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn agent_hosted_run_without_admin_owner_is_refused() {
    let home = hosted_agent_home(hosted_offer_tokens()).await;
    demote_hosted_owner(home.ctx.data_dir.as_deref().unwrap(), &home.owner_id);
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let refused = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    assert_eq!(
        refused["response"]["code"], "hosted_run_admin_only",
        "{refused}"
    );
    let mut guest = home.ctx.clone();
    guest.principal_id = Some(home.owner_id.clone());
    guest.model_token_ceiling = None;
    guest.model_budget = None;
    let guest_run = hosted_runs_create(&guest, "model-v1:1700000000000:s8g").await;
    assert_eq!(
        guest_run["response"]["code"], "hosted_run_admin_only",
        "{guest_run}"
    );
    let mut unknown = home.ctx.clone();
    unknown.principal_id = Some("agent:v2:notstored".to_string());
    let unknown_run = hosted_runs_create(&unknown, "model-v1:1700000000000:s8u").await;
    assert_eq!(
        unknown_run["response"]["code"], "principal_context_required",
        "{unknown_run}"
    );
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    home.sink.abort();
}

/// A run that does not fit the signed ceiling is refused before dispatch.
/// This row does not name a provider process.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn agent_hosted_run_over_its_ceiling_is_refused_before_dispatch() {
    let home = hosted_agent_home(hosted_offer_tokens() - 1).await;
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let refused = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    let message = refused["response"]["message"].as_str().unwrap_or("");
    assert!(message.contains("model_budget_exceeded"), "{refused}");
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.account.held_for_test(&home.agent_key), 0);
    let (_owner, spent) =
        crate::agents::model_spend(home.ctx.data_dir.as_deref().unwrap(), &home.agent_id).unwrap();
    assert_eq!(spent, 0);
    home.sink.abort();
}

/// Spend, then open the same folder in a new account. The next create does
/// not fit and is refused before dispatch. The first create names the
/// hosted-effect probe through `spawn_confined_model`. The refused create
/// does not name a provider process.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn spent_total_survives_a_new_runtime_and_blocks_the_next_create() {
    let mut home = hosted_agent_home(hosted_offer_tokens()).await;
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let created = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    assert_eq!(created["response"]["result"]["status"], "ok", "{created}");
    let offers = home.ctx.model_budget.as_ref().unwrap().offers.clone();
    let data_dir = home.ctx.data_dir.clone().unwrap();
    let restarted = std::sync::Arc::new(ModelBudget::new());
    restarted.bind_home(data_dir);
    restarted
        .open(&home.agent_key, hosted_offer_tokens())
        .unwrap();
    assert_eq!(
        restarted.held_for_test(&home.agent_key),
        hosted_offer_tokens()
    );
    home.ctx.model_budget = Some(ModelDispatchBudget {
        agent: home.agent_key.clone(),
        account: restarted,
        offers,
    });
    let refused = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8b").await;
    let message = refused["response"]["message"].as_str().unwrap_or("");
    assert!(message.contains("model_budget_exceeded"), "{refused}");
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    home.sink.abort();
}

/// A record that does not parse is refused by that name before dispatch.
/// This row does not name a provider process.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn unreadable_agent_record_refuses_the_create_by_name() {
    let home = hosted_agent_home(hosted_offer_tokens()).await;
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let path = crate::agents::agent_file_path(home.ctx.data_dir.as_deref().unwrap()).unwrap();
    std::fs::write(&path, b"{").unwrap();
    let refused = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    let message = refused["response"]["message"].as_str().unwrap_or("");
    // merge_into drops a file that does not load, so the principal root
    // check refuses before the charge. The charge's own name is the unit row.
    assert!(message.contains("has no stored record"), "{refused}");
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    home.sink.abort();
}

/// Another Runtime fills the store. This Runtime's memory is still zero,
/// and the create is refused from the stored total before dispatch.
/// This row does not name a provider process.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn two_runtimes_refuse_from_the_stored_total_before_dispatch() {
    let home = hosted_agent_home(hosted_offer_tokens()).await;
    let listed = model_invoke(
        &home.ctx,
        "offers_list",
        Action::Read,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(listed["response"]["result"]["status"], "ok", "{listed}");
    let other = ModelBudget::new();
    other.bind_home(home.ctx.data_dir.clone().unwrap());
    other.open(&home.agent_key, hosted_offer_tokens()).unwrap();
    other
        .reserve(
            &home.agent_key,
            &RunKey::of(
                &RuntimeCreateBinding {
                    schema: RUNTIME_CREATE_BINDING_SCHEMA.to_string(),
                    principal_id: home.agent_id.clone(),
                    session_id: HOSTED_CAPSULE.to_string(),
                    capsule_id: HOSTED_CAPSULE.to_string(),
                    grant_id: "capability:other".to_string(),
                    request_id: "model-v1:1700000000000:other".to_string(),
                    offer_id: HOSTED_OFFER.to_string(),
                    operation: "text.generate".to_string(),
                    input_hash: model_input_hash(&hosted_input()).unwrap(),
                },
                "other-revision",
            ),
            hosted_offer_tokens(),
        )
        .unwrap();
    assert_eq!(home.account.held_for_test(&home.agent_key), 0);
    let refused = hosted_runs_create(&home.ctx, "model-v1:1700000000000:s8").await;
    let message = refused["response"]["message"].as_str().unwrap_or("");
    assert!(message.contains("model_budget_exceeded"), "{refused}");
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    home.sink.abort();
}

/// An HTTP caller with an agent principal is refused. The same principal
/// is allowed on the Bus path that reserves. The context is injected.
/// This row does not name a provider process. The HTTP gate and the Bus
/// path do not spawn one.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn http_caller_with_an_agent_principal_is_refused() {
    let home = hosted_agent_home(hosted_offer_tokens()).await;
    let request = serde_json::json!({
        "offer_id": HOSTED_OFFER,
        "operation": "text.generate",
        "input": {"prompt": "hi"},
        "request_id": "model-v1:1700000000000:s8",
    });
    let data_dir = home.ctx.data_dir.as_deref().unwrap();
    assert!(
        !crate::api::gateway::http_hosted_agent::http_hosted_run_with_principal_for_test(
            data_dir,
            &home.agent_id,
            &request,
        ),
        "the HTTP gate admitted an agent principal"
    );
    let bus = crate::api::gateway::bus_model_provider_request(
        "runs_create",
        &request,
        Some(data_dir),
        Some(&home.agent_id),
        &home.ctx.capsule_id,
        "capability:s8-http",
        &home.ctx.capsule_id,
    );
    assert!(
        bus.is_ok(),
        "the reserving Bus path refused the agent: {bus:?}"
    );
    assert_eq!(home.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(home.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    home.sink.abort();
}
