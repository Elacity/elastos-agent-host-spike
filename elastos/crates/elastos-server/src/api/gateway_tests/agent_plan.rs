//! A15-R slice 4: the owner approves the exact agent plan shown in Inbox.
//!
//! Every case drives the real Inbox action route with a Home launch token and a
//! fresh passkey step-up token bound to the request.

#![cfg(unix)]

use super::*;
use crate::api::gateway::submit_pending_agent_plan;
use std::path::Path;

static PLAN_REGISTRIES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Arc<ProviderRegistry>>>,
> = std::sync::OnceLock::new();

fn plan_registries(
) -> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Arc<ProviderRegistry>>>
{
    PLAN_REGISTRIES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn agent_plan_state(dir: &Path) -> GatewayState {
    GatewayState {
        provider_registry: None,
        collaboration_chat_product_port: None,
        collaboration_presence_product_port: None,
        carrier_endpoint: None,
        collaboration_discovery_service: None,
        browser_internet: Default::default(),
        identity_manager: Arc::new(std::sync::OnceLock::new()),
        cache_dir: dir.to_path_buf(),
        data_dir: dir.to_path_buf(),
    }
}

struct AgentPlanProvider {
    calls: Arc<TokioMutex<Vec<serde_json::Value>>>,
}

#[async_trait::async_trait]
impl Provider for AgentPlanProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw request required".to_string()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["availability", "localhost"]
    }

    fn name(&self) -> &'static str {
        "agent-plan-test"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        self.calls.lock().await.push(request.clone());
        if request["hang"] == true {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if request["transport_error"] == true {
            return Err(ProviderError::Provider(
                "private provider diagnostic".to_string(),
            ));
        }
        Ok(json!({"status": "ok", "data": {"observed": request}}))
    }
}

async fn agent_plan_dispatch_state(
    dir: &Path,
) -> (GatewayState, Arc<TokioMutex<Vec<serde_json::Value>>>) {
    let mut state = agent_plan_state(dir);
    let calls = Arc::new(TokioMutex::new(Vec::new()));
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register(Arc::new(AgentPlanProvider {
            calls: calls.clone(),
        }))
        .await;
    plan_registries()
        .lock()
        .unwrap()
        .entry(dir.to_path_buf())
        .or_insert_with(|| registry.clone());
    state.provider_registry = Some(registry);
    (state, calls)
}

async fn routed_agent_plan_state(dir: &Path) -> GatewayState {
    agent_plan_dispatch_state(dir).await.0
}

fn dispatch_context(owner: &str) -> HomeLaunchTokenContext {
    HomeLaunchTokenContext::for_test(
        owner.to_string(),
        "session:owner",
        None,
        "grant:owner",
        crate::auth::PrincipalKind::Human,
    )
}

fn set_approved(dir: &Path, request_id: &str) {
    let mut record = read_record(dir, request_id);
    record["status"] = json!("approved");
    write_record(dir, request_id, &record);
}

fn read_plan() -> serde_json::Value {
    json!({ "steps": [{ "scheme": "availability", "operation": "status", "request": {} }] })
}

fn write_plan() -> serde_json::Value {
    json!({
        "steps": [{
            "scheme": "localhost",
            "operation": "write",
            "request": {
                "path": "localhost://UsersAI/self/Documents/plan.md",
                "content": [112, 108, 97, 110],
            },
        }],
    })
}

fn submit(
    dir: &Path,
    owner: &str,
    requester: &str,
    plan: serde_json::Value,
    now: u64,
) -> serde_json::Value {
    submit_with_bounds(dir, owner, requester, plan, now, None)
}

fn submit_with_bounds(
    dir: &Path,
    owner: &str,
    requester: &str,
    plan: serde_json::Value,
    now: u64,
    bounds: Option<Vec<elastos_common::AuthorityBound>>,
) -> serde_json::Value {
    let record = submit_pending_agent_plan(
        dir,
        owner,
        requester,
        "capsule:agent-host",
        "session:agent-1",
        &plan,
        now,
    )
    .unwrap();
    if let Some(registry) = plan_registries().lock().unwrap().get(dir).cloned() {
        let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
        let manager = Arc::new(elastos_runtime::capability::CapabilityManager::new(
            Arc::new(elastos_runtime::capability::CapabilityStore::new()),
            audit.clone(),
            Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
        ));
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: registry,
            capability_manager: manager,
            pending_store: Arc::new(
                elastos_runtime::capability::pending::PendingRequestStore::new(audit),
            ),
            capsule_id: "capsule:agent-host".to_string(),
            session_id: "session:agent-1".to_string(),
            principal_id: Some(requester.to_string()),
            manifest_capabilities: bounds.unwrap_or_else(|| {
                (if requester == "agent:narrow" {
                    vec!["elastos://did/*"]
                } else {
                    vec![
                        "elastos://availability/*",
                        "localhost://UsersAI/*",
                        "localhost://Users/*",
                    ]
                })
                .into_iter()
                .map(|resource| elastos_common::AuthorityBound {
                    resource: resource.to_string(),
                    actions: None,
                })
                .collect()
            }),
            data_dir: Some(dir.to_path_buf()),
            launch: None,
            model_token_ceiling: Some(16),
            model_budget: None,
            stop: None,
        };
        crate::resource_bridge::retain_agent_plan_dispatch_authority(
            record["request_id"].as_str().unwrap(),
            owner,
            &ctx,
            &record["request"],
        )
        .unwrap();
    }
    record
}

async fn grant_admin_for_record(record: &serde_json::Value) {
    crate::resource_bridge::grant_agent_plan_capability_for_test(
        record["request_id"].as_str().unwrap(),
        &record["request"],
    )
    .await;
}

fn approve_body(
    request_id: &str,
    binding: &serde_json::Value,
    step_up_token: Option<&str>,
) -> serde_json::Value {
    let mut body = json!({
        "action_id": format!("agent-plan-approve-request:{request_id}"),
        "request_binding": binding,
    });
    if let Some(token) = step_up_token {
        body["step_up_token"] = json!(token);
    }
    body
}

fn record_path(dir: &Path, request_id: &str) -> std::path::PathBuf {
    dir.join("inspect-actions")
        .join(format!("{request_id}.json"))
}

fn read_record(dir: &Path, request_id: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(record_path(dir, request_id)).unwrap()).unwrap()
}

fn write_record(dir: &Path, request_id: &str, record: &serde_json::Value) {
    std::fs::write(
        record_path(dir, request_id),
        serde_json::to_vec_pretty(record).unwrap(),
    )
    .unwrap();
}

async fn agent_plan_cards(app: &Router, token: &str) -> Vec<serde_json::Value> {
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("GET")
                .uri("/api/apps/inbox/summary")
                .header("x-elastos-home-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    payload["notifications"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry["kind"] == "agent_plan")
        .collect()
}

async fn post_action(app: &Router, token: &str, body: serde_json::Value) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri("/api/apps/inbox/actions")
                .header("x-elastos-home-token", token)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The owner's one card for `request_id`: its action and exact binding.
async fn owner_card(app: &Router, token: &str, request_id: &str) -> serde_json::Value {
    let cards = agent_plan_cards(app, token).await;
    assert_eq!(cards.len(), 1, "{cards:?}");
    assert_eq!(
        cards[0]["action_ref"]["action_id"],
        format!("agent-plan-approve-request:{request_id}")
    );
    cards[0].clone()
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_approve_requires_the_exact_plan_shown() {
    // The binding the card showed is approved as shown after one fresh
    // passkey, and nothing runs.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(dir.path(), &owner.principal_id, &agent_id, read_plan(), 51);
    let request_id = created["request_id"].as_str().unwrap();
    grant_admin_for_record(&created).await;
    let card = owner_card(&app, &token, request_id).await;
    assert_eq!(card["request_binding"], created["request_binding"]);

    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Agent plan dispatch completed"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "completed");
    assert_eq!(record["request_binding"], created["request_binding"]);
    assert_eq!(record["result"]["status"], "ok");

    // A card hash other than the stored binding is refused and leaves the
    // record stale.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        52,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let mut wrong_card = created["request_binding"].clone();
    wrong_card["sha256"] = json!("00".repeat(32));
    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &wrong_card, Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("changed before Inbox approval"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "stale");
    assert!(record["result"].is_null(), "a stale plan runs nothing");

    // A changed non-hash card field is stale even when its sha256 is the
    // same. A launch token alone cannot write the stale decision.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        53,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &token, request_id).await;
    let mut wrong_card = card["request_binding"].clone();
    wrong_card["preview"]["step"]["operation"] = json!("changed");
    assert_eq!(wrong_card["sha256"], card["request_binding"]["sha256"]);
    let (status, body) =
        post_action(&app, &token, approve_body(request_id, &wrong_card, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");
    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &wrong_card, Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("changed before Inbox approval"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "stale");
    assert!(record["result"].is_null(), "a stale plan runs nothing");

    // A record changed after storing no longer matches the binding stored with
    // it, even when the click carries the old card value.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        53,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &token, request_id).await;
    let mut changed = read_record(dir.path(), request_id);
    changed["request"]["request"]["principal"] = json!("person:changed");
    write_record(dir.path(), request_id, &changed);
    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("changed before Inbox approval"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "stale");
    assert!(record["result"].is_null());

    // A record whose stored binding was changed under the same step is refused
    // too: the whole stored binding is compared, not only the recomputed one.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        54,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &token, request_id).await;
    let mut changed = read_record(dir.path(), request_id);
    changed["request_binding"]["sha256"] = json!("11".repeat(32));
    write_record(dir.path(), request_id, &changed);
    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("changed before Inbox approval"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "stale");
    assert!(record["result"].is_null());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_approve_is_the_owners_alone() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let other = passkey_authority_with_name_role_credential(
        dir.path(),
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Guest,
        "other-passkey",
    );
    let owner_token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let other_token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &other);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        61,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &owner_token, request_id).await;

    // Another person gets no agent-plan card and cannot approve this one.
    assert!(
        agent_plan_cards(&app, &other_token).await.is_empty(),
        "another principal gets no agent-plan card"
    );
    let (status, body) = post_action(
        &app,
        &other_token,
        approve_body(request_id, &card["request_binding"], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("its owner"), "{body}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");

    // The requesting agent cannot approve an agent plan, even one that names
    // the agent as its principal. An agent launch token is refused by the
    // gateway admission before any route, so this row drives the approve
    // decision itself with an Agent context.
    let agent = crate::auth::valid_agent::plant(dir.path());
    let agent_context = HomeLaunchTokenContext::for_test(
        agent.principal_id.clone(),
        "session:agent-test",
        None,
        "grant:agent-test",
        crate::auth::PrincipalKind::Agent,
    );
    let agent_launch = RequiredHomeLaunchToken {
        expires_at: crate::auth::now_ts() + 60,
        launch_id: "launch:agent-test".to_string(),
        launch_context: HomeLaunchContext {
            schema: "elastos.runtime.browser-launch/v1".to_string(),
            selected_resource: INBOX_CAPSULE_ID.to_string(),
            executable_actor: INBOX_CAPSULE_ID.to_string(),
            authority_actor: INBOX_CAPSULE_ID.to_string(),
        },
        context: agent_context.clone(),
        grant: super::gateway_home_token::VerifiedLaunchGrant::for_test(&agent.principal_id),
    };
    let state = agent_plan_state(dir.path());
    let refused = super::gateway_inspect_actions::approve_agent_plan_request(
        &state,
        &agent_launch,
        &agent_context,
        request_id,
        &card["request_binding"],
        None,
    )
    .unwrap_err();
    assert!(refused.to_string().contains("its owner"), "{refused}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");

    let self_owned = submit(
        dir.path(),
        &agent.principal_id,
        &agent.principal_id,
        read_plan(),
        62,
    );
    let self_id = self_owned["request_id"].as_str().unwrap();
    let refused = super::gateway_inspect_actions::approve_agent_plan_request(
        &state,
        &agent_launch,
        &agent_context,
        self_id,
        &self_owned["request_binding"],
        None,
    )
    .unwrap_err();
    assert!(refused.to_string().contains("its owner"), "{refused}");
    assert_eq!(read_record(dir.path(), self_id)["status"], "pending");
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_approve_a_writing_step_needs_a_fresh_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        write_plan(),
        71,
    );
    let request_id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &token, request_id).await;

    // A writing step with no passkey stays pending.
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("fresh passkey"), "{body}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");

    // A stale passkey is refused and the record stays pending.
    let stale = stale_step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&stale)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("passkey step-up"), "{body}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");

    // A fresh passkey bound to another request is refused.
    let other_request = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": "inspect-act-other" }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&other_request)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("passkey step-up"), "{body}");
    assert_eq!(read_record(dir.path(), request_id)["status"], "pending");

    // A fresh passkey approves the card; the protected-root bridge then
    // refuses this synthetic agent, which has no stored principal root.
    let fresh = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({ "request_id": request_id }),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Agent plan dispatch refused"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "refused");
    assert_eq!(record["result"]["status"], "refused");
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_double_clicks_claim_one_plan() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(routed_agent_plan_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(dir.path(), &owner.principal_id, &agent_id, read_plan(), 81);
    let request_id = created["request_id"].as_str().unwrap();
    grant_admin_for_record(&created).await;
    let card = owner_card(&app, &token, request_id).await;
    let passkey = || {
        step_up_token_for_app_context(
            dir.path(),
            INBOX_CAPSULE_ID,
            &token,
            "agent_plan.approve",
            &json!({ "request_id": request_id }),
        )
    };
    let first_token = passkey();
    let second_token = passkey();
    let first = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&first_token)),
    )
    .await;
    let second = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&second_token)),
    )
    .await;
    let outcomes = [first, second];
    assert_eq!(
        outcomes
            .iter()
            .filter(|(status, _)| *status == StatusCode::OK)
            .count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(status, _)| *status == StatusCode::BAD_REQUEST)
            .count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(read_record(dir.path(), request_id)["status"], "completed");
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_dispatch_once_stored_body_receipt_and_audit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let app = gateway_router(state.clone());
    let owner = passkey_authority(dir.path());
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let plan = json!({"steps": [{"scheme": "availability", "operation": "status",
        "request": {"literal": "stored-body"}}]});
    let created = submit(dir.path(), &owner.principal_id, &agent_id, plan, 91);
    let request_id = created["request_id"].as_str().unwrap();
    grant_admin_for_record(&created).await;
    let card = owner_card(&app, &token, request_id).await;
    let passkey = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({"request_id": request_id}),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&passkey)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        *calls.lock().await,
        vec![json!({"op": "status", "literal": "stored-body"})]
    );
    let receipt = super::gateway_inspect_actions::agent_plan_result_for_requester(
        dir.path(),
        request_id,
        &owner.principal_id,
        &agent_id,
        "capsule:agent-host",
        "session:agent-1",
    )
    .unwrap();
    assert_eq!(receipt["schema"], "elastos.agent-plan.result/v1");
    assert_eq!(receipt["request_binding"], created["request_binding"]);
    assert_eq!(
        receipt["dispatch_result"]["data"]["observed"]["literal"],
        "stored-body"
    );
    assert_eq!(read_record(dir.path(), request_id)["status"], "completed");
    let auth = crate::auth::load_auth_state(dir.path()).unwrap();
    let audit = auth
        .audit
        .iter()
        .find(|event| {
            event.event_type == "agent_plan.dispatch.completed"
                && event.challenge_id.as_deref() == Some(request_id)
        })
        .expect("signed effect audit");
    assert_eq!(audit.result, "completed");
    assert!(audit.signature.is_some());
}

async fn approve_plan_for_row(
    dir: &Path,
    state: GatewayState,
    requester: &str,
    plan: serde_json::Value,
) -> (String, serde_json::Value) {
    approve_plan_for_row_with_grant(dir, state, requester, plan, true).await
}

async fn approve_plan_for_row_with_grant(
    dir: &Path,
    state: GatewayState,
    requester: &str,
    plan: serde_json::Value,
    admin_grant: bool,
) -> (String, serde_json::Value) {
    let app = gateway_router(state);
    let owner = passkey_authority(dir);
    let agent_id = if crate::agents::stored_agent(dir, &owner.principal_id, requester).is_ok() {
        requester.to_string()
    } else {
        crate::agents::tests::plant_for_dispatch(dir, &owner.principal_id, &owner.principal_id)
    };
    let token = app_token_for_authority(dir, INBOX_CAPSULE_ID, &owner);
    let created = submit(dir, &owner.principal_id, &agent_id, plan, 190);
    let request_id = created["request_id"].as_str().unwrap();
    if requester == "agent:narrow" {
        crate::resource_bridge::narrow_agent_plan_manifest_for_test(request_id);
    }
    if admin_grant && created["request"]["scheme"] == "availability" {
        grant_admin_for_record(&created).await;
    }
    let card = owner_card(&app, &token, request_id).await;
    let passkey = step_up_token_for_app_context(
        dir,
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({"request_id": request_id}),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(request_id, &card["request_binding"], Some(&passkey)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (request_id.to_string(), read_record(dir, request_id))
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_cross_person_zero_provider_calls() {
    // A approves the exact card. The bridge's principal-root rule refuses B.
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let b = passkey_authority_with_name_role(
        dir.path(),
        Some("B"),
        crate::auth::RuntimePrincipalRole::Guest,
    );
    let a = passkey_authority(dir.path());
    let agent_id =
        crate::agents::tests::plant_for_dispatch(dir.path(), &a.principal_id, &a.principal_id);
    let b_uri = format!(
        "{}/Documents/notes.md",
        crate::auth::principal_localhost_root(&b.principal_id)
    );
    let b_file = elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &b_uri).unwrap();
    std::fs::create_dir_all(b_file.parent().unwrap()).unwrap();
    std::fs::write(&b_file, b"B's original note").unwrap();
    let (id, record) = approve_plan_for_row(
        dir.path(),
        state,
        &agent_id,
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": b_uri,
            "content": [99, 104, 97, 110, 103, 101]
        }}]}),
    )
    .await;
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "invalid_resource_invoke");
    assert!(calls.lock().await.is_empty());
    assert_eq!(std::fs::read(&b_file).unwrap(), b"B's original note");
    assert!(crate::auth::load_auth_state(dir.path())
        .unwrap()
        .audit
        .iter()
        .any(|event| {
            event.event_type == "agent_plan.dispatch.refused"
                && event.challenge_id.as_deref() == Some(id.as_str())
        }));
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_protected_root_zero_provider_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    crate::auth::store_test_human_principal(dir.path(), crate::auth::valid_agent::OWNER_ID);
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        crate::auth::valid_agent::OWNER_ID,
        crate::auth::valid_agent::OWNER_ID,
    );
    let root = crate::auth::principal_stored_localhost_root(Some(dir.path()), &agent_id).unwrap();
    let target = format!("{root}/Documents/plan.md");
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &target).unwrap();
    crate::auth::write_principal_root_object(
        dir.path(),
        &agent_id,
        &root,
        &target,
        &path,
        b"already exists",
    )
    .unwrap();
    let created = submit(
        dir.path(),
        crate::auth::valid_agent::OWNER_ID,
        &agent_id,
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target,
            "content": [112, 108, 97, 110], "create_only": true
        }}]}),
        191,
    );
    let id = created["request_id"].as_str().unwrap();
    set_approved(dir.path(), id);
    super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &state,
        &dispatch_context(crate::auth::valid_agent::OWNER_ID),
        id,
    )
    .await
    .unwrap();
    let record = read_record(dir.path(), id);
    assert_eq!(record["status"], "failed", "{record}");
    assert_eq!(record["result"]["code"], "provider_result_error");
    assert_eq!(
        crate::auth::read_principal_root_object(dir.path(), &agent_id, &root, &target, &path,)
            .unwrap(),
        b"already exists"
    );
    assert!(calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_manifest_ceiling_zero_provider_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let (_, record) = approve_plan_for_row(dir.path(), state, "agent:narrow", read_plan()).await;
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "manifest_capability_denied");
    assert!(calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_shared_resource_requires_admin_grant() {
    for granted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
        let app = gateway_router(state);
        let admin = passkey_authority(dir.path());
        let owner = passkey_authority_with_name_role(
            dir.path(),
            Some("Agent owner"),
            crate::auth::RuntimePrincipalRole::Guest,
        );
        let agent_id = crate::agents::tests::plant_for_dispatch(
            dir.path(),
            &owner.principal_id,
            &admin.principal_id,
        );
        let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
        let created = submit(dir.path(), &owner.principal_id, &agent_id, read_plan(), 199);
        if granted {
            grant_admin_for_record(&created).await;
        }
        let id = created["request_id"].as_str().unwrap();
        let card = owner_card(&app, &token, id).await;
        let passkey = step_up_token_for_app_context(
            dir.path(),
            INBOX_CAPSULE_ID,
            &token,
            "agent_plan.approve",
            &json!({"request_id": id}),
        );
        let (status, body) = post_action(
            &app,
            &token,
            approve_body(id, &card["request_binding"], Some(&passkey)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let record = read_record(dir.path(), id);
        if granted {
            assert_eq!(record["status"], "completed", "{record}");
            assert_eq!(calls.lock().await.len(), 1);
        } else {
            assert_eq!(record["status"], "refused", "{record}");
            assert_eq!(record["result"]["code"], "needs_admin_grant");
            assert!(calls.lock().await.is_empty());
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_agent_standing_rechecked_at_dispatch() {
    for disable in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
        let owner = passkey_authority(dir.path());
        let agent_id = crate::agents::tests::plant_for_dispatch(
            dir.path(),
            &owner.principal_id,
            &owner.principal_id,
        );
        let created = submit(dir.path(), &owner.principal_id, &agent_id, read_plan(), 201);
        grant_admin_for_record(&created).await;
        let id = created["request_id"].as_str().unwrap();
        set_approved(dir.path(), id);
        crate::agents::tests::stop_dispatch_agent(
            dir.path(),
            &owner.principal_id,
            &agent_id,
            disable,
        );
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner.principal_id),
            id,
        )
        .await
        .unwrap();
        let record = read_record(dir.path(), id);
        assert_eq!(record["status"], "refused", "{record}");
        assert_eq!(record["result"]["code"], "agent_inactive");
        assert!(calls.lock().await.is_empty());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_approved_own_root_write_completes_once() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let owner = passkey_authority(dir.path());
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let root = crate::auth::principal_stored_localhost_root(Some(dir.path()), &agent_id).unwrap();
    let target = format!("{root}/Documents/approved.md");
    let app = gateway_router(state.clone());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        &agent_id,
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]}),
        200,
    );
    let id = created["request_id"].as_str().unwrap();
    let card = owner_card(&app, &token, id).await;
    let passkey = step_up_token_for_app_context(
        dir.path(),
        INBOX_CAPSULE_ID,
        &token,
        "agent_plan.approve",
        &json!({"request_id": id}),
    );
    let (status, body) = post_action(
        &app,
        &token,
        approve_body(id, &card["request_binding"], Some(&passkey)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(read_record(dir.path(), id)["status"], "completed");
    assert!(crate::resource_bridge::own_root_token_replay_refused_for_test(id).await);
    assert!(calls.lock().await.is_empty());
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &target).unwrap();
    assert_eq!(
        crate::auth::read_principal_root_object(dir.path(), &agent_id, &root, &target, &path,)
            .unwrap(),
        b"plan"
    );
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner.principal_id),
            id,
        )
        .await
        .is_err()
    );
    assert!(calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_transport_error_is_unknown_and_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let (_, record) = approve_plan_for_row(
        dir.path(),
        state,
        "agent:requester",
        json!({"steps": [{"scheme": "availability", "operation": "status", "request": {
            "transport_error": true
        }}]}),
    )
    .await;
    assert_eq!(calls.lock().await.len(), 1);
    assert_eq!(record["status"], "unknown");
    assert_eq!(record["result"]["code"], "provider_transport_error");
    assert!(!record.to_string().contains("private provider diagnostic"));
}

#[tokio::test]
async fn a15r_unapproved_zero_provider_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let created = submit(
        dir.path(),
        "person:owner",
        "agent:requester",
        read_plan(),
        92,
    );
    let id = created["request_id"].as_str().unwrap();
    let refused = super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &state,
        &dispatch_context("person:owner"),
        id,
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("not approved"), "{refused}");
    assert!(calls.lock().await.is_empty());
    assert_eq!(read_record(dir.path(), id)["status"], "pending");
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_replay_zero_after_restart_and_cancelled_request() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    crate::auth::store_test_human_principal(dir.path(), crate::auth::valid_agent::OWNER_ID);
    let agent_id = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        crate::auth::valid_agent::OWNER_ID,
        crate::auth::valid_agent::OWNER_ID,
    );
    let created = submit(
        dir.path(),
        crate::auth::valid_agent::OWNER_ID,
        &agent_id,
        read_plan(),
        93,
    );
    let id = created["request_id"].as_str().unwrap();
    grant_admin_for_record(&created).await;
    set_approved(dir.path(), id);
    let context = dispatch_context(crate::auth::valid_agent::OWNER_ID);
    super::gateway_inspect_actions::dispatch_approved_agent_plan(&state, &context, id)
        .await
        .unwrap();
    assert_eq!(calls.lock().await.len(), 1);
    let (restarted, calls_after_restart) = agent_plan_dispatch_state(dir.path()).await;
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(&restarted, &context, id)
            .await
            .is_err()
    );
    assert_eq!(calls.lock().await.len(), 1);
    assert!(calls_after_restart.lock().await.is_empty());

    let unknown = submit(
        dir.path(),
        crate::auth::valid_agent::OWNER_ID,
        &agent_id,
        json!({"steps": [{"scheme": "availability", "operation": "status",
            "request": {"hang": true}}]}),
        94,
    );
    let unknown_id = unknown["request_id"].as_str().unwrap();
    grant_admin_for_record(&unknown).await;
    set_approved(dir.path(), unknown_id);
    let id_for_task = unknown_id.to_string();
    let state_for_task = state.clone();
    let context_for_task = context.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state_for_task,
            &context_for_task,
            &id_for_task,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while calls.lock().await.len() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider reached after durable claim");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if !read_record(dir.path(), unknown_id)["result"].is_null() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached settlement completes after request cancellation");
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &restarted, &context, unknown_id
        )
        .await
        .is_err()
    );
    assert_eq!(read_record(dir.path(), unknown_id)["status"], "completed");
    assert!(!read_record(dir.path(), unknown_id)["result"].is_null());
    let audit = crate::auth::load_auth_state(dir.path()).unwrap().audit;
    assert!(audit.iter().any(|event| {
        event.event_type == "agent_plan.dispatch.started"
            && event.challenge_id.as_deref() == Some(unknown_id)
            && event.signature.is_some()
    }));
    assert_eq!(calls.lock().await.len(), 2);
    assert!(calls_after_restart.lock().await.is_empty());
}

#[tokio::test]
async fn a15r_stale_zero_after_binding_or_gate_change() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let context = dispatch_context("person:owner");
    let changed = submit(
        dir.path(),
        "person:owner",
        "agent:requester",
        read_plan(),
        96,
    );
    let id = changed["request_id"].as_str().unwrap();
    set_approved(dir.path(), id);
    let mut record = read_record(dir.path(), id);
    record["request"]["request"]["changed"] = json!(true);
    write_record(dir.path(), id, &record);
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(&state, &context, id)
            .await
            .is_err()
    );
    assert_eq!(read_record(dir.path(), id)["status"], "stale");
    assert!(calls.lock().await.is_empty());

    let changed = submit(
        dir.path(),
        "person:owner",
        "agent:requester",
        read_plan(),
        97,
    );
    let id = changed["request_id"].as_str().unwrap();
    set_approved(dir.path(), id);
    let mut record = read_record(dir.path(), id);
    record["plan"]["operation"] = json!("changed");
    write_record(dir.path(), id, &record);
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(&state, &context, id)
            .await
            .is_err()
    );
    assert!(calls.lock().await.is_empty());
}

#[tokio::test]
async fn a15r_current_gate_recheck_refuses_rebound_preview() {
    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let created = submit(
        dir.path(),
        "person:owner",
        "agent:requester",
        read_plan(),
        198,
    );
    let id = created["request_id"].as_str().unwrap();
    set_approved(dir.path(), id);
    let mut record = read_record(dir.path(), id);
    record["plan"]["operation"] = json!("changed");
    write_record(dir.path(), id, &record);
    super::gateway_inspect_actions::rebind_agent_plan_for_test(dir.path(), id).unwrap();
    let refused = super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &state,
        &dispatch_context("person:owner"),
        id,
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(read_record(dir.path(), id)["status"], "stale");
    assert!(calls.lock().await.is_empty());
}

// The literal stays with the slice 7 refusal rows. The joined row runs the
// Agent Host planner and reads its preview and submitted bytes instead.
const REAL_STEP: &str = "{\"operation\":\"write\",\"request\":{\"content\":[116,104,114,101,101,32,108,105,110,101,115],\"path\":\"localhost://UsersAI/self/Documents/note.txt\"},\"scheme\":\"localhost\"}";

fn real_planner_output() -> (serde_json::Value, Vec<u8>, String) {
    let temp = tempfile::tempdir().unwrap();
    let preview = temp.path().join("preview.json");
    let submitted = temp.path().join("submitted.json");
    let journal = temp.path().join("journal.txt");
    let host_manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../examples/agent-host/Cargo.toml");
    let host_target = host_manifest.parent().unwrap().join("target");
    let output = std::process::Command::new("cargo")
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(host_manifest)
        .arg("--target-dir")
        .arg(host_target)
        .arg("--lib")
        .arg("tests::a15r_june_plan_preview_and_submit_keep_the_document_step")
        .arg("--")
        .arg("--exact")
        .env("A15R_PREVIEW_STEP_PATH", &preview)
        .env("A15R_SUBMIT_PLAN_PATH", &submitted)
        .env("A15R_JOURNAL_PATH", &journal)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("run the Agent Host planner");
    assert!(
        output.status.success(),
        "Agent Host planner failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let preview_bytes = std::fs::read(preview).expect("planner preview bytes");
    let submitted_bytes = std::fs::read(submitted).expect("planner submit bytes");
    let plan: serde_json::Value = serde_json::from_slice(&submitted_bytes).unwrap();
    assert_eq!(
        serde_json::to_vec(&plan["steps"][0]).unwrap(),
        preview_bytes,
        "the submitted step is the previewed step"
    );
    let journal_uri = std::fs::read_to_string(journal).expect("guest journal URI");
    (plan, preview_bytes, journal_uri)
}

fn real_submit(dir: &Path, owner: &str, agent: &str, now: u64) -> serde_json::Value {
    let manifest: elastos_common::CapsuleManifest = serde_json::from_str(include_str!(
        "../../../../../../examples/agent-host/capsule.json"
    ))
    .unwrap();
    assert_eq!(manifest.asks.len(), 3);
    let step = serde_json::from_str::<serde_json::Value>(REAL_STEP).unwrap();
    submit_with_bounds(
        dir,
        owner,
        agent,
        json!({"steps": [step]}),
        now,
        Some(manifest.resource_authority_bounds()),
    )
}

fn real_object(dir: &Path, principal: &str, uri: &str) -> anyhow::Result<Vec<u8>> {
    let root = crate::auth::principal_stored_localhost_root(Some(dir), principal).unwrap();
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir, uri).unwrap();
    crate::auth::read_principal_root_object(dir, principal, &root, uri, &path)
}

struct RealCase {
    dir: tempfile::TempDir,
    state: GatewayState,
    app: Router,
    calls: Arc<TokioMutex<Vec<serde_json::Value>>>,
    owner: String,
    agent: String,
    token: String,
    id: String,
}

impl RealCase {
    async fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
        let app = gateway_router(state.clone());
        let owner = passkey_authority(dir.path());
        let agent = crate::agents::tests::plant_for_dispatch(
            dir.path(),
            &owner.principal_id,
            &owner.principal_id,
        );
        let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
        Self {
            dir,
            state,
            app,
            calls,
            owner: owner.principal_id,
            agent,
            token,
            id: String::new(),
        }
    }

    async fn new(now: u64) -> Self {
        let mut case = Self::empty().await;
        case.next(now);
        case
    }

    async fn from_guest(
        plan: &serde_json::Value,
        journal_uri: &str,
    ) -> (Self, String, String, String) {
        let mut case = Self::empty().await;
        let (response, journal, capsule, session) =
            crate::resource_bridge::tests::a15r_guest_journal_and_submit(
                case.dir.path(),
                &case.agent,
                journal_uri,
                plan,
            )
            .await;
        case.id = response["response"]["result"]["data"]["request_id"]
            .as_str()
            .expect("bridge pending record id")
            .to_string();
        (case, journal, capsule, session)
    }

    fn record(&self) -> serde_json::Value {
        read_record(self.dir.path(), &self.id)
    }
    fn target(&self) -> String {
        let root = crate::auth::principal_stored_localhost_root(Some(self.dir.path()), &self.agent)
            .unwrap();
        format!("{root}/Documents/note.txt")
    }
    fn object(&self) -> anyhow::Result<Vec<u8>> {
        real_object(self.dir.path(), &self.agent, &self.target())
    }
    async fn card(&self) -> serde_json::Value {
        owner_card(&self.app, &self.token, &self.id).await
    }
    async fn click(&self, binding: &serde_json::Value, fresh: bool) -> (StatusCode, String) {
        let passkey = fresh.then(|| {
            step_up_token_for_app_context(
                self.dir.path(),
                INBOX_CAPSULE_ID,
                &self.token,
                "agent_plan.approve",
                &json!({"request_id": self.id}),
            )
        });
        post_action(
            &self.app,
            &self.token,
            approve_body(&self.id, binding, passkey.as_deref()),
        )
        .await
    }
    async fn dispatch(&self) -> anyhow::Result<String> {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &self.state,
            &dispatch_context(&self.owner),
            &self.id,
        )
        .await
    }
    fn audit(&self, event_type: &str) -> usize {
        crate::auth::load_auth_state(self.dir.path())
            .unwrap()
            .audit
            .iter()
            .filter(|event| {
                event.event_type == event_type
                    && event.challenge_id.as_deref() == Some(&self.id)
                    && event.signature.is_some()
            })
            .count()
    }
    fn next(&mut self, now: u64) {
        let created = real_submit(self.dir.path(), &self.owner, &self.agent, now);
        self.id = created["request_id"].as_str().unwrap().to_string();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_journey_one_step_one_result() {
    if !crate::agents::build_allows() {
        assert_eq!(
            crate::agents::require_build().unwrap_err().to_string(),
            crate::agents::FEATURE_OFF
        );
        return;
    }
    let (plan, proposed, journal_alias) = real_planner_output();
    let (case, journal_uri, capsule, session) = RealCase::from_guest(&plan, &journal_alias).await;
    let person_root =
        crate::auth::principal_stored_localhost_root(Some(case.dir.path()), &case.owner).unwrap();
    let person_target = format!("{person_root}/Documents/note.txt");
    let person_path =
        elastos_common::localhost::rooted_localhost_fs_path(case.dir.path(), &person_target)
            .unwrap();
    crate::auth::write_principal_root_object(
        case.dir.path(),
        &case.owner,
        &person_root,
        &person_target,
        &person_path,
        b"person's note",
    )
    .unwrap();
    let record = case.record();
    assert_eq!(record["status"], "pending");
    assert_eq!(
        std::fs::read_dir(case.dir.path().join("inspect-actions"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(serde_json::to_vec(&record["request"]).unwrap(), proposed);
    assert_eq!(record["request"], plan["steps"][0]);
    assert_eq!(
        real_object(case.dir.path(), &case.agent, &journal_uri).unwrap(),
        b"agent journal v1"
    );
    let card = case.card().await;
    assert_eq!(card["request_binding"], record["request_binding"]);
    assert!(card["body"]
        .as_str()
        .unwrap()
        .contains(&format!("Step 1: {}", String::from_utf8_lossy(&proposed))));
    let hash = card["request_binding"]["sha256"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(card["body"]
        .as_str()
        .unwrap()
        .contains(&format!("Binding sha256: {hash}")));
    assert_eq!(
        case.click(&card["request_binding"], false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(case.record()["status"], "pending");
    assert!(case.object().is_err());
    let (status, body) = case.click(&card["request_binding"], true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Agent plan dispatch completed"), "{body}");
    let record = case.record();
    assert_eq!(record["status"], "completed");
    assert_eq!(record["result"]["status"], "ok");
    assert_eq!(
        std::fs::read_dir(case.dir.path().join("inspect-actions"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(case.object().unwrap(), b"three lines");
    assert_eq!(
        real_object(case.dir.path(), &case.owner, &person_target).unwrap(),
        b"person's note"
    );
    assert!(case.calls.lock().await.is_empty());
    assert_eq!(case.audit("agent_plan.dispatch.started"), 1);
    assert_eq!(case.audit("agent_plan.dispatch.completed"), 1);
    assert_eq!(record["principal_id"], case.owner, "{record}");
    assert_eq!(record["requester_id"], case.agent, "{record}");
    assert_eq!(record["id"], capsule, "{record}");
    assert_eq!(record["session_id"], session, "{record}");
    let receipt = super::gateway_inspect_actions::agent_plan_result_for_requester(
        case.dir.path(),
        &case.id,
        &case.owner,
        &case.agent,
        &capsule,
        &session,
    )
    .unwrap();
    assert_eq!(receipt["schema"], "elastos.agent-plan.result/v1");
    assert_eq!(receipt["request_binding"], record["request_binding"]);
    assert_eq!(receipt["dispatch_result"], record["result"]);
    assert!(agent_plan_cards(&case.app, &case.token).await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_unapproved_zero() {
    let case = RealCase::new(303).await;
    assert!(case
        .dispatch()
        .await
        .unwrap_err()
        .to_string()
        .contains("not approved"));
    assert_eq!(case.record()["status"], "pending");
    assert!(case.object().is_err());
    assert!(case.calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_changed_plan_zero() {
    let case = RealCase::new(304).await;
    set_approved(case.dir.path(), &case.id);
    let mut changed = case.record();
    changed["request_binding"]["sha256"] = json!("0".repeat(64));
    write_record(case.dir.path(), &case.id, &changed);
    assert!(case.dispatch().await.is_err());
    assert_eq!(case.record()["status"], "stale");
    assert!(case.object().is_err());
    assert!(case.calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_self_approval_zero() {
    let case = RealCase::new(305).await;
    let context = HomeLaunchTokenContext::for_test(
        case.agent.clone(),
        "session:agent-test",
        None,
        "grant:agent-test",
        crate::auth::PrincipalKind::Agent,
    );
    let launch = RequiredHomeLaunchToken {
        expires_at: crate::auth::now_ts() + 60,
        launch_id: "launch:agent-test".to_string(),
        launch_context: HomeLaunchContext {
            schema: "elastos.runtime.browser-launch/v1".to_string(),
            selected_resource: INBOX_CAPSULE_ID.to_string(),
            executable_actor: INBOX_CAPSULE_ID.to_string(),
            authority_actor: INBOX_CAPSULE_ID.to_string(),
        },
        context: context.clone(),
        grant: super::gateway_home_token::VerifiedLaunchGrant::for_test(&case.agent),
    };
    let refused = super::gateway_inspect_actions::approve_agent_plan_request(
        &case.state,
        &launch,
        &context,
        &case.id,
        &case.record()["request_binding"],
        None,
    )
    .unwrap_err();
    assert!(refused.to_string().contains("its owner"), "{refused}");
    assert_eq!(case.record()["status"], "pending");
    assert!(case.object().is_err());
    assert!(case.calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_replay_zero() {
    let case = RealCase::new(306).await;
    let card = case.card().await;
    let fresh = step_up_token_for_app_context(
        case.dir.path(),
        INBOX_CAPSULE_ID,
        &case.token,
        "agent_plan.approve",
        &json!({"request_id": case.id}),
    );
    let body = approve_body(&case.id, &card["request_binding"], Some(&fresh));
    assert_eq!(
        post_action(&case.app, &case.token, body.clone()).await.0,
        StatusCode::OK
    );
    assert_ne!(
        post_action(&case.app, &case.token, body).await.0,
        StatusCode::OK
    );
    assert!(case.dispatch().await.is_err());
    assert_eq!(case.object().unwrap(), b"three lines");
    assert_eq!(case.audit("agent_plan.dispatch.started"), 1);
    assert!(case.calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a15r_real_restart_zero() {
    let case = RealCase::new(307).await;
    let card = case.card().await;
    assert_eq!(
        case.click(&card["request_binding"], true).await.0,
        StatusCode::OK
    );
    let before = case.record();
    let (restarted, after_calls) = agent_plan_dispatch_state(case.dir.path()).await;
    assert!(
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &restarted,
            &dispatch_context(&case.owner),
            &case.id
        )
        .await
        .is_err()
    );
    assert_eq!(case.record(), before);
    assert_eq!(case.audit("agent_plan.dispatch.started"), 1);
    assert!(case.calls.lock().await.is_empty() && after_calls.lock().await.is_empty());
}
