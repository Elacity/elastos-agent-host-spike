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
        if request["provider_result_error"] == true {
            return Ok(json!({"status": "error"}));
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
        let mut ctx = crate::resource_bridge::BridgeContext {
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
            plan_book: None,
        };
        crate::runtime::Runtime::bind_detached_plan_for_test(
            &mut ctx,
            "capsule:agent-host",
            requester,
        );
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
        issued_at: crate::auth::now_ts(),
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
        issued_at: crate::auth::now_ts(),
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

/// Where an approved step is held, and how the instance ends while it is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlanRowEnd {
    Stop,
    Completed,
    Retire,
    AgentsOff,
}

struct IdleCompute;

#[async_trait::async_trait]
impl elastos_compute::ComputeProvider for IdleCompute {
    async fn load(
        &self,
        _: &std::path::Path,
        _: elastos_common::CapsuleManifest,
    ) -> elastos_common::Result<elastos_compute::CapsuleHandle> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn start(&self, _: &elastos_compute::CapsuleHandle) -> elastos_common::Result<()> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn stop(&self, _: &elastos_compute::CapsuleHandle) -> elastos_common::Result<()> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn status(
        &self,
        _: &elastos_compute::CapsuleHandle,
    ) -> elastos_common::Result<elastos_common::CapsuleStatus> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn info(
        &self,
        _: &elastos_compute::CapsuleHandle,
    ) -> elastos_common::Result<elastos_compute::CapsuleInfo> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    fn supports(&self, _: &elastos_common::CapsuleType) -> bool {
        false
    }
}

fn plan_bytes(dir: &Path, agent: &str, root: &str, target: &str) -> Vec<u8> {
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir, target).unwrap();
    crate::auth::read_principal_root_object(dir, agent, root, target, &path).unwrap()
}

async fn stop_plan_agent(
    runtime: Arc<crate::runtime::Runtime>,
    agent: &str,
) -> (StatusCode, serde_json::Value) {
    let response = crate::api::routes::stop_agent_session(
        axum::Extension(runtime),
        axum::Extension(Arc::new(elastos_runtime::primitives::audit::AuditLog::new())),
        axum::body::Bytes::from(serde_json::to_vec(&json!({ "agent_id": agent })).unwrap()),
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or(json!(String::from_utf8_lossy(&bytes).to_string())),
    )
}

/// An approved own-root step cannot start, or write, after the instance ends.
/// The hold is before the running check, after the one-use token is registered,
/// or immediately before the write. Stop, natural completion, retire, and
/// agents off are applied while the hold is set. The file stays as it was,
/// except when the write had already reached the effect: that write lands,
/// and Stop's answer while it was held is `stopping` (202).
#[cfg(unix)]
#[tokio::test]
async fn an_approved_step_does_not_write_after_the_instance_ends() {
    use crate::resource_bridge::PlanDispatchPoint;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ROWS: AtomicU64 = AtomicU64::new(1);
    let points = [
        PlanDispatchPoint::BeforeCheck,
        PlanDispatchPoint::AfterToken,
        PlanDispatchPoint::InEffect,
    ];
    let ends = [
        PlanRowEnd::Stop,
        PlanRowEnd::Completed,
        PlanRowEnd::Retire,
        PlanRowEnd::AgentsOff,
    ];
    for point in points {
        for end in ends {
            let n = ROWS.fetch_add(1, Ordering::Relaxed);
            plan_inflight_row(point, end, n).await;
        }
    }
}

async fn plan_inflight_row(
    point: crate::resource_bridge::PlanDispatchPoint,
    end: PlanRowEnd,
    n: u64,
) {
    use crate::resource_bridge::PlanDispatchPoint;

    let dir = tempfile::tempdir().unwrap();
    let (state, calls) = agent_plan_dispatch_state(dir.path()).await;
    let owner = passkey_authority(dir.path());
    let agent = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let root = crate::auth::principal_stored_localhost_root(Some(dir.path()), &agent).unwrap();
    let target = format!("{root}/Documents/plan.md");
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &target).unwrap();
    crate::auth::write_principal_root_object(dir.path(), &agent, &root, &target, &path, b"before")
        .unwrap();
    let before_raw = std::fs::read(&path).unwrap();

    let storage = dir.path().join("cap-storage");
    std::fs::create_dir_all(&storage).unwrap();
    let runtime = Arc::new(crate::runtime::Runtime::new(
        Arc::new(
            elastos_storage::providers::LocalFSProvider::new(storage)
                .await
                .unwrap(),
        ),
        Arc::new(IdleCompute),
    ));
    let session = format!("session-plan-{n}");
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.clone(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.clone(),
            principal: Some(agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: agent.clone(),
            owner: owner.principal_id.clone(),
            host_cid: "cid".to_string(),
            launch_id: format!("launch:{session}"),
            session_id: session.clone(),
        })
        .await;
    runtime.bind_plan_instance(&session, &agent);

    let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let manager = Arc::new(elastos_runtime::capability::CapabilityManager::new(
        Arc::new(elastos_runtime::capability::CapabilityStore::new()),
        audit.clone(),
        Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
    ));
    let store = Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit));
    runtime
        .set_provider_registry(
            state.provider_registry.clone().unwrap(),
            manager.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        )
        .await;
    let plan = json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
        "path": target, "content": [112, 108, 97, 110]
    }}]});
    let created = crate::api::gateway::submit_pending_agent_plan(
        dir.path(),
        &owner.principal_id,
        &agent,
        &session,
        &session,
        &plan,
        400 + n,
    )
    .unwrap();
    let id = created["request_id"].as_str().unwrap().to_string();
    let registry = state.provider_registry.clone().unwrap();
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: registry,
        capability_manager: manager.clone(),
        pending_store: store.clone(),
        capsule_id: session.clone(),
        session_id: session.clone(),
        principal_id: Some(agent.clone()),
        manifest_capabilities: [
            "elastos://availability/*",
            "localhost://UsersAI/*",
            "localhost://Users/*",
        ]
        .into_iter()
        .map(|resource| elastos_common::AuthorityBound {
            resource: resource.to_string(),
            actions: None,
        })
        .collect(),
        data_dir: Some(dir.path().to_path_buf()),
        launch: None,
        model_token_ceiling: Some(16),
        model_budget: None,
        stop: None,
        plan_book: Some(runtime.plan_book()),
    };
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        &id,
        &owner.principal_id,
        &ctx,
        &created["request"],
    )
    .unwrap();
    set_approved(dir.path(), &id);
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(&id, point);
    let state_for_dispatch = state.clone();
    let owner_id = owner.principal_id.clone();
    let request_id = id.clone();
    let dispatch = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state_for_dispatch,
            &dispatch_context(&owner_id),
            &request_id,
        )
        .await
    });
    let reached =
        tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified()).await;
    assert!(reached.is_ok(), "{point:?} {end:?} did not reach its seam");

    let mut stop_guard = None;
    if point == PlanDispatchPoint::InEffect && end == PlanRowEnd::Stop {
        let (status, body) = stop_plan_agent(Arc::clone(&runtime), &agent).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{point:?} {end:?} {body}");
        assert!(
            body["stopped"]
                .as_array()
                .is_some_and(|rows| rows.is_empty()),
            "Stop said stopped while the write can still land: {body}"
        );
        assert!(body.get("already").is_none(), "{body}");
        assert_eq!(body["stopping"][0]["status"], "stopping", "{body}");
        assert_eq!(
            plan_bytes(dir.path(), &agent, &root, &target),
            b"before",
            "{point:?} {end:?} wrote before Stop answered"
        );
    } else {
        match end {
            PlanRowEnd::Stop => {
                // `begin_agent_stop` does not end the instance. Before the
                // effect is admitted, Stop goes through the product route,
                // which is what ends this row.
                if point == PlanDispatchPoint::BeforeCheck {
                    let (status, body) = stop_plan_agent(Arc::clone(&runtime), &agent).await;
                    assert_eq!(status, StatusCode::OK, "{point:?} {end:?} {body}");
                } else {
                    stop_guard = Some(runtime.begin_agent_stop(&agent).await);
                }
                if point == PlanDispatchPoint::AfterToken {
                    crate::api::handlers::settle::settle_and_revoke(
                        &store,
                        &manager,
                        dir.path(),
                        &session,
                        "stopped: owner",
                    )
                    .await
                    .unwrap();
                }
            }
            PlanRowEnd::Completed => {
                runtime.note_plan_instance_ended(&session);
                runtime.end_planted_session_for_test(&session).await;
                if point == PlanDispatchPoint::AfterToken {
                    crate::api::handlers::settle::settle_and_revoke(
                        &store,
                        &manager,
                        dir.path(),
                        &session,
                        "completed",
                    )
                    .await
                    .unwrap();
                }
            }
            PlanRowEnd::Retire => {
                crate::agents::tests::stop_dispatch_agent(
                    dir.path(),
                    &owner.principal_id,
                    &agent,
                    false,
                );
            }
            PlanRowEnd::AgentsOff => {
                crate::agents::tests::stop_dispatch_agent(
                    dir.path(),
                    &owner.principal_id,
                    &agent,
                    true,
                );
            }
        }
    }
    pause.release.notify_one();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), dispatch)
        .await
        .unwrap_or_else(|_| panic!("{point:?} {end:?} dispatch did not finish"));
    drop(stop_guard);
    finished
        .unwrap()
        .unwrap_or_else(|err| panic!("{point:?} {end:?} dispatch failed: {err}"));

    let record = read_record(dir.path(), &id);
    // Agents off drops the principal from the auth store, so the root API
    // cannot open the object. The bytes on disk are the effect.
    let raw = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{point:?} {end:?} file after {record}: {err}"));
    assert!(
        calls.lock().await.is_empty(),
        "{point:?} {end:?} called a provider"
    );
    if point == PlanDispatchPoint::InEffect {
        // Agents off removes the principal before the write, so the write
        // that already passed its checks is refused and the file stays.
        // Stop, natural completion and retire leave the principal: the write lands.
        if end == PlanRowEnd::AgentsOff {
            assert_eq!(raw, before_raw, "{point:?} {end:?} wrote: {record}");
            assert_eq!(record["status"], "refused", "{point:?} {end:?} {record}");
            assert_eq!(
                record["result"]["code"], "principal_context_required",
                "{point:?} {end:?} {record}"
            );
            return;
        }
        assert_ne!(
            raw, before_raw,
            "{point:?} {end:?} did not record the write: {record}"
        );
        if let Ok(text) =
            crate::auth::read_principal_root_object(dir.path(), &agent, &root, &target, &path)
        {
            assert_eq!(text, b"plan", "{point:?} {end:?} {record}");
        }
        assert_eq!(record["status"], "completed", "{point:?} {end:?} {record}");
        return;
    }
    assert_eq!(
        raw, before_raw,
        "{point:?} {end:?} wrote after the instance ended"
    );
    assert_eq!(record["status"], "refused", "{point:?} {end:?} {record}");
    let code = record["result"]["code"].as_str().unwrap_or("");
    let expected = match (point, end) {
        // Stop does not end the instance, so admit succeeds and the revoked
        // grant is what refuses the write. Completion ends the instance
        // before admit, so the one-use grant is never counted.
        (PlanDispatchPoint::AfterToken, PlanRowEnd::Stop) => {
            assert_plan_grant_closed(&id, &store).await;
            "capability_denied"
        }
        (PlanDispatchPoint::AfterToken, PlanRowEnd::Completed) => {
            assert_plan_grant_closed(&id, &store).await;
            assert!(
                crate::resource_bridge::own_root_token_is_unused_for_test(&id).await,
                "{id} counted the one-use grant after the instance ended"
            );
            "instance ended"
        }
        // Turning agents off removes the principal, so the second invoke
        // resolution refuses before the standing check. Retire leaves the
        // principal and is caught as agent_inactive. Both refusals are after
        // the one-use token was registered, so the token is revoked and the
        // pending grant is gone.
        (PlanDispatchPoint::AfterToken, PlanRowEnd::AgentsOff) => {
            assert_plan_grant_closed(&id, &store).await;
            "invalid_resource_invoke"
        }
        (PlanDispatchPoint::AfterToken, PlanRowEnd::Retire) => {
            assert_plan_grant_closed(&id, &store).await;
            "agent_inactive"
        }
        (_, PlanRowEnd::Retire | PlanRowEnd::AgentsOff) => "agent_inactive",
        _ => "instance ended",
    };
    assert_eq!(code, expected, "{point:?} {end:?} {record}");
    if code == "agent_inactive" {
        let open = store.list_requests().await;
        assert!(
            open.iter().all(|request| !matches!(
                &request.status,
                elastos_runtime::capability::pending::RequestStatus::Denied { reason, .. }
                    if reason == "instance ended"
            )),
            "{point:?} {end:?} revoked the grant as instance ended"
        );
    }
}

async fn assert_plan_grant_closed(
    request_id: &str,
    store: &elastos_runtime::capability::pending::PendingRequestStore,
) {
    assert!(
        crate::resource_bridge::own_root_token_revoked_for_test(request_id).await,
        "{request_id} left the one-use token usable"
    );
    let open = store.list_requests().await;
    assert!(
        open.iter().all(|request| !matches!(
            request.status,
            elastos_runtime::capability::pending::RequestStatus::Pending
        )),
        "{request_id} left a pending approval"
    );
}

async fn bare_runtime(dir: &std::path::Path) -> Arc<crate::runtime::Runtime> {
    let storage = dir.join("cap-storage");
    std::fs::create_dir_all(&storage).unwrap();
    let runtime = Arc::new(crate::runtime::Runtime::with_providers_and_component(
        Arc::new(
            elastos_storage::providers::LocalFSProvider::new(storage)
                .await
                .unwrap(),
        ),
        vec![Arc::new(IdleCompute)],
        Some(Arc::new(
            elastos_compute::providers::ComponentProvider::new(),
        )),
    ));
    runtime.set_plant_dir_for_test(dir);
    runtime
}

struct PlantedEffect {
    dir: tempfile::TempDir,
    state: GatewayState,
    runtime: Arc<crate::runtime::Runtime>,
    owner: String,
    agent: String,
    session: String,
    id: String,
    manager: Arc<elastos_runtime::capability::CapabilityManager>,
    store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    path: std::path::PathBuf,
    before: Vec<u8>,
}

async fn plant_approved(
    n: u64,
    grant: bool,
    plan: impl FnOnce(&str, &str) -> serde_json::Value,
) -> PlantedEffect {
    let dir = tempfile::tempdir().unwrap();
    let (state, _) = agent_plan_dispatch_state(dir.path()).await;
    let owner = passkey_authority(dir.path());
    let agent = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &owner.principal_id,
        &owner.principal_id,
    );
    let root = crate::auth::principal_stored_localhost_root(Some(dir.path()), &agent).unwrap();
    let target = format!("{root}/Documents/plan.md");
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &target).unwrap();
    crate::auth::write_principal_root_object(dir.path(), &agent, &root, &target, &path, b"before")
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let session = format!("session-effect-{n}");
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.clone(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.clone(),
            principal: Some(agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: agent.clone(),
            owner: owner.principal_id.clone(),
            host_cid: "cid".to_string(),
            launch_id: format!("launch:{session}"),
            session_id: session.clone(),
        })
        .await;
    runtime.bind_plan_instance(&session, &agent);
    let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let manager = Arc::new(elastos_runtime::capability::CapabilityManager::new(
        Arc::new(elastos_runtime::capability::CapabilityStore::new()),
        audit.clone(),
        Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
    ));
    let store = Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit));
    runtime
        .set_provider_registry(
            state.provider_registry.clone().unwrap(),
            manager.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        )
        .await;
    let created = crate::api::gateway::submit_pending_agent_plan(
        dir.path(),
        &owner.principal_id,
        &agent,
        &session,
        &session,
        &plan(&root, &target),
        800 + n,
    )
    .unwrap();
    let id = created["request_id"].as_str().unwrap().to_string();
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: state.provider_registry.clone().unwrap(),
        capability_manager: manager.clone(),
        pending_store: store.clone(),
        capsule_id: session.clone(),
        session_id: session.clone(),
        principal_id: Some(agent.clone()),
        manifest_capabilities: [
            "elastos://availability/*",
            "elastos://inspect/*",
            "localhost://UsersAI/*",
            "localhost://Users/*",
        ]
        .into_iter()
        .map(|resource| elastos_common::AuthorityBound {
            resource: resource.to_string(),
            actions: None,
        })
        .collect(),
        data_dir: Some(dir.path().to_path_buf()),
        launch: None,
        model_token_ceiling: Some(16),
        model_budget: None,
        stop: None,
        plan_book: Some(runtime.plan_book()),
    };
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        &id,
        &owner.principal_id,
        &ctx,
        &created["request"],
    )
    .unwrap();
    if grant {
        crate::resource_bridge::grant_agent_plan_capability_for_test(&id, &created["request"])
            .await;
    }
    set_approved(dir.path(), &id);
    PlantedEffect {
        dir,
        state,
        runtime,
        owner: owner.principal_id,
        agent,
        session,
        id,
        manager,
        store,
        path,
        before,
    }
}

async fn dispatch_planted(plant: &PlantedEffect) -> anyhow::Result<String> {
    super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &plant.state,
        &dispatch_context(&plant.owner),
        &plant.id,
    )
    .await
}

/// The check and the mark are one hold of the plan lock. Closing in that hold
/// refuses the effect. An effect that entered first stays marked after the end.
#[cfg(unix)]
#[tokio::test]
async fn the_end_and_the_effect_share_one_lock() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let session = "session-seam";
    let agent = "agent-seam";
    runtime.bind_plan_instance(session, agent);
    let book = runtime.plan_book();
    crate::runtime::arm_plan_decision_hook(session, {
        let session = session.to_string();
        move |book| book.close_for_test(&session)
    });
    assert!(
        crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").is_err(),
        "the end inside the same hold let the effect in"
    );
    assert!(!runtime.plan_effect_inflight(session));
    crate::runtime::disarm_plan_decision_hook(session);

    runtime.bind_plan_instance(session, agent);
    let guard = crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "")
        .expect("an open instance enters");
    runtime.note_plan_instance_ended(session);
    assert!(
        runtime.plan_effect_inflight(session),
        "the end cleared an effect that had already entered"
    );
    assert_eq!(
        runtime.inflight_plan_sessions(agent),
        vec![session.to_string()]
    );
    guard.release();
    assert!(!runtime.plan_effect_inflight(session));
    assert!(crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").is_err());
}

/// Two effects of one session are two marks. The first to finish leaves the second.
#[cfg(unix)]
#[tokio::test]
async fn two_effects_of_one_session_are_counted_apart() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let session = "session-two";
    let agent = "agent-two";
    runtime.bind_plan_instance(session, agent);
    let book = runtime.plan_book();
    let first = crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").unwrap();
    let second = crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").unwrap();
    assert!(runtime.plan_effect_inflight(session));
    first.release();
    assert!(
        runtime.plan_effect_inflight(session),
        "the first effect to finish cleared the second"
    );
    second.release();
    assert!(!runtime.plan_effect_inflight(session));
}

/// One Runtime's end does not close another Runtime's session of the same id.
#[cfg(unix)]
#[tokio::test]
async fn one_runtime_does_not_end_another_runtimes_plan() {
    let dir = tempfile::tempdir().unwrap();
    let left = bare_runtime(dir.path()).await;
    let right = bare_runtime(&dir.path().join("other")).await;
    let session = "session-shared";
    let agent = "agent-shared";
    left.bind_plan_instance(session, agent);
    right.bind_plan_instance(session, agent);
    left.note_plan_instance_ended(session);
    let left_book = left.plan_book();
    let right_book = right.plan_book();
    assert!(
        crate::runtime::Runtime::try_enter_plan_effect(&left_book, session, agent, "").is_err()
    );
    let guard = crate::runtime::Runtime::try_enter_plan_effect(&right_book, session, agent, "")
        .expect("the other Runtime's session is still open");
    assert!(right.plan_effect_inflight(session));
    assert!(!left.plan_effect_inflight(session));
    guard.release();
}

async fn dispatch_without_an_open_instance(bound_then_gone: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _) = agent_plan_dispatch_state(dir.path()).await;
    let owner = "person:closed";
    let agent = "agent:closed";
    let session = if bound_then_gone {
        "capsule:gone"
    } else {
        "capsule:unbound"
    };
    let created = crate::api::gateway::submit_pending_agent_plan(
        dir.path(),
        owner,
        agent,
        session,
        session,
        &read_plan(),
        70,
    )
    .unwrap();
    let id = created["request_id"].as_str().unwrap();
    let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let manager = Arc::new(elastos_runtime::capability::CapabilityManager::new(
        Arc::new(elastos_runtime::capability::CapabilityStore::new()),
        audit.clone(),
        Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
    ));
    let mut ctx = crate::resource_bridge::BridgeContext {
        provider_registry: state.provider_registry.clone().unwrap(),
        capability_manager: manager,
        pending_store: Arc::new(
            elastos_runtime::capability::pending::PendingRequestStore::new(audit),
        ),
        capsule_id: session.to_string(),
        session_id: session.to_string(),
        principal_id: Some(agent.to_string()),
        manifest_capabilities: Vec::new(),
        data_dir: Some(dir.path().to_path_buf()),
        launch: None,
        model_token_ceiling: None,
        model_budget: None,
        stop: None,
        plan_book: None,
    };
    if bound_then_gone {
        crate::runtime::Runtime::bind_detached_plan_for_test(&mut ctx, session, agent);
        ctx.plan_book
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .close_for_test(session);
    }
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        id,
        owner,
        &ctx,
        &created["request"],
    )
    .unwrap();
    set_approved(dir.path(), id);
    super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &state,
        &dispatch_context(owner),
        id,
    )
    .await
    .unwrap();
    let record = read_record(dir.path(), id);
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "instance ended", "{record}");
}

/// A dispatch for an instance that was never bound, or was bound and then
/// removed, is refused. There is no open default.
#[cfg(unix)]
#[tokio::test]
async fn a_dispatch_for_an_unbound_or_gone_instance_is_refused() {
    dispatch_without_an_open_instance(false).await;
    dispatch_without_an_open_instance(true).await;
}

/// Delete, which is how a running capsule is cancelled, does not say stopped
/// while that session's effect is in flight.
#[cfg(unix)]
#[tokio::test]
async fn stop_capsule_says_stopping_while_an_effect_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let session = "session-cancel";
    let agent = "agent-cancel";
    runtime.bind_plan_instance(session, agent);
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.to_string(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.to_string(),
            principal: Some(agent.to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
    let book = runtime.plan_book();
    let guard = crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").unwrap();
    let response = crate::api::routes::stop_capsule(
        axum::Extension(runtime.clone()),
        axum::extract::Path(session.to_string()),
        axum::body::Bytes::new(),
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "stopping", "{body}");
    assert_ne!(body["status"], "stopped", "{body}");
    assert!(
        crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").is_err(),
        "Stop answered without closing the instance"
    );
    assert!(runtime.plan_effect_inflight(session));
    guard.release();
    assert!(!runtime.plan_effect_inflight(session));
    assert!(crate::runtime::Runtime::try_enter_plan_effect(&book, session, agent, "").is_err());
}

/// A nested submit is an effect. Closing the instance in the admit hold writes
/// no second plan and raises no approval card.
#[cfg(unix)]
#[tokio::test]
async fn a_nested_submit_after_the_end_writes_no_plan() {
    let plant = plant_approved(1, true, |_, _| {
        json!({"steps": [{"scheme": "inspect", "operation": "submit_agent_plan", "request": {
            "steps": [{"scheme": "availability", "operation": "status", "request": {}}]
        }}]})
    })
    .await;
    crate::runtime::arm_plan_decision_hook(&plant.session, {
        let session = plant.session.clone();
        move |book| book.close_for_test(&session)
    });
    dispatch_planted(&plant).await.unwrap();
    crate::runtime::disarm_plan_decision_hook(&plant.session);
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "instance ended", "{record}");
    let files: Vec<_> = std::fs::read_dir(plant.dir.path().join("inspect-actions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        files,
        vec![std::ffi::OsString::from(format!("{}.json", plant.id))],
        "a nested submit wrote a plan after the end: {files:?}"
    );
}

/// A refusal after the one-use token is registered revokes it and leaves no
/// pending grant.
#[cfg(unix)]
#[tokio::test]
async fn a_refusal_after_the_token_is_registered_revokes_it() {
    let plant = plant_approved(2, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    crate::runtime::arm_plan_decision_hook(&plant.session, {
        let session = plant.session.clone();
        move |book| book.close_for_test(&session)
    });
    dispatch_planted(&plant).await.unwrap();
    crate::runtime::disarm_plan_decision_hook(&plant.session);
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "instance ended", "{record}");
    assert_eq!(std::fs::read(&plant.path).unwrap(), plant.before);
    assert_plan_grant_closed(&plant.id, &plant.store).await;
}

/// A timed-out dispatch records unknown and resolves the flight. Stop answers
/// stopped and names the step. The record stays unknown.
#[cfg(unix)]
#[tokio::test]
async fn a_timed_out_effect_stays_unresolved() {
    let plant = plant_approved(3, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    super::gateway_inspect_actions::set_plan_dispatch_wait_for_test(
        &plant.id,
        std::time::Duration::from_secs(8),
    );
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::InEffect,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    let reached =
        tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified()).await;
    assert!(reached.is_ok(), "the effect did not reach its hold");
    let finished = tokio::time::timeout(std::time::Duration::from_secs(20), task)
        .await
        .expect("the short wait did not settle the dispatch");
    super::gateway_inspect_actions::clear_plan_dispatch_wait_for_test(&plant.id);
    finished.unwrap().unwrap();
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "unknown", "{record}");
    assert_eq!(record["result"]["code"], "provider_timeout", "{record}");
    assert_ne!(record["status"], "completed");
    assert_ne!(record["status"], "refused");
    assert_eq!(std::fs::read(&plant.path).unwrap(), plant.before);
    assert_plan_grant_closed(&plant.id, &plant.store).await;
    assert!(
        !plant.runtime.plan_effect_inflight(&plant.session),
        "unknown left the flight holding the instance"
    );
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["stopped"][0]["status"], "stopped", "{body}");
    assert!(
        body["stopping"]
            .as_array()
            .is_none_or(|rows| rows.is_empty()),
        "{body}"
    );
    assert_eq!(body["unknown"][0]["request_id"], plant.id, "{body}");
    assert_eq!(body["unknown"][0]["outcome"], "unknown", "{body}");
    assert_ne!(body["unknown"][0]["outcome"], "done");
    assert_ne!(body["unknown"][0]["outcome"], "refused");
    let again = read_record(plant.dir.path(), &plant.id);
    assert_eq!(again["status"], "unknown", "{again}");
}

/// A panic after the mark records unknown and resolves the flight.
#[cfg(unix)]
#[tokio::test]
async fn a_panic_in_dispatch_records_unknown() {
    let plant = plant_approved(4, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    crate::resource_bridge::arm_plan_dispatch_panic(&plant.id);
    dispatch_planted(&plant)
        .await
        .expect("a panicked dispatch still settles");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "unknown", "{record}");
    assert_eq!(record["result"]["code"], "dispatch_panic", "{record}");
    let unknown_audits = crate::auth::load_auth_state(plant.dir.path())
        .unwrap()
        .audit
        .iter()
        .filter(|event| {
            event.event_type == "agent_plan.dispatch.unknown"
                && event.challenge_id.as_deref() == Some(plant.id.as_str())
        })
        .count();
    assert_eq!(
        unknown_audits, 1,
        "a panic wrote more than one unknown audit"
    );
    assert_ne!(record["status"], "completed");
    assert_ne!(record["status"], "refused");
    assert_eq!(std::fs::read(&plant.path).unwrap(), plant.before);
    assert_plan_grant_closed(&plant.id, &plant.store).await;
    assert!(
        !plant.runtime.plan_effect_inflight(&plant.session),
        "the panic left the flight holding the instance"
    );
    plant.runtime.note_plan_instance_ended(&plant.session);
    let named = plant.runtime.take_unknown_plan_steps(&plant.agent);
    assert_eq!(named.len(), 1);
    assert_eq!(named[0].request_id, plant.id);
    assert!(plant.runtime.plan_book_is_empty());
}

/// Drop and the task error arm both revoke. One audit is written.
#[cfg(unix)]
#[tokio::test]
async fn two_callers_revoke_an_abandoned_grant_once() {
    let audit = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let manager = Arc::new(elastos_runtime::capability::CapabilityManager::new(
        Arc::new(elastos_runtime::capability::CapabilityStore::new()),
        audit,
        Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
    ));
    let store = Arc::new(
        elastos_runtime::capability::pending::PendingRequestStore::new(manager.audit_log().clone()),
    );
    let resource = elastos_runtime::capability::ResourceId::new("elastos://availability/status");
    let token = manager.grant(
        "capsule:revoke-once",
        resource.clone(),
        elastos_runtime::capability::Action::Read,
        elastos_runtime::capability::TokenConstraints::default(),
        None,
    );
    let pending = store
        .create_request(
            elastos_runtime::session::SessionId::from_string("capsule:revoke-once"),
            resource,
            elastos_runtime::capability::Action::Read,
        )
        .await;
    let pending_id = pending.id.as_str().to_string();
    store
        .grant_request(
            &pending_id,
            token.clone(),
            elastos_runtime::capability::pending::GrantDuration::Session,
        )
        .await
        .unwrap();
    crate::resource_bridge::park_abandoned_grant_for_test(
        "revoke-once",
        Arc::clone(&manager),
        store,
        token,
        pending_id,
    );
    let overlap = crate::resource_bridge::arm_abandoned_revoke_overlap("revoke-once");
    let left = tokio::spawn(crate::resource_bridge::revoke_abandoned_plan_grant(
        "revoke-once",
    ));
    let right = tokio::spawn(crate::resource_bridge::revoke_abandoned_plan_grant(
        "revoke-once",
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let seen = overlap.entered.load(std::sync::atomic::Ordering::SeqCst)
            + overlap.skipped.load(std::sync::atomic::Ordering::SeqCst);
        if seen >= 2 || std::time::Instant::now() >= deadline {
            break;
        }
        let wait = overlap.progress.notified();
        let seen = overlap.entered.load(std::sync::atomic::Ordering::SeqCst)
            + overlap.skipped.load(std::sync::atomic::Ordering::SeqCst);
        if seen >= 2 {
            break;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let _ = tokio::time::timeout(left, wait).await;
    }
    assert_eq!(
        overlap.entered.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "both callers revoked"
    );
    overlap.release_for_test();
    left.await.unwrap();
    right.await.unwrap();
    let revokes = manager
        .audit_log()
        .recent_events(40)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                elastos_runtime::primitives::audit::AuditEvent::CapabilityRevoke { reason, .. }
                    if reason == "plan dispatch abandoned"
            )
        })
        .count();
    assert_eq!(revokes, 1, "two callers each audited the revoke");
}

/// A late store after unknown is the same effect. The record stays unknown,
/// and a journal write still loses a stale revision.
#[cfg(unix)]
#[tokio::test]
async fn a_late_landing_after_unknown_is_not_a_new_action() {
    let plant = plant_approved(41, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    super::gateway_inspect_actions::set_plan_dispatch_wait_for_test(
        &plant.id,
        std::time::Duration::from_secs(8),
    );
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::InEffect,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the effect did not reach its hold");
    tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the short wait did not settle")
        .unwrap()
        .unwrap();
    super::gateway_inspect_actions::clear_plan_dispatch_wait_for_test(&plant.id);
    std::fs::write(&plant.path, b"late bytes").unwrap();
    assert_eq!(std::fs::read(&plant.path).unwrap(), b"late bytes");
    let settled = super::gateway_inspect_actions::resettle_plan_for_test(
        plant.dir.path(),
        &plant.id,
        "completed",
    )
    .unwrap();
    assert!(settled.contains("unknown"), "{settled}");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "unknown", "{record}");
    assert_ne!(record["status"], "completed");
    assert_ne!(record["status"], "refused");
    assert_ne!(record["status"], "done");
    let files: Vec<_> = std::fs::read_dir(plant.dir.path().join("inspect-actions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        files.len(),
        1,
        "a late landing wrote a new action: {files:?}"
    );
    let root =
        crate::auth::principal_stored_localhost_root(Some(plant.dir.path()), &plant.agent).unwrap();
    let journal = format!("{root}/.AppData/Agents/demo/tasks/t/journal");
    let journal_path =
        elastos_common::localhost::rooted_localhost_fs_path(plant.dir.path(), &journal).unwrap();
    let write_journal = |bytes: &[u8], precondition| {
        crate::auth::write_principal_root_object_if_revision(
            plant.dir.path(),
            &plant.agent,
            &root,
            &journal,
            &journal_path,
            bytes,
            precondition,
        )
    };
    write_journal(
        b"journal v1",
        crate::auth::PrincipalRootObjectPrecondition::Absent,
    )
    .expect("the journal's first revision is stored");
    let revision =
        crate::auth::principal_root_object_revision(&plant.agent, &journal, b"journal v1");
    write_journal(
        b"journal v2",
        crate::auth::PrincipalRootObjectPrecondition::Revision(&revision),
    )
    .expect("the current journal revision is accepted");
    let stale = write_journal(
        b"journal v3",
        crate::auth::PrincipalRootObjectPrecondition::Revision(&revision),
    );
    let err = stale.expect_err("a stale journal revision was stored");
    assert!(
        err.is::<crate::auth::PrincipalRootObjectWriteConflict>(),
        "the journal refusal is the revision check, not another error: {err:#}"
    );
    assert_eq!(
        crate::auth::read_principal_root_object(
            plant.dir.path(),
            &plant.agent,
            &root,
            &journal,
            &journal_path,
        )
        .unwrap(),
        b"journal v2"
    );
    plant.runtime.note_plan_instance_ended(&plant.session);
    let _ = plant.runtime.take_unknown_plan_steps(&plant.agent);
    assert!(plant.runtime.plan_book_is_empty());
}

/// One hundred timed-out effects leave no flight and no instance.
#[cfg(unix)]
#[tokio::test]
async fn a_hundred_timeouts_leave_no_flight_and_no_instance() {
    let plant = plant_approved(42, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let start = std::time::Instant::now();
    plant.runtime.set_plan_clock_for_test(Some(start));
    for n in 0..100u64 {
        let session = format!("session-hundred-{n}");
        plant
            .runtime
            .register_capsule(crate::runtime::RunningCapsuleInfo {
                id: session.clone(),
                name: "planted".to_string(),
                status: crate::runtime::CAPSULE_RUNNING.to_string(),
                capsule_type: elastos_common::CapsuleType::Wasm,
                handle: None,
                session_id: session.clone(),
                principal: Some(plant.agent.clone()),
                cause: None,
                ended_at: None,
            })
            .await;
        plant
            .runtime
            .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
                agent_id: plant.agent.clone(),
                owner: plant.owner.clone(),
                host_cid: "cid".to_string(),
                launch_id: format!("launch:{session}"),
                session_id: session.clone(),
            })
            .await;
        plant.runtime.bind_plan_instance(&session, &plant.agent);
        let root =
            crate::auth::principal_stored_localhost_root(Some(plant.dir.path()), &plant.agent)
                .unwrap();
        let target = format!("{root}/Documents/plan.md");
        let created = crate::api::gateway::submit_pending_agent_plan(
            plant.dir.path(),
            &plant.owner,
            &plant.agent,
            &session,
            &session,
            &json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
                "path": target, "content": [112, 108, 97, 110]
            }}]}),
            2_000 + n,
        )
        .unwrap();
        let id = created["request_id"].as_str().unwrap().to_string();
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: plant.state.provider_registry.clone().unwrap(),
            capability_manager: plant.manager.clone(),
            pending_store: plant.store.clone(),
            capsule_id: session.clone(),
            session_id: session.clone(),
            principal_id: Some(plant.agent.clone()),
            manifest_capabilities: [
                "elastos://availability/*",
                "localhost://UsersAI/*",
                "localhost://Users/*",
            ]
            .into_iter()
            .map(|resource| elastos_common::AuthorityBound {
                resource: resource.to_string(),
                actions: None,
            })
            .collect(),
            data_dir: Some(plant.dir.path().to_path_buf()),
            launch: None,
            model_token_ceiling: Some(16),
            model_budget: None,
            stop: None,
            plan_book: Some(plant.runtime.plan_book()),
        };
        crate::resource_bridge::retain_agent_plan_dispatch_authority(
            &id,
            &plant.owner,
            &ctx,
            &created["request"],
        )
        .unwrap();
        set_approved(plant.dir.path(), &id);
        super::gateway_inspect_actions::set_plan_dispatch_wait_for_test(
            &id,
            std::time::Duration::from_millis(200),
        );
        let pause = crate::resource_bridge::arm_plan_dispatch_hold(
            &id,
            crate::resource_bridge::PlanDispatchPoint::InEffect,
        );
        let state = plant.state.clone();
        let owner = plant.owner.clone();
        let request_id = id.clone();
        let task = tokio::spawn(async move {
            super::gateway_inspect_actions::dispatch_approved_agent_plan(
                &state,
                &dispatch_context(&owner),
                &request_id,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
            .await
            .unwrap_or_else(|_| panic!("timeout {n} did not reach its effect"));
        tokio::time::timeout(std::time::Duration::from_secs(15), task)
            .await
            .unwrap_or_else(|_| panic!("timeout {n} did not settle"))
            .unwrap()
            .unwrap();
        super::gateway_inspect_actions::clear_plan_dispatch_wait_for_test(&id);
        let record = read_record(plant.dir.path(), &id);
        assert_eq!(record["status"], "unknown", "{n} {record}");
        assert!(!plant.runtime.plan_effect_inflight(&session), "{n}");
        plant.runtime.note_plan_instance_ended(&session);
        plant.runtime.evict_ended_session_for_test(&session).await;
    }
    plant.runtime.note_plan_instance_ended(&plant.session);
    plant
        .runtime
        .evict_ended_session_for_test(&plant.session)
        .await;
    assert_eq!(
        plant.runtime.plan_run_state_for_test(),
        (0, 0, 0),
        "a hundred timeouts left a flight or an instance"
    );
    assert!(
        plant.runtime.unknown_count_for_test(&plant.agent) <= 32,
        "a hundred timeouts kept more than 32 names"
    );
    plant
        .runtime
        .set_plan_clock_for_test(Some(start + crate::runtime::ENDED_CAPSULE_RETENTION));
    assert!(
        plant.runtime.plan_book_is_empty(),
        "names stayed after the retention that started at the end"
    );
    plant.runtime.set_plan_clock_for_test(None);
}

/// An effect already in flight when the instance ends is recorded as it
/// finished: here the provider's result is an error, so the record is failed.
#[cfg(unix)]
#[tokio::test]
async fn an_effect_in_flight_at_the_end_is_recorded_failed() {
    let plant = plant_approved(5, true, |_, _| {
        json!({"steps": [{"scheme": "availability", "operation": "status", "request": {
            "provider_result_error": true
        }}]})
    })
    .await;
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::InEffect,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    let reached =
        tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified()).await;
    assert!(reached.is_ok(), "the effect did not reach its hold");
    assert!(plant.runtime.plan_effect_inflight(&plant.session));
    plant.runtime.note_plan_instance_ended(&plant.session);
    assert!(
        plant.runtime.plan_effect_inflight(&plant.session),
        "the end cleared the effect that was already in flight"
    );
    pause.release.notify_one();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the failed effect did not settle");
    finished.unwrap().unwrap();
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "failed", "{record}");
    assert_eq!(
        record["result"]["code"], "provider_result_error",
        "{record}"
    );
    assert!(!plant.runtime.plan_effect_inflight(&plant.session));
}

async fn assert_the_run_can_still_dispatch(plant: &PlantedEffect) {
    dispatch_planted(plant)
        .await
        .expect("the run can still dispatch");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_ne!(record["status"], "refused", "{record}");
    assert_ne!(record["result"]["code"], "instance ended", "{record}");
    assert_eq!(record["status"], "completed", "{record}");
    assert_ne!(std::fs::read(&plant.path).unwrap(), plant.before);
}

/// A Stop that does not end the row leaves that run able to dispatch.
/// The end is per session, when the row ends, not at the start of the request.
#[cfg(unix)]
#[tokio::test]
async fn a_conflict_stop_leaves_the_run_able_to_dispatch() {
    let plant = plant_approved(43, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    plant
        .runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: format!("{}-other", plant.agent),
            owner: plant.owner.clone(),
            host_cid: "cid".to_string(),
            launch_id: "launch:other".to_string(),
            session_id: plant.session.clone(),
        })
        .await;
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(crate::runtime::Runtime::plan_instance_is_open(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent
    ));
    assert_the_run_can_still_dispatch(&plant).await;
}

/// A Stop that finds no running row does not close a bound instance.
#[cfg(unix)]
#[tokio::test]
async fn a_missing_stop_leaves_the_run_able_to_dispatch() {
    let plant = plant_approved(44, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(crate::runtime::Runtime::plan_instance_is_open(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent
    ));
    assert_the_run_can_still_dispatch(&plant).await;
}

/// A stop that fails before the row ends does not close the instance.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_stop_leaves_the_run_able_to_dispatch() {
    let plant = plant_approved(45, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    plant.runtime.arm_failing_capsule_stop(&plant.session);
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(crate::runtime::Runtime::plan_instance_is_open(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent
    ));
    assert_the_run_can_still_dispatch(&plant).await;
}

/// Dropping the Stop request before it ends the row leaves the run able to dispatch.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_stop_leaves_the_run_able_to_dispatch() {
    let plant = plant_approved(46, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pause = plant.runtime.arm_stop_before_rows(&plant.agent);
    let runtime = plant.runtime.clone();
    let agent = plant.agent.clone();
    let task = tokio::spawn(async move { stop_plan_agent(runtime, &agent).await });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the stop did not reach its pause");
    task.abort();
    let _ = task.await;
    assert!(crate::runtime::Runtime::plan_instance_is_open(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent
    ));
    assert_the_run_can_still_dispatch(&plant).await;
}

/// A per-agent Stop names a session whose row has ended while its effect is
/// still landing, and answers 202. A second live session of the same agent
/// can stop in the same call.
#[cfg(unix)]
#[tokio::test]
async fn a_stop_names_an_inflight_session_that_already_ended() {
    let plant = plant_approved(47, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let live = format!("session-live-{}", plant.session);
    plant
        .runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: live.clone(),
            name: "planted-live".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: live.clone(),
            principal: Some(plant.agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    plant
        .runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: plant.agent.clone(),
            owner: plant.owner.clone(),
            host_cid: "cid".to_string(),
            launch_id: format!("launch:{live}"),
            session_id: live.clone(),
        })
        .await;
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::InEffect,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the effect did not reach its hold");
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let stopping = body["stopping"].as_array().expect("stopping is a list");
    assert!(
        stopping
            .iter()
            .any(|row| row["session_id"] == plant.session && row["status"] == "stopping"),
        "the landing session is unlisted: {body}"
    );
    pause.release.notify_one();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the effect did not settle");
    finished.expect("dispatch task").expect("dispatch");
}

/// Stop cannot answer stopped while the stored record still says dispatching.
/// Settlement writes the record before the flight is released.
#[cfg(unix)]
#[tokio::test]
async fn stop_cannot_say_stopped_while_the_record_is_dispatching() {
    let plant = plant_approved(48, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::BeforeSettle,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("dispatch did not reach settlement");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "dispatching", "{record}");
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "stop answered stopped while the record says dispatching: {body}"
    );
    pause.release.notify_one();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the effect did not settle");
    finished.expect("dispatch task").expect("dispatch");
}

/// The stored record is the answer. An audit write that fails still answers
/// with the status the record holds. One record-write fault is retried and
/// the real outcome is stored. Three faults leave the record `dispatching`,
/// resolve the flight as unknown, and Stop then names that step.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_settle_write_matches_the_stored_record() {
    let audit = plant_approved(49, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    super::gateway_inspect_actions::arm_plan_settle_fault(&audit.id, "audit");
    let answer = dispatch_planted(&audit)
        .await
        .expect("a failed audit still answers with the stored outcome");
    assert!(
        answer.contains("completed"),
        "the answer disagreed with the record: {answer}"
    );
    let record = read_record(audit.dir.path(), &audit.id);
    assert_eq!(record["status"], "completed", "{record}");
    assert!(!audit.runtime.plan_effect_inflight(&audit.session));

    let missed = plant_approved(50, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    super::gateway_inspect_actions::arm_plan_settle_fault(&missed.id, "record");
    let answer = dispatch_planted(&missed)
        .await
        .expect("one record fault is retried");
    assert!(
        answer.contains("completed"),
        "the retried write did not store the outcome: {answer}"
    );
    let record = read_record(missed.dir.path(), &missed.id);
    assert_eq!(record["status"], "completed", "{record}");
    assert!(!missed.runtime.plan_effect_inflight(&missed.session));

    let stuck = plant_approved(51, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    super::gateway_inspect_actions::arm_plan_settle_faults(&stuck.id, "record", 3);
    let refused = dispatch_planted(&stuck).await;
    assert!(
        refused.is_err(),
        "three record faults answered success: {refused:?}"
    );
    let record = read_record(stuck.dir.path(), &stuck.id);
    assert_eq!(record["status"], "dispatching", "{record}");
    assert!(!stuck.runtime.plan_effect_inflight(&stuck.session));
    stuck.runtime.note_plan_instance_ended(&stuck.session);
    stuck
        .runtime
        .end_planted_session_for_test(&stuck.session)
        .await;
    let (status, body) = stop_plan_agent(stuck.runtime.clone(), &stuck.agent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let named = body["unknown"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|step| step["request_id"] == stuck.id && step["outcome"] == "unknown");
    assert!(named, "Stop did not name the unresolved step: {body}");
}

async fn stop_one_capsule(
    runtime: Arc<crate::runtime::Runtime>,
    id: &str,
) -> (StatusCode, serde_json::Value) {
    let response = crate::api::routes::stop_capsule(
        axum::Extension(runtime),
        axum::extract::Path(id.to_string()),
        axum::body::Bytes::new(),
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or(json!(String::from_utf8_lossy(&bytes).to_string())),
    )
}

/// A live session with an earlier unknown step is stopping, not stopped.
#[cfg(unix)]
#[tokio::test]
async fn a_live_session_with_an_unknown_step_is_not_stopped() {
    let plant = plant_approved(60, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    plant
        .runtime
        .remember_unknown_for_test(&plant.session, &plant.agent, "earlier-unknown");
    // A stop request with no watcher end leaves the row running. The answer
    // is stopping, and the unknown name stays in the book.
    plant.runtime.plant_activation_stop_for_test(&plant.session);
    let _wait = plant
        .runtime
        .limit_stop_wait_for_test(std::time::Duration::from_millis(30));
    let (status, body) = stop_one_capsule(plant.runtime.clone(), &plant.session).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "stopping", "{body}");
    assert_eq!(
        plant.runtime.unknown_count_for_test(&plant.agent),
        1,
        "a stopping answer took the name"
    );
}

/// A landing effect is stopping, and that session is not also listed as stopped.
#[cfg(unix)]
#[tokio::test]
async fn a_landing_effect_is_not_also_stopped() {
    let plant = plant_approved(61, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent,
        "landing-step",
    )
    .expect("the instance admits an effect");
    // `release` is still false, so this drop leaves the flight in the book.
    drop(guard);
    plant
        .runtime
        .remember_unknown_for_test(&plant.session, &plant.agent, "earlier-unknown");
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let stopping = body["stopping"].as_array().unwrap();
    assert!(
        stopping
            .iter()
            .any(|row| row["session_id"] == plant.session),
        "{body}"
    );
    let stopped = body["stopped"].as_array().unwrap();
    assert!(
        stopped.iter().all(|row| row["session_id"] != plant.session),
        "a stopping session is also stopped: {body}"
    );
    assert_eq!(plant.runtime.unknown_count_for_test(&plant.agent), 1);
}

/// A 409 is the answer. An earlier unknown step does not replace it or get taken.
#[cfg(unix)]
#[tokio::test]
async fn a_conflict_stop_is_not_swallowed_by_an_unknown_step() {
    let plant = plant_approved(62, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    plant
        .runtime
        .forget_agent_session_for_test(&plant.session)
        .await;
    plant
        .runtime
        .remember_unknown_for_test(&plant.session, &plant.agent, "kept-unknown");
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(plant.runtime.unknown_count_for_test(&plant.agent), 1);
}

/// After retention, a landing effect is still stopping, and a step that
/// resolves once the row has gone is still named.
#[cfg(unix)]
#[tokio::test]
async fn a_stop_after_retention_names_the_outcome() {
    let plant = plant_approved(63, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent,
        "outlives-the-row",
    )
    .expect("the instance admits an effect");
    drop(guard);
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    plant
        .runtime
        .evict_ended_session_for_test(&plant.session)
        .await;
    let (status, body) = stop_one_capsule(plant.runtime.clone(), &plant.session).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "stopping", "{body}");
    crate::runtime::resolve_unknown_plan_effect("outlives-the-row");
    let (status, body) = stop_one_capsule(plant.runtime.clone(), &plant.session).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "stopped", "{body}");
    assert!(
        body["unknown_steps"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| step == "outlives-the-row")),
        "{body}"
    );
}

/// Unknown names are capped per agent, and one agent's Stop does not list another's.
#[cfg(unix)]
#[tokio::test]
async fn unknown_steps_are_capped_and_stay_with_their_agent() {
    let plant = plant_approved(64, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    for n in 0..40 {
        plant.runtime.remember_unknown_for_test(
            &plant.session,
            &plant.agent,
            &format!("capped-{n}"),
        );
    }
    assert_eq!(plant.runtime.unknown_count_for_test(&plant.agent), 32);
    let other = "agent-other";
    plant
        .runtime
        .remember_unknown_for_test("session-other", other, "other-step");
    let (status, body) = stop_plan_agent(plant.runtime.clone(), other).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let named = body["unknown"].to_string();
    assert!(named.contains("other-step"), "{body}");
    assert!(!named.contains("capped-"), "{body}");
    assert_eq!(plant.runtime.unknown_count_for_test(&plant.agent), 32);
}

/// A provider stop that fails, on a detached run, leaves the run able to act.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_provider_stop_leaves_the_detached_run_able_to_dispatch() {
    let plant = plant_approved(65, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let manifest: elastos_common::CapsuleManifest = serde_json::from_str(
        &crate::runtime::tests::component_manifest_json("detached-stop"),
    )
    .unwrap();
    let handle = elastos_compute::CapsuleHandle {
        id: elastos_common::CapsuleId(plant.session.clone()),
        manifest,
        args: Vec::new(),
    };
    plant
        .runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: plant.session.clone(),
            name: "detached".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: Some(handle),
            session_id: plant.session.clone(),
            principal: Some(plant.agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    plant.runtime.plant_activation_stop_for_test(&plant.session);
    plant.runtime.arm_failing_capsule_stop(&plant.session);
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(
        plant.runtime.provider_stop_count_for_test() >= 1,
        "the provider stop was not called"
    );
    assert!(
        !plant
            .runtime
            .activation_stop_requested_for_test(&plant.session),
        "a failed provider stop left the flag up"
    );
    assert!(crate::runtime::Runtime::plan_instance_is_open(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent
    ));
    assert_the_run_can_still_dispatch(&plant).await;
}

/// Ending the instance after the token is minted and before admit leaves the
/// one-use grant unused.
#[cfg(unix)]
#[tokio::test]
async fn an_end_before_admit_leaves_the_one_use_grant_unused() {
    let plant = plant_approved(66, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::AfterToken,
    );
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the step did not reach the token");
    plant.runtime.note_plan_instance_ended(&plant.session);
    pause.release.notify_one();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the step did not finish");
    finished.expect("dispatch task").expect("dispatch");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "instance ended", "{record}");
    assert!(
        crate::resource_bridge::own_root_token_is_unused_for_test(&plant.id).await,
        "admit refused after the one-use grant was counted"
    );
}

/// Three hundred successful own-root steps, then the settle Stop's end runs.
/// A spent one-use grant must leave `Granted`, or that settle's revocation
/// list fills at 256 and the end is `revocation not saved`.
#[cfg(unix)]
#[tokio::test]
async fn three_hundred_spent_grants_still_let_stop_settle() {
    let plant = plant_approved(77, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let root =
        crate::auth::principal_stored_localhost_root(Some(plant.dir.path()), &plant.agent).unwrap();
    let target = format!("{root}/Documents/plan.md");
    for n in 0..300u64 {
        let created = crate::api::gateway::submit_pending_agent_plan(
            plant.dir.path(),
            &plant.owner,
            &plant.agent,
            &plant.session,
            &plant.session,
            &json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
                "path": target, "content": [112, 108, 97, 110]
            }}]}),
            8_000 + n,
        )
        .unwrap();
        let id = created["request_id"].as_str().unwrap().to_string();
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: plant.state.provider_registry.clone().unwrap(),
            capability_manager: plant.manager.clone(),
            pending_store: plant.store.clone(),
            capsule_id: plant.session.clone(),
            session_id: plant.session.clone(),
            principal_id: Some(plant.agent.clone()),
            manifest_capabilities: [
                "elastos://availability/*",
                "localhost://UsersAI/*",
                "localhost://Users/*",
            ]
            .into_iter()
            .map(|resource| elastos_common::AuthorityBound {
                resource: resource.to_string(),
                actions: None,
            })
            .collect(),
            data_dir: Some(plant.dir.path().to_path_buf()),
            launch: None,
            model_token_ceiling: Some(16),
            model_budget: None,
            stop: None,
            plan_book: Some(plant.runtime.plan_book()),
        };
        crate::resource_bridge::retain_agent_plan_dispatch_authority(
            &id,
            &plant.owner,
            &ctx,
            &created["request"],
        )
        .unwrap();
        set_approved(plant.dir.path(), &id);
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &plant.state,
            &dispatch_context(&plant.owner),
            &id,
        )
        .await
        .unwrap_or_else(|err| panic!("step {n} did not finish: {err}"));
        let record = read_record(plant.dir.path(), &id);
        assert_eq!(record["status"], "completed", "{n} {record}");
    }
    let rows = plant.store.list_requests().await;
    let spent = rows
        .iter()
        .filter(|request| {
            request.session_id.as_str() == plant.session
                && matches!(
                    &request.status,
                    elastos_runtime::capability::pending::RequestStatus::Denied { reason, .. }
                        if reason == "one-use plan grant spent"
                )
        })
        .count();
    let granted = rows
        .iter()
        .filter(|request| request.session_id.as_str() == plant.session && request.is_granted())
        .count();
    assert_eq!(spent, 300, "granted still held: {granted}");
    assert_eq!(granted, 0, "{granted} one-use grants stayed open");
    let settled = crate::api::handlers::settle::settle_and_revoke(
        &plant.store,
        &plant.manager,
        plant.dir.path(),
        &plant.session,
        "owner",
    )
    .await;
    assert!(
        settled.is_ok(),
        "Stop's settle could not save the revocations: {settled:?}"
    );
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let extra = plant
        .store
        .create_request(
            elastos_runtime::session::SessionId(plant.session.clone()),
            elastos_runtime::capability::ResourceId::new("elastos://availability/status"),
            elastos_runtime::capability::Action::Read,
        )
        .await;
    assert!(
        !matches!(
            &extra.status,
            elastos_runtime::capability::pending::RequestStatus::Denied { reason, .. }
                if reason == "Too many pending requests"
        ),
        "a later request was refused: {extra:?}"
    );
}

/// Dropping the caller's future, then panicking inside the detached task,
/// still resolves the flight.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_dispatch_future_resolves_the_flight() {
    let plant = plant_approved(67, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let gate = super::gateway_inspect_actions::arm_plan_task_gate(&plant.id);
    crate::resource_bridge::arm_plan_dispatch_panic(&plant.id);
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), gate.entered.notified())
        .await
        .expect("the dispatch task did not start");
    task.abort();
    let _ = task.await;
    gate.release.notify_one();
    let record = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let record = read_record(plant.dir.path(), &plant.id);
            if record["status"] == "unknown" && !plant.runtime.plan_effect_inflight(&plant.session)
            {
                break record;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the dropped task left the flight or the dispatching record");
    assert_eq!(record["status"], "unknown", "{record}");
    plant.runtime.note_plan_instance_ended(&plant.session);
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["unknown"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| step["request_id"] == plant.id)),
        "{body}"
    );
}

async fn register_component_handle(runtime: &crate::runtime::Runtime, agent: &str, session: &str) {
    let manifest: elastos_common::CapsuleManifest = serde_json::from_str(
        &crate::runtime::tests::component_manifest_json("failed-stop"),
    )
    .unwrap();
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.to_string(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: Some(elastos_compute::CapsuleHandle {
                id: elastos_common::CapsuleId(session.to_string()),
                manifest,
                args: Vec::new(),
            }),
            session_id: session.to_string(),
            principal: Some(agent.to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
}

/// The dispatch timeout is longer than retention. The row is already gone when
/// the unknown name is recorded. An injected clock stands in for that wait.
/// After one retention, Stop of the idle agent is the no-session answer.
#[cfg(unix)]
#[tokio::test]
async fn an_unknown_name_leaves_after_the_row_when_the_timeout_is_longer() {
    let plant = plant_approved(78, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let wait = crate::runtime::ENDED_CAPSULE_RETENTION + std::time::Duration::from_secs(60);
    assert!(wait > crate::runtime::ENDED_CAPSULE_RETENTION);
    super::gateway_inspect_actions::set_plan_dispatch_wait_for_test(&plant.id, wait);
    let book = plant.runtime.plan_book();
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &book,
        &plant.session,
        &plant.agent,
        &plant.id,
    )
    .expect("the flight enters");
    drop(guard);
    plant.runtime.note_plan_instance_ended(&plant.session);
    plant
        .runtime
        .end_planted_session_for_test(&plant.session)
        .await;
    plant
        .runtime
        .evict_ended_session_for_test(&plant.session)
        .await;
    assert!(
        plant.runtime.get_capsule(&plant.session).await.is_none(),
        "the row was still listed"
    );
    let start = std::time::Instant::now();
    plant.runtime.set_plan_clock_for_test(Some(start));
    crate::runtime::resolve_unknown_plan_effect(&plant.id);
    assert_eq!(
        plant.runtime.unknown_count_for_test(&plant.agent),
        1,
        "the name did not outlive the row"
    );
    plant
        .runtime
        .set_plan_clock_for_test(Some(start + crate::runtime::ENDED_CAPSULE_RETENTION));
    assert_eq!(plant.runtime.unknown_count_for_test(&plant.agent), 0);
    let (status, body) = stop_plan_agent(plant.runtime.clone(), &plant.agent).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        !body.to_string().contains(&plant.id),
        "Stop still named the old step: {body}"
    );
    plant.runtime.set_plan_clock_for_test(None);
    super::gateway_inspect_actions::clear_plan_dispatch_wait_for_test(&plant.id);
}

/// Unknown at 5s on a live run. Stop at 70s still names the step.
#[cfg(unix)]
#[tokio::test]
async fn an_unknown_on_a_live_run_is_named_when_stop_comes_later() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r7-live";
    let session = "session-r7-live";
    let start = std::time::Instant::now();
    runtime.set_plan_clock_for_test(Some(start));
    register_open_row(&runtime, agent, session).await;
    runtime.set_plan_clock_for_test(Some(start + std::time::Duration::from_secs(5)));
    leave_flight(&runtime, session, agent, "live-step");
    crate::runtime::resolve_unknown_plan_effect("live-step");
    runtime.set_plan_clock_for_test(Some(start + std::time::Duration::from_secs(70)));
    assert_eq!(runtime.unknown_count_for_test(agent), 1);
    let (status, body) = stop_one_capsule(runtime.clone(), session).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let named = body["unknown_steps"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|step| step == "live-step");
    assert!(named, "Stop did not name the live step: {body}");
    runtime.set_plan_clock_for_test(None);
}

/// A capability poll watching the flag during a failing stop does not cancel.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_stop_does_not_cut_a_waiting_poll() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r5-poll";
    let session = "session-r5-poll";
    runtime.plant_open_agent_stop_for_test(agent, session).await;
    register_component_handle(&runtime, agent, session).await;
    let flag = runtime
        .activation_stop_flag_for_test(session)
        .expect("the planted stop");
    let hold = runtime.arm_provider_stop_hold(session);
    runtime.arm_failing_capsule_stop(session);
    let saw = Arc::new(AtomicBool::new(false));
    let poll_flag = Arc::clone(&flag);
    let saw_poll = Arc::clone(&saw);
    let poll = tokio::spawn(async move {
        loop {
            if poll_flag.requested.load(Ordering::Acquire) {
                poll_flag.cancelled.store(true, Ordering::Release);
                saw_poll.store(true, Ordering::Release);
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    let stopping = runtime.clone();
    let stop =
        tokio::spawn(async move { stopping.stop_capsule_with_reason(session, "owner").await });
    tokio::time::timeout(std::time::Duration::from_secs(5), hold.entered())
        .await
        .expect("the stop did not reach the provider");
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert!(
        !flag.requested.load(Ordering::Acquire),
        "the flag was up before the provider stop returned"
    );
    assert!(!saw.load(Ordering::Acquire), "the poll cancelled early");
    hold.release_one();
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), stop)
        .await
        .expect("the stop did not return")
        .expect("the stop task");
    assert!(stopped.is_err(), "the provider stop succeeded");
    assert!(!flag.requested.load(Ordering::Acquire));
    assert!(!flag.cancelled.load(Ordering::Acquire));
    assert!(!saw.load(Ordering::Acquire), "the poll left the call");
    assert!(runtime.requested_stop_for_test(session).is_none());
    poll.abort();
}

/// Two stops overlap. The one that succeeds keeps its cause and its flag.
/// The one that fails does not clear either.
#[cfg(unix)]
#[tokio::test]
async fn two_stops_keep_the_cause_the_first_success_raised() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r5-two";
    let session = "session-r5-two";
    runtime.plant_open_agent_stop_for_test(agent, session).await;
    register_component_handle(&runtime, agent, session).await;
    let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_millis(0));
    let hold = runtime.arm_provider_stop_hold(session);
    let flag = runtime
        .activation_stop_flag_for_test(session)
        .expect("the planted stop");
    let first_runtime = runtime.clone();
    let second_runtime = runtime.clone();
    let first = tokio::spawn(async move {
        first_runtime
            .stop_capsule_with_reason(session, "alpha")
            .await
    });
    let second = tokio::spawn(async move {
        second_runtime
            .stop_capsule_with_reason(session, "beta")
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if hold.arrived() >= 2 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both stops did not reach the provider");
    assert!(
        runtime.requested_stop_for_test(session).is_none(),
        "a cause was written before either stop committed"
    );
    assert!(!flag.requested.load(Ordering::Acquire));
    hold.release_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if flag.requested.load(Ordering::Acquire) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the successful stop did not raise the flag");
    let cause = runtime.requested_stop_for_test(session);
    assert!(cause.is_some(), "the successful stop wrote no cause");
    runtime.arm_failing_capsule_stop(session);
    hold.release_one();
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first stop task");
    let second = second.expect("second stop task");
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second.is_ok()),
        1,
        "first {first:?} second {second:?}"
    );
    assert_eq!(runtime.requested_stop_for_test(session), cause);
    assert!(flag.requested.load(Ordering::Acquire));
    assert!(!flag.cancelled.load(Ordering::Acquire));
}

/// A failed Stop leaves the live run. The next Start says already running.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_stop_lets_start_say_already_running() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r5-start";
    let session = "session-r5-start";
    runtime.plant_open_agent_stop_for_test(agent, session).await;
    register_component_handle(&runtime, agent, session).await;
    runtime.arm_failing_capsule_stop(session);
    let (status, body) = stop_plan_agent(runtime.clone(), agent).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(!runtime.stop_requested_for_test(agent));
    assert!(!runtime.activation_stop_requested_for_test(session));
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600;
    let err = runtime
        .start_agent_once(
            Path::new("unused"),
            crate::agent_admission::AdmissionContext::for_test(agent),
            crate::runtime::AgentStartFacts {
                agent_id: agent,
                owner: "person:owner",
                host_cid: "cid",
                launch_id: "launch:r5-after-fail",
                expires_at: expires,
            },
        )
        .await
        .expect_err("Start accepted a live run");
    let elastos_common::ElastosError::InvalidManifest(message) = err else {
        panic!("Start returned {err}");
    };
    assert_eq!(message, crate::runtime::Runtime::AGENT_ALREADY_RUNNING);
}

/// Dropping an unsettled dispatch on a thread with no Tokio runtime settles
/// once. The grant stays in this process's memory and the spend is refused.
/// Nothing waits on the async revoke.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_dispatch_revokes_without_a_runtime() {
    let plant = plant_approved(82, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pending = plant
        .store
        .create_request(
            elastos_runtime::session::SessionId(plant.session.clone()),
            elastos_runtime::capability::ResourceId::new("elastos://availability/status"),
            elastos_runtime::capability::Action::Read,
        )
        .await;
    let token = plant.manager.grant(
        &plant.session,
        pending.resource.clone(),
        pending.action,
        elastos_runtime::capability::TokenConstraints::new(0, false, None, None),
        None,
    );
    plant
        .store
        .grant_request(
            pending.id.as_str(),
            token.clone(),
            elastos_runtime::capability::pending::GrantDuration::Session,
        )
        .await
        .expect("the grant is pending");
    let spend_token = token.clone();
    crate::resource_bridge::park_abandoned_grant_for_test(
        &plant.id,
        plant.manager.clone(),
        plant.store.clone(),
        token,
        pending.id.as_str().to_string(),
    );
    let dir = plant.dir.path().to_path_buf();
    let id = plant.id.clone();
    let joined = std::thread::spawn(move || {
        assert!(tokio::runtime::Handle::try_current().is_err());
        super::gateway_inspect_actions::drop_unsettled_dispatch_for_test(&dir, &id);
    })
    .join();
    assert!(joined.is_ok(), "{joined:?}");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "unknown", "{record}");
    assert_eq!(record["result"]["code"], "dispatch_lost", "{record}");
    let unknown_audits = crate::auth::load_auth_state(plant.dir.path())
        .unwrap()
        .audit
        .iter()
        .filter(|event| {
            event.event_type == "agent_plan.dispatch.unknown"
                && event.challenge_id.as_deref() == Some(plant.id.as_str())
        })
        .count();
    assert_eq!(
        unknown_audits, 1,
        "the drop wrote more than one unknown audit"
    );
    let spent =
        crate::resource_bridge::spend_plan_grant_for_test(&plant.manager, &spend_token).await;
    assert!(
        spent.is_err(),
        "the dropped grant was still spendable: {spent:?}"
    );
    let row = plant
        .store
        .get_request(pending.id.as_str())
        .await
        .expect("the pending row");
    assert!(
        row.is_granted(),
        "a drop with no runtime revoked the in-memory row: {row:?}"
    );
}

/// Drop on a current-thread runtime returns while another task holds the
/// request-map write lock. A spend in that window is refused. One audit.
#[cfg(unix)]
#[test]
fn a_drop_on_a_current_thread_runtime_returns_while_the_write_lock_is_held() {
    let setup = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (dir, path, manager, store, id, spend_token) = setup.block_on(async {
        let plant = plant_approved(84, false, |_, target| {
            json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
                "path": target, "content": [112, 108, 97, 110]
            }}]})
        })
        .await;
        let pending = plant
            .store
            .create_request(
                elastos_runtime::session::SessionId(plant.session.clone()),
                elastos_runtime::capability::ResourceId::new("elastos://availability/status"),
                elastos_runtime::capability::Action::Read,
            )
            .await;
        let token = plant.manager.grant(
            &plant.session,
            pending.resource.clone(),
            pending.action,
            elastos_runtime::capability::TokenConstraints::new(0, false, None, None),
            None,
        );
        plant
            .store
            .grant_request(
                pending.id.as_str(),
                token.clone(),
                elastos_runtime::capability::pending::GrantDuration::Session,
            )
            .await
            .expect("the grant is pending");
        let spend_token = token.clone();
        crate::resource_bridge::park_abandoned_grant_for_test(
            &plant.id,
            plant.manager.clone(),
            plant.store.clone(),
            token,
            pending.id.as_str().to_string(),
        );
        let path = plant.dir.path().to_path_buf();
        (
            plant.dir,
            path,
            plant.manager,
            plant.store,
            plant.id,
            spend_token,
        )
    });
    let _keep_dir = dir;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async move {
                let entered = std::sync::Arc::new(tokio::sync::Notify::new());
                let release = std::sync::Arc::new(tokio::sync::Notify::new());
                let holding = store.clone();
                let entered_hold = std::sync::Arc::clone(&entered);
                let release_hold = std::sync::Arc::clone(&release);
                tokio::spawn(async move {
                    holding
                        .hold_requests_write_for_test(&entered_hold, &release_hold)
                        .await;
                });
                tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
                    .await
                    .expect("the write lock was not taken");
                ready_tx.send(()).expect("the ready signal");
                super::gateway_inspect_actions::drop_unsettled_dispatch_for_test(&path, &id);
                let spent =
                    crate::resource_bridge::spend_plan_grant_for_test(&manager, &spend_token).await;
                assert!(
                    spent.is_err(),
                    "the grant was spendable before revoke: {spent:?}"
                );
                let unknown_audits = crate::auth::load_auth_state(&path)
                    .unwrap()
                    .audit
                    .iter()
                    .filter(|event| {
                        event.event_type == "agent_plan.dispatch.unknown"
                            && event.challenge_id.as_deref() == Some(id.as_str())
                    })
                    .count();
                assert_eq!(
                    unknown_audits, 1,
                    "the drop wrote more than one unknown audit"
                );
                release.notify_one();
            });
        }));
        let message = match outcome {
            Ok(()) => Ok(()),
            Err(payload) => Err(panic_text(payload)),
        };
        let _ = done_tx.send(message);
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the current-thread drop did not reach the lock");
    match done_rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok(Ok(())) => {}
        Ok(Err(message)) => panic!("{message}"),
        Err(_) => panic!("the drop did not return while the write lock was held"),
    }
}

/// Dropping the dispatch takes the guard that was parked for the flight.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_dispatch_takes_the_parked_guard() {
    let plant = plant_approved(88, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent,
        &plant.id,
    )
    .expect("the flight enters");
    crate::resource_bridge::park_plan_guard_for_test(&plant.id, guard);
    assert!(
        crate::resource_bridge::parked_plan_guard_is_held(&plant.id),
        "the guard was not parked"
    );
    super::gateway_inspect_actions::drop_unsettled_dispatch_for_test(plant.dir.path(), &plant.id);
    assert!(
        !crate::resource_bridge::parked_plan_guard_is_held(&plant.id),
        "the drop left the parked guard"
    );
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "the drop row panicked".to_string()
    }
}

/// A concurrent grant of the same pending row is revoked when registration fails.
#[cfg(unix)]
#[tokio::test]
async fn a_grant_registered_by_a_racer_is_revoked() {
    let plant = plant_approved(83, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pause = crate::resource_bridge::arm_one_use_grant_race(&plant.id);
    let state = plant.state.clone();
    let owner = plant.owner.clone();
    let id = plant.id.clone();
    let task = tokio::spawn(async move {
        super::gateway_inspect_actions::dispatch_approved_agent_plan(
            &state,
            &dispatch_context(&owner),
            &id,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("registration did not reach the race");
    let pending_id = pause.pending_id().expect("the pending id");
    let pending = plant
        .store
        .get_request(&pending_id)
        .await
        .expect("the pending row");
    let token = plant.manager.grant(
        &plant.session,
        pending.resource.clone(),
        pending.action,
        elastos_runtime::capability::TokenConstraints::new(0, false, None, None),
        None,
    );
    plant
        .store
        .grant_request(
            &pending_id,
            token,
            elastos_runtime::capability::pending::GrantDuration::Once,
        )
        .await
        .expect("the racer grants the pending row");
    drop(pause);
    let settled = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .expect("the dispatch did not settle")
        .expect("the dispatch task");
    assert!(settled.is_ok(), "{settled:?}");
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "refused", "{record}");
    assert_eq!(record["result"]["code"], "capability_denied", "{record}");
    let row = plant
        .store
        .get_request(&pending_id)
        .await
        .expect("the pending row");
    assert!(
        matches!(
            row.status,
            elastos_runtime::capability::pending::RequestStatus::Denied { ref reason, .. }
                if reason == "grant not registered"
        ),
        "the concurrent grant was left {row:?}"
    );
}

async fn register_open_row(runtime: &crate::runtime::Runtime, agent: &str, session: &str) {
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.to_string(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.to_string(),
            principal: Some(agent.to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
    runtime.bind_plan_instance(session, agent);
}

fn leave_flight(runtime: &crate::runtime::Runtime, session: &str, agent: &str, request: &str) {
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &runtime.plan_book(),
        session,
        agent,
        request,
    )
    .expect("the flight enters");
    drop(guard);
}

/// Resolved one second before the row is swept. The name stays, then an
/// ordinary bind drops it when the retention is reached.
#[cfg(unix)]
#[tokio::test]
async fn an_unknown_resolved_a_second_before_the_sweep_survives_it() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r6-sweep";
    let session = "session-r6-sweep";
    let start = std::time::Instant::now();
    runtime.set_plan_clock_for_test(Some(start));
    register_open_row(&runtime, agent, session).await;
    leave_flight(&runtime, session, agent, "sweep-step");
    crate::runtime::resolve_unknown_plan_effect("sweep-step");
    runtime.set_plan_clock_for_test(Some(start + std::time::Duration::from_secs(1)));
    runtime.evict_ended_session_for_test(session).await;
    assert_eq!(
        runtime.unknown_ids_for_test(agent),
        vec!["sweep-step".to_string()],
        "the sweep dropped a name one second old"
    );
    runtime.note_plan_instance_ended(session);
    runtime.set_plan_clock_for_test(Some(
        start + std::time::Duration::from_secs(1) + crate::runtime::ENDED_CAPSULE_RETENTION,
    ));
    runtime.bind_plan_instance("session-r6-sweep-next", agent);
    assert!(
        runtime.unknown_ids_for_test(agent).is_empty(),
        "the name outlived its retention"
    );
    runtime.set_plan_clock_for_test(None);
}

/// Unregister keeps a name inside its retention and drops one that is due.
#[cfg(unix)]
#[tokio::test]
async fn a_watcherless_unregister_keeps_the_unknown_name() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r6-unreg";
    let start = std::time::Instant::now();
    runtime.set_plan_clock_for_test(Some(start));
    register_open_row(&runtime, agent, "session-r6-unreg").await;
    leave_flight(&runtime, "session-r6-unreg", agent, "unreg-step");
    crate::runtime::resolve_unknown_plan_effect("unreg-step");
    runtime.unregister_capsule("session-r6-unreg").await;
    assert_eq!(
        runtime.unknown_ids_for_test(agent),
        vec!["unreg-step".to_string()],
        "unregister dropped a name inside its retention"
    );
    register_open_row(&runtime, agent, "session-r6-due").await;
    leave_flight(&runtime, "session-r6-due", agent, "due-step");
    crate::runtime::resolve_unknown_plan_effect("due-step");
    runtime.note_plan_instance_ended("session-r6-unreg");
    runtime.note_plan_instance_ended("session-r6-due");
    runtime.set_plan_clock_for_test(Some(start + crate::runtime::ENDED_CAPSULE_RETENTION));
    runtime.unregister_capsule("session-r6-due").await;
    let ids = runtime.unknown_ids_for_test(agent);
    assert!(
        ids.is_empty(),
        "an expired name survived unregister: {ids:?}"
    );
    runtime.set_plan_clock_for_test(None);
}

/// After the retention, try_enter drops both names. A later burst keeps 32.
#[cfg(unix)]
#[tokio::test]
async fn unknown_names_leave_after_retention_and_stay_within_thirty_two() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r6-cap";
    let start = std::time::Instant::now();
    runtime.set_plan_clock_for_test(Some(start));
    register_open_row(&runtime, agent, "session-r6-cap-sweep").await;
    leave_flight(&runtime, "session-r6-cap-sweep", agent, "cap-sweep");
    crate::runtime::resolve_unknown_plan_effect("cap-sweep");
    runtime.set_plan_clock_for_test(Some(start + std::time::Duration::from_secs(1)));
    runtime
        .evict_ended_session_for_test("session-r6-cap-sweep")
        .await;
    runtime.set_plan_clock_for_test(Some(start));
    register_open_row(&runtime, agent, "session-r6-cap-unreg").await;
    leave_flight(&runtime, "session-r6-cap-unreg", agent, "cap-unreg");
    crate::runtime::resolve_unknown_plan_effect("cap-unreg");
    runtime.unregister_capsule("session-r6-cap-unreg").await;
    assert_eq!(runtime.unknown_ids_for_test(agent).len(), 2);
    runtime.note_plan_instance_ended("session-r6-cap-sweep");
    runtime.note_plan_instance_ended("session-r6-cap-unreg");
    // Both names are due at this clock. The later try_enter is what drops them.
    register_open_row(&runtime, agent, "session-r6-cap-live").await;
    runtime.set_plan_clock_for_test(Some(start + crate::runtime::ENDED_CAPSULE_RETENTION));
    leave_flight(&runtime, "session-r6-cap-live", agent, "cap-probe");
    assert!(
        runtime.unknown_ids_for_test(agent).is_empty(),
        "try_enter left an expired name: {:?}",
        runtime.unknown_ids_for_test(agent)
    );
    runtime.set_plan_clock_for_test(Some(
        start + crate::runtime::ENDED_CAPSULE_RETENTION + std::time::Duration::from_secs(1),
    ));
    for n in 0..33 {
        let id = format!("cap-{n}");
        leave_flight(&runtime, "session-r6-cap-live", agent, &id);
        crate::runtime::resolve_unknown_plan_effect(&id);
    }
    let ids = runtime.unknown_ids_for_test(agent);
    assert_eq!(ids.len(), 32, "{ids:?}");
    assert!(!ids.iter().any(|id| id == "cap-0"), "{ids:?}");
    assert!(ids.iter().any(|id| id == "cap-32"), "{ids:?}");
    runtime.set_plan_clock_for_test(None);
}

/// The first caller fails while the second is still open. The second cause wins.
#[cfg(unix)]
#[tokio::test]
async fn the_second_callers_cause_wins_when_the_first_fails() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r6-cause";
    let session = "session-r6-cause";
    runtime.plant_open_agent_stop_for_test(agent, session).await;
    register_component_handle(&runtime, agent, session).await;
    let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_millis(0));
    let hold = runtime.arm_provider_stop_hold(session);
    let first_runtime = runtime.clone();
    let first = tokio::spawn(async move {
        first_runtime
            .stop_capsule_with_reason(session, "alpha")
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if hold.arrived() >= 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first stop did not reach the provider");
    let second_runtime = runtime.clone();
    let second = tokio::spawn(async move {
        second_runtime
            .stop_capsule_with_reason(session, "beta")
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if hold.arrived() >= 2 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second stop did not reach the provider");
    assert!(runtime.requested_stop_for_test(session).is_none());
    runtime.arm_failing_capsule_stop(session);
    hold.release_oldest();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), first)
        .await
        .expect("the first stop did not return")
        .expect("the first stop task");
    assert!(first.is_err(), "the first stop succeeded: {first:?}");
    assert!(
        runtime.requested_stop_for_test(session).is_none(),
        "the failed caller left its cause"
    );
    hold.release_one();
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .expect("the second stop did not return")
        .expect("the second stop task");
    assert!(second.is_ok(), "the second stop failed: {second:?}");
    assert_eq!(
        runtime.requested_stop_for_test(session).as_deref(),
        Some("stopped: beta")
    );
}

/// The mark is up while Stop is still waiting for the end. Start says stopping.
#[cfg(unix)]
#[tokio::test]
async fn a_stop_dropped_while_waiting_leaves_start_stopping() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = bare_runtime(dir.path()).await;
    let agent = "agent:r6-wait";
    let session = "session-r6-wait";
    runtime.plant_open_agent_stop_for_test(agent, session).await;
    let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_secs(5));
    let stopping = runtime.clone();
    let task =
        tokio::spawn(async move { stopping.stop_capsule_with_reason(session, "owner").await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if runtime.stop_requested_for_test(agent) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the stop mark did not rise before the wait ended");
    assert!(runtime
        .get_capsule(session)
        .await
        .unwrap()
        .ended_at
        .is_none());
    task.abort();
    let _ = task.await;
    assert!(runtime.stop_requested_for_test(agent));
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600;
    let err = runtime
        .start_agent_once(
            Path::new("unused"),
            crate::agent_admission::AdmissionContext::for_test(agent),
            crate::runtime::AgentStartFacts {
                agent_id: agent,
                owner: "person:owner",
                host_cid: "cid",
                launch_id: "launch:r6-while-stopping",
                expires_at: expires,
            },
        )
        .await
        .expect_err("Start accepted an agent whose stop is waiting");
    let elastos_common::ElastosError::InvalidManifest(message) = err else {
        panic!("Start returned {err}");
    };
    assert_eq!(message, crate::runtime::Runtime::AGENT_STOPPING);
}

/// The task is aborted before its first poll. The claim settles once.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn an_unpolled_dispatch_settles_unknown_once() {
    let plant = plant_approved(86, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pending = plant
        .store
        .create_request(
            elastos_runtime::session::SessionId(plant.session.clone()),
            elastos_runtime::capability::ResourceId::new("elastos://availability/status"),
            elastos_runtime::capability::Action::Read,
        )
        .await;
    let token = plant.manager.grant(
        &plant.session,
        pending.resource.clone(),
        pending.action,
        elastos_runtime::capability::TokenConstraints::new(0, false, None, None),
        None,
    );
    plant
        .store
        .grant_request(
            pending.id.as_str(),
            token.clone(),
            elastos_runtime::capability::pending::GrantDuration::Session,
        )
        .await
        .expect("the grant is pending");
    crate::resource_bridge::park_abandoned_grant_for_test(
        &plant.id,
        plant.manager.clone(),
        plant.store.clone(),
        token,
        pending.id.as_str().to_string(),
    );
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &plant.runtime.plan_book(),
        &plant.session,
        &plant.agent,
        &plant.id,
    )
    .expect("the flight enters");
    drop(guard);
    assert!(plant.runtime.plan_effect_inflight(&plant.session));
    super::gateway_inspect_actions::arm_unpolled_dispatch(&plant.id);
    let settled = super::gateway_inspect_actions::dispatch_approved_agent_plan(
        &plant.state,
        &dispatch_context(&plant.owner),
        &plant.id,
    )
    .await;
    assert!(settled.is_ok(), "{settled:?}");
    assert!(
        !super::gateway_inspect_actions::dispatch_was_polled(&plant.id),
        "the task was polled"
    );
    let record = read_record(plant.dir.path(), &plant.id);
    assert_eq!(record["status"], "unknown", "{record}");
    assert_eq!(record["result"]["code"], "dispatch_lost", "{record}");
    let unknown_audits = crate::auth::load_auth_state(plant.dir.path())
        .unwrap()
        .audit
        .iter()
        .filter(|event| {
            event.event_type == "agent_plan.dispatch.unknown"
                && event.challenge_id.as_deref() == Some(plant.id.as_str())
        })
        .count();
    assert_eq!(
        unknown_audits, 1,
        "the drop wrote more than one unknown audit"
    );
    assert!(!plant.runtime.plan_effect_inflight(&plant.session));
    let row = plant
        .store
        .get_request(pending.id.as_str())
        .await
        .expect("the pending row");
    assert!(
        matches!(
            row.status,
            elastos_runtime::capability::pending::RequestStatus::Denied { ref reason, .. }
                if reason == "plan dispatch abandoned"
        ),
        "the grant was left {row:?}"
    );
}

/// The post-effect revoke is still awaiting when the task is dropped. The
/// grant stays in the guard until that await ends, so the drop leaves it in
/// the abandoned list. One revoke runs, and the pending store no longer holds
/// the grant as granted.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_revoke_revokes_the_grant_once_and_frees_its_place() {
    let plant = plant_approved(90, false, |_, target| {
        json!({"steps": [{"scheme": "localhost", "operation": "write", "request": {
            "path": target, "content": [112, 108, 97, 110]
        }}]})
    })
    .await;
    let pause = crate::resource_bridge::arm_plan_dispatch_hold(
        &plant.id,
        crate::resource_bridge::PlanDispatchPoint::Revoke,
    );
    let record = read_record(plant.dir.path(), &plant.id);
    let id = plant.id.clone();
    let owner = record["principal_id"].as_str().unwrap().to_string();
    let requester = record["requester_id"].as_str().unwrap().to_string();
    let capsule = record["id"].as_str().unwrap().to_string();
    let session = record["session_id"].as_str().unwrap().to_string();
    let dir = plant.dir.path().to_path_buf();
    let step = record["request"].clone();
    let task = tokio::spawn(async move {
        crate::resource_bridge::dispatch_agent_plan_step(
            &id, &owner, &requester, &capsule, &session, &dir, &step,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the revoke await was not held");
    task.abort();
    let dropped = task.await.expect_err("the revoke task kept running");
    assert!(dropped.is_cancelled(), "{dropped:?}");
    drop(crate::resource_bridge::take_parked_plan_guard(&plant.id));
    crate::resource_bridge::revoke_abandoned_plan_grant(&plant.id).await;
    let revokes = plant
        .manager
        .audit_log()
        .recent_events(40)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                elastos_runtime::primitives::audit::AuditEvent::CapabilityRevoke { reason, .. }
                    if reason == "plan dispatch abandoned"
            )
        })
        .count();
    assert_eq!(revokes, 1, "the dropped revoke did not revoke once");
    let rows = plant.store.list_requests().await;
    let granted = rows
        .iter()
        .filter(|request| request.session_id.as_str() == plant.session && request.is_granted())
        .count();
    assert_eq!(granted, 0, "the pending store kept the grant");
    let freed = rows
        .iter()
        .filter(|request| {
            request.session_id.as_str() == plant.session
                && matches!(
                    &request.status,
                    elastos_runtime::capability::pending::RequestStatus::Denied { reason, .. }
                        if reason == "plan dispatch abandoned"
                )
        })
        .count();
    assert_eq!(freed, 1, "the pending place was not freed: {rows:?}");
}
