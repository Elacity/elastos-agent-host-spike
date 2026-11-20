//! A15-R slice 4: the owner approves the exact agent plan shown in Inbox.
//!
//! Every case drives the real Inbox action route with a Home launch token and a
//! fresh passkey step-up token bound to the request.

use super::*;
use crate::api::gateway::submit_pending_agent_plan;
use std::path::Path;

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
    submit_pending_agent_plan(
        dir,
        owner,
        requester,
        "capsule:agent-host",
        "session:agent-1",
        &plan,
        now,
    )
    .unwrap()
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

#[tokio::test]
async fn a15r_approve_requires_the_exact_plan_shown() {
    // The binding the card showed is approved as shown after one fresh
    // passkey, and nothing runs.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(agent_plan_state(dir.path()));
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        51,
    );
    let request_id = created["request_id"].as_str().unwrap();
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
    assert!(body.contains("Approved agent plan"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "approved");
    assert_eq!(record["request_binding"], created["request_binding"]);
    assert!(record["result"].is_null(), "approval runs nothing");

    // A card hash other than the stored binding is refused and leaves the
    // record stale.
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(agent_plan_state(dir.path()));
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
    let app = gateway_router(agent_plan_state(dir.path()));
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
    let app = gateway_router(agent_plan_state(dir.path()));
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
    let app = gateway_router(agent_plan_state(dir.path()));
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

#[tokio::test]
async fn a15r_approve_is_the_owners_alone() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(agent_plan_state(dir.path()));
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

#[tokio::test]
async fn a15r_approve_a_writing_step_needs_a_fresh_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(agent_plan_state(dir.path()));
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

    // A fresh passkey bound to this request approves the write step and
    // nothing runs here.
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
    assert!(body.contains("Approved agent plan"), "{body}");
    let record = read_record(dir.path(), request_id);
    assert_eq!(record["status"], "approved");
    assert!(record["result"].is_null(), "approval runs nothing");
}

#[tokio::test]
async fn a15r_double_clicks_claim_one_plan() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(agent_plan_state(dir.path()));
    let owner = passkey_authority(dir.path());
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &owner);
    let created = submit(
        dir.path(),
        &owner.principal_id,
        "agent:v2:plan-requester",
        read_plan(),
        81,
    );
    let request_id = created["request_id"].as_str().unwrap();
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
    assert_eq!(read_record(dir.path(), request_id)["status"], "approved");
}
