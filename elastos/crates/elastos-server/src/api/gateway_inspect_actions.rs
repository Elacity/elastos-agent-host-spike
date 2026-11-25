use super::*;

#[path = "gateway_inspect_actions/agent_plan.rs"]
mod agent_plan;
#[path = "gateway_inspect_actions/binding.rs"]
mod binding;
#[path = "gateway_inspect_actions/store.rs"]
mod store;

use binding::{
    inspect_action_request_binding, inspect_action_request_id, inspect_action_request_nonce,
};
use store::{
    claim_pending_inspect_action_record, read_inspect_action_record, write_inspect_action_record,
    InspectActionRequestRecord, AGENT_PLAN_KIND, INSPECT_ACTION_KIND, INSPECT_ACTION_SCHEMA,
};

/// The one entry point an agent's Bus submission uses: write the pending
/// agent plan record and return it. The record's principal is the owner, so
/// it is the owner's to read and decide; the agent is its requester. Every
/// identity is the caller's Runtime context; the submitted plan cannot name
/// one. Nothing here runs a step.
pub(crate) fn submit_pending_agent_plan(
    data_dir: &FsPath,
    owner_id: &str,
    requester_id: &str,
    capsule_id: &str,
    session_id: &str,
    plan: &serde_json::Value,
    now: u64,
) -> anyhow::Result<serde_json::Value> {
    let context = agent_plan::AgentPlanContext {
        principal_id: owner_id,
        requester_id,
        capsule_id,
        session_id,
    };
    let record = agent_plan::create_pending_agent_plan_record(data_dir, &context, plan, now)?;
    Ok(serde_json::json!({
        "schema": INSPECT_ACTION_SCHEMA,
        "status": "pending",
        "request_id": record.request_id,
        "id": record.id,
        "operation": record.operation,
        "request": record.request,
        "plan": record.plan,
        "request_binding": record.request_binding,
        "principal_id": record.principal_id,
        "requester_id": record.requester_id,
        "created_at": record.created_at,
    }))
}

pub(super) async fn gateway_inspect_action_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request: &serde_json::Value,
) -> Response {
    match create_inspect_action_request(state, context, request).await {
        Ok(record) => Json(serde_json::json!({
            "schema": INSPECT_ACTION_SCHEMA,
            "status": "pending",
            "request_id": record.request_id,
            "id": record.id,
            "operation": record.operation,
            "plan": record.plan,
            "request_binding": record.request_binding,
        }))
        .into_response(),
        Err(err) => gateway_provider_error_response("inspect", err),
    }
}

pub(super) fn append_inspect_action_notifications(
    notifications: &mut HomeNotificationsSummary,
    requests: Vec<serde_json::Value>,
) {
    for request in requests {
        if request.get("kind").and_then(serde_json::Value::as_str) == Some(AGENT_PLAN_KIND) {
            append_agent_plan_notification(notifications, &request);
            continue;
        }
        let request_id = request
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let target = request
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("inspect target");
        let operation = request
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("provider operation");
        let created_at = request
            .get("created_at")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(now_ts);
        let request_hash = request
            .pointer("/request_binding/sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let request_hash_short = request_hash
            .get(..12)
            .filter(|value| !value.is_empty())
            .unwrap_or("unbound");
        let gate_summary = inspect_action_gate_summary(request.get("plan"));
        let body = match gate_summary {
            Some(summary) => format!(
                "System requests approval to run {operation} on {target} with request {request_hash_short}. {summary}"
            ),
            None => format!(
                "System requests approval to run {operation} on {target} with request {request_hash_short}."
            ),
        };
        notifications.unread_count += 1;
        notifications.attention_count += 1;
        notifications.entries.push(HomeNotificationEntrySummary {
            id: format!("inspect-action-request:{request_id}"),
            source_app: SYSTEM_CAPSULE_ID.to_string(),
            kind: "inspect_action_request".to_string(),
            title: "Runtime action request".to_string(),
            body,
            action_ref: Some(HomeNotificationActionSummary {
                app: INBOX_CAPSULE_ID.to_string(),
                action_id: format!("inspect-approve-request:{request_id}"),
            }),
            severity: "attention".to_string(),
            read: false,
            created_at,
            ..Default::default()
        });
    }
}

/// One Inbox card for a pending agent plan: every stored step, the gate preview,
/// the full binding hash and the exact binding the click sends back. The owner
/// alone approves it; a writing step says it needs a fresh passkey.
fn append_agent_plan_notification(
    notifications: &mut HomeNotificationsSummary,
    request: &serde_json::Value,
) {
    let request_id = request
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let target = request
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("agent plan");
    let created_at = request
        .get("created_at")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(now_ts);
    let steps = request
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::with_capacity(steps.len() + 2);
    for (index, step) in steps.iter().enumerate() {
        let step = serde_json::to_string(step).unwrap_or_default();
        lines.push(format!("Step {}: {step}", index + 1));
    }
    if let Some(summary) = inspect_action_gate_summary(request.get("plan")) {
        lines.push(summary);
    }
    let sha256 = request
        .pointer("/request_binding/sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    lines.push(format!("Binding sha256: {sha256}"));
    notifications.unread_count += 1;
    notifications.attention_count += 1;
    notifications.entries.push(HomeNotificationEntrySummary {
        id: format!("agent-plan-request:{request_id}"),
        source_app: INBOX_CAPSULE_ID.to_string(),
        kind: AGENT_PLAN_KIND.to_string(),
        title: format!("Agent plan for {target}"),
        body: lines.join("\n"),
        action_ref: Some(HomeNotificationActionSummary {
            app: INBOX_CAPSULE_ID.to_string(),
            action_id: format!("agent-plan-approve-request:{request_id}"),
        }),
        request_binding: request.get("request_binding").cloned(),
        severity: "attention".to_string(),
        read: false,
        created_at,
    });
}

fn inspect_action_gate_summary(plan: Option<&serde_json::Value>) -> Option<String> {
    let plan = plan?;
    let mut parts = Vec::new();
    let capabilities = plan
        .get("capabilities")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|capability| {
                    let resource = capability
                        .get("resource")
                        .and_then(serde_json::Value::as_str)?
                        .trim();
                    if resource.is_empty() {
                        return None;
                    }
                    let actions = capability
                        .get("actions")
                        .and_then(serde_json::Value::as_array)
                        .map(|actions| {
                            actions
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                                .take(3)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    if actions.is_empty() {
                        Some(format!("Capability {resource}"))
                    } else {
                        Some(format!("Capability {resource}: {}", actions.join(", ")))
                    }
                })
                .take(2)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    parts.extend(capabilities);
    let audits = plan
        .get("audit_events")
        .and_then(serde_json::Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .take(3)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !audits.is_empty() {
        parts.push(format!("Audit {}", audits.join(", ")));
    }
    (!parts.is_empty()).then(|| format!("Gate preview: {}.", parts.join(". ")))
}

pub(super) fn pending_inspect_action_requests(
    data_dir: &FsPath,
    principal_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    store::pending_inspect_action_requests(data_dir, principal_id)
}

pub(super) async fn approve_inspect_action_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    context: &HomeLaunchTokenContext,
    request_id: &str,
    step_up_token: &str,
) -> anyhow::Result<String> {
    let (mut record, request_binding) =
        claim_bound_pending_inspect_action(state, context, request_id, "approving")?;
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("inspect provider unavailable"))?;
    let current_plan = registry
        .send_raw(
            "inspect",
            &serde_json::json!({
                "op": "plan",
                "id": record.id,
                "operation": record.operation,
            }),
        )
        .await?;
    if current_plan
        .get("status")
        .and_then(serde_json::Value::as_str)
        != Some("ok")
        || current_plan.get("data") != Some(&record.plan)
    {
        let message =
            "Inspector action request is no longer pending because its authority plan changed";
        record.status = "stale".to_string();
        record.error = Some(message.to_string());
        record.result = Some(current_plan);
        record.updated_at = now_ts();
        write_inspect_action_record(&state.data_dir, &record)?;
        append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: INBOX_CAPSULE_ID,
                event_type: "inspect.action.stale",
                principal_id: context.principal_id(),
                session_id: context.session_id(),
                request_id,
                result: "stale",
                reason: "Inspector action authority changed before Inbox approval",
            },
        )?;
        anyhow::bail!(message);
    }
    if let Err(err) = consume_passkey_step_up_token(
        &state.data_dir,
        step_up_token,
        launch,
        180,
        "inspect.approve",
        &serde_json::json!({ "request_id": record.request_id }),
    ) {
        record.status = "pending".to_string();
        record.updated_at = now_ts();
        write_inspect_action_record(&state.data_dir, &record)?;
        return Err(err);
    }
    let response = registry
        .send_raw(
            "inspect",
            &serde_json::json!({
                "op": "dispatch_approved",
                "id": record.id,
                "operation": record.operation,
                "request": record.request,
                "request_binding": request_binding,
            }),
        )
        .await?;
    if response.get("status").and_then(serde_json::Value::as_str) == Some("ok") {
        if let Err(message) = validate_inspect_dispatch_result(&response, &request_binding) {
            record.status = "failed".to_string();
            record.error = Some(message.clone());
            record.result = Some(serde_json::json!({
                "status": "error",
                "code": "result_binding_mismatch",
                "message": message,
                "provider_result": response,
                "request_binding": request_binding,
            }));
            record.updated_at = now_ts();
            write_inspect_action_record(&state.data_dir, &record)?;
            append_provider_effect_audit(
                &state.data_dir,
                ProviderEffectAuditInput {
                    capsule_id: INBOX_CAPSULE_ID,
                    event_type: "inspect.action.failed",
                    principal_id: context.principal_id(),
                    session_id: context.session_id(),
                    request_id,
                    result: "failed",
                    reason: "Inspector action result did not match its exact request binding",
                },
            )?;
            anyhow::bail!("Inspector action result did not match its exact request binding");
        }
        record.status = "completed".to_string();
        record.result = Some(response.clone());
        record.updated_at = now_ts();
        write_inspect_action_record(&state.data_dir, &record)?;
        append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: INBOX_CAPSULE_ID,
                event_type: "inspect.action.completed",
                principal_id: context.principal_id(),
                session_id: context.session_id(),
                request_id,
                result: "completed",
                reason: "Approved Inspector action through Inbox",
            },
        )?;
        return Ok("Approved and dispatched Inspector action.".to_string());
    }
    let message = response
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Inspector action dispatch failed")
        .to_string();
    record.status = "failed".to_string();
    record.error = Some(message.clone());
    record.result = Some(response);
    record.updated_at = now_ts();
    write_inspect_action_record(&state.data_dir, &record)?;
    append_provider_effect_audit(
        &state.data_dir,
        ProviderEffectAuditInput {
            capsule_id: INBOX_CAPSULE_ID,
            event_type: "inspect.action.failed",
            principal_id: context.principal_id(),
            session_id: context.session_id(),
            request_id,
            result: "failed",
            reason: "Approved Inspector action dispatch failed through Inbox",
        },
    )?;
    anyhow::bail!(message);
}

/// Approve the exact card the owner saw: owner alone, one fresh passkey, one claim.
pub(super) fn approve_agent_plan_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    context: &HomeLaunchTokenContext,
    request_id: &str,
    card_binding: &serde_json::Value,
    step_up_token: Option<&str>,
) -> anyhow::Result<String> {
    store::claim_pending_agent_plan_for_owner(
        &state.data_dir,
        request_id,
        context.principal_id(),
        context.root().kind() == Some(crate::auth::PrincipalKind::Human),
        card_binding,
        now_ts(),
        |record| {
            let token = step_up_token.ok_or_else(|| {
                anyhow::anyhow!("fresh passkey is required to approve an agent plan")
            })?;
            consume_passkey_step_up_token(
                &state.data_dir,
                token,
                launch,
                180,
                "agent_plan.approve",
                &serde_json::json!({ "request_id": record.request_id }),
            )
        },
    )?;
    Ok("Approved agent plan. The step is ready for Runtime dispatch.".to_string())
}

pub(super) fn settle_agent_plans_lost_before_start(data_dir: &FsPath) -> anyhow::Result<()> {
    store::settle_agent_plans_lost_before_start(data_dir, now_ts())
}

/// The spawned dispatch owns this. `finish` is called once a settlement was
/// attempted. A drop before that, including a panic after the caller's future
/// was dropped, stores unknown and resolves the flight.
struct UnsettledDispatch {
    data_dir: std::path::PathBuf,
    record: InspectActionRequestRecord,
    request_id: String,
    finished: bool,
}

impl UnsettledDispatch {
    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for UnsettledDispatch {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        // A parked flight is not part of this value. Take it here so a
        // cancelled task does not leave the guard in the map.
        drop(crate::resource_bridge::take_parked_plan_guard(
            &self.request_id,
        ));
        let code = if std::thread::panicking() {
            "dispatch_panic"
        } else {
            "dispatch_lost"
        };
        let record = self.record.clone();
        let _ = settle_agent_plan_dispatch(
            &self.data_dir,
            record,
            "unknown",
            serde_json::json!({"status": "unknown", "code": code}),
        );
        crate::runtime::resolve_unknown_plan_effect(&self.request_id);
        let request_id = self.request_id.clone();
        crate::resource_bridge::refuse_abandoned_plan_grant(&request_id);
        // The grant table is process memory. A live runtime finishes the
        // revoke later. With no runtime, the mark and the stored unknown
        // are the whole end: this process is not going to spend it.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                crate::resource_bridge::revoke_abandoned_plan_grant(&request_id).await;
            });
        }
    }
}

/// Drops an unsettled dispatch. A row calls this on a thread with no runtime.
#[cfg(all(test, unix))]
pub(crate) fn drop_unsettled_dispatch_for_test(data_dir: &FsPath, request_id: &str) {
    let record = read_inspect_action_record(data_dir, request_id).expect("the plan record");
    let _cleanup = UnsettledDispatch {
        data_dir: data_dir.to_path_buf(),
        record,
        request_id: request_id.to_string(),
        finished: false,
    };
}

/// Claim the stored step, audit the claim, then let its settlement outlive the
/// Inbox request. A stopped process still leaves a one-way claim.
pub(in crate::api) async fn dispatch_approved_agent_plan(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request_id: &str,
) -> anyhow::Result<String> {
    let record = match store::claim_approved_agent_plan_for_dispatch(
        &state.data_dir,
        request_id,
        context.principal_id(),
        now_ts(),
    ) {
        Ok(record) => record,
        Err(err) => {
            if err.is::<store::AgentPlanClaimStale>() {
                let record = read_inspect_action_record(&state.data_dir, request_id)?;
                append_agent_plan_dispatch_audit(&state.data_dir, &record, "stale")?;
            }
            return Err(err);
        }
    };
    let data_dir = state.data_dir.clone();
    if let Err(err) = append_agent_plan_dispatch_audit(&data_dir, &record, "started") {
        settle_agent_plan_dispatch(
            &data_dir,
            record,
            "not_sent",
            serde_json::json!({"status": "not_sent", "code": "claim_audit_error"}),
        )?;
        return Err(err);
    }
    let record_if_lost = record.clone();
    let data_dir_if_lost = data_dir.clone();
    let request_id = record.request_id.clone();
    // Built before the task is spawned, so a drop before the first poll
    // still settles the claim.
    let cleanup = UnsettledDispatch {
        data_dir: data_dir.clone(),
        record: record.clone(),
        request_id: request_id.clone(),
        finished: false,
    };
    #[cfg(all(test, unix))]
    let unpolled_id = request_id.clone();
    let task = tokio::spawn(async move {
        #[cfg(all(test, unix))]
        note_dispatch_was_polled(&request_id);
        let mut cleanup = cleanup;
        #[cfg(all(test, unix))]
        wait_plan_task_gate(&request_id).await;
        let response = tokio::time::timeout(
            plan_dispatch_wait(&request_id),
            crate::resource_bridge::dispatch_agent_plan_step(
                &record.request_id,
                &record.principal_id,
                record.requester_id.as_deref().unwrap_or_default(),
                &record.id,
                &record.session_id,
                &data_dir,
                &record.request,
            ),
        )
        .await;
        let (status, result, guard) = match response {
            Ok(response)
                if response["type"] == "resource_result"
                    && response["result"]["status"]
                        .as_str()
                        .is_none_or(|status| status == "ok") =>
            {
                (
                    "completed",
                    response["result"].clone(),
                    crate::resource_bridge::take_parked_plan_guard(&request_id),
                )
            }
            Ok(response) if response["code"] == "provider_error" => (
                "unknown",
                serde_json::json!({"status": "unknown", "code": "provider_transport_error"}),
                crate::resource_bridge::take_parked_plan_guard(&request_id),
            ),
            Ok(response) if response["type"] == "resource_result" => (
                "failed",
                serde_json::json!({"status": "error", "code": "provider_result_error"}),
                crate::resource_bridge::take_parked_plan_guard(&request_id),
            ),
            Ok(response) => (
                "refused",
                serde_json::json!({"status": "refused", "code": response["code"].as_str().unwrap_or("authority_refused")}),
                crate::resource_bridge::take_parked_plan_guard(&request_id),
            ),
            Err(_) => {
                // The dispatch future is gone. The one-use grant does not stay.
                // A guard already parked is dropped here without release, so
                // the flight stays until this settlement records unknown.
                drop(crate::resource_bridge::take_parked_plan_guard(&request_id));
                crate::resource_bridge::revoke_abandoned_plan_grant(&request_id).await;
                (
                    "unknown",
                    serde_json::json!({"status": "unknown", "code": "provider_timeout"}),
                    None,
                )
            }
        };
        // The effect has returned. The record is still `dispatching` until the
        // settle below, and this guard still holds the flight. Stop cannot
        // answer stopped in this window. Release comes after the record write.
        #[cfg(all(test, unix))]
        crate::resource_bridge::pause_plan_dispatch_for_test(
            &request_id,
            crate::resource_bridge::PlanDispatchPoint::BeforeSettle,
        )
        .await;
        let settled = settle_agent_plan_dispatch(&data_dir, record, status, result);
        // A later drop must not write over a settlement this task already
        // attempted, including one whose record write did not land.
        cleanup.finish();
        if settled.is_err() || status == "unknown" {
            crate::runtime::resolve_unknown_plan_effect(&request_id);
        }
        if settled.is_ok() && status != "unknown" {
            if let Some(guard) = guard {
                guard.release();
            }
        }
        settled
    });
    #[cfg(all(test, unix))]
    if take_unpolled_dispatch(&unpolled_id) {
        task.abort();
    }
    match task.await {
        Ok(settled) => settled,
        Err(err) => {
            drop(crate::resource_bridge::take_parked_plan_guard(
                &record_if_lost.request_id,
            ));
            crate::resource_bridge::revoke_abandoned_plan_grant(&record_if_lost.request_id).await;
            let code = if err.is_cancelled() {
                "dispatch_cancelled"
            } else {
                "dispatch_panic"
            };
            let settled = settle_agent_plan_dispatch(
                &data_dir_if_lost,
                record_if_lost.clone(),
                "unknown",
                serde_json::json!({"status": "unknown", "code": code}),
            );
            if settled.is_ok() {
                crate::runtime::resolve_unknown_plan_effect(&record_if_lost.request_id);
            }
            settled
        }
    }
}

#[cfg(test)]
fn plan_dispatch_waits(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::time::Duration>> {
    static WAITS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Duration>>,
    > = std::sync::OnceLock::new();
    WAITS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn plan_dispatch_wait(request_id: &str) -> std::time::Duration {
    #[cfg(test)]
    if let Some(wait) = plan_dispatch_waits()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .get(request_id)
        .copied()
    {
        return wait;
    }
    let _ = request_id;
    std::time::Duration::from_secs(120)
}

#[cfg(all(test, unix))]
pub(crate) fn set_plan_dispatch_wait_for_test(request_id: &str, wait: std::time::Duration) {
    plan_dispatch_waits()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .insert(request_id.to_string(), wait);
}

#[cfg(all(test, unix))]
pub(crate) fn clear_plan_dispatch_wait_for_test(request_id: &str) {
    plan_dispatch_waits()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .remove(request_id);
}

#[cfg(all(test, unix))]
struct PlanTaskGate {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(all(test, unix))]
fn plan_task_gates() -> &'static std::sync::Mutex<Vec<(String, PlanTaskGate)>> {
    static GATES: std::sync::OnceLock<std::sync::Mutex<Vec<(String, PlanTaskGate)>>> =
        std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// The spawned dispatch task waits here until the test releases it.
#[cfg(all(test, unix))]
pub(crate) struct PlanTaskPause {
    pub(crate) entered: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(all(test, unix))]
pub(crate) fn arm_plan_task_gate(request_id: &str) -> PlanTaskPause {
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    plan_task_gates()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push((
            request_id.to_string(),
            PlanTaskGate {
                entered: std::sync::Arc::clone(&entered),
                release: std::sync::Arc::clone(&release),
            },
        ));
    PlanTaskPause { entered, release }
}

/// The next dispatch of this id aborts its task before the task is polled.
#[cfg(all(test, unix))]
pub(crate) fn arm_unpolled_dispatch(request_id: &str) {
    unpolled_dispatches()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push(request_id.to_string());
}

#[cfg(all(test, unix))]
fn unpolled_dispatches() -> &'static std::sync::Mutex<Vec<String>> {
    static IDS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Set when a spawned dispatch is polled. An abort before the first poll leaves it clear.
#[cfg(all(test, unix))]
fn dispatch_poll_marks() -> &'static std::sync::Mutex<Vec<String>> {
    static MARKS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    MARKS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

#[cfg(all(test, unix))]
fn note_dispatch_was_polled(request_id: &str) {
    dispatch_poll_marks()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push(request_id.to_string());
}

#[cfg(all(test, unix))]
pub(crate) fn dispatch_was_polled(request_id: &str) -> bool {
    dispatch_poll_marks()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .iter()
        .any(|id| id == request_id)
}

#[cfg(all(test, unix))]
fn take_unpolled_dispatch(request_id: &str) -> bool {
    let mut ids = unpolled_dispatches()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let Some(pos) = ids.iter().rposition(|id| id == request_id) else {
        return false;
    };
    ids.swap_remove(pos);
    true
}

#[cfg(all(test, unix))]
async fn wait_plan_task_gate(request_id: &str) {
    let gate = {
        let mut gates = plan_task_gates()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let pos = gates.iter().rposition(|(id, _)| id == request_id);
        pos.map(|pos| gates.swap_remove(pos).1)
    };
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
}

#[cfg(test)]
fn plan_settle_faults() -> &'static std::sync::Mutex<Vec<&'static str>> {
    static FAULTS: std::sync::OnceLock<std::sync::Mutex<Vec<&'static str>>> =
        std::sync::OnceLock::new();
    FAULTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// The next settle fails at `which`: `"record"` or `"audit"`.
#[cfg(all(test, unix))]
pub(crate) fn arm_plan_settle_fault(which: &'static str) {
    arm_plan_settle_faults(which, 1);
}

/// `count` failures of `which`, consumed one per settle attempt.
#[cfg(all(test, unix))]
pub(crate) fn arm_plan_settle_faults(which: &'static str, count: usize) {
    let mut faults = plan_settle_faults()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    for _ in 0..count {
        faults.push(which);
    }
}

fn take_plan_settle_fault(which: &str) -> bool {
    #[cfg(test)]
    {
        let mut faults = plan_settle_faults()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(pos) = faults.iter().rposition(|fault| *fault == which) {
            faults.swap_remove(pos);
            return true;
        }
    }
    let _ = which;
    false
}

fn settle_agent_plan_dispatch(
    data_dir: &FsPath,
    mut record: InspectActionRequestRecord,
    status: &str,
    result: serde_json::Value,
) -> anyhow::Result<String> {
    // A late landing does not become a new action. The stored unknown stays
    // unknown: nothing here calls it done, completed, or refused.
    if let Ok(stored) = read_inspect_action_record(data_dir, &record.request_id) {
        if stored.status == "unknown" {
            return Ok("Agent plan dispatch unknown.".to_string());
        }
    }
    // The stored record is the answer. A failed record write returns Err and
    // leaves the previous record, and the flight stays held. A failed audit
    // append does not change that answer: the record already states the
    // outcome, so this call still returns Ok.
    record.status = status.to_string();
    record.result = Some(result);
    record.updated_at = now_ts();
    // Three attempts. A fault or a write error spends one. When none land,
    // the stored record stays as it was (still `dispatching` when the claim
    // is the last write) and the caller resolves the flight as unknown.
    let mut wrote = false;
    for _ in 0..3 {
        if take_plan_settle_fault("record") {
            continue;
        }
        if write_inspect_action_record(data_dir, &record).is_ok() {
            wrote = true;
            break;
        }
    }
    if !wrote {
        anyhow::bail!("plan record write failed");
    }
    if take_plan_settle_fault("audit") {
        tracing::warn!(
            "agent plan dispatch audit was not stored: injected plan audit write failure"
        );
    } else if let Err(err) = append_agent_plan_dispatch_audit(data_dir, &record, status) {
        tracing::warn!("agent plan dispatch audit was not stored: {err}");
    }
    Ok(format!("Agent plan dispatch {status}."))
}

/// A second settlement after unknown. The stored record stays unknown.
#[cfg(all(test, unix))]
pub(crate) fn resettle_plan_for_test(
    data_dir: &FsPath,
    request_id: &str,
    status: &str,
) -> anyhow::Result<String> {
    let record = read_inspect_action_record(data_dir, request_id)?;
    settle_agent_plan_dispatch(
        data_dir,
        record,
        status,
        serde_json::json!({"status": status, "code": "late"}),
    )
}

fn append_agent_plan_dispatch_audit(
    data_dir: &FsPath,
    record: &InspectActionRequestRecord,
    status: &str,
) -> anyhow::Result<()> {
    let event_type = match status {
        "started" => "agent_plan.dispatch.started",
        "completed" => "agent_plan.dispatch.completed",
        "failed" => "agent_plan.dispatch.failed",
        "refused" => "agent_plan.dispatch.refused",
        "not_sent" => "agent_plan.dispatch.not_sent",
        "stale" => "agent_plan.dispatch.stale",
        _ => "agent_plan.dispatch.unknown",
    };
    append_provider_effect_audit(
        data_dir,
        ProviderEffectAuditInput {
            capsule_id: &record.id,
            event_type,
            principal_id: &record.principal_id,
            session_id: &record.session_id,
            request_id: &record.request_id,
            result: status,
            reason: if status == "started" {
                "Owner-approved agent plan claimed by Runtime"
            } else {
                "Owner-approved agent plan settled by Runtime"
            },
        },
    )
}

#[cfg(unix)]
#[cfg(test)]
pub(in crate::api::gateway) fn rebind_agent_plan_for_test(
    data_dir: &FsPath,
    request_id: &str,
) -> anyhow::Result<()> {
    let mut record = read_inspect_action_record(data_dir, request_id)?;
    record.request_binding = agent_plan::agent_plan_request_binding(&record);
    write_inspect_action_record(data_dir, &record)
}

pub(crate) fn agent_plan_result_for_requester(
    data_dir: &FsPath,
    request_id: &str,
    owner_id: &str,
    requester_id: &str,
    capsule_id: &str,
    session_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let record = read_inspect_action_record(data_dir, request_id)?;
    if record.kind != AGENT_PLAN_KIND
        || record.principal_id != owner_id
        || record.requester_id.as_deref() != Some(requester_id)
        || record.id != capsule_id
        || record.session_id != session_id
    {
        anyhow::bail!("agent plan result belongs to a different requester or activation");
    }
    if !matches!(
        record.status.as_str(),
        "completed" | "failed" | "refused" | "unknown"
    ) {
        anyhow::bail!("agent plan has no settled result");
    }
    let binding = record
        .request_binding
        .as_ref()
        .filter(|binding| agent_plan::agent_plan_request_binding(&record).as_ref() == Some(binding))
        .ok_or_else(|| anyhow::anyhow!("agent plan result binding is invalid"))?;
    Ok(serde_json::json!({
        "schema": "elastos.agent-plan.result/v1",
        "request_id": record.request_id,
        "status": record.status,
        "request_binding": binding,
        "dispatch_result": record.result,
    }))
}

pub(super) fn deny_inspect_action_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request_id: &str,
) -> anyhow::Result<String> {
    let (mut record, _) =
        claim_bound_pending_inspect_action(state, context, request_id, "denying")?;
    record.status = "denied".to_string();
    record.updated_at = now_ts();
    write_inspect_action_record(&state.data_dir, &record)?;
    append_provider_effect_audit(
        &state.data_dir,
        ProviderEffectAuditInput {
            capsule_id: INBOX_CAPSULE_ID,
            event_type: "inspect.action.denied",
            principal_id: context.principal_id(),
            session_id: context.session_id(),
            request_id,
            result: "denied",
            reason: "Denied Inspector action through Inbox",
        },
    )?;
    Ok("Denied Inspector action.".to_string())
}

pub(super) fn inspect_action_result_receipt(
    data_dir: &FsPath,
    request_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let record = read_inspect_action_record(data_dir, request_id)?;
    if !matches!(record.status.as_str(), "completed" | "denied") {
        anyhow::bail!("Inspector action has no completed result");
    }
    let expected = inspect_action_request_binding(
        &record.request_id,
        &record.principal_id,
        &record.id,
        &record.operation,
        &record.plan,
        &record.request,
    );
    let binding = record
        .request_binding
        .filter(|binding| binding == &expected)
        .ok_or_else(|| anyhow::anyhow!("Inspector action result binding is invalid"))?;
    let dispatch_result = if record.status == "completed" {
        record.result.as_ref().and_then(|result| result.get("data"))
    } else {
        None
    };
    if record.status == "completed" {
        let provider_result = record
            .result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Inspector action completed result is missing"))?;
        validate_inspect_dispatch_result(provider_result, &binding).map_err(anyhow::Error::msg)?;
    }
    Ok(serde_json::json!({
        "schema": "elastos.inspect.action-result/v1",
        "status": record.status,
        "request_id": record.request_id,
        "request_binding": binding,
        "dispatch_result": dispatch_result,
    }))
}

fn claim_bound_pending_inspect_action(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request_id: &str,
    claim_status: &str,
) -> anyhow::Result<(
    InspectActionRequestRecord,
    crate::esp_binding::EspRequestBinding,
)> {
    let mut record = claim_pending_inspect_action_record(
        &state.data_dir,
        request_id,
        context.principal_id(),
        claim_status,
        now_ts(),
    )?;
    let current = inspect_action_request_binding(
        &record.request_id,
        &record.principal_id,
        &record.id,
        &record.operation,
        &record.plan,
        &record.request,
    );
    let matches = record
        .request_binding
        .as_ref()
        .is_some_and(|stored| stored == &current)
        && record.request_id == request_id;
    if matches {
        return Ok((record, current));
    }

    let stored_request_id = record.request_id.clone();
    record.request_id = request_id.to_string();
    record.status = "stale".to_string();
    record.error = Some(
        "Inspector action request binding changed before Inbox approval or denial".to_string(),
    );
    record.result = Some(serde_json::json!({
        "status": "error",
        "code": "request_binding_changed",
        "expected": record.request_binding.clone(),
        "actual": current,
        "stored_request_id": stored_request_id,
    }));
    record.updated_at = now_ts();
    write_inspect_action_record(&state.data_dir, &record)?;
    append_provider_effect_audit(
        &state.data_dir,
        ProviderEffectAuditInput {
            capsule_id: INBOX_CAPSULE_ID,
            event_type: "inspect.action.stale",
            principal_id: context.principal_id(),
            session_id: context.session_id(),
            request_id,
            result: "stale",
            reason: "Inspector action request binding changed before Inbox approval or denial",
        },
    )?;
    anyhow::bail!("Inspector action request binding changed before Inbox approval or denial")
}

fn validate_inspect_dispatch_result(
    response: &serde_json::Value,
    expected: &crate::esp_binding::EspRequestBinding,
) -> Result<(), String> {
    if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Err(response
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Inspector action dispatch failed")
            .to_string());
    }
    let data = response
        .get("data")
        .ok_or_else(|| "Inspector action result is missing data".to_string())?;
    if data.get("schema").and_then(serde_json::Value::as_str)
        != Some("elastos.inspect.dispatch-result/v1")
    {
        return Err("Inspector action result has the wrong schema".to_string());
    }
    let actual = data
        .get("request_binding")
        .ok_or_else(|| "Inspector action result is missing its request binding".to_string())?;
    let actual: crate::esp_binding::EspRequestBinding = serde_json::from_value(actual.clone())
        .map_err(|err| format!("Inspector action result request binding is invalid: {err}"))?;
    if &actual != expected {
        return Err("Inspector action result request binding does not match".to_string());
    }
    if data.get("id").and_then(serde_json::Value::as_str) != Some(expected.capsule.as_str())
        || data.get("operation").and_then(serde_json::Value::as_str)
            != Some(expected.method.as_str())
    {
        return Err("Inspector action result target or method does not match".to_string());
    }
    let mut result_resources = data
        .get("capabilities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|capability| capability.get("resource"))
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    result_resources.sort();
    result_resources.dedup();
    if result_resources != expected.resources {
        return Err("Inspector action result resources do not match".to_string());
    }
    let provider_status = data
        .pointer("/provider_response/status")
        .and_then(serde_json::Value::as_str);
    if provider_status != Some("ok") {
        return Err("Inspector action provider result did not complete successfully".to_string());
    }
    let transfer = data
        .pointer("/provider_response/_runtime_transfer")
        .ok_or_else(|| {
            "Inspector action provider result is missing its Runtime receipt".to_string()
        })?;
    let target = data
        .get("target")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if transfer.get("schema").and_then(serde_json::Value::as_str)
        != Some("elastos.provider.transfer/v1")
        || transfer.get("source").and_then(serde_json::Value::as_str) != Some("inspect")
        || transfer.get("target").and_then(serde_json::Value::as_str) != Some(target)
        || transfer.get("op").and_then(serde_json::Value::as_str) != Some(expected.method.as_str())
        || transfer.get("status").and_then(serde_json::Value::as_str) != Some("completed")
    {
        return Err("Inspector action provider result Runtime receipt does not match".to_string());
    }
    Ok(())
}

async fn create_inspect_action_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request: &serde_json::Value,
) -> anyhow::Result<InspectActionRequestRecord> {
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("inspect provider unavailable"))?;
    let id = request
        .get("id")
        .or_else(|| request.get("capsule_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("inspect action request requires id"))?;
    let operation = request
        .get("operation")
        .or_else(|| request.get("provider_operation"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("inspect action request requires operation"))?;
    let provider_request = request
        .get("request")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if !provider_request.is_object() {
        anyhow::bail!("inspect action request body must be a JSON object");
    }
    if provider_request.get("_runtime_invocation").is_some()
        || provider_request.get("_runtime_transfer").is_some()
    {
        anyhow::bail!("inspect action request must not predeclare runtime metadata");
    }
    if let Some(field) = provider_proxy_runtime_metadata_field(&provider_request) {
        anyhow::bail!("inspect action request must not predeclare Runtime metadata field {field}");
    }
    let plan = registry
        .send_raw(
            "inspect",
            &serde_json::json!({
                "op": "plan",
                "id": id,
                "operation": operation,
            }),
        )
        .await?;
    if plan.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        anyhow::bail!(
            "{}",
            plan.get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("inspect action planning failed")
        );
    }
    let now = now_ts();
    let nonce = inspect_action_request_nonce();
    let request_id = inspect_action_request_id(id, operation, now, &nonce);
    let request_binding = inspect_action_request_binding(
        &request_id,
        context.principal_id(),
        id,
        operation,
        &plan["data"],
        &provider_request,
    );
    let record = InspectActionRequestRecord {
        schema: INSPECT_ACTION_SCHEMA.to_string(),
        kind: INSPECT_ACTION_KIND.to_string(),
        request_id,
        principal_id: context.principal_id().to_string(),
        requester_id: None,
        session_id: context.session_id().to_string(),
        id: id.to_string(),
        operation: operation.to_string(),
        request: provider_request,
        plan: plan["data"].clone(),
        request_binding: Some(request_binding),
        status: "pending".to_string(),
        created_at: now,
        updated_at: now,
        result: None,
        error: None,
    };
    write_inspect_action_record(&state.data_dir, &record)?;
    append_provider_effect_audit(
        &state.data_dir,
        ProviderEffectAuditInput {
            capsule_id: SYSTEM_CAPSULE_ID,
            event_type: "inspect.action.requested",
            principal_id: context.principal_id(),
            session_id: context.session_id(),
            request_id: &record.request_id,
            result: "pending",
            reason: "System requested Inspector action approval",
        },
    )?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_dispatch_result_requires_the_exact_request_and_runtime_receipt() {
        let binding = crate::esp_binding::esp_request_binding(
            "inspect-act-test",
            "person:test",
            "capsule:exit-provider",
            None,
            "status",
            ["elastos://exit/*".to_string()],
            &serde_json::json!({ "probe": true }),
        );
        let valid = serde_json::json!({
            "status": "ok",
            "data": {
                "schema": "elastos.inspect.dispatch-result/v1",
                "id": "capsule:exit-provider",
                "target": "exit",
                "operation": "status",
                "request_binding": binding,
                "capabilities": [{ "resource": "elastos://exit/*", "actions": ["read"] }],
                "provider_response": {
                    "status": "ok",
                    "data": { "status": "ready" },
                    "_runtime_transfer": {
                        "schema": "elastos.provider.transfer/v1",
                        "source": "inspect",
                        "target": "exit",
                        "op": "status",
                        "status": "completed"
                    }
                }
            }
        });
        assert!(validate_inspect_dispatch_result(&valid, &binding).is_ok());

        for (field, replacement) in [
            ("request_id", serde_json::json!("inspect-act-other")),
            ("principal", serde_json::json!("person:other")),
            ("capsule", serde_json::json!("capsule:other")),
            ("interface", serde_json::json!("elastos.other")),
            ("method", serde_json::json!("other")),
            ("resources", serde_json::json!(["elastos://other/*"])),
            ("sha256", serde_json::json!("00".repeat(32))),
        ] {
            let mut mutated = valid.clone();
            mutated["data"]["request_binding"][field] = replacement;
            assert!(
                validate_inspect_dispatch_result(&mutated, &binding).is_err(),
                "accepted mutated result binding field {field}"
            );
        }

        for pointer in [
            "/data/id",
            "/data/operation",
            "/data/capabilities/0/resource",
            "/data/provider_response/status",
            "/data/provider_response/_runtime_transfer/target",
            "/data/provider_response/_runtime_transfer/op",
            "/data/provider_response/_runtime_transfer/status",
        ] {
            let mut mutated = valid.clone();
            *mutated.pointer_mut(pointer).unwrap() = serde_json::json!("unrelated");
            assert!(
                validate_inspect_dispatch_result(&mutated, &binding).is_err(),
                "accepted unrelated result at {pointer}"
            );
        }
    }

    #[cfg(unix)]
    const PLAN_PRINCIPAL: &str = "person:owner";
    #[cfg(unix)]
    const PLAN_REQUESTER: &str = "agent:v2:planrequester";
    #[cfg(unix)]
    const PLAN_CAPSULE: &str = "capsule:agent-host";
    #[cfg(unix)]
    const PLAN_SESSION: &str = "session:agent-1";

    #[cfg(unix)]
    fn plan_context() -> agent_plan::AgentPlanContext<'static> {
        agent_plan::AgentPlanContext {
            principal_id: PLAN_PRINCIPAL,
            requester_id: PLAN_REQUESTER,
            capsule_id: PLAN_CAPSULE,
            session_id: PLAN_SESSION,
        }
    }

    #[cfg(unix)]
    fn status_plan(request: serde_json::Value) -> serde_json::Value {
        let step = stored_step(request);
        serde_json::json!({ "steps": [step] })
    }

    #[cfg(unix)]
    fn stored_step(request: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "scheme": "availability",
            "operation": "status",
            "request": request,
        })
    }

    #[cfg(unix)]
    fn expected_binding(
        request_id: &str,
        request: serde_json::Value,
    ) -> crate::esp_binding::EspRequestBinding {
        crate::esp_binding::esp_request_binding(
            request_id,
            PLAN_PRINCIPAL,
            PLAN_CAPSULE,
            None,
            "status",
            ["elastos://availability/status".to_string()],
            &serde_json::json!({
                "owner": PLAN_PRINCIPAL,
                "requester": PLAN_REQUESTER,
                "session": PLAN_SESSION,
                "step": stored_step(request),
            }),
        )
    }

    #[cfg(unix)]
    fn agent_plan_cards(dir: &std::path::Path) -> Vec<HomeNotificationEntrySummary> {
        let pending = store::pending_inspect_action_requests(dir, PLAN_PRINCIPAL).unwrap();
        let mut notifications = HomeNotificationsSummary::default();
        append_inspect_action_notifications(&mut notifications, pending);
        notifications.entries
    }

    #[cfg(unix)]
    #[test]
    fn a15r_inbox_card_shows_every_stored_step_and_the_full_binding_hash() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "principal": "person:other",
            "capsule": "capsule:impostor",
        });
        let record = agent_plan::create_pending_agent_plan_record(
            dir.path(),
            &plan_context(),
            &status_plan(body.clone()),
            41,
        )
        .unwrap();
        let expected = expected_binding(&record.request_id, body);
        assert_eq!(record.request_binding.as_ref(), Some(&expected));

        let cards = agent_plan_cards(dir.path());
        assert_eq!(cards.len(), 1);
        let card = &cards[0];
        assert_eq!(card.kind, AGENT_PLAN_KIND);
        assert_eq!(card.id, format!("agent-plan-request:{}", record.request_id));
        assert_eq!(
            card.action_ref
                .as_ref()
                .map(|action| action.action_id.as_str()),
            Some(format!("agent-plan-approve-request:{}", record.request_id).as_str()),
            "the owner's card carries the one approve action"
        );
        assert_eq!(
            card.request_binding.as_ref(),
            Some(&serde_json::json!(expected)),
            "the card carries the exact binding its click sends back"
        );
        assert_eq!(expected.sha256.len(), 64);
        assert!(card.body.contains(&expected.sha256), "{}", card.body);
        assert!(
            card.body.contains(
                r#"{"operation":"status","request":{"capsule":"capsule:impostor","principal":"person:other"},"scheme":"availability"}"#
            ),
            "{}",
            card.body
        );
        assert!(
            card.body
                .contains("Gate preview: Capability elastos://availability/status: read"),
            "{}",
            card.body
        );
    }

    #[cfg(unix)]
    #[test]
    fn a15r_plan_changed_after_storing_shows_the_new_hash() {
        let dir = tempfile::tempdir().unwrap();
        let record = agent_plan::create_pending_agent_plan_record(
            dir.path(),
            &plan_context(),
            &status_plan(serde_json::json!({ "principal": "person:other" })),
            42,
        )
        .unwrap();
        let stored_hash = record.request_binding.as_ref().unwrap().sha256.clone();
        let first = agent_plan_cards(dir.path());
        assert_eq!(first.len(), 1);
        assert!(first[0].body.contains(&stored_hash));

        let mut changed =
            store::read_inspect_action_record(dir.path(), &record.request_id).unwrap();
        changed.request["request"]["principal"] = serde_json::json!("person:changed");
        store::write_inspect_action_record(dir.path(), &changed).unwrap();

        let expected = expected_binding(
            &record.request_id,
            serde_json::json!({ "principal": "person:changed" }),
        );
        assert_ne!(expected.sha256, stored_hash);
        let second = agent_plan_cards(dir.path());
        assert_eq!(second.len(), 1);
        assert!(
            second[0].body.contains(&expected.sha256),
            "{}",
            second[0].body
        );
        assert!(!second[0].body.contains(&stored_hash), "{}", second[0].body);
    }

    #[cfg(unix)]
    #[test]
    fn a15r_over_long_plan_is_refused_not_cut() {
        let dir = tempfile::tempdir().unwrap();
        let record = agent_plan::create_pending_agent_plan_record(
            dir.path(),
            &plan_context(),
            &status_plan(serde_json::json!({})),
            43,
        )
        .unwrap();
        let mut oversize =
            store::read_inspect_action_record(dir.path(), &record.request_id).unwrap();
        oversize.request["request"]["pad"] = serde_json::json!("x".repeat(2000));
        store::write_inspect_action_record(dir.path(), &oversize).unwrap();
        assert!(agent_plan_cards(dir.path()).is_empty());

        let whole = agent_plan::create_pending_agent_plan_record(
            dir.path(),
            &plan_context(),
            &status_plan(serde_json::json!({})),
            44,
        )
        .unwrap();
        let cards = agent_plan_cards(dir.path());
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0].id,
            format!("agent-plan-request:{}", whole.request_id)
        );
        assert!(!cards
            .iter()
            .any(|card| card.id.ends_with(&record.request_id)));
    }
}
