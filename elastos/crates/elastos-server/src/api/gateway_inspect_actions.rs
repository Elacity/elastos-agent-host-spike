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
        });
    }
}

/// One Inbox card for a pending agent plan: every stored step, the gate preview
/// and the full binding hash. No approve action exists yet, so the card carries
/// none.
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
        action_ref: None,
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

    const PLAN_PRINCIPAL: &str = "person:owner";
    const PLAN_REQUESTER: &str = "agent:v2:planrequester";
    const PLAN_CAPSULE: &str = "capsule:agent-host";
    const PLAN_SESSION: &str = "session:agent-1";

    fn plan_context() -> agent_plan::AgentPlanContext<'static> {
        agent_plan::AgentPlanContext {
            principal_id: PLAN_PRINCIPAL,
            requester_id: PLAN_REQUESTER,
            capsule_id: PLAN_CAPSULE,
            session_id: PLAN_SESSION,
        }
    }

    fn status_plan(request: serde_json::Value) -> serde_json::Value {
        let step = stored_step(request);
        serde_json::json!({ "steps": [step] })
    }

    fn stored_step(request: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "scheme": "availability",
            "operation": "status",
            "request": request,
        })
    }

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

    fn agent_plan_cards(dir: &std::path::Path) -> Vec<HomeNotificationEntrySummary> {
        let pending = store::pending_inspect_action_requests(dir, PLAN_PRINCIPAL).unwrap();
        let mut notifications = HomeNotificationsSummary::default();
        append_inspect_action_notifications(&mut notifications, pending);
        notifications.entries
    }

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
        assert!(card.action_ref.is_none());
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
