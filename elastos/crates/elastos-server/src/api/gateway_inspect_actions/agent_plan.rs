//! Runtime-owned pending agent plan records.
//!
//! A record holds one exact typed step (scheme, operation, body) and the ESP
//! binding over it, in the same file-backed Inspector action store and under the
//! same binding rule. Creating a record has no effect: the gate preview comes
//! from the Inspector `scheme` planner, and no grant, token or provider dispatch
//! exists on this path.

use std::path::Path;

use serde_json::{json, Value};

use super::binding::{
    inspect_action_request_binding, inspect_action_request_id, inspect_action_request_nonce,
};
use super::store::{
    write_inspect_action_record, InspectActionRequestRecord, AGENT_PLAN_KIND, INSPECT_ACTION_SCHEMA,
};
use crate::inspect_provider::plan_scheme;

/// Identity for a pending agent plan. It comes from Runtime context and never
/// from the submitted plan.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct AgentPlanContext<'a> {
    pub(super) principal_id: &'a str,
    pub(super) capsule_id: &'a str,
    pub(super) session_id: &'a str,
}

/// Record one pending agent plan without any effect.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn create_pending_agent_plan_record(
    data_dir: &Path,
    context: &AgentPlanContext<'_>,
    plan: &Value,
    now: u64,
) -> anyhow::Result<InspectActionRequestRecord> {
    for value in [context.principal_id, context.capsule_id, context.session_id] {
        if value.is_empty() || value.trim() != value {
            anyhow::bail!("agent plan context requires a trimmed principal, capsule and session");
        }
    }
    let step = agent_plan_step(plan)?;
    let scheme = step["scheme"].as_str().unwrap_or_default();
    let operation = step["operation"].as_str().unwrap_or_default();
    let gate_preview = plan_scheme(operation, scheme, &step["request"]);
    if gate_preview.get("status").and_then(Value::as_str) != Some("ok") {
        anyhow::bail!(
            "{}",
            gate_preview
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("agent plan step is not a supported provider operation")
        );
    }
    let preview = gate_preview
        .get("data")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("agent plan step preview is missing"))?;
    let request_id = inspect_action_request_id(
        context.capsule_id,
        operation,
        now,
        &inspect_action_request_nonce(),
    );
    let request_binding = inspect_action_request_binding(
        &request_id,
        context.principal_id,
        context.capsule_id,
        operation,
        &preview,
        &step,
    );
    if request_binding.truncated {
        anyhow::bail!("agent plan step preview is too large and is refused rather than cut");
    }
    let record = InspectActionRequestRecord {
        schema: INSPECT_ACTION_SCHEMA.to_string(),
        kind: AGENT_PLAN_KIND.to_string(),
        request_id,
        principal_id: context.principal_id.to_string(),
        session_id: context.session_id.to_string(),
        id: context.capsule_id.to_string(),
        operation: operation.to_string(),
        request: step,
        plan: preview,
        request_binding: Some(request_binding),
        status: "pending".to_string(),
        created_at: now,
        updated_at: now,
        result: None,
        error: None,
    };
    write_inspect_action_record(data_dir, &record)?;
    Ok(record)
}

/// The one typed step a record keeps. More than one step fails closed until the
/// multi-step decision is made.
fn agent_plan_step(plan: &Value) -> anyhow::Result<Value> {
    let steps = plan
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("agent plan requires steps"))?;
    let [step] = steps.as_slice() else {
        anyhow::bail!("agent plan must carry exactly one step");
    };
    let scheme = step
        .get("scheme")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("agent plan step requires scheme"))?;
    let operation = step
        .get("operation")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("agent plan step requires operation"))?;
    let body = step.get("request").cloned().unwrap_or_else(|| json!({}));
    if !body.is_object() {
        anyhow::bail!("agent plan step request must be a JSON object");
    }
    if body.get("_runtime_invocation").is_some() || body.get("_runtime_transfer").is_some() {
        anyhow::bail!("agent plan step request must not predeclare runtime metadata");
    }
    if let Some(field) = super::super::provider_proxy_runtime_metadata_field(&body) {
        anyhow::bail!("agent plan step request must not predeclare Runtime metadata field {field}");
    }
    let canonical_step = json!({
        "scheme": scheme,
        "operation": operation,
        "request": body,
    });
    if plan != &json!({ "steps": [canonical_step.clone()] }) {
        anyhow::bail!("agent plan must match the typed step exactly");
    }
    Ok(canonical_step)
}

#[cfg(test)]
mod tests {
    use super::super::store::{pending_inspect_action_requests, read_inspect_action_record};
    use super::*;

    const PRINCIPAL: &str = "person:owner";
    const CAPSULE: &str = "capsule:agent-host";
    const SESSION: &str = "session:agent-1";

    fn context() -> AgentPlanContext<'static> {
        AgentPlanContext {
            principal_id: PRINCIPAL,
            capsule_id: CAPSULE,
            session_id: SESSION,
        }
    }

    fn status_plan(body: Value) -> Value {
        json!({
            "steps": [{
                "scheme": "availability",
                "operation": "status",
                "request": body,
            }],
        })
    }

    #[test]
    fn a15r_record_binds_the_stored_step_to_runtime_identity() {
        let dir = tempfile::tempdir().unwrap();
        let body = json!({ "principal": "person:other", "capsule": "capsule:impostor" });
        let created =
            create_pending_agent_plan_record(dir.path(), &context(), &status_plan(body.clone()), 7)
                .unwrap();
        let stored = read_inspect_action_record(dir.path(), &created.request_id).unwrap();

        let expected = inspect_action_request_binding(
            &stored.request_id,
            PRINCIPAL,
            CAPSULE,
            "status",
            &stored.plan,
            &json!({ "scheme": "availability", "operation": "status", "request": body }),
        );
        assert_eq!(stored.request_binding.as_ref(), Some(&expected));
        let binding = stored.request_binding.unwrap();
        assert_eq!(binding.principal, PRINCIPAL);
        assert_eq!(stored.principal_id, PRINCIPAL);
        assert_eq!(binding.capsule, CAPSULE);
        assert_eq!(binding.method, "status");
        assert_eq!(
            binding.resources,
            vec!["elastos://availability/status".to_string()]
        );
        assert_eq!(stored.request["request"]["principal"], "person:other");
        assert_eq!(stored.kind, AGENT_PLAN_KIND);
        assert_eq!(
            stored.plan["capabilities"][0]["resource"],
            "elastos://availability/status"
        );
    }

    #[test]
    fn a15r_pending_record_stores_one_plan_and_no_effect() {
        let dir = tempfile::tempdir().unwrap();
        let created =
            create_pending_agent_plan_record(dir.path(), &context(), &status_plan(json!({})), 11)
                .unwrap();

        assert_eq!(created.status, "pending");
        assert!(created.result.is_none() && created.error.is_none());
        assert_eq!(created.plan["mode"], "provider_resource");
        assert_eq!(created.plan["dispatch"], false);
        assert_eq!(created.plan["execution"]["can_dispatch"], false);
        assert_eq!(created.session_id, SESSION);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(dir.path().join("inspect-actions"))
                .unwrap()
                .count(),
            1
        );
        assert!(dir
            .path()
            .join(format!("inspect-actions/{}.json", created.request_id))
            .is_file());
        assert!(pending_inspect_action_requests(dir.path(), PRINCIPAL)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a15r_record_requires_the_exact_submitted_step() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = status_plan(json!({}));
        plan["note"] = json!("plan note");
        plan["steps"][0]["note"] = json!("step note");

        let refused = create_pending_agent_plan_record(dir.path(), &context(), &plan, 11);
        assert!(refused.is_err());
        assert!(!dir.path().join("inspect-actions").exists());

        let exact =
            create_pending_agent_plan_record(dir.path(), &context(), &status_plan(json!({})), 11)
                .unwrap();
        assert!(dir
            .path()
            .join(format!("inspect-actions/{}.json", exact.request_id))
            .is_file());
    }

    #[test]
    fn a15r_preview_is_whole_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let stored =
            create_pending_agent_plan_record(dir.path(), &context(), &status_plan(json!({})), 1)
                .unwrap();
        let binding = stored.request_binding.unwrap();
        assert!(!binding.truncated);
        assert_eq!(
            binding.preview,
            json!({ "scheme": "availability", "operation": "status", "request": {} })
        );

        let refused = tempfile::tempdir().unwrap();
        let oversize = create_pending_agent_plan_record(
            refused.path(),
            &context(),
            &status_plan(json!({ "pad": "x".repeat(2000) })),
            2,
        )
        .unwrap_err();
        assert!(oversize.to_string().contains("refused rather than cut"));
        assert!(!refused.path().join("inspect-actions").exists());
    }

    #[test]
    fn a15r_plan_fails_closed_on_multiple_steps_or_runtime_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let two_steps = json!({
            "steps": [
                { "scheme": "availability", "operation": "status" },
                { "scheme": "availability", "operation": "status" },
            ],
        });
        assert!(create_pending_agent_plan_record(dir.path(), &context(), &two_steps, 1).is_err());
        let metadata = status_plan(json!({ "_runtime_invocation": {} }));
        assert!(create_pending_agent_plan_record(dir.path(), &context(), &metadata, 1).is_err());
        assert!(!dir.path().join("inspect-actions").exists());
    }

    #[test]
    fn a15r_record_refuses_an_empty_or_padded_context() {
        let dir = tempfile::tempdir().unwrap();
        let plan = status_plan(json!({}));
        let padded = AgentPlanContext {
            principal_id: " person:owner",
            ..context()
        };
        let empty = AgentPlanContext {
            session_id: "",
            ..context()
        };
        for bad in [padded, empty] {
            let refused = create_pending_agent_plan_record(dir.path(), &bad, &plan, 1).unwrap_err();
            assert!(refused.to_string().contains("trimmed principal"));
        }
        assert!(!dir.path().join("inspect-actions").exists());
    }
}
