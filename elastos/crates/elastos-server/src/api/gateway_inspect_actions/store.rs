use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::binding::inspect_action_request_binding;
use crate::esp_binding::EspRequestBinding;

pub(super) const INSPECT_ACTION_SCHEMA: &str = "elastos.inspect.action-request/v1";
/// Kind of an Inspector action request; the only kind the Inbox can approve.
pub(super) const INSPECT_ACTION_KIND: &str = "inspect_action";
/// Kind of a pending agent plan: a record of an exact plan with no effect.
pub(super) const AGENT_PLAN_KIND: &str = "agent_plan";
const INSPECT_ACTIONS_DIR: &str = "inspect-actions";
static INSPECT_ACTION_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn default_record_kind() -> String {
    INSPECT_ACTION_KIND.to_string()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct InspectActionRequestRecord {
    pub(super) schema: String,
    #[serde(default = "default_record_kind")]
    pub(super) kind: String,
    pub(super) request_id: String,
    pub(super) principal_id: String,
    /// The agent that submitted an agent plan for `principal_id`, its owner.
    /// Absent on an Inspector action, whose principal made the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) requester_id: Option<String>,
    pub(super) session_id: String,
    pub(super) id: String,
    pub(super) operation: String,
    pub(super) request: serde_json::Value,
    pub(super) plan: serde_json::Value,
    #[serde(default)]
    pub(super) request_binding: Option<EspRequestBinding>,
    pub(super) status: String,
    pub(super) created_at: u64,
    pub(super) updated_at: u64,
    #[serde(default)]
    pub(super) result: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) error: Option<String>,
    /// Whether the signed row for this status is in the chain. A crash after
    /// the file write and before the append leaves this false, and the next
    /// start appends that row once.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) audit_recorded: bool,
}

pub(super) fn pending_inspect_action_requests(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut records = load_inspect_action_records(data_dir)?;
    records.sort_by_key(|record| record.created_at);
    Ok(records
        .into_iter()
        .filter(|record| {
            record.status == "pending"
                && record.principal_id == principal_id
                && !(record.kind == AGENT_PLAN_KIND
                    && approval_landed(data_dir, &record.request_id))
        })
        .filter_map(pending_request_view)
        .collect())
}

/// One pending request as the Inbox reads it. An agent plan carries the stored
/// step and a binding recomputed from the stored fields, so a plan that changed
/// after storing shows its new hash. A plan whose binding would be cut is
/// refused rather than shown in part.
fn pending_request_view(record: InspectActionRequestRecord) -> Option<serde_json::Value> {
    let agent_plan = record.kind == AGENT_PLAN_KIND;
    if !agent_plan && record.kind != INSPECT_ACTION_KIND {
        return None;
    }
    let binding = if agent_plan {
        let current = super::agent_plan::agent_plan_request_binding(&record)?;
        if current.truncated {
            return None;
        }
        current
    } else {
        record.request_binding.clone().unwrap_or_else(|| {
            inspect_action_request_binding(
                &record.request_id,
                &record.principal_id,
                &record.id,
                &record.operation,
                &record.plan,
                &record.request,
            )
        })
    };
    let mut view = serde_json::json!({
        "schema": record.schema,
        "kind": record.kind,
        "request_id": record.request_id,
        "id": record.id,
        "operation": record.operation,
        "plan": record.plan,
        "request_binding": binding,
        "status": record.status,
        "created_at": record.created_at,
    });
    if agent_plan {
        view["steps"] = serde_json::json!([record.request]);
    }
    Some(view)
}

pub(super) fn read_inspect_action_record(
    data_dir: &Path,
    request_id: &str,
) -> anyhow::Result<InspectActionRequestRecord> {
    let _guard = inspect_action_store_lock()?;
    read_inspect_action_record_unlocked(data_dir, request_id)
}

pub(super) fn claim_pending_inspect_action_record(
    data_dir: &Path,
    request_id: &str,
    principal_id: &str,
    claim_status: &str,
    updated_at: u64,
) -> anyhow::Result<InspectActionRequestRecord> {
    let _guard = inspect_action_store_lock()?;
    let mut record = read_inspect_action_record_unlocked(data_dir, request_id)?;
    if record.kind != INSPECT_ACTION_KIND {
        anyhow::bail!("Inspector action request has a different kind");
    }
    if record.status != "pending" {
        anyhow::bail!("Inspector action request is not pending");
    }
    if record.principal_id != principal_id {
        anyhow::bail!("Inspector action request belongs to a different principal");
    }
    record.status = claim_status.to_string();
    record.updated_at = updated_at;
    write_inspect_action_record_unlocked(data_dir, &record)?;
    Ok(record)
}

/// Claims one pending agent plan for its owner under the store lock. The card's
/// whole binding must equal both the stored and the recomputed one, so a changed
/// plan becomes stale and claims nothing. On the success path the caller spends
/// the passkey before the signed row. A failed row leaves the record pending
/// and that passkey spent. A changed card spends the passkey and stays
/// stale, so that token cannot approve the new bytes.
pub(super) fn claim_pending_agent_plan_for_owner(
    data_dir: &Path,
    request_id: &str,
    owner_id: &str,
    approver_is_human: bool,
    card_binding: &serde_json::Value,
    updated_at: u64,
    commit: impl FnOnce(&InspectActionRequestRecord, bool) -> anyhow::Result<()>,
) -> anyhow::Result<InspectActionRequestRecord> {
    let _guard = inspect_action_store_lock()?;
    let mut record = read_inspect_action_record_unlocked(data_dir, request_id)?;
    if record.kind != AGENT_PLAN_KIND {
        anyhow::bail!("agent plan has a different kind");
    }
    if !approver_is_human
        || record.principal_id != owner_id
        || record.requester_id.as_deref() == Some(owner_id)
    {
        anyhow::bail!(
            "an agent plan is approved by its owner, never the requesting agent or another person"
        );
    }
    if record.status != "pending" {
        anyhow::bail!("agent plan is not pending");
    }
    let card: EspRequestBinding = serde_json::from_value(card_binding.clone())
        .map_err(|err| anyhow::anyhow!("agent plan card binding is invalid: {err}"))?;
    if record.request_binding.as_ref() != Some(&card)
        || super::agent_plan::agent_plan_request_binding(&record) != Some(card.clone())
    {
        // A changed card spends the passkey, then stays stale. The token
        // cannot approve the new bytes.
        commit(&record, false)?;
        let message = "agent plan changed before Inbox approval; it is stale";
        record.status = "stale".to_string();
        record.error = Some(message.to_string());
        record.updated_at = updated_at;
        write_inspect_action_record_unlocked(data_dir, &record)?;
        crate::resource_bridge::forget_one_agent_plan_authority(&record.request_id);
        crate::resource_bridge::notify_plan_waiters();
        anyhow::bail!(message);
    }
    // The passkey is spent in `commit` before the approval row. A failed
    // append leaves the card pending and costs one re-verification.
    if approval_landed(data_dir, &record.request_id) {
        record.status = "approved".to_string();
        record.updated_at = updated_at;
        write_inspect_action_record_unlocked(data_dir, &record)?;
        return Ok(record);
    }
    let mut approved = record.clone();
    approved.status = "approved".to_string();
    approved.updated_at = updated_at;
    commit(&approved, true)?;
    record = approved;
    if let Err(error) = write_inspect_action_record_unlocked(data_dir, &record) {
        if !approval_landed(data_dir, &record.request_id) {
            return Err(error);
        }
        write_inspect_action_record_unlocked(data_dir, &record)?;
    }
    Ok(record)
}

fn approval_landed(data_dir: &Path, request_id: &str) -> bool {
    crate::auth::load_auth_state(data_dir)
        .ok()
        .is_some_and(|state| {
            state.audit.iter().any(|event| {
                event.event_type == "agent.plan.approved"
                    && event.result == "approved"
                    && event.challenge_id.as_deref() == Some(request_id)
            })
        })
}

/// A durable one-way claim. A stranded dispatching record has an unknown
/// outcome and cannot be sent again after a restart.
#[derive(Debug)]
pub(super) struct AgentPlanClaimStale;

impl std::fmt::Display for AgentPlanClaimStale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("agent plan binding or gate changed before dispatch")
    }
}

impl std::error::Error for AgentPlanClaimStale {}

pub(super) fn claim_approved_agent_plan_for_dispatch(
    data_dir: &Path,
    request_id: &str,
    owner_id: &str,
    updated_at: u64,
) -> anyhow::Result<InspectActionRequestRecord> {
    let _guard = inspect_action_store_lock()?;
    let mut record = read_inspect_action_record_unlocked(data_dir, request_id)?;
    if record.kind != AGENT_PLAN_KIND || record.principal_id != owner_id {
        anyhow::bail!("agent plan belongs to a different owner or kind");
    }
    if record.status != "approved" {
        anyhow::bail!("agent plan is not approved for dispatch");
    }
    let step = &record.request;
    let scheme = step["scheme"].as_str().unwrap_or_default();
    let operation = step["operation"].as_str().unwrap_or_default();
    let body = &step["request"];
    let current = super::agent_plan::agent_plan_request_binding(&record);
    let gate = crate::inspect_provider::plan_scheme(operation, scheme, body);
    if record.operation != operation
        || !body.is_object()
        || body.get("op").is_some()
        || record.request_binding != current
        || current.as_ref().is_none_or(|binding| binding.truncated)
        || gate.get("status").and_then(serde_json::Value::as_str) != Some("ok")
        || gate.get("data") != Some(&record.plan)
    {
        record.status = "stale".to_string();
        record.error = Some("agent plan binding or gate changed before dispatch".to_string());
        record.updated_at = updated_at;
        write_inspect_action_record_unlocked(data_dir, &record)?;
        crate::resource_bridge::forget_one_agent_plan_authority(&record.request_id);
        crate::resource_bridge::notify_plan_waiters();
        return Err(AgentPlanClaimStale.into());
    }
    record.status = "dispatching".to_string();
    record.updated_at = updated_at;
    write_inspect_action_record_unlocked(data_dir, &record)?;
    Ok(record)
}

fn read_inspect_action_record_unlocked(
    data_dir: &Path,
    request_id: &str,
) -> anyhow::Result<InspectActionRequestRecord> {
    let path = inspect_action_path(data_dir, request_id)?;
    let data = std::fs::read_to_string(path)?;
    let record: InspectActionRequestRecord = serde_json::from_str(&data)?;
    Ok(record)
}

pub(super) fn write_inspect_action_record(
    data_dir: &Path,
    record: &InspectActionRequestRecord,
) -> anyhow::Result<()> {
    let _guard = inspect_action_store_lock()?;
    write_inspect_action_record_unlocked(data_dir, record)
}

fn write_inspect_action_record_unlocked(
    data_dir: &Path,
    record: &InspectActionRequestRecord,
) -> anyhow::Result<()> {
    let root = inspect_actions_root(data_dir);
    #[cfg(test)]
    if crate::api::gateway::seams::take_grant_kind(data_dir, "plan-file") {
        anyhow::bail!("injected plan file write failure");
    }
    std::fs::create_dir_all(&root)?;
    let path = inspect_action_path(data_dir, &record.request_id)?;
    let data = serde_json::to_vec_pretty(record)?;
    let mut pending = tempfile::NamedTempFile::new_in(&root)?;
    std::io::Write::write_all(&mut pending, &data)?;
    pending.as_file().sync_all()?;
    pending.persist(path)?;
    Ok(())
}

fn inspect_action_store_lock() -> anyhow::Result<std::sync::MutexGuard<'static, ()>> {
    INSPECT_ACTION_STORE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("Inspector action store lock is poisoned"))
}

fn inspect_actions_root(data_dir: &Path) -> PathBuf {
    data_dir.join(INSPECT_ACTIONS_DIR)
}

fn inspect_action_path(data_dir: &Path, request_id: &str) -> anyhow::Result<PathBuf> {
    if !request_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        anyhow::bail!("invalid Inspector action request id");
    }
    Ok(inspect_actions_root(data_dir).join(format!("{request_id}.json")))
}

/// Reads every record. An unreadable file and a corrupt JSON file are skipped
/// with a log line that names the file. Both scans use this read.
fn load_inspect_action_records_skipping_unreadable(
    data_dir: &Path,
) -> anyhow::Result<Vec<(PathBuf, InspectActionRequestRecord)>> {
    let root = inspect_actions_root(data_dir);
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            eprintln!("[gateway] skipped unreadable inspect action record");
            continue;
        };
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            eprintln!(
                "[gateway] skipped unreadable inspect action record {}",
                path.display()
            );
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(data) = std::fs::read_to_string(&path) else {
            eprintln!(
                "[gateway] skipped unreadable inspect action record {}",
                path.display()
            );
            continue;
        };
        let Ok(record) = serde_json::from_str::<InspectActionRequestRecord>(&data) else {
            eprintln!("[gateway] skipped corrupt JSON {}", path.display());
            continue;
        };
        records.push((path, record));
    }
    Ok(records)
}

pub(super) fn load_agent_plan_records(
    data_dir: &Path,
) -> anyhow::Result<Vec<InspectActionRequestRecord>> {
    let _guard = inspect_action_store_lock()?;
    let records = load_inspect_action_records(data_dir)?;
    Ok(records
        .into_iter()
        .filter(|record| record.kind == AGENT_PLAN_KIND)
        .collect())
}

/// Close pending agent plans the predicate names. The status becomes `outcome`.
pub(super) fn close_pending_agent_plans(
    data_dir: &Path,
    outcome: &str,
    now: u64,
    open: bool,
    keep: impl Fn(&InspectActionRequestRecord) -> bool,
) -> anyhow::Result<Vec<InspectActionRequestRecord>> {
    let _guard = inspect_action_store_lock()?;
    let records = load_inspect_action_records(data_dir)?;
    let mut closed = Vec::new();
    for mut record in records {
        // `open` closes pending|approved only; dispatching settles via stop.
        let open_status = if open {
            matches!(record.status.as_str(), "pending" | "approved")
        } else {
            record.status == "pending"
        };
        if record.kind != AGENT_PLAN_KIND || !open_status || !keep(&record) {
            continue;
        }
        if record.status == "pending" && approval_landed(data_dir, &record.request_id) {
            continue;
        }
        record.status = outcome.to_string();
        record.error = Some(outcome.to_string());
        record.updated_at = now;
        record.audit_recorded = false;
        write_inspect_action_record_unlocked(data_dir, &record)?;
        closed.push(record);
    }
    Ok(closed)
}

pub(super) fn mark_plan_audit_recorded(data_dir: &Path, request_id: &str) -> anyhow::Result<()> {
    let _guard = inspect_action_store_lock()?;
    let mut record = read_inspect_action_record_unlocked(data_dir, request_id)?;
    if record.audit_recorded {
        return Ok(());
    }
    record.audit_recorded = true;
    write_inspect_action_record_unlocked(data_dir, &record)
}

pub(super) fn set_agent_plan_status(
    data_dir: &Path,
    request_id: &str,
    status: &str,
    now: u64,
) -> anyhow::Result<InspectActionRequestRecord> {
    let _guard = inspect_action_store_lock()?;
    let mut record = read_inspect_action_record_unlocked(data_dir, request_id)?;
    if record.kind != AGENT_PLAN_KIND {
        anyhow::bail!("agent plan has a different kind");
    }
    record.status = status.to_string();
    record.error = Some(status.to_string());
    record.updated_at = now;
    write_inspect_action_record_unlocked(data_dir, &record)?;
    Ok(record)
}

fn load_inspect_action_records(data_dir: &Path) -> anyhow::Result<Vec<InspectActionRequestRecord>> {
    Ok(load_inspect_action_records_skipping_unreadable(data_dir)?
        .into_iter()
        .map(|(_, record)| record)
        .collect())
}

fn write_inspect_action_at_path(
    path: &Path,
    record: &InspectActionRequestRecord,
) -> anyhow::Result<()> {
    let parent = path.parent().filter(|dir| dir.is_dir()).ok_or_else(|| {
        anyhow::anyhow!("inspect action record {} has no directory", path.display())
    })?;
    let data = serde_json::to_vec_pretty(record)?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut pending, &data)?;
    pending.as_file().sync_all()?;
    pending.persist(path)?;
    Ok(())
}

/// One startup pass. An `approved` or `dispatching` plan did not finish in
/// the process that admitted it. It becomes `unresolved` and one signed
/// `agent_plan.dispatch.unresolved` row is appended. It is not dispatched
/// again. A write that fails is skipped, and that record stays as it was.
pub(super) fn settle_agent_plans_lost_before_start(
    data_dir: &Path,
    updated_at: u64,
) -> anyhow::Result<()> {
    let _guard = inspect_action_store_lock()?;
    let records = load_inspect_action_records_skipping_unreadable(data_dir)?;
    settle_records_in_place(data_dir, records, updated_at);
    Ok(())
}

fn settle_records_in_place(
    data_dir: &Path,
    records: Vec<(PathBuf, InspectActionRequestRecord)>,
    updated_at: u64,
) {
    let reason = "a dispatch cannot survive a restart";
    for (path, mut record) in records {
        if record.kind == AGENT_PLAN_KIND
            && record.status == "pending"
            && approval_landed(data_dir, &record.request_id)
        {
            record.status = "approved".into();
        }
        let lost = matches!(record.status.as_str(), "approved" | "dispatching");
        let owed = record.status == "unresolved" && !record.audit_recorded;
        let down = record.status == "pending"
            && !crate::api::agent_plane::instance_is_running(data_dir, &record.id);
        let owed_end = record.status == "instance ended" && !record.audit_recorded;
        let owed_terminal = record.kind == AGENT_PLAN_KIND
            && !record.audit_recorded
            && is_terminal_plan(&record.status);
        if record.kind == AGENT_PLAN_KIND && (down || owed_end) {
            if down {
                record.status = "instance ended".into();
                record.error = Some("instance ended".into());
                record.updated_at = updated_at;
                record.audit_recorded = false;
                if let Err(error) = write_inspect_action_at_path(&path, &record) {
                    eprintln!(
                        "[gateway] skipped inspect action record {}: {error}",
                        path.display()
                    );
                    continue;
                }
            }
            if instance_end_audit_landed(data_dir, &record.request_id, record.updated_at) {
                record.audit_recorded = true;
                let _ = write_inspect_action_at_path(&path, &record);
                continue;
            }
            if let Err(error) = super::append_agent_plan_decision_audit(
                data_dir,
                &record,
                "agent.plan.closed",
                "instance ended",
            ) {
                eprintln!(
                    "[gateway] instance ended plan {} has no signed row: {error}",
                    record.request_id
                );
                continue;
            }
            record.audit_recorded = true;
            let _ = write_inspect_action_at_path(&path, &record);
            crate::resource_bridge::notify_plan_waiters();
            continue;
        }
        if record.kind != AGENT_PLAN_KIND || (!lost && !owed && !owed_terminal) {
            continue;
        }
        if owed_terminal && !lost && !owed {
            record_terminal_audit(data_dir, &path, &mut record);
            continue;
        }
        if lost {
            record.status = "unresolved".into();
            record.error = Some(reason.into());
            record.result = Some(serde_json::json!({ "status": "unresolved", "reason": reason }));
            record.updated_at = updated_at;
            record.audit_recorded = false;
            if let Err(error) = write_inspect_action_at_path(&path, &record) {
                eprintln!(
                    "[gateway] skipped inspect action record {}: {error}",
                    path.display()
                );
                continue;
            }
        }
        if unresolved_audit_landed(data_dir, &record.request_id, record.updated_at) {
            record.audit_recorded = true;
            let _ = write_inspect_action_at_path(&path, &record);
            continue;
        }
        if let Err(error) = super::append_agent_plan_decision_audit(
            data_dir,
            &record,
            "agent_plan.dispatch.unresolved",
            "unresolved",
        ) {
            eprintln!(
                "[gateway] unresolved plan {} has no signed row: {error}",
                record.request_id
            );
            continue;
        }
        record.audit_recorded = true;
        let _ = write_inspect_action_at_path(&path, &record);
    }
}

fn is_terminal_plan(status: &str) -> bool {
    matches!(
        status,
        "denied"
            | "agent off"
            | "agents off"
            | "expired"
            | "completed"
            | "failed"
            | "refused"
            | "unknown"
            | "not_sent"
            | "stale"
            | "stopped"
            | "owner demoted"
            | "passkey revoked"
    )
}

fn record_terminal_audit(data_dir: &Path, path: &Path, record: &mut InspectActionRequestRecord) {
    let status = record.status.clone();
    let dispatch = matches!(
        status.as_str(),
        "completed" | "failed" | "refused" | "unknown" | "not_sent" | "stale"
    );
    let event_type = if dispatch {
        match status.as_str() {
            "completed" => "agent_plan.dispatch.completed",
            "failed" => "agent_plan.dispatch.failed",
            "refused" => "agent_plan.dispatch.refused",
            "not_sent" => "agent_plan.dispatch.not_sent",
            "stale" => "agent_plan.dispatch.stale",
            _ => "agent_plan.dispatch.unknown",
        }
    } else {
        "agent.plan.closed"
    };
    let at = record.updated_at;
    if plan_row_landed(data_dir, event_type, &status, &record.request_id, at) {
        record.audit_recorded = true;
        let _ = write_inspect_action_at_path(path, record);
        return;
    }
    let appended = if dispatch {
        super::append_agent_plan_dispatch_audit(data_dir, record, &status)
    } else {
        super::append_agent_plan_decision_audit(data_dir, record, "agent.plan.closed", &status)
    };
    if appended.is_err() {
        return;
    }
    record.audit_recorded = true;
    let _ = write_inspect_action_at_path(path, record);
}

fn row_rolled_off(state: &crate::auth::AuthState, at: u64) -> bool {
    let oldest = state.audit.first().map(|event| event.occurred_at);
    !(state.audit_chain_anchor.is_none() || oldest.is_some_and(|oldest| oldest < at))
}

fn plan_row_landed(
    data_dir: &Path,
    event_type: &str,
    result: &str,
    request_id: &str,
    at: u64,
) -> bool {
    crate::auth::load_auth_state(data_dir)
        .map(|state| {
            state.audit.iter().any(|event| {
                event.event_type == event_type
                    && event.result == result
                    && event.challenge_id.as_deref() == Some(request_id)
            }) || row_rolled_off(&state, at)
        })
        .unwrap_or(false)
}

fn instance_end_audit_landed(data_dir: &Path, request_id: &str, at: u64) -> bool {
    crate::auth::load_auth_state(data_dir)
        .map(|state| {
            state.audit.iter().any(|event| {
                event.event_type == "agent.plan.closed"
                    && event.result == "instance ended"
                    && event.challenge_id.as_deref() == Some(request_id)
            }) || row_rolled_off(&state, at)
        })
        .unwrap_or(false)
}

fn unresolved_audit_landed(data_dir: &Path, request_id: &str, at: u64) -> bool {
    crate::auth::load_auth_state(data_dir)
        .map(|state| {
            state.audit.iter().any(|event| {
                event.event_type == "agent_plan.dispatch.unresolved"
                    && event.challenge_id.as_deref() == Some(request_id)
            }) || row_rolled_off(&state, at)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn pending_record(request_id: &str) -> InspectActionRequestRecord {
        InspectActionRequestRecord {
            schema: INSPECT_ACTION_SCHEMA.to_string(),
            kind: INSPECT_ACTION_KIND.to_string(),
            request_id: request_id.to_string(),
            principal_id: "person:test".to_string(),
            requester_id: None,
            session_id: "session:test".to_string(),
            id: "capsule:test".to_string(),
            operation: "write".to_string(),
            request: serde_json::json!({}),
            plan: serde_json::json!({}),
            request_binding: None,
            status: "pending".to_string(),
            created_at: 1,
            updated_at: 1,
            result: None,
            error: None,
            audit_recorded: false,
        }
    }

    #[test]
    fn corrupt_json_is_skipped_by_both_scans() {
        let dir = tempfile::tempdir().unwrap();
        write_inspect_action_record(dir.path(), &pending_record("inspect-good")).unwrap();
        std::fs::write(dir.path().join("inspect-actions/bad.json"), b"{").unwrap();
        let first = load_inspect_action_records(dir.path()).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].request_id, "inspect-good");
        settle_agent_plans_lost_before_start(dir.path(), 2).unwrap();
        let second = load_inspect_action_records_skipping_unreadable(dir.path()).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].1.request_id, "inspect-good");
        let pending = pending_inspect_action_requests(dir.path(), "person:test").unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn only_one_caller_can_claim_a_pending_action() {
        let dir = tempfile::tempdir().unwrap();
        let request_id = "inspect-action-test";
        write_inspect_action_record(dir.path(), &pending_record(request_id)).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let data_dir = dir.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    claim_pending_inspect_action_record(
                        &data_dir,
                        request_id,
                        "person:test",
                        "approving",
                        2,
                    )
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        assert_eq!(
            read_inspect_action_record(dir.path(), request_id)
                .unwrap()
                .status,
            "approving"
        );
    }

    #[test]
    fn inspector_claim_selects_inspect_action_kind() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = pending_record("agent-plan-test");
        plan.kind = AGENT_PLAN_KIND.to_string();
        plan.request_binding = Some(inspect_action_request_binding(
            &plan.request_id,
            &plan.principal_id,
            &plan.id,
            &plan.operation,
            &plan.plan,
            &plan.request,
        ));
        write_inspect_action_record(dir.path(), &plan).unwrap();

        assert!(claim_pending_inspect_action_record(
            dir.path(),
            &plan.request_id,
            &plan.principal_id,
            "denied",
            2,
        )
        .is_err());
        let stored = read_inspect_action_record(dir.path(), &plan.request_id).unwrap();
        assert_eq!(stored.status, "pending");
        assert_eq!(stored.updated_at, 1);

        let action = pending_record("inspect-action-test");
        write_inspect_action_record(dir.path(), &action).unwrap();
        let claimed = claim_pending_inspect_action_record(
            dir.path(),
            &action.request_id,
            &action.principal_id,
            "denied",
            2,
        )
        .unwrap();
        assert_eq!(claimed.status, "denied");
    }

    /// Corrupt JSON is skipped by the list and by the startup settle. The
    /// good plan still becomes unresolved, and the bad file stays.
    #[test]
    fn an_unreadable_record_does_not_stop_settling_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = pending_record("agent-plan-good");
        plan.kind = AGENT_PLAN_KIND.to_string();
        plan.status = "dispatching".to_string();
        write_inspect_action_record(dir.path(), &plan).unwrap();
        let bad = dir.path().join("inspect-actions").join("bad.json");
        std::fs::write(&bad, b"not json").unwrap();

        let listed = pending_inspect_action_requests(dir.path(), "person:test");
        assert!(listed.is_ok(), "corrupt JSON stopped the list: {listed:?}");
        settle_agent_plans_lost_before_start(dir.path(), 9).unwrap();
        let stored = read_inspect_action_record(dir.path(), "agent-plan-good").unwrap();
        assert_eq!(stored.status, "unresolved");
        assert_eq!(
            stored.error.as_deref(),
            Some("a dispatch cannot survive a restart")
        );
        assert_eq!(std::fs::read(&bad).unwrap(), b"not json");
    }

    /// The settle writes the file it read. A different request id does not
    /// become a second file, and an id the path check would refuse is still
    /// settled in place.
    #[test]
    fn a_mismatched_request_id_is_settled_in_the_file_that_was_read() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("inspect-actions");
        std::fs::create_dir_all(&root).unwrap();
        let mut kept = pending_record("other-id");
        kept.kind = AGENT_PLAN_KIND.to_string();
        kept.status = "dispatching".to_string();
        let kept_path = root.join("kept-name.json");
        std::fs::write(&kept_path, serde_json::to_vec_pretty(&kept).unwrap()).unwrap();
        let mut dotted = pending_record("bad.id");
        dotted.kind = AGENT_PLAN_KIND.to_string();
        dotted.status = "dispatching".to_string();
        let dotted_path = root.join("bad.id.json");
        std::fs::write(&dotted_path, serde_json::to_vec_pretty(&dotted).unwrap()).unwrap();

        settle_agent_plans_lost_before_start(dir.path(), 9).unwrap();

        let kept_stored: InspectActionRequestRecord =
            serde_json::from_slice(&std::fs::read(&kept_path).unwrap()).unwrap();
        let dotted_stored: InspectActionRequestRecord =
            serde_json::from_slice(&std::fs::read(&dotted_path).unwrap()).unwrap();
        assert_eq!(kept_stored.status, "unresolved");
        assert_eq!(dotted_stored.status, "unresolved");
        assert!(
            !root.join("other-id.json").exists(),
            "a mismatched request id was settled into a new file"
        );
    }

    /// A record that cannot be written back is skipped. The Home still settles
    /// the records that can be written.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_record_that_cannot_be_written_back_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut good = pending_record("agent-plan-good");
        good.kind = AGENT_PLAN_KIND.to_string();
        good.status = "dispatching".to_string();
        write_inspect_action_record(dir.path(), &good).unwrap();
        let mut stuck = pending_record("agent-plan-stuck");
        stuck.kind = AGENT_PLAN_KIND.to_string();
        stuck.status = "dispatching".to_string();
        write_inspect_action_record(dir.path(), &stuck).unwrap();
        let stuck_path = dir
            .path()
            .join("inspect-actions")
            .join("agent-plan-stuck.json");
        let status = std::process::Command::new("chflags")
            .arg("uchg")
            .arg(&stuck_path)
            .status()
            .expect("chflags");
        assert!(status.success(), "chflags uchg failed: {status}");
        let _clear = ClearImmutable(stuck_path.clone());

        let settled = settle_agent_plans_lost_before_start(dir.path(), 9);
        assert!(
            settled.is_ok(),
            "one record that cannot be written back stopped settling: {settled:?}"
        );
        assert_eq!(
            read_inspect_action_record(dir.path(), "agent-plan-good")
                .unwrap()
                .status,
            "unresolved"
        );
        let stuck_text = std::fs::read_to_string(&stuck_path).unwrap();
        assert!(
            stuck_text.contains("\"dispatching\""),
            "the record that could not be written was changed: {stuck_text}"
        );
    }

    #[cfg(target_os = "macos")]
    struct ClearImmutable(std::path::PathBuf);

    #[cfg(target_os = "macos")]
    impl Drop for ClearImmutable {
        fn drop(&mut self) {
            let _ = std::process::Command::new("chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
        }
    }

    /// A record whose directory is gone is skipped. Settling continues with
    /// the record that can be written.
    #[test]
    fn a_record_whose_directory_is_gone_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut good = pending_record("agent-plan-good");
        good.kind = AGENT_PLAN_KIND.to_string();
        good.status = "dispatching".to_string();
        write_inspect_action_record(dir.path(), &good).unwrap();
        let good_path = dir
            .path()
            .join("inspect-actions")
            .join("agent-plan-good.json");
        let mut stuck = pending_record("agent-plan-missing-dir");
        stuck.kind = AGENT_PLAN_KIND.to_string();
        stuck.status = "dispatching".to_string();
        let missing = dir
            .path()
            .join("no-such-dir")
            .join("agent-plan-missing-dir.json");
        settle_records_in_place(dir.path(), vec![(missing, stuck), (good_path, good)], 9);
        assert_eq!(
            read_inspect_action_record(dir.path(), "agent-plan-good")
                .unwrap()
                .status,
            "unresolved"
        );
    }

    /// The startup pass sees a record the real claim moved to `dispatching`,
    /// writes `unresolved`, and appends that signed row once.
    #[test]
    fn a_claimed_dispatch_is_unresolved_on_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:owner";
        let plan = serde_json::json!({
            "steps": [{ "scheme": "availability", "operation": "status", "request": {} }]
        });
        let created = super::super::submit_pending_agent_plan(
            dir.path(),
            owner,
            "agent:v2:0123456789abcdef0123456789abcdef",
            "capsule:agent-host",
            "session:agent-1",
            &plan,
            1,
        )
        .unwrap();
        let request_id = created["request_id"].as_str().unwrap().to_string();
        let binding = created["request_binding"].clone();
        super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            2,
            |_, _| Ok(()),
        )
        .unwrap();
        let claimed =
            super::claim_approved_agent_plan_for_dispatch(dir.path(), &request_id, owner, 3)
                .unwrap();
        assert_eq!(claimed.status, "dispatching");
        super::settle_agent_plans_lost_before_start(dir.path(), 4).unwrap();
        assert_eq!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .status,
            "unresolved"
        );
        let unresolved = |path: &std::path::Path| {
            crate::auth::load_auth_state(path)
                .unwrap()
                .audit
                .into_iter()
                .filter(|event| event.event_type == "agent_plan.dispatch.unresolved")
                .count()
        };
        assert_eq!(unresolved(dir.path()), 1);
        super::settle_agent_plans_lost_before_start(dir.path(), 5).unwrap();
        assert_eq!(unresolved(dir.path()), 1, "the row is appended once");
    }

    /// The file was written `unresolved` and the process died before the
    /// append. The next start writes that row once. A later start that finds
    /// the row and a missing flag does not write it again.
    #[test]
    fn a_crash_between_the_unresolved_file_and_its_row_is_repaired_once() {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:owner";
        let plan = serde_json::json!({
            "steps": [{ "scheme": "availability", "operation": "status", "request": {} }]
        });
        let created = super::super::submit_pending_agent_plan(
            dir.path(),
            owner,
            "agent:v2:0123456789abcdef0123456789abcdef",
            "capsule:agent-host",
            "session:agent-1",
            &plan,
            1,
        )
        .unwrap();
        let request_id = created["request_id"].as_str().unwrap().to_string();
        let binding = created["request_binding"].clone();
        super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            2,
            |_, _| Ok(()),
        )
        .unwrap();
        super::claim_approved_agent_plan_for_dispatch(dir.path(), &request_id, owner, 3).unwrap();
        let mut record = super::read_inspect_action_record(dir.path(), &request_id).unwrap();
        record.status = "unresolved".to_string();
        record.audit_recorded = false;
        record.error = Some("a dispatch cannot survive a restart".to_string());
        super::write_inspect_action_record(dir.path(), &record).unwrap();
        let rows = |path: &std::path::Path| {
            crate::auth::load_auth_state(path)
                .unwrap()
                .audit
                .into_iter()
                .filter(|event| {
                    event.event_type == "agent_plan.dispatch.unresolved"
                        && event.challenge_id.as_deref() == Some(request_id.as_str())
                })
                .count()
        };
        assert_eq!(rows(dir.path()), 0, "the crash left no signed row");
        super::settle_agent_plans_lost_before_start(dir.path(), 4).unwrap();
        assert_eq!(rows(dir.path()), 1);
        assert!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .audit_recorded
        );
        let mut again = super::read_inspect_action_record(dir.path(), &request_id).unwrap();
        again.audit_recorded = false;
        super::write_inspect_action_record(dir.path(), &again).unwrap();
        super::settle_agent_plans_lost_before_start(dir.path(), 5).unwrap();
        assert_eq!(
            rows(dir.path()),
            1,
            "the row that already landed is not repeated"
        );
        assert!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .audit_recorded
        );
    }

    /// The passkey is spent before the approval row. A failed append leaves
    /// the card pending and that passkey spent.
    #[test]
    fn a_failed_approval_audit_leaves_the_card_pending_and_the_passkey() {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:owner";
        let plan = serde_json::json!({
            "steps": [{ "scheme": "availability", "operation": "status", "request": {} }]
        });
        let created = super::super::submit_pending_agent_plan(
            dir.path(),
            owner,
            "agent:v2:0123456789abcdef0123456789abcdef",
            "capsule:agent-host",
            "session:agent-1",
            &plan,
            1,
        )
        .unwrap();
        let request_id = created["request_id"].as_str().unwrap().to_string();
        let binding = created["request_binding"].clone();
        let mut spent = false;
        let error = super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            2,
            |_, audit_first| {
                spent = true;
                if audit_first {
                    anyhow::bail!("injected agent plan approval audit failure");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected agent plan approval audit failure"),
            "{error}"
        );
        assert!(spent, "a failed approval row still spent the passkey");
        assert_eq!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .status,
            "pending"
        );
        let approved = super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            3,
            |record, audit_first| {
                if audit_first {
                    assert_eq!(record.status, "approved");
                }
                spent = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(spent, "the passkey is spent before the approval row");
        assert_eq!(approved.status, "approved");
        assert_eq!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .status,
            "approved"
        );
    }
    fn audit_rows(
        dir: &std::path::Path,
        event_type: &str,
        result: &str,
        request_id: &str,
    ) -> usize {
        crate::auth::load_auth_state(dir)
            .unwrap()
            .audit
            .iter()
            .filter(|event| {
                event.event_type == event_type
                    && event.result == result
                    && event.challenge_id.as_deref() == Some(request_id)
            })
            .count()
    }

    fn planted_pending(dir: &std::path::Path) -> (String, serde_json::Value) {
        let created = super::super::submit_pending_agent_plan(
            dir,
            "person:owner",
            "agent:v2:0123456789abcdef0123456789abcdef",
            "capsule:agent-host",
            "session:agent-1",
            &serde_json::json!({
                "steps": [{ "scheme": "availability", "operation": "status", "request": {} }]
            }),
            1,
        )
        .unwrap();
        let request_id = created["request_id"].as_str().unwrap().to_string();
        (request_id, created["request_binding"].clone())
    }

    /// The approval row is signed and the plan file write then fails. The file
    /// becomes approved from that row. Inbox has nothing to approve or deny,
    /// and a second approval or a denial adds no row.
    #[test]
    fn a_failed_plan_file_write_after_the_signed_approval_is_reconciled() {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:owner";
        let (request_id, binding) = planted_pending(dir.path());
        crate::api::gateway::seams::arm_grant_kind(dir.path(), "plan-file");
        let approved = super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            2,
            |record, audit_first| {
                if audit_first {
                    super::super::append_agent_plan_decision_audit(
                        dir.path(),
                        record,
                        "agent.plan.approved",
                        "approved",
                    )?;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(approved.status, "approved");
        assert_eq!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .status,
            "approved"
        );
        assert!(
            super::pending_inspect_action_requests(dir.path(), owner)
                .unwrap()
                .is_empty(),
            "Inbox still offers Approve/Deny"
        );
        assert_eq!(
            audit_rows(dir.path(), "agent.plan.approved", "approved", &request_id),
            1
        );
        let denied = super::super::deny_agent_plan_request(dir.path(), owner, &request_id);
        assert!(denied.is_err(), "Deny was offered on an approved plan");
        assert_eq!(
            audit_rows(dir.path(), "agent.plan.closed", "denied", &request_id),
            0
        );
        let again = super::claim_pending_agent_plan_for_owner(
            dir.path(),
            &request_id,
            owner,
            true,
            &binding,
            3,
            |_, audit_first| {
                if audit_first {
                    super::super::append_agent_plan_decision_audit(
                        dir.path(),
                        &super::read_inspect_action_record(dir.path(), &request_id).unwrap(),
                        "agent.plan.approved",
                        "approved",
                    )?;
                }
                Ok(())
            },
        );
        assert!(again.is_err(), "a second approval was accepted");
        assert_eq!(
            audit_rows(dir.path(), "agent.plan.approved", "approved", &request_id),
            1,
            "the approval row was signed twice"
        );
    }

    /// The process dies after the signed approval and before the file write.
    /// Restart settles that pending plan as unresolved, once, and Inbox does
    /// not offer Approve or Deny on it.
    #[test]
    fn a_crash_after_the_signed_approval_settles_unresolved_once() {
        let dir = tempfile::tempdir().unwrap();
        let owner = "person:owner";
        let (request_id, _) = planted_pending(dir.path());
        let record = super::read_inspect_action_record(dir.path(), &request_id).unwrap();
        super::super::append_agent_plan_decision_audit(
            dir.path(),
            &record,
            "agent.plan.approved",
            "approved",
        )
        .unwrap();
        assert_eq!(record.status, "pending");
        assert!(
            super::pending_inspect_action_requests(dir.path(), owner)
                .unwrap()
                .is_empty(),
            "Inbox offers Approve/Deny for a plan that is already signed approved"
        );
        let denied = super::super::deny_agent_plan_request(dir.path(), owner, &request_id);
        assert!(
            denied.is_err(),
            "Deny closed a plan that was already approved"
        );
        assert_eq!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .status,
            "pending"
        );
        assert_eq!(
            audit_rows(dir.path(), "agent.plan.closed", "denied", &request_id),
            0
        );
        super::settle_agent_plans_lost_before_start(dir.path(), 4).unwrap();
        let settled = super::read_inspect_action_record(dir.path(), &request_id).unwrap();
        assert_eq!(settled.status, "unresolved");
        assert_ne!(settled.status, "instance ended");
        assert_eq!(
            audit_rows(
                dir.path(),
                "agent_plan.dispatch.unresolved",
                "unresolved",
                &request_id
            ),
            1
        );
        assert_eq!(
            audit_rows(dir.path(), "agent.plan.approved", "approved", &request_id),
            1
        );
        super::settle_agent_plans_lost_before_start(dir.path(), 5).unwrap();
        assert_eq!(
            audit_rows(
                dir.path(),
                "agent_plan.dispatch.unresolved",
                "unresolved",
                &request_id
            ),
            1,
            "restart signed the unresolved row twice"
        );
        assert!(super::pending_inspect_action_requests(dir.path(), owner)
            .unwrap()
            .is_empty());
    }

    /// A terminal plan whose signed row has rolled off the kept audit, with
    /// the file still saying the row was not recorded. Restart does not sign
    /// that terminal row again.
    #[test]
    fn a_rolled_off_terminal_plan_is_not_signed_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (request_id, _) = planted_pending(dir.path());
        let mut record = super::read_inspect_action_record(dir.path(), &request_id).unwrap();
        record.status = "completed".to_string();
        record.audit_recorded = false;
        record.updated_at = 1_700_000_000;
        super::write_inspect_action_record(dir.path(), &record).unwrap();
        crate::auth::append_audit_event(
            dir.path(),
            elastos_runtime::auth::RuntimeAuditEventV1 {
                schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
                event_id: "audit:terminal:completed".to_string(),
                event_type: "agent_plan.dispatch.completed".to_string(),
                principal_id: Some("person:owner".to_string()),
                proof_binding_id: None,
                session_id: Some("session:agent-1".to_string()),
                challenge_id: Some(request_id.clone()),
                capsule_id: Some("capsule:agent-host".to_string()),
                result: "completed".to_string(),
                reason: "completed".to_string(),
                occurred_at: 1_700_000_000,
                signer_did: None,
                signature: None,
            },
        )
        .unwrap();
        for index in 0..513u64 {
            crate::auth::append_audit_event(
                dir.path(),
                elastos_runtime::auth::RuntimeAuditEventV1 {
                    schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
                    event_id: format!("audit:pad:{index}"),
                    event_type: "audit.pad".to_string(),
                    principal_id: Some("person:owner".to_string()),
                    proof_binding_id: None,
                    session_id: None,
                    challenge_id: None,
                    capsule_id: None,
                    result: "ok".to_string(),
                    reason: "pad".to_string(),
                    occurred_at: 1_700_000_001 + index,
                    signer_did: None,
                    signature: None,
                },
            )
            .unwrap();
        }
        let state = crate::auth::load_auth_state(dir.path()).unwrap();
        assert!(state.audit_chain_anchor.is_some(), "the chain did not roll");
        assert_eq!(
            audit_rows(
                dir.path(),
                "agent_plan.dispatch.completed",
                "completed",
                &request_id
            ),
            0,
            "the pad did not roll the terminal row off the kept audit"
        );
        super::settle_agent_plans_lost_before_start(dir.path(), 9).unwrap();
        assert_eq!(
            audit_rows(
                dir.path(),
                "agent_plan.dispatch.completed",
                "completed",
                &request_id
            ),
            0,
            "startup signed a second terminal row"
        );
        assert!(
            super::read_inspect_action_record(dir.path(), &request_id)
                .unwrap()
                .audit_recorded
        );
    }

    /// A plan that ends `not_sent` or `stale` answers the agent already waiting
    /// on it, and that wait drops its permit. The park clock is long, so this
    /// passes only when the write wakes the wait. A dispatch claim that returns
    /// `AgentPlanClaimStale` is the same answer, and it drops the plan authority.
    #[cfg(unix)]
    #[test]
    fn a_not_sent_and_stale_plan_answer_the_waiting_agent_at_once() {
        let mut misses = Vec::new();
        for (case, status) in [
            ("not_sent", "not_sent"),
            ("card", "stale"),
            ("dispatch", "stale"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let owner = "person:owner";
            let requester = "agent:requester";
            let capsule = "capsule:agent-host";
            let session = "session:agent-1";
            let created = super::super::submit_pending_agent_plan(
                dir.path(),
                owner,
                requester,
                capsule,
                session,
                &serde_json::json!({
                    "steps": [{
                        "scheme": "availability",
                        "operation": "status",
                        "request": {}
                    }]
                }),
                now,
            )
            .unwrap();
            let request_id = created["request_id"].as_str().unwrap().to_string();
            let bridge = crate::resource_bridge::tests::plan_wait_bridge_for_test(
                dir.path(),
                requester,
                capsule,
                session,
            );
            crate::resource_bridge::retain_agent_plan_dispatch_authority(
                &request_id,
                owner,
                &bridge,
                &created["request"],
            )
            .unwrap();
            assert!(crate::resource_bridge::agent_plan_authority_is_held(
                &request_id
            ));
            crate::api::gateway::seams::set_plan_park_ms(dir.path(), 15_000);
            let _sentinel = crate::resource_bridge::hold_plan_wait_for_test(dir.path())
                .expect("sentinel permit");
            let (tx, rx) = std::sync::mpsc::channel();
            let home = dir.path().to_path_buf();
            let parked_id = request_id.clone();
            let parked_owner = owner.to_string();
            let parked_requester = requester.to_string();
            let parked_capsule = capsule.to_string();
            let parked_session = session.to_string();
            std::thread::spawn(move || {
                let answer = crate::resource_bridge::tests::park_agent_plan_result_for_test(
                    &home,
                    &parked_id,
                    &parked_owner,
                    &parked_requester,
                    &parked_capsule,
                    &parked_session,
                );
                let _ = tx.send(answer);
            });
            let waiting = std::time::Instant::now();
            while !crate::resource_bridge::plan_park_is_waiting(dir.path()) {
                assert!(
                    waiting.elapsed() < std::time::Duration::from_secs(2),
                    "{status} did not park"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if case == "not_sent" {
                super::super::settle_plan_through_dispatch_for_test(
                    dir.path(),
                    &request_id,
                    "not_sent",
                    serde_json::json!({"status": "not_sent", "code": "claim_audit_error"}),
                )
                .unwrap();
            } else if case == "dispatch" {
                let mut record =
                    super::read_inspect_action_record(dir.path(), &request_id).unwrap();
                record.status = "approved".to_string();
                record.operation = "changed".to_string();
                super::write_inspect_action_record(dir.path(), &record).unwrap();
                super::super::rebind_agent_plan_for_test(dir.path(), &request_id).unwrap();
                let error = super::claim_approved_agent_plan_for_dispatch(
                    dir.path(),
                    &request_id,
                    owner,
                    now,
                )
                .expect_err("a changed binding leaves the dispatch stale");
                assert!(
                    error.downcast_ref::<super::AgentPlanClaimStale>().is_some(),
                    "{error}"
                );
            } else {
                let mut card = created["request_binding"].clone();
                card["sha256"] = serde_json::json!("ab".repeat(32));
                let error = super::claim_pending_agent_plan_for_owner(
                    dir.path(),
                    &request_id,
                    owner,
                    true,
                    &card,
                    now,
                    |_record, _audit_first| Ok(()),
                )
                .expect_err("a changed card leaves the plan stale");
                assert!(error.to_string().contains("stale"), "{error}");
            }
            let answered = rx.recv_timeout(std::time::Duration::from_secs(2));
            crate::api::gateway::seams::set_plan_park_ms(dir.path(), 0);
            let Ok(answer) = answered else {
                misses.push(format!("{case} did not answer the waiting agent at once"));
                continue;
            };
            if answer["result"]["data"]["status"] != status
                || answer["result"]["data"]["schema"] != "elastos.agent-plan.result/v1"
            {
                misses.push(format!("{case} answered {answer}"));
                continue;
            }
            if crate::resource_bridge::plan_waits_block_another_start(dir.path()) {
                misses.push(format!("{case} did not release the permit"));
            }
            if crate::resource_bridge::agent_plan_authority_is_held(&request_id) {
                misses.push(format!("{case} kept the plan authority"));
            }
            match super::super::agent_plan_approval_block(dir.path(), &request_id) {
                Some(block) if block.contains(status) && block.contains("cannot be approved") => {}
                other => misses.push(format!("{case} can still be approved: {other:?}")),
            }
        }
        assert!(misses.is_empty(), "{misses:?}");
    }
}
