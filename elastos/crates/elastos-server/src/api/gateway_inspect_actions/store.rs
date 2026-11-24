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
}

pub(super) fn pending_inspect_action_requests(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut records = load_inspect_action_records(data_dir)?;
    records.sort_by_key(|record| record.created_at);
    Ok(records
        .into_iter()
        .filter(|record| record.status == "pending" && record.principal_id == principal_id)
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
/// plan becomes stale and claims nothing. The passkey check runs before any
/// state write: a failed passkey leaves the record pending, and a second click
/// finds it claimed.
pub(super) fn claim_pending_agent_plan_for_owner(
    data_dir: &Path,
    request_id: &str,
    owner_id: &str,
    approver_is_human: bool,
    card_binding: &serde_json::Value,
    updated_at: u64,
    consume_step_up: impl FnOnce(&InspectActionRequestRecord) -> anyhow::Result<()>,
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
    consume_step_up(&record)?;
    if record.request_binding.as_ref() != Some(&card)
        || super::agent_plan::agent_plan_request_binding(&record) != Some(card.clone())
    {
        let message = "agent plan changed before Inbox approval; it is stale";
        record.status = "stale".to_string();
        record.error = Some(message.to_string());
        record.updated_at = updated_at;
        write_inspect_action_record_unlocked(data_dir, &record)?;
        anyhow::bail!(message);
    }
    record.status = "approved".to_string();
    record.updated_at = updated_at;
    write_inspect_action_record_unlocked(data_dir, &record)?;
    Ok(record)
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

/// Reads every record, skipping one unreadable file with a log line that
/// names the file and not its bytes. The strict loader is unchanged.
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
            eprintln!(
                "[gateway] skipped unreadable inspect action record {}",
                path.display()
            );
            continue;
        };
        records.push((path, record));
    }
    Ok(records)
}

fn load_inspect_action_records(data_dir: &Path) -> anyhow::Result<Vec<InspectActionRequestRecord>> {
    let root = inspect_actions_root(data_dir);
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(path)?;
        let record: InspectActionRequestRecord = serde_json::from_str(&data)?;
        records.push(record);
    }
    Ok(records)
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

/// The store lock is per process, so an update successor can mark a plan
/// unknown after the draining process completed it.
pub(super) fn settle_agent_plans_lost_before_start(
    data_dir: &Path,
    updated_at: u64,
) -> anyhow::Result<()> {
    let _guard = inspect_action_store_lock()?;
    let records = load_inspect_action_records_skipping_unreadable(data_dir)?;
    settle_records_in_place(records, updated_at);
    Ok(())
}

fn settle_records_in_place(records: Vec<(PathBuf, InspectActionRequestRecord)>, updated_at: u64) {
    let reason = "a dispatch cannot survive a restart";
    for (path, mut record) in records {
        if record.kind != AGENT_PLAN_KIND
            || !matches!(record.status.as_str(), "approved" | "dispatching")
        {
            continue;
        }
        record.status = "unknown".into();
        record.error = Some(reason.into());
        record.result = Some(serde_json::json!({ "status": "unknown", "reason": reason }));
        record.updated_at = updated_at;
        if let Err(error) = write_inspect_action_at_path(&path, &record) {
            eprintln!(
                "[gateway] skipped inspect action record {}: {error}",
                path.display()
            );
        }
    }
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
        }
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

    /// A leftover file the loader cannot read must not stop settling, and the
    /// inbox list still fails on that same file.
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
        assert!(
            listed.is_err(),
            "the inbox list still fails on a bad file: {listed:?}"
        );
        settle_agent_plans_lost_before_start(dir.path(), 9).unwrap();
        let stored = read_inspect_action_record(dir.path(), "agent-plan-good").unwrap();
        assert_eq!(stored.status, "unknown");
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
        assert_eq!(kept_stored.status, "unknown");
        assert_eq!(dotted_stored.status, "unknown");
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
            "unknown"
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
        settle_records_in_place(vec![(missing, stuck), (good_path, good)], 9);
        assert_eq!(
            read_inspect_action_record(dir.path(), "agent-plan-good")
                .unwrap()
                .status,
            "unknown"
        );
    }
}
