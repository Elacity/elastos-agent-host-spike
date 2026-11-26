//! Signed rows that follow an agent-file write or a stopping session.
//!
//! `agents.rs` does not read the sign-in file. This module does, and only
//! to see whether the promised audit row is already there.

use std::path::Path;

use elastos_runtime::auth::RuntimeAuditEventV1;
use sha2::{Digest, Sha256};

/// The file write stores the operation with the confirmation clear, then
/// appends the audit row of those bytes. A second write of the same sequence
/// sets the confirmation. If the append fails, the next open under the agent
/// lock appends the row for this sequence once. A later open that already
/// finds the row only marks the file confirmed.
pub(crate) fn repair_recorded_audit(
    data_dir: &Path,
    pending: &crate::agents::LastAudit,
    file_bytes: &[u8],
) -> anyhow::Result<()> {
    if pending.sequence == 0 || pending.confirmed {
        return Ok(());
    }
    let digest = hex::encode(Sha256::digest(file_bytes));
    let prefix = format!("audit:agent-records:{}:", pending.sequence);
    let seq = format!("seq={} ", pending.sequence);
    let state = crate::auth::load_auth_state(data_dir)?;
    let present = state.audit.iter().any(|event| {
        event.event_id.starts_with(&prefix)
            || (event.event_type == pending.operation
                && event.principal_id.as_deref() == Some(pending.subject.as_str())
                && event.reason.contains(&seq))
    });
    if present {
        return Ok(());
    }
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:agent-records:{}:{}", pending.sequence, &digest[..16]),
            event_type: pending.operation.clone(),
            principal_id: Some(pending.subject.clone()),
            proof_binding_id: Some(pending.proof_binding_id.clone()),
            session_id: Some(pending.session_id.clone()),
            challenge_id: None,
            capsule_id: None,
            result: "ok".to_string(),
            reason: format!("seq={} sha256={digest}", pending.sequence),
            occurred_at: pending.at,
            signer_did: None,
            signature: None,
        },
    )
}

/// An open stop (`stopping` or `failed`) is owed in the agent file first, and
/// a failed write is the answer. A settling row is signed first and its owed
/// stop is cleared after. Either way one of the two records always exists,
/// and `reconcile_owed_stops` settles a crash between them at the next start.
pub(crate) fn append_agent_row(data_dir: &Path, event: RuntimeAuditEventV1) -> anyhow::Result<()> {
    let row = std::slice::from_ref(&event);
    if matches!(event.result.as_str(), "stopping" | "failed") {
        crate::agents::note_stop_rows(data_dir, row)?;
        return crate::auth::append_audit_event(data_dir, event);
    }
    if event.event_type == "agent.stopped" && event.result == "ok" {
        if let Some(session) = event.session_id.as_deref() {
            if settling_stop_landed(data_dir, session)? {
                return crate::agents::note_stop_rows(data_dir, row);
            }
            mark_confirm(data_dir, session)?;
        }
    }
    crate::auth::append_audit_event(data_dir, event.clone())?;
    #[cfg(test)]
    if crate::api::gateway::seams::take_grant_kind(data_dir, "after-signed-stop") {
        anyhow::bail!("crash after the signed stop row");
    }
    crate::agents::note_stop_rows(data_dir, row)
}

/// An `ok` stop for this session is already in the kept chain, or the confirm
/// was marked and that mark has rolled off the anchor. A retry then clears
/// the owed row and does not append a second one.
fn settling_stop_landed(data_dir: &Path, session: &str) -> anyhow::Result<bool> {
    let state = crate::auth::load_auth_state(data_dir)?;
    if state.audit.iter().any(|row| {
        row.event_type == "agent.stopped"
            && row.result == "ok"
            && row.session_id.as_deref() == Some(session)
    }) {
        return Ok(true);
    }
    let owed = crate::agents::owed_stop_rows(data_dir);
    let Some(row) = owed
        .iter()
        .find(|row| row.result == "stopping" && row.session_id.as_deref() == Some(session))
    else {
        return Ok(false);
    };
    let Some(at) = confirm_marked_at(row) else {
        return Ok(false);
    };
    Ok(chain_rolled_off(&state, at))
}

pub(crate) fn signed_stop_kept(data_dir: &Path, session_id: &str) -> anyhow::Result<bool> {
    let state = crate::auth::load_auth_state(data_dir)?;
    Ok(state.audit.iter().any(|row| {
        row.event_type == "agent.stopped" && row.session_id.as_deref() == Some(session_id)
    }))
}

fn confirm_marked_at(row: &RuntimeAuditEventV1) -> Option<u64> {
    let id = row.challenge_id.as_deref()?;
    let stamp = id.strip_prefix("audit:stop-confirm|")?;
    stamp.parse().ok()
}

fn chain_rolled_off(state: &crate::auth::AuthState, at: u64) -> bool {
    let oldest = state.audit.first().map(|event| event.occurred_at);
    !(state.audit_chain_anchor.is_none() || oldest.is_some_and(|oldest| oldest < at))
}

/// Remember the confirm time on the owed `stopping` row before the `ok` row
/// is appended. The result stays `stopping`, so a crash here still owes the
/// stop. A later retry whose `ok` row has rolled off the anchor sees the mark.
fn mark_confirm(data_dir: &Path, session: &str) -> anyhow::Result<()> {
    let owed = crate::agents::owed_stop_rows(data_dir);
    let Some(mut row) = owed
        .into_iter()
        .find(|row| row.result == "stopping" && row.session_id.as_deref() == Some(session))
    else {
        return Ok(());
    };
    if confirm_marked_at(&row).is_some() {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    row.challenge_id = Some(format!("audit:stop-confirm|{now}"));
    crate::agents::note_stop_rows(data_dir, std::slice::from_ref(&row))
}

/// At start, an owed row the kept chain lacks is signed once. Then the kept
/// stop rows fold over the owed list in order: a signed later row settles an
/// owed stop, and a signed open stop the file lost is owed again. A trimmed
/// chain that no longer reaches an owed row's time does not sign it again.
pub(crate) fn reconcile_owed_stops(data_dir: &Path) -> anyhow::Result<()> {
    let state = crate::auth::load_auth_state(data_dir)?;
    let oldest = state.audit.first().map(|event| event.occurred_at);
    for owed in crate::agents::owed_stop_rows(data_dir) {
        let reached = state.audit_chain_anchor.is_none()
            || oldest.is_some_and(|oldest| oldest < owed.occurred_at);
        let present = state
            .audit
            .iter()
            .any(|event| event.event_id == owed.event_id);
        if reached && !present {
            crate::auth::append_audit_event(data_dir, owed)?;
        }
    }
    let signed = crate::auth::load_auth_state(data_dir)?.audit;
    crate::agents::note_stop_rows(data_dir, &signed)
}

/// Sessions whose latest `agent.stopped` row is still `stopping`.
pub(crate) fn open_stopping_sessions(data_dir: &Path) -> anyhow::Result<Vec<String>> {
    let owed = crate::agents::owed_stop_rows(data_dir);
    Ok(open_stopping(&owed).into_keys().collect())
}

fn open_stopping(
    audit: &[RuntimeAuditEventV1],
) -> std::collections::HashMap<String, &RuntimeAuditEventV1> {
    let mut open = std::collections::HashMap::new();
    for event in audit {
        if event.event_type != "agent.stopped" {
            continue;
        }
        let Some(session) = event.session_id.clone() else {
            continue;
        };
        if event.result == "stopping" {
            open.insert(session, event);
        } else if event.result == "ok" || event.result == "failed" {
            open.remove(&session);
        }
    }
    open
}

/// A `stopping` row is confirmed once, and only when `session_has_ended`
/// says that session is no longer running and has no plan effect in flight.
/// Two callers cannot both append: the check and the append share one lock.
pub(crate) fn confirm_stopping_rows(
    data_dir: &Path,
    session_has_ended: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    use std::sync::Mutex;
    static CONFIRM: Mutex<()> = Mutex::new(());
    let _guard = CONFIRM.lock().unwrap_or_else(|error| error.into_inner());
    let owed = crate::agents::owed_stop_rows(data_dir);
    let open = open_stopping(&owed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    for event in open.into_values() {
        let Some(session) = event.session_id.as_deref() else {
            continue;
        };
        if !session_has_ended(session) {
            continue;
        }
        append_agent_row(
            data_dir,
            RuntimeAuditEventV1 {
                schema: RuntimeAuditEventV1::SCHEMA.to_string(),
                event_id: format!("audit:stop-confirm:{now}:{}", confirm_nonce()),
                event_type: "agent.stopped".to_string(),
                principal_id: event.principal_id.clone(),
                proof_binding_id: event.proof_binding_id.clone(),
                session_id: event.session_id.clone(),
                challenge_id: event.challenge_id.clone(),
                capsule_id: event.capsule_id.clone(),
                result: "ok".to_string(),
                reason: event.reason.clone(),
                occurred_at: now,
                signer_did: None,
                signature: None,
            },
        )?;
    }
    Ok(())
}

fn confirm_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

/// Another admin with a live passkey. `owner_id` is not a candidate.
#[cfg(test)]
pub(crate) fn another_live_admin(
    data_dir: &Path,
    owner_id: &str,
) -> Option<crate::auth::PrincipalRecord> {
    crate::auth::load_owner_principals(data_dir)
        .ok()?
        .into_iter()
        .find(|principal| {
            principal.principal_id != owner_id
                && crate::auth::is_admin(principal)
                && principal
                    .proof_binding
                    .passkey
                    .as_ref()
                    .is_some_and(|passkey| passkey.revoked_at.is_none())
        })
}

/// One agent whose latest `agent.stopped` row is `failed`, with the principal
/// that signed it. A later `ok` or `stopping` row drops that agent, and so
/// does a later `agent.start.completed` `ok`: that is a new run, not the one
/// the failed stop was about.
pub(crate) struct FailedAgentStop {
    pub(crate) agent_id: String,
    pub(crate) principal: crate::auth::PrincipalRecord,
    pub(crate) reason: serde_json::Value,
}

pub(crate) fn latest_failed_agent_stops(data_dir: &Path) -> Vec<FailedAgentStop> {
    let Ok(auth) = crate::auth::load_auth_state(data_dir) else {
        return Vec::new();
    };
    let mut latest =
        std::collections::HashMap::<String, (String, String, serde_json::Value)>::new();
    for event in &crate::agents::owed_stop_rows(data_dir) {
        let started = event.event_type == "agent.start.completed" && event.result == "ok";
        if event.event_type != "agent.stopped" && !started {
            continue;
        }
        let Ok(reason) = serde_json::from_str::<serde_json::Value>(&event.reason) else {
            continue;
        };
        let Some(agent_id) = reason.get("agent_id").and_then(|value| value.as_str()) else {
            continue;
        };
        if started {
            latest.remove(agent_id);
            continue;
        }
        let Some(principal_id) = event.principal_id.clone() else {
            continue;
        };
        latest.insert(
            agent_id.to_string(),
            (event.result.clone(), principal_id, reason),
        );
    }
    let mut failed = Vec::new();
    for (agent_id, (result, principal_id, reason)) in latest {
        if result != "failed" {
            continue;
        }
        let Some(principal) = auth
            .principals
            .iter()
            .find(|principal| principal.principal_id == principal_id)
            .cloned()
        else {
            continue;
        };
        failed.push(FailedAgentStop {
            agent_id,
            principal,
            reason,
        });
    }
    failed
}
