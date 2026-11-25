//! Signed rows that follow an agent-file write or a stopping session.
//!
//! `agents.rs` does not read the sign-in file. This module does, and only
//! to see whether the promised audit row is already there.

use std::path::Path;

use elastos_runtime::auth::RuntimeAuditEventV1;
use sha2::{Digest, Sha256};

/// The file write stores the operation and then appends its audit row. If
/// that append fails, the next open under the agent lock appends the row for
/// this sequence's operation and subject once. A later open that already
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
    let seq = format!("seq={}", pending.sequence);
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

/// Sessions whose latest `agent.stopped` row is still `stopping`.
pub(crate) fn open_stopping_sessions(data_dir: &Path) -> anyhow::Result<Vec<String>> {
    let state = crate::auth::load_auth_state(data_dir)?;
    Ok(open_stopping(&state.audit).into_keys().collect())
}

fn open_stopping<'a>(
    audit: &'a [RuntimeAuditEventV1],
) -> std::collections::HashMap<String, &'a RuntimeAuditEventV1> {
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
    let state = crate::auth::load_auth_state(data_dir)?;
    let open = open_stopping(&state.audit);
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
        crate::auth::append_audit_event(
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
