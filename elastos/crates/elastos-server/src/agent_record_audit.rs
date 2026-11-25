//! Signed rows that follow an agent-file write or a stopping session.
//!
//! `agents.rs` does not read the sign-in file. This module does, and only
//! to see whether the promised audit row is already there.

use std::path::Path;

use elastos_runtime::auth::RuntimeAuditEventV1;
use sha2::{Digest, Sha256};

/// The retire write stores the tombstone and then appends `agent.record.retire`.
/// If that append fails, the next open under the agent lock finds this
/// sequence with no audit event and appends the retire row once.
pub(crate) fn repair_missing_retire(
    data_dir: &Path,
    sequence: u64,
    agent_id: &str,
    retired_at: Option<u64>,
    owner_proof_binding_id: Option<&str>,
    file_bytes: &[u8],
) -> anyhow::Result<()> {
    if sequence == 0 {
        return Ok(());
    }
    let Some(retired_at) = retired_at else {
        return Ok(());
    };
    let digest = hex::encode(Sha256::digest(file_bytes));
    let prefix = format!("audit:agent-records:{sequence}:");
    let seq = format!("seq={sequence}");
    let state = crate::auth::load_auth_state(data_dir)?;
    let present = state.audit.iter().any(|event| {
        event.event_id.starts_with(&prefix)
            || (event.event_type == "agent.record.retire" && event.reason.contains(&seq))
    });
    if present {
        return Ok(());
    }
    let Some(proof_binding_id) = owner_proof_binding_id else {
        anyhow::bail!("retired agent's owner is not in the sign-in file");
    };
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:agent-records:{sequence}:{}", &digest[..16]),
            event_type: "agent.record.retire".to_string(),
            principal_id: Some(agent_id.to_string()),
            proof_binding_id: Some(proof_binding_id.to_string()),
            session_id: Some("agent-file-repair".to_string()),
            challenge_id: None,
            capsule_id: None,
            result: "ok".to_string(),
            reason: format!("seq={sequence} sha256={digest}"),
            occurred_at: retired_at,
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
