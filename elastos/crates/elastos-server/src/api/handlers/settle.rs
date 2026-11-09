//! Runtime settle for one ending session (M1-R N2). No production caller
//! yet: N5's `end_instance` will call `settle_and_revoke`.

use elastos_runtime::capability::{RequestStatus, Settler};

use super::capability::CapabilityState;

/// Deny every pending request and revoke every granted request of exactly
/// `session_id`, settled by the Runtime with a reason that names `cause`.
/// Tokens are revoked through `CapabilityManager::revoke`. Other sessions'
/// requests and grants are left as they are.
pub async fn settle_and_revoke(state: &CapabilityState, session_id: &str, cause: &str) {
    let reason = format!("instance ended: {cause}");
    let store = &state.pending_store;
    for request in store.list_session_pending(session_id).await {
        // Fails only if the request left Pending after the listing; a grant
        // made in between is revoked by the loop below, which lists later.
        if let Err(err) = store
            .deny_request_by(request.id.as_str(), &reason, Settler::Runtime)
            .await
        {
            tracing::debug!("settle {session_id}: {err}");
        }
    }
    for request in store.list_granted().await {
        if request.session_id.as_str() != session_id {
            continue;
        }
        if let RequestStatus::Granted { token, .. } = &request.status {
            state.capability_manager.revoke(*token.id(), &reason).await;
            store
                .revoke_request_by(request.id.as_str(), &reason, Settler::Runtime)
                .await;
        }
    }
}
