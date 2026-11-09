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

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_runtime::capability::evaluator::ShellPassthroughVerifier;
    use elastos_runtime::capability::manager::ValidationError;
    use elastos_runtime::capability::{
        Action, CapabilityManager, CapabilityStore, CapabilityToken, GrantDuration,
        PendingRequestStore, PolicyEvaluator, ResourceId, TokenConstraints,
    };
    use elastos_runtime::primitives::{audit::AuditLog, metrics::MetricsManager};
    use elastos_runtime::session::SessionId;
    use std::sync::Arc;

    const RESOURCE: &str = "elastos://content/publish";

    fn state() -> CapabilityState {
        let audit = Arc::new(AuditLog::new());
        let tokens = Arc::new(CapabilityStore::new());
        let manager =
            CapabilityManager::new(tokens, audit.clone(), Arc::new(MetricsManager::new()));
        CapabilityState {
            pending_store: Arc::new(PendingRequestStore::new(audit.clone())),
            capability_manager: Arc::new(manager),
            policy_evaluator: Arc::new(PolicyEvaluator::new(
                Box::new(ShellPassthroughVerifier),
                audit,
            )),
        }
    }

    /// One pending and one granted request for `session`.
    async fn seed(state: &CapabilityState, session: &str) -> (String, String, CapabilityToken) {
        let store = &state.pending_store;
        let mut ids = Vec::new();
        for _ in 0..2 {
            let id = SessionId::from_string(session);
            let request = store.create_request(id, ResourceId::new(RESOURCE), Action::Write);
            ids.push(request.await.id.to_string());
        }
        let constraints = TokenConstraints::default();
        let resource = ResourceId::new(RESOURCE);
        let manager = &state.capability_manager;
        let token = manager.grant(session, resource, Action::Write, constraints, None);
        let granted = store.grant_request(&ids[1], token.clone(), GrantDuration::Session);
        granted.await.unwrap();
        (ids[0].clone(), ids[1].clone(), token)
    }

    async fn status(state: &CapabilityState, id: &str) -> RequestStatus {
        state.pending_store.get_request(id).await.unwrap().status
    }

    async fn validate(
        state: &CapabilityState,
        session: &str,
        token: &CapabilityToken,
    ) -> Result<(), ValidationError> {
        let resource = ResourceId::new(RESOURCE);
        let manager = &state.capability_manager;
        manager
            .validate(token, session, Action::Write, &resource, None)
            .await
    }

    #[tokio::test]
    async fn settle_and_revoke_settles_only_the_named_session() {
        let state = state();
        let (a_pending, a_grant, a_token) = seed(&state, "session-a").await;
        let (b_pending, b_grant, b_token) = seed(&state, "session-b").await;
        settle_and_revoke(&state, "session-a", "stopped").await;

        for (row, id) in [("A pending", &a_pending), ("A grant", &a_grant)] {
            let RequestStatus::Denied { reason, settled_by } = status(&state, id).await else {
                panic!("{row} {id} is not denied");
            };
            assert_eq!(settled_by, Settler::Runtime, "{row} settler");
            assert_eq!(reason, "instance ended: stopped", "{row} reason");
        }
        let a_check = validate(&state, "session-a", &a_token).await;
        assert_eq!(a_check, Err(ValidationError::TokenRevoked), "A token");
        let b_status = status(&state, &b_pending).await;
        assert!(
            matches!(b_status, RequestStatus::Pending),
            "B request: {b_status:?}"
        );
        let b_status = status(&state, &b_grant).await;
        assert!(
            matches!(b_status, RequestStatus::Granted { .. }),
            "B grant: {b_status:?}"
        );
        let b_check = validate(&state, "session-b", &b_token).await;
        assert_eq!(b_check, Ok(()), "B token still live");
    }
}
