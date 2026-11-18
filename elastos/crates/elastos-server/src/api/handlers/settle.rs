//! Runtime settle for one ending instance (M1-R N2). Its caller is
//! `runtime.rs`'s `ActivationContextHeld::end_instance`.

use elastos_runtime::capability::pending::PendingRequestStore;
use elastos_runtime::capability::{CapabilityManager, RequestStatus, Settler};

/// Deny every pending request and revoke every granted request of exactly
/// `session_id`, settled by the Runtime with a reason that names `cause`.
/// Tokens are revoked through `CapabilityManager::revoke`. Other sessions'
/// requests and grants are left as they are.
///
/// A revoke whose save fails still refuses its token in this process, and the
/// rest of the session still settles. The save error is returned: the saved
/// revoke list may lack that token, so a restart could accept it again, and
/// the caller records the end as not settled.
pub async fn settle_and_revoke(
    store: &PendingRequestStore,
    manager: &CapabilityManager,
    session_id: &str,
    cause: &str,
) -> std::io::Result<()> {
    let reason = format!("instance ended: {cause}");
    let mut saved = Ok(());
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
    for request in store.list_requests().await {
        if request.session_id.as_str() != session_id {
            continue;
        }
        if let RequestStatus::Granted { token, .. } = &request.status {
            if let Err(error) = manager.revoke(*token.id(), &reason).await {
                tracing::error!(%error, "settle {session_id}: revocation persistence failed");
                saved = Err(error);
            }
            store
                .revoke_request_by(request.id.as_str(), &reason, Settler::Runtime)
                .await;
        }
    }
    saved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::CapabilityState;
    use elastos_runtime::capability::evaluator::ShellPassthroughVerifier;
    use elastos_runtime::capability::manager::ValidationError;
    use elastos_runtime::capability::{
        Action, CapabilityManager, CapabilityStore, CapabilityToken, GrantDuration,
        PendingRequestStore, PolicyEvaluator, ResourceId, TokenConstraints,
    };
    use elastos_runtime::primitives::{audit::AuditLog, metrics::MetricsManager};
    use elastos_runtime::session::SessionId;
    use elastos_runtime::signature::SigningKey;
    use std::sync::Arc;

    const RESOURCE: &str = "elastos://content/publish";

    fn state() -> CapabilityState {
        let tokens = Arc::new(CapabilityStore::new());
        state_over(tokens, SigningKey::from_bytes(&[0x50; 32]))
    }

    /// A Home's capability plane whose revoke list is saved under `dir` and
    /// whose tokens are signed with `key`. A second call over the same `dir`
    /// and `key` is that Home after a restart.
    async fn saved_state(dir: &std::path::Path, key: &[u8; 32]) -> CapabilityState {
        let tokens = Arc::new(CapabilityStore::with_persistence(dir).await.unwrap());
        state_over(tokens, SigningKey::from_bytes(key))
    }

    fn state_over(tokens: Arc<CapabilityStore>, key: SigningKey) -> CapabilityState {
        let audit = Arc::new(AuditLog::new());
        let manager = CapabilityManager::with_key(
            key,
            tokens.clone(),
            audit.clone(),
            Arc::new(MetricsManager::new()),
        );
        CapabilityState {
            capability_store: tokens,
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
        settle_and_revoke(
            &state.pending_store,
            &state.capability_manager,
            "session-a",
            "stopped",
        )
        .await
        .unwrap();

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

    /// A revoke whose save fails is returned to the caller; the token is
    /// refused in this process and its request still settles. Reloaded from
    /// the store, that token validates again, which is why the caller records
    /// the end as not settled. With a working store the revoke holds across
    /// the reload, so the reload is a real restart and not a refusal of every
    /// token.
    #[tokio::test]
    async fn settle_and_revoke_returns_a_revoke_it_could_not_save() {
        let key = [0x51; 32];
        for broken in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let state = saved_state(dir.path(), &key).await;
            let (_, grant, token) = seed(&state, "session-a").await;
            if broken {
                // The saved list's replacement cannot be renamed over a folder.
                std::fs::create_dir(dir.path().join("revoked_tokens")).unwrap();
            }
            let settled = settle_and_revoke(
                &state.pending_store,
                &state.capability_manager,
                "session-a",
                "trapped",
            )
            .await;
            assert_eq!(settled.is_err(), broken, "broken={broken}: {settled:?}");
            let here = validate(&state, "session-a", &token).await;
            assert_eq!(here, Err(ValidationError::TokenRevoked), "broken={broken}");
            assert!(
                matches!(status(&state, &grant).await, RequestStatus::Denied { .. }),
                "broken={broken}: the grant's request still settles"
            );

            let restarted = saved_state(dir.path(), &key).await;
            let after = validate(&restarted, "session-a", &token).await;
            let expected = if broken {
                Ok(())
            } else {
                Err(ValidationError::TokenRevoked)
            };
            assert_eq!(after, expected, "broken={broken}: after the reload");
        }
    }
}
