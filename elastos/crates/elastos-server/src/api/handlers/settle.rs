//! Runtime settle for one ending instance (M1-R N2). Its caller is
//! `runtime.rs`'s `ActivationContextHeld::end_instance`.
//!
//! A revoke the capability store could not save is kept in the Home's
//! pending revocation list (A3-R S3 fix 2). The Home's start opens the store
//! through [`open_capability_store`], which revokes every token in that list
//! before the store is returned, so no such token validates after a restart.

use std::path::{Path, PathBuf};

use elastos_runtime::capability::pending::PendingRequestStore;
use elastos_runtime::capability::token::TokenId;
use elastos_runtime::capability::{CapabilityManager, CapabilityStore, RequestStatus, Settler};

/// The pending revocation list: one token id in hex per line, in the
/// capability store's folder. The store itself never reads or writes it.
const PENDING_REVOCATIONS: &str = "pending_revocations";

/// Every read and replacement of a pending list in this process is made
/// under this lock, so two ends that add at once both stay in the list.
static PENDING_LIST: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The capability store's folder in the Home's data folder `data_dir`.
pub fn capability_store_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("capability_store")
}

fn pending_list_path(data_dir: &Path) -> PathBuf {
    capability_store_dir(data_dir).join(PENDING_REVOCATIONS)
}

/// The ids in the pending list. A missing list is empty. A list that cannot
/// be read, or has a line that is not a token id, is an error: it is never
/// taken as empty.
fn read_pending_list(path: &Path) -> anyhow::Result<Vec<TokenId>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| TokenId::from_hex(line).map_err(anyhow::Error::msg))
        .collect()
}

/// Replaces the pending list with `ids` through `crate::auth::atomic_write`,
/// the server's write-then-rename helper. The caller holds [`PENDING_LIST`].
fn write_pending_list(path: &Path, ids: &[TokenId]) -> anyhow::Result<()> {
    let text: String = ids.iter().map(|id| format!("{id}\n")).collect();
    crate::auth::atomic_write(path, text.as_bytes())
}

/// Adds `token` to the pending list of the Home at `data_dir`.
fn keep_pending(data_dir: &Path, token: TokenId) -> anyhow::Result<()> {
    let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
    let path = pending_list_path(data_dir);
    let mut ids = read_pending_list(&path)?;
    if !ids.contains(&token) {
        ids.push(token);
    }
    write_pending_list(&path, &ids)
}

/// Opens the capability store of the Home at `data_dir` and revokes every
/// token in its pending list before returning it. The list loses those ids
/// only after the store saved each revoke; until then it keeps them for the
/// next start, and this run refuses them from memory. A pending list that
/// cannot be read refuses the store, so the Home does not start without it.
pub async fn open_capability_store(data_dir: &Path) -> anyhow::Result<CapabilityStore> {
    let store = CapabilityStore::with_persistence(capability_store_dir(data_dir)).await?;
    let path = pending_list_path(data_dir);
    let pending = {
        let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
        read_pending_list(&path)
    }
    .map_err(|error| anyhow::anyhow!("pending revocations unreadable: {error}"))?;
    if pending.is_empty() {
        return Ok(store);
    }
    let mut saved = true;
    for token in &pending {
        if let Err(error) = store.revoke_token(*token).await {
            tracing::error!(%error, "pending revocation {token} still not saved");
            saved = false;
        }
    }
    if saved {
        let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
        let cleared = read_pending_list(&path).and_then(|now| {
            let rest: Vec<TokenId> = now.into_iter().filter(|id| !pending.contains(id)).collect();
            write_pending_list(&path, &rest)
        });
        if let Err(error) = cleared {
            tracing::warn!(%error, "pending revocations saved but not cleared");
        }
    }
    Ok(store)
}

/// Deny every pending request and revoke every granted request of exactly
/// `session_id`, settled by the Runtime with a reason that names `cause`.
/// Tokens are revoked through `CapabilityManager::revoke`. Other sessions'
/// requests and grants are left as they are.
///
/// A revoke whose save fails still refuses its token in this process, and the
/// rest of the session still settles. That token is added to the pending
/// revocation list of the Home at `data_dir`, which its next start applies.
/// The save error is returned, with what became of the list, and the caller
/// records the end as not settled. A list that also cannot be written leaves
/// the token refused only in memory until a later save of the store, which
/// writes every token this process revoked.
pub async fn settle_and_revoke(
    store: &PendingRequestStore,
    manager: &CapabilityManager,
    data_dir: &Path,
    session_id: &str,
    cause: &str,
) -> Result<(), String> {
    let reason = format!("instance ended: {cause}");
    let mut unsaved = None;
    let mut lost = None;
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
                if let Err(list) = keep_pending(data_dir, *token.id()) {
                    tracing::error!(%list, "settle {session_id}: pending revocation not saved");
                    lost = Some(list);
                }
                unsaved = Some(error);
            }
            store
                .revoke_request_by(request.id.as_str(), &reason, Settler::Runtime)
                .await;
        }
    }
    match (unsaved, lost) {
        (None, _) => Ok(()),
        (Some(error), None) => Err(format!("{error}; kept in pending revocations")),
        (Some(error), Some(list)) => Err(format!("{error}; pending revocations not saved: {list}")),
    }
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

    /// The capability plane of the Home whose data folder is `dir`, opened as
    /// its start opens it, with tokens signed by `key`. A second call over the
    /// same `dir` and `key` is that Home after a restart.
    async fn saved_state(dir: &Path, key: &[u8; 32]) -> CapabilityState {
        let tokens = Arc::new(open_capability_store(dir).await.unwrap());
        state_over(tokens, SigningKey::from_bytes(key))
    }

    /// That Home's capability plane read from its saved store alone, without
    /// its pending revocation list.
    async fn store_only(dir: &Path, key: &[u8; 32]) -> CapabilityState {
        let saved = CapabilityStore::with_persistence(capability_store_dir(dir));
        state_over(Arc::new(saved.await.unwrap()), SigningKey::from_bytes(key))
    }

    /// The store's replacement of its saved list cannot be renamed over a
    /// folder, so every revoke save of the Home at `dir` fails until
    /// [`unblock_store`] moves that folder aside.
    fn block_store(dir: &Path) {
        std::fs::create_dir(capability_store_dir(dir).join("revoked_tokens")).unwrap();
    }

    fn unblock_store(dir: &Path) {
        let store = capability_store_dir(dir);
        std::fs::rename(store.join("revoked_tokens"), store.join("blocked")).unwrap();
    }

    fn pending_list(dir: &Path) -> Vec<TokenId> {
        read_pending_list(&pending_list_path(dir)).unwrap()
    }

    async fn settle_session_a(state: &CapabilityState, dir: &Path) -> Result<(), String> {
        let (store, manager) = (&state.pending_store, &state.capability_manager);
        settle_and_revoke(store, manager, dir, "session-a", "trapped").await
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
        let dir = tempfile::tempdir().unwrap();
        let state = state();
        let (a_pending, a_grant, a_token) = seed(&state, "session-a").await;
        let (b_pending, b_grant, b_token) = seed(&state, "session-b").await;
        settle_and_revoke(
            &state.pending_store,
            &state.capability_manager,
            dir.path(),
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

    /// A3-R S3 fix 2 row 1. A revoke whose save fails is returned to the
    /// caller; the token is refused in this process, its request still
    /// settles, and its id is kept in the pending revocation list. The saved
    /// store alone lacks it, yet the Home restarted from the store and that
    /// list refuses it. With a working store nothing is kept and the revoke
    /// holds across the restart, so the restart is a real one and not a
    /// refusal of every token.
    #[tokio::test]
    async fn an_unsaved_revoke_is_refused_after_a_restart() {
        let key = [0x51; 32];
        for broken in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let state = saved_state(dir.path(), &key).await;
            let (_, grant, token) = seed(&state, "session-a").await;
            if broken {
                block_store(dir.path());
            }
            let settled = settle_session_a(&state, dir.path()).await;
            match &settled {
                Err(detail) => assert!(
                    broken && detail.ends_with("; kept in pending revocations"),
                    "broken={broken}: {detail}"
                ),
                Ok(()) => assert!(!broken, "a failed save is reported"),
            }
            let here = validate(&state, "session-a", &token).await;
            assert_eq!(here, Err(ValidationError::TokenRevoked), "broken={broken}");
            assert!(
                matches!(status(&state, &grant).await, RequestStatus::Denied { .. }),
                "broken={broken}: the grant's request still settles"
            );
            let kept = if broken {
                vec![*token.id()]
            } else {
                Vec::new()
            };
            assert_eq!(pending_list(dir.path()), kept, "broken={broken}");

            let saved_alone = store_only(dir.path(), &key).await;
            let alone = validate(&saved_alone, "session-a", &token).await;
            let expected = if broken {
                Ok(())
            } else {
                Err(ValidationError::TokenRevoked)
            };
            assert_eq!(alone, expected, "broken={broken}: the saved store alone");
            let restarted = saved_state(dir.path(), &key).await;
            let after = validate(&restarted, "session-a", &token).await;
            assert_eq!(
                after,
                Err(ValidationError::TokenRevoked),
                "broken={broken}: after a restart"
            );
        }
    }

    /// A3-R S3 fix 2 row 2. A start applies the pending list and keeps it
    /// while the store still cannot save; the first start whose saves
    /// succeed clears it. From then the saved store alone refuses the token,
    /// and a further start has nothing left to apply.
    #[tokio::test]
    async fn the_pending_list_is_applied_once_and_cleared_after_the_store_saves() {
        let key = [0x52; 32];
        let dir = tempfile::tempdir().unwrap();
        let state = saved_state(dir.path(), &key).await;
        let (_, _, token) = seed(&state, "session-a").await;
        block_store(dir.path());
        assert!(settle_session_a(&state, dir.path()).await.is_err());
        assert_eq!(pending_list(dir.path()), vec![*token.id()]);

        let still_blocked = saved_state(dir.path(), &key).await;
        let check = validate(&still_blocked, "session-a", &token).await;
        assert_eq!(
            check,
            Err(ValidationError::TokenRevoked),
            "store still blocked"
        );
        assert_eq!(
            pending_list(dir.path()),
            vec![*token.id()],
            "kept while the store cannot save"
        );

        unblock_store(dir.path());
        let saved = saved_state(dir.path(), &key).await;
        let check = validate(&saved, "session-a", &token).await;
        assert_eq!(check, Err(ValidationError::TokenRevoked), "store saved");
        assert_eq!(pending_list(dir.path()), Vec::new(), "cleared once saved");

        let saved_alone = store_only(dir.path(), &key).await;
        let check = validate(&saved_alone, "session-a", &token).await;
        assert_eq!(
            check,
            Err(ValidationError::TokenRevoked),
            "the store holds it"
        );
        let again = saved_state(dir.path(), &key).await;
        let check = validate(&again, "session-a", &token).await;
        assert_eq!(check, Err(ValidationError::TokenRevoked), "a further start");
        assert_eq!(
            pending_list(dir.path()),
            Vec::new(),
            "nothing to apply again"
        );
    }

    /// A3-R S3 fix 2: neither the store nor the pending list can be written.
    /// The end is told both, and the token is refused in this process. A
    /// restart before any later save accepts it again: that is the gap left.
    /// The next revoke this process saves writes every token it revoked, and
    /// closes it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_revoke_with_no_list_is_refused_only_in_memory_until_a_later_save() {
        use std::os::unix::fs::PermissionsExt;
        let key = [0x53; 32];
        let dir = tempfile::tempdir().unwrap();
        let state = saved_state(dir.path(), &key).await;
        let (_, _, token) = seed(&state, "session-a").await;
        let (_, _, later) = seed(&state, "session-b").await;
        let folder = capability_store_dir(dir.path());
        let mode = |bits| std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(bits));
        mode(0o500).unwrap();
        let settled = settle_session_a(&state, dir.path()).await;
        mode(0o700).unwrap();

        let detail = settled.expect_err("the end is told");
        assert!(
            detail.contains("; pending revocations not saved: "),
            "{detail}"
        );
        let here = validate(&state, "session-a", &token).await;
        assert_eq!(here, Err(ValidationError::TokenRevoked), "in this process");
        assert_eq!(pending_list(dir.path()), Vec::new());
        let restarted = saved_state(dir.path(), &key).await;
        let after = validate(&restarted, "session-a", &token).await;
        assert_eq!(after, Ok(()), "the gap: nothing saved the revoke");

        let manager = &state.capability_manager;
        manager.revoke(*later.id(), "later").await.unwrap();
        let restarted = saved_state(dir.path(), &key).await;
        let after = validate(&restarted, "session-a", &token).await;
        assert_eq!(after, Err(ValidationError::TokenRevoked), "a later save");
    }
}
