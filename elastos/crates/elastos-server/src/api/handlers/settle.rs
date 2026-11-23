//! Runtime settle for one ending instance (M1-R N2). Its caller is
//! `runtime.rs`'s `ActivationContextHeld::end_instance`.
//!
//! An end writes the token ids of its grants to the Home's pending revocation
//! list before it asks the capability store to revoke them, and takes an id
//! out only after the store saved that revoke (A3-R S3 fixes 2 and 3). The
//! Home's start opens the store through [`open_capability_store`], which
//! revokes every listed token before the store is returned. So an end that
//! stops at any point leaves no grant of its session valid after a restart.

use std::path::{Path, PathBuf};

use elastos_runtime::capability::pending::PendingRequestStore;
use elastos_runtime::capability::token::TokenId;
use elastos_runtime::capability::{CapabilityManager, CapabilityStore, RequestStatus, Settler};

/// The pending revocation list: one token id in hex per line, in the
/// capability store's folder. The store itself never reads or writes it.
const PENDING_REVOCATIONS: &str = "pending_revocations";

/// The most ids the pending list holds. An end whose ids do not fit is
/// refused the list: its grants are still refused in this process, and the
/// end is reported as not settled. This also bounds the store saves that a
/// start makes to apply the list.
const PENDING_CAP: usize = 256;

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

/// The ids in the pending list, each once, in list order. A missing list is
/// empty. A list that cannot be read, or has a line that is not a token id,
/// is an error: it is never taken as empty.
fn read_pending_list(path: &Path) -> anyhow::Result<Vec<TokenId>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut ids = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let id = TokenId::from_hex(line).map_err(anyhow::Error::msg)?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Replaces the pending list with `ids` through `crate::auth::atomic_write`,
/// the server's write-then-rename helper. The caller holds [`PENDING_LIST`].
fn write_pending_list(path: &Path, ids: &[TokenId]) -> anyhow::Result<()> {
    let text: String = ids.iter().map(|id| format!("{id}\n")).collect();
    crate::auth::atomic_write(path, text.as_bytes())
}

/// Adds `tokens` to the pending list of the Home at `data_dir`, each once.
/// Ids already listed cost no write. Ids that would take the list past
/// [`PENDING_CAP`] are refused, and none of them is added.
fn keep_pending(data_dir: &Path, tokens: &[TokenId]) -> anyhow::Result<()> {
    let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
    let path = pending_list_path(data_dir);
    let mut ids = read_pending_list(&path)?;
    let listed = ids.len();
    for token in tokens {
        if !ids.contains(token) {
            ids.push(*token);
        }
    }
    if ids.len() == listed {
        return Ok(());
    }
    if ids.len() > PENDING_CAP {
        anyhow::bail!("the list is full ({PENDING_CAP} ids)");
    }
    write_pending_list(&path, &ids)
}

/// Takes `saved`, whose revokes the store saved, out of the pending list of
/// the Home at `data_dir`. A list without them costs no write.
fn drop_pending(data_dir: &Path, saved: &[TokenId]) -> anyhow::Result<()> {
    let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
    let path = pending_list_path(data_dir);
    let ids = read_pending_list(&path)?;
    let rest: Vec<TokenId> = ids
        .iter()
        .filter(|id| !saved.contains(id))
        .copied()
        .collect();
    if rest.len() == ids.len() {
        return Ok(());
    }
    write_pending_list(&path, &rest)
}

/// Opens the capability store of the Home at `data_dir` and revokes every
/// token in its pending list before returning it, in one pass. A token the
/// saved store already holds costs no store save. Each save writes every
/// token revoked before it, so the list keeps only the ids revoked after the
/// last save that succeeded, for the next start; this run refuses them from
/// memory. The list is rewritten at most once. A pending list that cannot be
/// read refuses the store, so the Home does not start without it.
pub async fn open_capability_store(data_dir: &Path) -> anyhow::Result<CapabilityStore> {
    let store = CapabilityStore::with_persistence(capability_store_dir(data_dir)).await?;
    let pending = {
        let _list = PENDING_LIST.lock().unwrap_or_else(|err| err.into_inner());
        read_pending_list(&pending_list_path(data_dir))
    }
    .map_err(|error| anyhow::anyhow!("pending revocations unreadable: {error}"))?;
    if pending.is_empty() {
        return Ok(store);
    }
    let mut saved = Vec::new();
    let mut unsaved = Vec::new();
    for token in pending {
        if store.is_token_revoked(&token).await {
            saved.push(token);
        } else if let Err(error) = store.revoke_token(token).await {
            tracing::error!(%error, "pending revocation {token} still not saved");
            unsaved.push(token);
        } else {
            saved.append(&mut unsaved);
            saved.push(token);
        }
    }
    if let Err(error) = drop_pending(data_dir, &saved) {
        tracing::warn!(%error, "pending revocations saved but not cleared");
    }
    Ok(store)
}

/// Deny every pending request and revoke every granted request of exactly
/// `session_id`, settled by the Runtime with a reason that names `cause`.
/// Tokens are revoked through `CapabilityManager::revoke`. Other sessions'
/// requests and grants are left as they are.
///
/// The grants' token ids are written to the pending revocation list of the
/// Home at `data_dir` before the first revoke, and each id leaves it once the
/// store saved its revoke, so the Home's next start applies every revoke
/// this end did not see saved. A revoke whose save fails still refuses its
/// token in this process, and the rest of the session still settles. The
/// save error is returned, with what became of the list, and the caller
/// records the end as not settled. A list that cannot take the ids, because
/// it is full or cannot be written, is returned the same way, even when every
/// save succeeds. Until a later save of the store, which writes every token
/// this process revoked, such a token is refused only in memory.
pub async fn settle_and_revoke(
    store: &PendingRequestStore,
    manager: &CapabilityManager,
    data_dir: &Path,
    session_id: &str,
    cause: &str,
) -> Result<(), String> {
    let reason = format!("instance ended: {cause}");
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
    let grants: Vec<_> = store
        .list_requests()
        .await
        .into_iter()
        .filter(|request| request.session_id.as_str() == session_id)
        .filter_map(|request| match request.status {
            RequestStatus::Granted { token, .. } => Some((request.id, *token.id())),
            _ => None,
        })
        .collect();
    if grants.is_empty() {
        return Ok(());
    }
    let tokens: Vec<TokenId> = grants.iter().map(|(_, token)| *token).collect();
    let kept = keep_pending(data_dir, &tokens);
    if let Err(list) = &kept {
        tracing::error!(%list, "settle {session_id}: pending revocations not saved");
    }
    let mut saved = Vec::new();
    let mut unsaved = None;
    for (request, token) in &grants {
        match manager.revoke(*token, &reason).await {
            Ok(()) => saved.push(*token),
            Err(error) => {
                tracing::error!(%error, "settle {session_id}: revocation persistence failed");
                unsaved = Some(error);
            }
        }
        store
            .revoke_request_by(request.as_str(), &reason, Settler::Runtime)
            .await;
    }
    if kept.is_ok() {
        if let Err(error) = drop_pending(data_dir, &saved) {
            tracing::warn!(%error, "settle {session_id}: saved revocations left pending");
        }
    }
    match (unsaved, kept) {
        (None, Ok(())) => Ok(()),
        (Some(error), Ok(())) => Err(format!("{error}; kept in pending revocations")),
        (None, Err(list)) => Err(format!("pending revocations not saved: {list}")),
        (Some(error), Err(list)) => Err(format!("{error}; pending revocations not saved: {list}")),
    }
}

#[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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

    /// A3-R S3 fix 3 row 1. An end is held after its list write and before
    /// the store saved its revoke, where a crash would stop it. The Home's
    /// capability folder copied at that point is the folder a restart finds:
    /// its saved store alone lacks the revoke, and the Home started from it
    /// refuses the grant.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_crash_between_the_list_and_the_store_save_leaves_the_grant_refused() {
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};
        let key = [0x54; 32];
        let dir = tempfile::tempdir().unwrap();
        let state = saved_state(dir.path(), &key).await;
        let (_, _, token) = seed(&state, "session-a").await;
        // The store's save opens this name to write it; as a FIFO it holds
        // the save there until it is opened to read.
        let fifo = capability_store_dir(dir.path()).join("revoked_tokens.tmp");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let pending = state.pending_store.clone();
        let manager = state.capability_manager.clone();
        let home = dir.path().to_path_buf();
        let end = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(settle_and_revoke(
                &pending,
                &manager,
                &home,
                "session-a",
                "trapped",
            ))
        });
        let start = Instant::now();
        while !pending_list(dir.path()).contains(token.id())
            && start.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!end.is_finished(), "the end is held in the store save");
        let crashed = tempfile::tempdir().unwrap();
        let copy = capability_store_dir(crashed.path());
        std::fs::create_dir_all(&copy).unwrap();
        for entry in std::fs::read_dir(capability_store_dir(dir.path())).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
            }
        }
        let mut written = Vec::new();
        let mut save = std::fs::File::open(&fifo).unwrap();
        save.read_to_end(&mut written).unwrap();
        let settled = end.join().unwrap();

        let saved_alone = store_only(crashed.path(), &key).await;
        let alone = validate(&saved_alone, "session-a", &token).await;
        assert_eq!(alone, Ok(()), "the saved store alone lacks the revoke");
        let restarted = saved_state(crashed.path(), &key).await;
        let after = validate(&restarted, "session-a", &token).await;
        assert_eq!(
            after,
            Err(ValidationError::TokenRevoked),
            "refused after a crash between the list and the store save"
        );
        let left = pending_list(dir.path());
        match settled {
            Ok(()) => assert_eq!(left, Vec::new(), "a saved revoke leaves the list"),
            Err(_) => assert_eq!(left, vec![*token.id()], "an unsaved one stays"),
        }
    }
    #[cfg(unix)]
    /// A3-R S3 fix 3 row 2. The pending list holds at most [`PENDING_CAP`]
    /// ids, each once. An id already listed takes no room. An end whose ids
    /// do not fit is reported as not settled and leaves the list as it was,
    /// yet its grant is refused, here and, through the store's save, after a
    /// restart. An end that fits exactly settles. A start applies a full list
    /// and clears it.
    #[tokio::test]
    async fn a_full_pending_list_refuses_the_end_and_keeps_each_id_once() {
        let key = [0x55; 32];
        let dir = tempfile::tempdir().unwrap();
        let state = saved_state(dir.path(), &key).await;
        let (_, grant, token) = seed(&state, "session-a").await;
        let (_, _, fits) = seed(&state, "session-b").await;
        let full: Vec<TokenId> = (0..PENDING_CAP).map(|_| TokenId::new()).collect();
        write_pending_list(&pending_list_path(dir.path()), &full).unwrap();
        let again = keep_pending(dir.path(), &[full[0], full[0]]);
        assert!(again.is_ok(), "a listed id takes no room: {again:?}");
        assert_eq!(pending_list(dir.path()), full, "each id once");

        let settled = settle_session_a(&state, dir.path()).await;
        assert_eq!(
            settled,
            Err(format!(
                "pending revocations not saved: the list is full ({PENDING_CAP} ids)"
            )),
            "a full list is refused"
        );
        let here = validate(&state, "session-a", &token).await;
        assert_eq!(here, Err(ValidationError::TokenRevoked), "in this process");
        assert!(
            matches!(status(&state, &grant).await, RequestStatus::Denied { .. }),
            "the grant's request still settles"
        );
        assert_eq!(pending_list(dir.path()), full, "the list is left as it was");
        let saved_alone = store_only(dir.path(), &key).await;
        let alone = validate(&saved_alone, "session-a", &token).await;
        assert_eq!(
            alone,
            Err(ValidationError::TokenRevoked),
            "the store saved it"
        );

        drop_pending(dir.path(), &full[..1]).unwrap();
        let (store, manager) = (&state.pending_store, &state.capability_manager);
        let settled = settle_and_revoke(store, manager, dir.path(), "session-b", "trapped").await;
        assert_eq!(settled, Ok(()), "an end that fills the list exactly");
        let check = validate(&state, "session-b", &fits).await;
        assert_eq!(check, Err(ValidationError::TokenRevoked));
        assert_eq!(pending_list(dir.path()), full[1..], "its saved id left");

        let started = open_capability_store(dir.path()).await.unwrap();
        for id in &full[1..] {
            assert!(started.is_token_revoked(id).await, "the start applies {id}");
        }
        assert_eq!(pending_list(dir.path()), Vec::new(), "and clears the list");
        let saved = CapabilityStore::with_persistence(capability_store_dir(dir.path()));
        let saved = saved.await.unwrap();
        for id in &full[1..] {
            assert!(saved.is_token_revoked(id).await, "the store saved {id}");
        }
    }
    #[cfg(unix)]
    /// A3-R S3 fix 3 row 3. A start applies the list in one pass. An id the
    /// saved store already holds costs no store save and leaves the list; an
    /// id listed twice is applied once, and it stays listed while its save
    /// fails, though this run refuses it.
    #[tokio::test]
    async fn a_start_saves_only_what_the_store_lacks() {
        let dir = tempfile::tempdir().unwrap();
        let (held, lacked) = (TokenId::new(), TokenId::new());
        let store = CapabilityStore::with_persistence(capability_store_dir(dir.path()));
        store.await.unwrap().revoke_token(held).await.unwrap();
        let list = format!("{held}\n{lacked}\n{lacked}\n");
        std::fs::write(pending_list_path(dir.path()), list).unwrap();
        // The store's save writes this name first; as a folder it fails
        // every save while the saved list still loads.
        std::fs::create_dir(capability_store_dir(dir.path()).join("revoked_tokens.tmp")).unwrap();

        let started = open_capability_store(dir.path()).await.unwrap();
        assert!(started.is_token_revoked(&held).await, "held");
        assert!(started.is_token_revoked(&lacked).await, "lacked, in memory");
        assert_eq!(
            pending_list(dir.path()),
            vec![lacked],
            "only the unsaved id stays listed"
        );
    }
}
