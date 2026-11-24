//! Each running instance gets fresh, limited access to its agent's storage,
//! which ends when the instance stops.
//!
//! The rows below use the route-level probe (`ProbeLaunch`, the launch route,
//! and the bridge). A journal write that succeeded is the storage grant. The
//! replay keeps the manifest ceiling the instance had while it ran, so the
//! answer is the grant check. A cleared ceiling would refuse the call earlier,
//! which the existing late-call rows already show. The stop flag is left unset
//! on the replay for the same reason: the row is the grant.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use elastos_runtime::capability::pending::{GrantDuration, RequestStatus, Settler};
use elastos_runtime::capability::{Action, CapabilityToken, TokenConstraints};

use super::{stop_route, ProbeLaunch};

const JOURNAL_SUFFIX: &str = "/.AppData/Agents/agent-host/tasks/t1/journal";
const NOTES_SUFFIX: &str = "/memory/notes.md";
const REPLAY: &[u8] = b"U7-REPLAY-MUST-NOT-LAND";

struct GrantControl {
    sessions: Mutex<Vec<String>>,
    hold_notes_writes: AtomicBool,
}

impl GrantControl {
    fn new(hold_notes_writes: bool) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(Vec::new()),
            hold_notes_writes: AtomicBool::new(hold_notes_writes),
        })
    }

    fn allow(&self, session: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.iter().any(|held| held == session) {
            sessions.push(session.to_string());
        }
    }

    fn release_notes(&self) {
        self.hold_notes_writes.store(false, Ordering::Release);
    }
}

fn spawn_grants(home: &ProbeLaunch, control: Arc<GrantControl>) -> tokio::task::JoinHandle<()> {
    let store = home.pending_store.clone();
    let manager = home.capability_manager.clone();
    tokio::spawn(async move {
        loop {
            let sessions = control.sessions.lock().unwrap().clone();
            let hold = control.hold_notes_writes.load(Ordering::Acquire);
            for pending in store.list_pending().await {
                if !sessions
                    .iter()
                    .any(|session| session == pending.session_id.as_str())
                {
                    continue;
                }
                if hold
                    && pending.action == Action::Write
                    && pending.resource.as_str().ends_with(NOTES_SUFFIX)
                {
                    continue;
                }
                let token = manager.grant(
                    pending.session_id.as_str(),
                    pending.resource.clone(),
                    pending.action,
                    TokenConstraints::default(),
                    None,
                );
                let _ = store
                    .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

fn journal_uri(home: &ProbeLaunch, agent: &str) -> String {
    format!("{}{JOURNAL_SUFFIX}", home.root(agent))
}

fn object_path(home: &ProbeLaunch, uri: &str) -> std::path::PathBuf {
    elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, uri)
        .unwrap_or_else(|| panic!("{uri} has no file"))
}

fn read_plain(home: &ProbeLaunch, agent: &str, uri: &str) -> Vec<u8> {
    let root = home.root(agent);
    let path = object_path(home, uri);
    crate::auth::read_principal_root_object(&home.data_dir, agent, &root, uri, &path)
        .unwrap_or_else(|err| panic!("journal {uri} does not open: {err}"))
}

fn probe_journal(bytes: &[u8], agent: &str) -> bool {
    bytes.starts_with(b"EAHJ")
        && bytes
            .windows(agent.len())
            .any(|window| window == agent.as_bytes())
}

async fn journal_write_grant(home: &ProbeLaunch, session: &str) -> Option<CapabilityToken> {
    for request in home.pending_store.list_requests().await {
        if request.session_id.as_str() != session || request.action != Action::Write {
            continue;
        }
        if !request.resource.as_str().ends_with(JOURNAL_SUFFIX) {
            continue;
        }
        if let RequestStatus::Granted { token, .. } = request.status {
            return Some(*token);
        }
    }
    None
}

async fn wait_journal_used(home: &ProbeLaunch, agent: &str, session: &str) -> CapabilityToken {
    let uri = journal_uri(home, agent);
    let path = object_path(home, &uri);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(token) = journal_write_grant(home, session).await {
                assert_eq!(
                    token.resource().as_str(),
                    uri,
                    "the storage grant names the journal the guest wrote"
                );
                if path.is_file() {
                    let plain = read_plain(home, agent, &uri);
                    if probe_journal(&plain, agent) {
                        return token;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the journal write succeeds under its storage grant")
}

async fn wait_notes_write(home: &ProbeLaunch, session: &str) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(request) =
                home.pending_store
                    .list_pending()
                    .await
                    .into_iter()
                    .find(|request| {
                        request.session_id.as_str() == session
                            && request.action == Action::Write
                            && request.resource.as_str().ends_with(NOTES_SUFFIX)
                    })
            {
                return request.id.to_string();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the guest waits on its notes write after the journal write")
}

fn ceiling(home: &ProbeLaunch, session: &str) -> Vec<elastos_common::AuthorityBound> {
    let manifest = home
        .runtime
        .bridge_tables_for_test(session)
        .manifest_capabilities;
    assert!(
        !manifest.is_empty(),
        "instance {session} has the manifest ceiling the grant check sits behind"
    );
    manifest
}

struct UsedGrant {
    session: String,
    token: CapabilityToken,
    manifest: Vec<elastos_common::AuthorityBound>,
}

async fn launch_until_journal_is_used(
    home: &ProbeLaunch,
    agent: &str,
    control: &GrantControl,
) -> UsedGrant {
    let run = home
        .launch(agent)
        .await
        .expect("the agent launch is admitted")
        .0;
    assert_eq!(run.status, "starting");
    control.allow(&run.id);
    let token = wait_journal_used(home, agent, &run.id).await;
    let manifest = ceiling(home, &run.id);
    UsedGrant {
        session: run.id,
        token,
        manifest,
    }
}

async fn replay(
    home: &ProbeLaunch,
    agent: &str,
    caller: &str,
    token: &CapabilityToken,
    manifest: Vec<elastos_common::AuthorityBound>,
) -> serde_json::Value {
    let uri = token.resource().as_str();
    let plain = read_plain(home, agent, uri);
    let revision = crate::auth::principal_root_object_revision(agent, uri, &plain);
    let line = serde_json::json!({
        "id": 91,
        "request": {
            "type": "resource_invoke",
            "uri": uri,
            "operation": "write",
            "token": token.to_base64().expect("the used grant encodes"),
            "body": { "content": REPLAY, "if_revision": revision },
        }
    })
    .to_string();
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: home.registry.clone(),
        capability_manager: home.capability_manager.clone(),
        pending_store: home.pending_store.clone(),
        capsule_id: caller.to_string(),
        session_id: caller.to_string(),
        principal_id: Some(agent.to_string()),
        manifest_capabilities: manifest,
        data_dir: Some(home.data_dir.clone()),
        launch: None,
        model_token_ceiling: None,
        model_budget: None,
        stop: None,
    };
    crate::resource_bridge::handle_component_resource_request(&line, ctx)
        .await
        .expect("the bridge answers the replay")
}

async fn assert_replay_refused(
    home: &ProbeLaunch,
    agent: &str,
    caller: &str,
    token: &CapabilityToken,
    manifest: Vec<elastos_common::AuthorityBound>,
) {
    let uri = token.resource().as_str().to_string();
    let path = object_path(home, &uri);
    let before = std::fs::read(&path).expect("the journal file is on disk");
    let plain = read_plain(home, agent, &uri);
    let answer = replay(home, agent, caller, token, manifest).await;
    assert_eq!(
        answer["response"]["code"], "capability_denied",
        "the used storage grant is refused: {answer}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the journal file stays on disk"),
        before,
        "the file is unchanged"
    );
    assert_eq!(
        read_plain(home, agent, &uri),
        plain,
        "the stored journal is unchanged"
    );
    assert!(
        !plain.windows(REPLAY.len()).any(|window| window == REPLAY),
        "the replay bytes are not the stored journal"
    );
}

fn require_agents() -> bool {
    crate::agents::require_build().is_ok()
}

async fn own_grant_finishes(
    home: &ProbeLaunch,
    agent: &str,
    session: &str,
    control: &GrantControl,
    earlier: &CapabilityToken,
) {
    control.allow(session);
    control.release_notes();
    let own = wait_journal_used(home, agent, session).await;
    assert_ne!(
        own.id(),
        earlier.id(),
        "the run receives its own storage grant"
    );
    assert_eq!(own.capsule(), session, "the new grant is bound to this run");
    let end = home.wait_ended(session).await;
    assert_eq!(end.cause.as_deref(), Some("completed"), "{end:?}");
    let wrote = home
        .invoked(agent)
        .into_iter()
        .any(|(ran, result, reason)| {
            ran.as_deref() == Some(session)
                && result == "ok"
                && reason.starts_with("write ")
                && reason.contains(JOURNAL_SUFFIX)
        });
    assert!(wrote, "the run's own storage grant writes the journal");
}

/// A storage grant the run used for a journal write is refused after the stop
/// route ends the instance. The file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_stop() {
    if !require_agents() {
        return;
    }
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;
    let (status, _) = stop_route(&home, &used.session, Some("journal written")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let end = home.wait_ended(&used.session).await;
    assert_eq!(end.status, "stopped");
    assert_eq!(end.cause.as_deref(), Some("stopped: journal written"));
    assert_replay_refused(&home, &agent, &used.session, &used.token, used.manifest).await;
    grants.abort();
}

/// The same used grant is refused when the stop route cancels the instance
/// while a later bridge call is still unanswered. That call is denied by the
/// Runtime, and the journal file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_cancel() {
    if !require_agents() {
        return;
    }
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let notes = wait_notes_write(&home, &used.session).await;
    let (status, _) = stop_route(&home, &used.session, Some("waiting too long")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let held = home
        .pending_store
        .get_request(&notes)
        .await
        .expect("the call the guest was inside is still recorded");
    let RequestStatus::Denied { reason, settled_by } = &held.status else {
        panic!("the cancelled call is not denied: {:?}", held.status);
    };
    assert_eq!(reason, "instance ended: stopped: waiting too long");
    assert_eq!(*settled_by, Settler::Runtime);
    let end = home.wait_ended(&used.session).await;
    assert_eq!(end.status, "stopped");
    assert_replay_refused(&home, &agent, &used.session, &used.token, used.manifest).await;
    grants.abort();
}

/// The same used grant is refused after the guest fails. The file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_failure() {
    if !require_agents() {
        return;
    }
    let home = ProbeLaunch::new(&["a", "b"]).await;
    let agent = home.agents[0].clone();
    let other = home.agents[1].clone();
    let (root_a, root_b) = (home.root(&agent), home.root(&other));
    let peer = format!("{root_b}/memory/notes.md");
    let pointer_uri = format!("{root_a}/memory/peer");
    let pointer_path = object_path(&home, &pointer_uri);
    crate::auth::write_principal_root_object(
        &home.data_dir,
        &agent,
        &root_a,
        &pointer_uri,
        &pointer_path,
        peer.as_bytes(),
    )
    .unwrap();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;
    control.release_notes();
    let end = home.wait_ended(&used.session).await;
    assert_eq!(end.status, "failed");
    let cause = end.cause.clone().expect("a failure records its cause");
    assert!(
        cause.contains(
            "localhost://UsersAI roots must use UsersAI/self or the active principal root"
        ),
        "{cause}"
    );
    assert_replay_refused(&home, &agent, &used.session, &used.token, used.manifest).await;
    grants.abort();
}

/// After one run has stopped, a later run of the same agent cannot use that
/// run's storage grant. The file is unchanged. The later run gets its own grant
/// and its own journal write succeeds.
#[cfg(unix)]
#[tokio::test]
async fn a_later_run_cannot_use_the_earlier_runs_storage_grant() {
    if !require_agents() {
        return;
    }
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;
    let (status, _) = stop_route(&home, &used.session, Some("journal written")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    home.wait_ended(&used.session).await;
    assert_replay_refused(
        &home,
        &agent,
        &used.session,
        &used.token,
        used.manifest.clone(),
    )
    .await;

    let later = tokio::time::timeout(Duration::from_secs(15), home.launch(&agent))
        .await
        .expect("the later run is admitted after the first has stopped")
        .expect("the later launch is admitted")
        .0;
    assert_ne!(later.id, used.session, "the later run is a new instance");
    home.wait_pending(&later.id).await;
    let manifest = ceiling(&home, &later.id);
    assert_replay_refused(&home, &agent, &later.id, &used.token, manifest).await;
    own_grant_finishes(&home, &agent, &later.id, &control, &used.token).await;
    grants.abort();
}

/// Where two runs of one agent are admitted together, the second cannot use
/// the first's live storage grant. The file is unchanged. The second run gets
/// its own grant.
#[cfg(unix)]
#[tokio::test]
async fn two_runs_of_one_agent_at_once_keep_separate_storage_grants() {
    if !require_agents() {
        return;
    }
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;

    let second = tokio::time::timeout(Duration::from_secs(15), home.launch(&agent))
        .await
        .expect("a second run is admitted while the first is live")
        .expect("the Runtime admits two runs of one agent at once")
        .0;
    assert_ne!(second.id, used.session);
    home.wait_pending(&second.id).await;
    let manifest = ceiling(&home, &second.id);
    assert_replay_refused(&home, &agent, &second.id, &used.token, manifest).await;
    own_grant_finishes(&home, &agent, &second.id, &control, &used.token).await;

    control.release_notes();
    let first = home.wait_ended(&used.session).await;
    assert_eq!(first.cause.as_deref(), Some("completed"), "{first:?}");
    grants.abort();
}
