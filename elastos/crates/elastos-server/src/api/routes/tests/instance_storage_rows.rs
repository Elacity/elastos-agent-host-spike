#![cfg(feature = "prototype-agents")]
//! Each running instance gets fresh, limited access to its agent's storage,
//! which ends when the instance stops. A step whose dispatch hasn't reached
//! its effect is refused; an effect already begun is tracked, and Stop says
//! stopping until it ends. A plan step still pending at the end is refused.
//!
//! The rows below use the route-level probe (`ProbeLaunch`, the launch route,
//! and the bridge). A journal write that succeeded is the storage grant. The
//! replay keeps the manifest ceiling the instance had while it ran, so the
//! answer is the grant check. A cleared ceiling would refuse the call earlier,
//! which the existing late-call rows already show. The stop flag is left unset
//! on the replay for the same reason: the row is the grant. Those replays call
//! `handle_component_resource_request`, the bridge handler, not the host-call
//! wrapper.
//!
//! The refusal is a new `capability_validation_failed` warning for this caller
//! and this token. After the instance has ended, that warning ends in
//! `individually_revoked`. A replay from another run ends in `wrong_capsule`,
//! the session check. A retained plan step is outside the pending store. The
//! instance end drops that admission while the plan is still pending. The
//! owner's later approval is then refused `admission_missing`, and the step's
//! file is unchanged. That row calls `dispatch_agent_plan_step`. It does not
//! call the approve route or the dispatch route.
//!
//! This module compiles only with `prototype-agents`. A build without that
//! feature does not contain these rows.
//!
//! U7 is proved in one process. Its installed proof comes with the agent
//! package, which puts the plan book, the Inbox dispatch and Stop on the
//! gateway's one Runtime.

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
        plan_book: None,
    };
    crate::resource_bridge::handle_component_resource_request(&line, ctx)
        .await
        .expect("the bridge answers the replay")
}

fn validation_failures(home: &ProbeLaunch) -> Vec<String> {
    home.audit_log
        .recent_events(8_000)
        .into_iter()
        .filter_map(|event| match event {
            elastos_runtime::primitives::audit::AuditEvent::SecurityWarning {
                warning_type,
                details,
                ..
            } if warning_type == "capability_validation_failed" => Some(details),
            _ => None,
        })
        .collect()
}

async fn assert_replay_refused(
    home: &ProbeLaunch,
    agent: &str,
    caller: &str,
    token: &CapabilityToken,
    manifest: Vec<elastos_common::AuthorityBound>,
    reason: &str,
) {
    let uri = token.resource().as_str().to_string();
    let path = object_path(home, &uri);
    let before = std::fs::read(&path).expect("the journal file is on disk");
    let plain = read_plain(home, agent, &uri);
    let before_warnings = validation_failures(home);
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
    let token_id = token.id().to_string();
    let expected =
        format!("capsule {caller} presented token {token_id} failed validation: {reason}");
    let count = |lines: &[String]| lines.iter().filter(|line| *line == &expected).count();
    let after_warnings = validation_failures(home);
    assert_eq!(
        count(&after_warnings) - count(&before_warnings),
        1,
        "a new capability_validation_failed warning for this caller and token ends in {reason}: {expected}; warnings {after_warnings:?}"
    );
}

fn require_agents() {
    if let Err(reason) = crate::agents::require_build() {
        panic!("instance_storage_rows compiles only with the prototype-agents feature: {reason}");
    }
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
    require_agents();
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
    assert_replay_refused(
        &home,
        &agent,
        &used.session,
        &used.token,
        used.manifest,
        "individually_revoked",
    )
    .await;
    grants.abort();
}

/// The stop row ends the instance and refuses the used grant. This row adds
/// the unanswered notes write: that call is still open when the stop route
/// runs, and the Runtime denies it. The used grant is refused after that
/// denial, and the journal file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_cancel() {
    require_agents();
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
    assert_replay_refused(
        &home,
        &agent,
        &used.session,
        &used.token,
        used.manifest,
        "individually_revoked",
    )
    .await;
    grants.abort();
}

/// The same used grant is refused after the guest fails. The file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_failure() {
    require_agents();
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
    assert_replay_refused(
        &home,
        &agent,
        &used.session,
        &used.token,
        used.manifest,
        "individually_revoked",
    )
    .await;
    grants.abort();
}

/// After the guest completes on its own, the storage grant that run used is
/// refused. The file is unchanged.
#[cfg(unix)]
#[tokio::test]
async fn a_used_storage_grant_is_refused_after_the_guest_completes() {
    require_agents();
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;
    control.release_notes();
    let end = home.wait_ended(&used.session).await;
    assert_eq!(end.cause.as_deref(), Some("completed"), "{end:?}");
    assert_replay_refused(
        &home,
        &agent,
        &used.session,
        &used.token,
        used.manifest,
        "individually_revoked",
    )
    .await;
    grants.abort();
}

/// After one run has stopped, a later run of the same agent cannot use that
/// run's storage grant. The same-session replay is revocation. The replay from
/// the later run is the session check (`wrong_capsule`). That check is the
/// proof that remains when a second live run is no longer admitted. The file
/// is unchanged. The later run gets its own grant and its own journal write
/// succeeds.
#[cfg(unix)]
#[tokio::test]
async fn a_later_run_cannot_use_the_earlier_runs_storage_grant() {
    require_agents();
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
        "individually_revoked",
    )
    .await;

    // The launch loads the component, and that load includes its compile.
    let later = tokio::time::timeout(Duration::from_secs(60), home.launch(&agent))
        .await
        .expect("the later run is admitted after the first has stopped")
        .expect("the later launch is admitted")
        .0;
    assert_ne!(later.id, used.session, "the later run is a new instance");
    home.wait_pending(&later.id).await;
    let manifest = ceiling(&home, &later.id);
    assert_replay_refused(
        &home,
        &agent,
        &later.id,
        &used.token,
        manifest,
        "wrong_capsule",
    )
    .await;
    own_grant_finishes(&home, &agent, &later.id, &control, &used.token).await;
    grants.abort();
}

/// The planted session sits behind the live run's manifest ceiling.
#[cfg(unix)]
fn copy_manifest_ceiling(runtime: &crate::runtime::Runtime, from: &str, to: &str) {
    let ceilings = runtime.manifest_ceilings_for_test();
    let mut bounds = ceilings.write().unwrap_or_else(|err| err.into_inner());
    if let Some(ceiling) = bounds.get(from).cloned() {
        bounds.insert(to.to_string(), ceiling);
    }
}

/// Two live sessions of one agent keep separate storage grants. The second
/// session is a resident row and did not Start. Before the refusal, the first
/// grant still validates for the first run. The refusal is the session check
/// (`wrong_capsule`). The file is unchanged. After the first run ends, a later
/// Start gets its own grant.
#[cfg(unix)]
#[tokio::test]
async fn two_runs_of_one_agent_at_once_keep_separate_storage_grants() {
    require_agents();
    let home = ProbeLaunch::new(&["a"]).await;
    let agent = home.agents[0].clone();
    let control = GrantControl::new(true);
    let grants = spawn_grants(&home, Arc::clone(&control));
    let used = launch_until_journal_is_used(&home, &agent, &control).await;
    let _notes = wait_notes_write(&home, &used.session).await;

    let second_id = "planted-storage-session";
    home.runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: second_id.to_string(),
            name: "planted".to_string(),
            status: "running".to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: second_id.to_string(),
            principal: Some(agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    home.runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: agent.clone(),
            owner: "planted-owner".into(),
            host_cid: "planted".into(),
            launch_id: "launch:planted-storage-session".into(),
            session_id: second_id.to_string(),
        })
        .await;
    copy_manifest_ceiling(&home.runtime, &used.session, second_id);
    assert_eq!(
        used.token.capsule(),
        used.session,
        "the first grant names the live session"
    );
    let sessions = home.runtime.live_sessions_for_agent(&agent).await;
    assert_eq!(
        sessions.len(),
        2,
        "the planted row is a second live session of this agent"
    );
    assert_ne!(sessions[0], sessions[1], "the two live sessions are one id");
    let manifest = ceiling(&home, second_id);
    // `wrong_capsule` is checked before revocation, so the refusal below does
    // not show that this token is still live. This read does not count a use.
    assert!(
        home.capability_manager
            .can_still_validate_for_caller(&used.token, &used.session)
            .await,
        "the first run's storage grant is still live"
    );
    assert_replay_refused(
        &home,
        &agent,
        second_id,
        &used.token,
        manifest,
        "wrong_capsule",
    )
    .await;

    control.release_notes();
    let first = home.wait_ended(&used.session).await;
    assert_eq!(first.cause.as_deref(), Some("completed"), "{first:?}");

    // The launch loads the component, and that load includes its compile.
    let second = tokio::time::timeout(Duration::from_secs(60), home.launch(&agent))
        .await
        .expect("a later run is admitted after the first has ended")
        .expect("the Runtime admits a Start after the first run has ended")
        .0;
    assert_ne!(second.id, used.session);
    home.wait_pending(&second.id).await;
    own_grant_finishes(&home, &agent, &second.id, &control, &used.token).await;
    grants.abort();
}

#[derive(Clone, Copy)]
enum InstanceEnd {
    Stop,
    Completed,
}

fn plan_record_path(dir: &std::path::Path, request_id: &str) -> std::path::PathBuf {
    dir.join("inspect-actions")
        .join(format!("{request_id}.json"))
}

/// The owner's approval is the stored move from `pending` to `approved`.
/// The approve route writes that status. This row then calls
/// `dispatch_agent_plan_step`, not the approve route and not the dispatch
/// route.
fn owner_approves_pending_plan(dir: &std::path::Path, request_id: &str) {
    let path = plan_record_path(dir, request_id);
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the plan record is on disk"))
            .expect("the plan record is json");
    assert_eq!(
        record["status"], "pending",
        "the plan is still pending when the instance has ended"
    );
    record["status"] = serde_json::json!("approved");
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
}

/// Today's rule for a plan step still pending at the end. A plan step is
/// retained for the live instance. The instance then ends, by the stop route
/// or by the guest completing, while that plan is still pending. Ending the
/// instance drops the retained admission. The owner then approves. This row
/// calls `dispatch_agent_plan_step`, which is refused `admission_missing`, and
/// the step's file is unchanged. An effect already begun is tracked, and Stop
/// says stopping until it ends. This row ends before the dispatch, so the
/// admission is already gone.
///
/// The admission is dropped for a pending plan as well as any other. A change
/// that keeps a pending plan's admission after the guest ends would let this
/// dispatch proceed, and this assert would fail.
async fn retained_plan_dispatch_after(end: InstanceEnd) {
    let home = ProbeLaunch::new(&["plan"]).await;
    let agent = home.agents[0].clone();
    let root = home.root(&agent);
    let target = format!("{root}/Documents/plan-step.md");
    let path = object_path(&home, &target);
    let plain = b"before-the-owner-approves";
    crate::auth::write_principal_root_object(&home.data_dir, &agent, &root, &target, &path, plain)
        .unwrap();
    let plan = serde_json::json!({
        "steps": [{
            "scheme": "localhost",
            "operation": "write",
            "request": {
                "path": target,
                "content": [65, 70, 84, 69, 82],
            },
        }],
    });

    let run = home
        .launch(&agent)
        .await
        .expect("the agent launch is admitted")
        .0;
    assert_eq!(run.id, run.session_id, "the instance id is its session");
    home.wait_pending(&run.id).await;
    let manifest = ceiling(&home, &run.id);
    let created = crate::api::gateway::submit_pending_agent_plan(
        &home.data_dir,
        &home.owner,
        &agent,
        &run.id,
        &run.session_id,
        &plan,
        91,
    )
    .expect("the plan step is retained as a pending record");
    let request_id = created["request_id"].as_str().expect("the plan has an id");
    assert_eq!(created["status"], "pending");
    assert_eq!(created["id"], run.id);
    let step = created["request"].clone();
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: home.registry.clone(),
        capability_manager: home.capability_manager.clone(),
        pending_store: home.pending_store.clone(),
        capsule_id: run.id.clone(),
        session_id: run.session_id.clone(),
        principal_id: Some(agent.clone()),
        manifest_capabilities: manifest,
        data_dir: Some(home.data_dir.clone()),
        launch: None,
        model_token_ceiling: None,
        model_budget: None,
        stop: None,
        plan_book: None,
    };
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        request_id,
        &home.owner,
        &ctx,
        &step,
    )
    .expect("the plan step's dispatch admission is retained");

    match end {
        InstanceEnd::Stop => {
            let (status, _) = stop_route(&home, &run.id, Some("plan still pending")).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let ended = home.wait_ended(&run.id).await;
            assert_eq!(ended.status, "stopped");
        }
        InstanceEnd::Completed => {
            let grants = super::grant_probe_requests(
                home.pending_store.clone(),
                home.capability_manager.clone(),
            );
            let ended = home.wait_ended(&run.id).await;
            grants.abort();
            assert_eq!(ended.cause.as_deref(), Some("completed"), "{ended:?}");
        }
    }

    let sealed_before = std::fs::read(&path).expect("the step's file is on disk");
    let plain_before =
        crate::auth::read_principal_root_object(&home.data_dir, &agent, &root, &target, &path)
            .expect("the step's file still opens");
    assert_eq!(plain_before, plain);
    owner_approves_pending_plan(&home.data_dir, request_id);
    let response = crate::resource_bridge::dispatch_agent_plan_step(
        request_id,
        &home.owner,
        &agent,
        &run.id,
        &run.session_id,
        &home.data_dir,
        &step,
    )
    .await;
    assert_eq!(
        response["code"], "admission_missing",
        "the dispatch is refused admission_missing: {response}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the step's file stays on disk"),
        sealed_before,
        "the file is unchanged"
    );
    assert_eq!(
        crate::auth::read_principal_root_object(&home.data_dir, &agent, &root, &target, &path)
            .expect("the step's file still opens"),
        plain_before,
        "the stored bytes are unchanged"
    );
}

/// A retained plan step does not survive the instance. After stop, and after
/// the guest completes, the owner's approval cannot dispatch it.
#[cfg(unix)]
#[tokio::test]
async fn a_retained_plan_step_is_refused_after_the_instance_ends() {
    require_agents();
    retained_plan_dispatch_after(InstanceEnd::Stop).await;
    retained_plan_dispatch_after(InstanceEnd::Completed).await;
}
