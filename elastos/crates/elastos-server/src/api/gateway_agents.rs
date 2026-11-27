//! The owner's agent routes: turn agents on or off for this Home, create,
//! list, rename, retire, turn one agent on or off, and start or stop one agent.
//! Start and Stop ask the Home Runtime to run or end the host. This route
//! does not admit the guest itself.
//!
//! Every route makes the same owner check as the System guest-registration
//! route: a Home launch token for System, on a proof binding that is stored,
//! not revoked and an admin's. Before that check each route refuses by name
//! in a build without agents, and on a Runtime that is not the Home.

use super::gateway_home_runtime::{
    stop_runtime_agent, stop_runtime_agent_for_cause, stop_runtime_agent_session,
};
use super::*;
use crate::agents::{Caller, CodedRefusal, CreateRequest, Refused};

#[derive(Serialize)]
struct CodedRefusalBody<'a> {
    code: &'a str,
    reason: &'a str,
}

use elastos_runtime::auth::RuntimeAuditEventV1;

/// The optional ids one signed agent row carries: the step-up challenge
/// that authorized a start, the agent host capsule, and the runtime
/// session, each present only when the row is about one.
struct AgentAuditIds<'a> {
    challenge_id: Option<&'a str>,
    capsule_id: Option<&'a str>,
    session_id: Option<&'a str>,
}

/// Test seam: the occurrence numbers of signed agent appends that fail for
/// one data dir, so a test can reach a Start whose later row cannot be
/// recorded.
#[cfg(test)]
static AGENT_AUDIT_APPEND_COUNTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, usize>>,
> = std::sync::LazyLock::new(Default::default);

#[cfg(test)]
pub(in crate::api) static AGENT_AUDIT_APPEND_FAILURES: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<std::path::PathBuf, std::collections::BTreeSet<usize>>,
    >,
> = std::sync::LazyLock::new(Default::default);

/// The next signed agent append for this Home fails.
#[cfg(all(test, unix))]
pub(in crate::api) fn fail_next_agent_audit(data_dir: &std::path::Path) {
    let counts = AGENT_AUDIT_APPEND_COUNTS
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let next = counts.get(data_dir).copied().unwrap_or(0) + 1;
    drop(counts);
    AGENT_AUDIT_APPEND_FAILURES
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .entry(data_dir.to_path_buf())
        .or_default()
        .insert(next);
}

/// Test seam: a Start returns after the Runtime has accepted the launch and
/// before the completion row, so the chain keeps only `agent.start.requested`.
#[cfg(test)]
pub(in crate::api) static AGENT_AUDIT_CRASH_AFTER_LAUNCH: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::LazyLock::new(Default::default);

/// Appends one signed audit row for an owner action on an agent, in the row
/// shape the passkey step-up completion writes: the owner is the principal,
/// and the agent's identity rides in the reason JSON because the signed
/// audit event carries no agent column.
fn append_agent_lifecycle_audit(
    data_dir: &std::path::Path,
    event_type: &str,
    owner: &AgentsOwner,
    ids: AgentAuditIds,
    result: &str,
    reason: serde_json::Value,
) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let mut counts = AGENT_AUDIT_APPEND_COUNTS.lock().unwrap();
        let count = counts.entry(data_dir.to_path_buf()).or_default();
        *count += 1;
        let failing = AGENT_AUDIT_APPEND_FAILURES
            .lock()
            .unwrap()
            .get(data_dir)
            .is_some_and(|failures| failures.contains(&*count));
        if failing {
            anyhow::bail!("injected signed agent audit append failure");
        }
    }
    crate::agent_record_audit::append_agent_row(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:{}", gateway_home_token::uuid_like_token()),
            event_type: event_type.to_string(),
            principal_id: Some(owner.principal.principal_id.clone()),
            proof_binding_id: Some(owner.principal.proof_binding_id.clone()),
            session_id: ids.session_id.map(str::to_string),
            challenge_id: ids.challenge_id.map(str::to_string),
            capsule_id: ids.capsule_id.map(str::to_string),
            result: result.to_string(),
            reason: serde_json::to_string(&reason)?,
            occurred_at: now_ts(),
            signer_did: None,
            signature: None,
        },
    )
}

/// Host package name on `agent.stopped`. The agent id is the fallback.
fn stopped_capsule_id(data_dir: &std::path::Path, agent_id: &str) -> String {
    crate::agents::agent_record(data_dir, agent_id)
        .ok()
        .and_then(|agent| agent.record.agent_host_package)
        .map(|package| package.name)
        .unwrap_or_else(|| agent_id.to_string())
}

/// One `agent.stopped` row. The path stays in the log.
fn sign_stopped(
    data_dir: &std::path::Path,
    owner: &AgentsOwner,
    agent_id: &str,
    session_id: Option<&str>,
    result: &str,
    reason: serde_json::Value,
) -> anyhow::Result<()> {
    let capsule = stopped_capsule_id(data_dir, agent_id);
    append_agent_lifecycle_audit(
        data_dir,
        "agent.stopped",
        owner,
        AgentAuditIds {
            challenge_id: None,
            capsule_id: Some(capsule.as_str()),
            session_id,
        },
        result,
        reason,
    )
    .map_err(|error| {
        tracing::warn!(
            "agent '{agent_id}' stopped; the signed stop row was not recorded: {error:#}"
        );
        anyhow::anyhow!("agent '{agent_id}' stopped; the signed stop row was not recorded")
    })
}

fn recorded_plan_close(result: anyhow::Result<usize>) -> anyhow::Result<()> {
    result.map(|_| ()).map_err(|error| {
        tracing::warn!("the signed plan close was not recorded: {error:#}");
        anyhow::anyhow!("the signed plan close was not recorded")
    })
}

type HomeLock = std::sync::Arc<tokio::sync::Mutex<()>>;
type HomeLockMap = std::collections::HashMap<(std::path::PathBuf, &'static str), HomeLock>;

fn home_async_lock(data_dir: &std::path::Path, kind: &'static str) -> HomeLock {
    static LOCKS: std::sync::LazyLock<std::sync::Mutex<HomeLockMap>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(HomeLockMap::new()));
    let mut map = LOCKS.lock().unwrap_or_else(|err| err.into_inner());
    map.entry((data_dir.to_path_buf(), kind))
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// A `stopping` row is confirmed once the owner and the build have already
/// been checked. `ok` is written when the live plane and the retiring plane
/// both say the session ended and no plan effect is in flight, or when this
/// process has neither plane, which is a Home that restarted. A session that
/// is still running on either plane stays `stopping`. The retry of failed
/// stops runs under the same lock, so two list loads cannot both stop.
pub(in crate::api) async fn confirm_stopping_rows(
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let lock = home_async_lock(data_dir, "confirm");
    let _held = lock.lock().await;
    crate::api::agent_plane::release_idle_retiring(data_dir).await;
    let open = crate::agent_record_audit::open_stopping_sessions(data_dir)?;
    let watched = crate::api::agent_plane::watched_runtimes(data_dir);
    let mut ended = std::collections::HashSet::new();
    for session in open {
        if crate::api::agent_plane::stopping_session_has_ended(data_dir, &session).await {
            ended.insert(session);
        }
    }
    crate::agent_record_audit::confirm_stopping_rows(data_dir, |session| {
        ended.contains(session)
            && watched
                .iter()
                .all(|runtime| !runtime.plan_effect_inflight(session))
    })?;
    retry_failed_stops(data_dir).await;
    Ok(())
}

/// A demotion or revocation whose stop failed is tried again at the next start.
/// A later `ok` or `stopping` row, or a later started run, means that agent is
/// no longer owed a retry. An admin-lost stop runs only while the owner is
/// still not an admin.
async fn retry_failed_stops(data_dir: &std::path::Path) {
    for stop in crate::agent_record_audit::latest_failed_agent_stops(data_dir) {
        let admin_lost = matches!(
            stop.reason["cause"].as_str(),
            Some("owner demoted" | "passkey revoked")
        );
        if admin_lost
            && !crate::agents::owner_of(data_dir, &stop.agent_id).is_none_or(|owner| {
                matches!(
                    crate::agents::owner_is_admin_now(data_dir, &owner),
                    Ok(false)
                )
            })
        {
            continue;
        }
        let agent_id = stop.agent_id;
        let reason = stop.reason;
        let principal_id = stop.principal.principal_id.clone();
        let Ok(root) =
            crate::auth::ResolvedPrincipalRoot::resolve(data_dir, data_dir, &principal_id)
        else {
            continue;
        };
        let context = super::gateway_home_token::agent_stop_signer_context(
            root,
            &principal_id,
            Some(stop.principal.proof_binding_id.clone()),
            "retry",
        );
        let owner = AgentsOwner {
            context,
            principal: stop.principal,
        };
        let cause = reason["cause"].as_str().unwrap_or("retry").to_string();
        let data = data_dir.to_path_buf();
        let agent_for_stop = agent_id.clone();
        if let Err(error) = finish_live_stop(
            data_dir,
            &StopRequest {
                actor: Some(&owner),
                agent_id: Some(&agent_id),
                session_id: None,
                cause: &cause,
                reason: Some(&reason),
                sign_failed: false,
                idle_ok: true,
            },
            || Ok(()),
            || {
                let data = data.clone();
                let agent_for_stop = agent_for_stop.clone();
                async move {
                    stop_runtime_agent(&data, &agent_for_stop)
                        .await
                        .map(|outcome| (live_end(&agent_for_stop, outcome), None))
                }
            },
        )
        .await
        {
            tracing::warn!("retry of agent '{agent_id}' did not stop: {error:#}");
        }
    }
}

fn record_caller_denial(
    state: &GatewayState,
    headers: &HeaderMap,
    event_type: &str,
    agent_id: Option<&str>,
) {
    if !crate::agents::build_allows() {
        return;
    }
    let Ok(context) =
        require_home_launch_token_context(&state.data_dir, headers, SYSTEM_CAPSULE_ID)
    else {
        return;
    };
    let Some(proof_binding_id) = context.proof_binding_id() else {
        return;
    };
    let Ok(principal) =
        crate::auth::load_principal_for_proof_binding(&state.data_dir, proof_binding_id)
    else {
        return;
    };
    let owner = AgentsOwner { context, principal };
    let _ = append_agent_lifecycle_audit(
        &state.data_dir,
        event_type,
        &owner,
        AgentAuditIds {
            challenge_id: None,
            capsule_id: agent_id,
            session_id: None,
        },
        "denied",
        serde_json::json!({
            "agent_id": agent_id.unwrap_or(""),
            "cause": "not the owner",
        }),
    );
}

/// The sha256 that names the host package's bytes: the root digest of the
/// bundle CID the admission walk produced, read back through the one CID
/// form the lab defines.
fn host_package_sha256(host: &crate::agent_admission::VerifiedAgentHost) -> anyhow::Result<String> {
    let digest = elastos_common::cid_form(&host.package().bundle_cid)
        .ok_or_else(|| anyhow::anyhow!("agent host package has no sha256 digest"))?;
    Ok(hex::encode(digest))
}

/// The reason JSON of a signed Start row: the agent, the owner launch that
/// authorized it, and the sha256 that names the host package's bytes. A
/// failed launch adds the runtime's refusal.
fn agent_start_reason(
    agent_id: &str,
    launch: &RequiredHomeLaunchToken,
    host: &crate::agent_admission::VerifiedAgentHost,
    host_sha256: &str,
    error: Option<&str>,
) -> serde_json::Value {
    let mut reason = serde_json::json!({
        "agent_id": agent_id,
        "launch_id": launch.launch_id,
        "host_package": host.package().name,
        "host_package_sha256": host_sha256,
    });
    if let Some(error) = error {
        reason["error"] = serde_json::Value::String(error.to_string());
    }
    reason
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireRequest {
    agent_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameRequest {
    agent_id: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRequest {
    agent_id: String,
    active: bool,
}

/// The checked caller: their token context and their stored admin record.
#[derive(Clone)]
struct AgentsOwner {
    context: HomeLaunchTokenContext,
    principal: crate::auth::PrincipalRecord,
}

impl AgentsOwner {
    fn caller(&self) -> Caller<'_> {
        Caller {
            principal_id: &self.principal.principal_id,
            proof_binding_id: &self.principal.proof_binding_id,
            session_id: self.context.session_id(),
        }
    }
}

fn agents_owner(state: &GatewayState, headers: &HeaderMap) -> anyhow::Result<AgentsOwner> {
    crate::agents::require_build()?;
    let sign_in_store = home_launch_auth_data_dir(&state.data_dir);
    crate::agent_admission::require_home_runtime(&state.data_dir, &sign_in_store)?;
    let context = require_home_launch_token_context(&state.data_dir, headers, SYSTEM_CAPSULE_ID)?;
    let Some(proof_binding_id) = context.proof_binding_id() else {
        anyhow::bail!("admin passkey required");
    };
    let principal =
        crate::auth::load_principal_for_proof_binding(&state.data_dir, proof_binding_id)?;
    crate::auth::ensure_proof_binding_not_revoked(&principal)?;
    if !crate::auth::is_admin(&principal) {
        anyhow::bail!("admin passkey required");
    }
    Ok(AgentsOwner { context, principal })
}

/// A coded refusal answers 409 as JSON with `code` and `reason`. A named
/// refusal, including a file the loader refuses, answers 409 as plain text.
/// Anything else answers as the System routes do, so a caller who fails the
/// owner check gets 403.
fn agents_response<T: Serialize>(result: anyhow::Result<T>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            // A coded refusal is JSON the Home page matches by `code`.
            // A named refusal, including a file the loader refuses, stays
            // plain text at 409.
            if let Some(coded) = error.downcast_ref::<CodedRefusal>() {
                return (
                    StatusCode::CONFLICT,
                    Json(CodedRefusalBody {
                        code: coded.code,
                        reason: coded.reason,
                    }),
                )
                    .into_response();
            }
            match crate::agents::refusal_text(&error) {
                Some(text) => (StatusCode::CONFLICT, text).into_response(),
                None => system_error_response(error),
            }
        }
    }
}

/// Reads a request body after the caller is checked, so a caller who may not
/// ask learns nothing from how a body is read.
fn agents_request<T: serde::de::DeserializeOwned>(body: &Bytes) -> anyhow::Result<T> {
    serde_json::from_slice(body)
        .map_err(|error| Refused(format!("agent request is invalid: {error}")).into())
}

fn agents_set_enabled(
    state: &GatewayState,
    headers: &HeaderMap,
    enabled: bool,
) -> anyhow::Result<serde_json::Value> {
    let owner = agents_owner(state, headers)?;
    let enabled = crate::agents::set_enabled(&state.data_dir, &owner.caller(), enabled, now_ts())?;
    Ok(serde_json::json!({ "enabled": enabled }))
}

pub(super) async fn agents_enable(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let owner = match agents_owner(&state, &headers) {
        Ok(owner) => owner,
        Err(error) => {
            return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
        }
    };
    // The retiring plane is checked, and the plane is running, before the
    // enabled flag or its ok row is written. A refused start leaves both.
    if let Err(error) = crate::api::agent_plane::bring_up_for_enable(
        &state.data_dir,
        state.provider_registry.clone(),
    )
    .await
    {
        return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
    }
    let enabled = (|| -> anyhow::Result<serde_json::Value> {
        let enabled = crate::agents::set_enabled(&state.data_dir, &owner.caller(), true, now_ts())?;
        Ok(serde_json::json!({ "enabled": enabled }))
    })();
    agents_response(enabled)
}

async fn owe_live_stops(
    data_dir: &std::path::Path,
    owner: &AgentsOwner,
    agent_id: Option<&str>,
    session_id: Option<&str>,
    cause: &str,
) -> anyhow::Result<()> {
    let mut rows = Vec::new();
    let mut covered = false;
    for runtime in crate::api::agent_plane::watched_runtimes(data_dir) {
        for info in runtime.list_capsules().await {
            let Some(agent) = info.principal.as_deref().filter(|id| !id.is_empty()) else {
                continue;
            };
            if info.ended_at.is_some() && !runtime.plan_effect_inflight(&info.id)
                || agent_id.is_some_and(|wanted| wanted != agent)
                || session_id.is_some_and(|wanted| wanted != info.id)
            {
                continue;
            }
            if session_id.is_some() {
                covered = true;
            }
            let session = info.id.clone();
            rows.push(owed_stop_row(data_dir, owner, agent, &session, cause));
        }
    }
    // A Start names the session it just made. That guest can live on the
    // agent Runtime without a row in this process's capsule list yet.
    if !covered {
        if let (Some(agent), Some(session)) = (agent_id, session_id) {
            rows.push(owed_stop_row(data_dir, owner, agent, session, cause));
        }
    }
    crate::agents::note_stop_rows(data_dir, &rows)
}

fn owed_stop_row(
    data_dir: &std::path::Path,
    owner: &AgentsOwner,
    agent: &str,
    session: &str,
    cause: &str,
) -> RuntimeAuditEventV1 {
    RuntimeAuditEventV1 {
        schema: RuntimeAuditEventV1::SCHEMA.to_string(),
        event_id: format!("audit:{}", gateway_home_token::uuid_like_token()),
        event_type: "agent.stopped".to_string(),
        principal_id: Some(owner.principal.principal_id.clone()),
        proof_binding_id: Some(owner.principal.proof_binding_id.clone()),
        session_id: Some(session.to_string()),
        challenge_id: None,
        capsule_id: Some(stopped_capsule_id(data_dir, agent)),
        result: "stopping".to_string(),
        reason: serde_json::json!({ "agent_id": agent, "cause": cause }).to_string(),
        occurred_at: now_ts(),
        signer_did: None,
        signature: None,
    }
}

/// The failed signature has no session, so it does not clear the session debt
/// recorded before the stop. Drop that debt once the failed row is signed.
/// The failed row stays owed. A crash before that signature leaves the debt.
fn release_signed_stop(
    data_dir: &std::path::Path,
    agent_id: &str,
    cause: &str,
) -> anyhow::Result<()> {
    let rows: Vec<_> = crate::agents::owed_stop_rows(data_dir)
        .into_iter()
        .filter(|row| {
            row.result == "stopping"
                && row.session_id.is_some()
                && row.reason.contains(agent_id)
                && row.reason.contains(cause)
        })
        .map(|mut row| {
            row.result = "ok".to_string();
            row.reason = "{}".to_string();
            row
        })
        .collect();
    crate::agents::note_stop_rows(data_dir, &rows)
}

/// The stop found no session. Sign each session this attempt owed, once.
/// A session-none `ok` does not clear those rows, and the next confirm would
/// append a second one. When nothing was owed, the session-none row clears
/// the failed debt.
fn settle_idle_stop(data_dir: &std::path::Path, request: &StopRequest<'_>) {
    let Some(agent_id) = request.agent_id else {
        return;
    };
    let sessions: Vec<String> = crate::agents::owed_stop_rows(data_dir)
        .into_iter()
        .filter(|row| {
            row.result == "stopping"
                && row.reason.contains(agent_id)
                && row.reason.contains(request.cause)
        })
        .filter_map(|row| row.session_id)
        .collect();
    if sessions.is_empty() {
        let _ = sign_one(data_dir, request, agent_id, None, "ok");
        return;
    }
    for session in &sessions {
        let _ = sign_one(data_dir, request, agent_id, Some(session), "ok");
    }
}

struct EndedRun {
    agent_id: String,
    session_id: String,
    result: &'static str,
}

struct LiveEnd {
    runs: Vec<EndedRun>,
    outcome: super::gateway_home_runtime::RuntimeAgentStop,
}

struct StopRequest<'a> {
    actor: Option<&'a AgentsOwner>,
    agent_id: Option<&'a str>,
    session_id: Option<&'a str>,
    cause: &'a str,
    reason: Option<&'a serde_json::Value>,
    sign_failed: bool,
    idle_ok: bool,
}

fn empty_end() -> LiveEnd {
    LiveEnd {
        runs: Vec::new(),
        outcome: super::gateway_home_runtime::RuntimeAgentStop::default(),
    }
}

fn live_end(agent_id: &str, outcome: super::gateway_home_runtime::RuntimeAgentStop) -> LiveEnd {
    let mut runs = Vec::new();
    for session in &outcome.stopped {
        let result = if session_ended(&session.status, session.ended) {
            "ok"
        } else {
            "stopping"
        };
        runs.push(EndedRun {
            agent_id: agent_id.to_string(),
            session_id: session.session_id.clone(),
            result,
        });
    }
    for session in &outcome.stopping {
        runs.push(EndedRun {
            agent_id: agent_id.to_string(),
            session_id: session.session_id.clone(),
            result: "stopping",
        });
    }
    LiveEnd { runs, outcome }
}

fn live_end_of_guests(guests: Vec<crate::api::agent_plane::EndedGuest>) -> LiveEnd {
    let mut outcome = super::gateway_home_runtime::RuntimeAgentStop::default();
    let mut runs = Vec::new();
    for guest in guests {
        if guest.agent_id.is_empty() || guest.session_id.is_empty() {
            continue;
        }
        let result = if session_ended(&guest.status, guest.ended) && !guest.effect_inflight {
            "ok"
        } else {
            "stopping"
        };
        let row = super::gateway_home_runtime::StoppedRuntimeAgent {
            session_id: guest.session_id.clone(),
            status: guest.status,
            ended: guest.ended,
        };
        if result == "ok" {
            outcome.stopped.push(row);
        } else {
            outcome.stopping.push(row);
        }
        runs.push(EndedRun {
            agent_id: guest.agent_id,
            session_id: guest.session_id,
            result,
        });
    }
    LiveEnd { runs, outcome }
}

fn plain_end(end: LiveEnd) -> anyhow::Result<(LiveEnd, Option<anyhow::Error>)> {
    Ok((end, None))
}

fn owner_signer(
    data_dir: &std::path::Path,
    agent_id: &str,
    kind: &str,
) -> anyhow::Result<AgentsOwner> {
    let owner_id = crate::agents::owner_of(data_dir, agent_id)
        .ok_or_else(|| anyhow::anyhow!("agent '{agent_id}' has no owner"))?;
    let principal = crate::auth::load_owner_principals(data_dir)?
        .into_iter()
        .find(|principal| principal.principal_id == owner_id)
        .ok_or_else(|| anyhow::anyhow!("agent '{agent_id}' owner is not stored"))?;
    let root = crate::auth::ResolvedPrincipalRoot::resolve(data_dir, data_dir, &owner_id)?;
    let context = super::gateway_home_token::agent_stop_signer_context(
        root,
        &owner_id,
        Some(principal.proof_binding_id.clone()),
        kind,
    );
    Ok(AgentsOwner { context, principal })
}

fn signer_for(
    data_dir: &std::path::Path,
    request: &StopRequest<'_>,
    agent_id: &str,
) -> anyhow::Result<AgentsOwner> {
    if let Some(actor) = request.actor {
        return Ok(actor.clone());
    }
    owner_signer(data_dir, agent_id, request.cause)
}

fn stop_reason(request: &StopRequest<'_>, agent_id: &str) -> serde_json::Value {
    request
        .reason
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "agent_id": agent_id, "cause": request.cause }))
}

fn sign_one(
    data_dir: &std::path::Path,
    request: &StopRequest<'_>,
    agent_id: &str,
    session_id: Option<&str>,
    result: &str,
) -> anyhow::Result<()> {
    let signer = signer_for(data_dir, request, agent_id)?;
    sign_stopped(
        data_dir,
        &signer,
        agent_id,
        session_id,
        result,
        stop_reason(request, agent_id),
    )
}

async fn owe_for_stop(data_dir: &std::path::Path, request: &StopRequest<'_>) -> anyhow::Result<()> {
    if let Some(actor) = request.actor {
        return owe_live_stops(
            data_dir,
            actor,
            request.agent_id,
            request.session_id,
            request.cause,
        )
        .await;
    }
    let mut agents = Vec::new();
    for runtime in crate::api::agent_plane::watched_runtimes(data_dir) {
        for info in runtime.list_capsules().await {
            if info.ended_at.is_some() {
                continue;
            }
            let Some(agent) = info.principal.filter(|id| !id.is_empty()) else {
                continue;
            };
            if request.agent_id.is_some_and(|wanted| wanted != agent)
                || request.session_id.is_some_and(|wanted| wanted != info.id)
            {
                continue;
            }
            agents.push(agent);
        }
    }
    agents.sort();
    agents.dedup();
    for agent in agents {
        let signer = owner_signer(data_dir, &agent, request.cause)?;
        owe_live_stops(
            data_dir,
            &signer,
            Some(&agent),
            request.session_id,
            request.cause,
        )
        .await?;
    }
    Ok(())
}

/// Every live-session end: owe the stop, stop the session, sign
/// `agent.stopped`, then clear the owed record. A failure between those
/// steps leaves the owed record. Restart signs that record once.
async fn finish_live_stop<B, F, Fut>(
    data_dir: &std::path::Path,
    request: &StopRequest<'_>,
    before_stop: B,
    stop: F,
) -> anyhow::Result<LiveEnd>
where
    B: FnOnce() -> anyhow::Result<()>,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(LiveEnd, Option<anyhow::Error>)>>,
{
    let lock = home_async_lock(data_dir, "finish");
    let _held = lock.lock().await;
    owe_for_stop(data_dir, request).await?;
    before_stop()?;
    let (report, plan_close) = match stop().await {
        Ok(pair) => pair,
        Err(error) if stop_is_a_refusal(&error) => {
            if request.idle_ok {
                settle_idle_stop(data_dir, request);
                return Ok(empty_end());
            }
            return Err(error);
        }
        Err(error) => {
            if request.sign_failed {
                if let Some(agent_id) = request.agent_id {
                    match sign_one(data_dir, request, agent_id, None, "failed") {
                        Ok(()) => release_signed_stop(data_dir, agent_id, request.cause)?,
                        Err(sign_error) => return Err(sign_error),
                    }
                }
            }
            return Err(error);
        }
    };
    #[cfg(test)]
    if crate::api::gateway::seams::take_grant_kind(data_dir, "after-stop")
        || crate::api::gateway::seams::take_grant_kind(data_dir, "after-off-stop")
    {
        anyhow::bail!("crash after the stop");
    }
    let mut report = report;
    report
        .runs
        .sort_by(|left, right| left.session_id.cmp(&right.session_id));
    if request.idle_ok && report.runs.is_empty() {
        settle_idle_stop(data_dir, request);
    } else {
        let mut recorded = Vec::new();
        let mut unrecorded = Vec::new();
        for run in &report.runs {
            if crate::agent_record_audit::signed_stop_kept(data_dir, &run.session_id)? {
                recorded.push(run.session_id.clone());
                continue;
            }
            match sign_one(
                data_dir,
                request,
                &run.agent_id,
                Some(&run.session_id),
                run.result,
            ) {
                Ok(()) => recorded.push(run.session_id.clone()),
                Err(_) => unrecorded.push(run.session_id.clone()),
            }
        }
        if !unrecorded.is_empty() {
            let name = request.agent_id.unwrap_or("agent");
            anyhow::bail!(
                "agent '{name}' stopped session(s) {}; the signed stop row was not recorded for session(s) {}",
                recorded.join(", "),
                unrecorded.join(", ")
            );
        }
    }
    if let Some(error) = plan_close {
        recorded_plan_close(Err::<usize, _>(error))?;
    }
    Ok(report)
}

/// The listener task panicked. Owe each live session, end it, and sign the
/// stop. A later Stop sees the same sessions and does not sign them again.
pub(in crate::api) async fn finish_task_ended(data_dir: &std::path::Path) {
    let data = data_dir.to_path_buf();
    if let Err(error) = finish_live_stop(
        data_dir,
        &StopRequest {
            actor: None,
            agent_id: None,
            session_id: None,
            cause: crate::api::agent_plane::TASK_ENDED,
            reason: None,
            sign_failed: false,
            idle_ok: false,
        },
        || Ok(()),
        || {
            let data = data.clone();
            async move {
                let guests =
                    crate::api::agent_plane::end_plane_guests_after_task_panic(&data).await;
                plain_end(live_end_of_guests(guests))
            }
        },
    )
    .await
    {
        tracing::warn!("task-ended stop did not finish: {error:#}");
    }
}

/// The gateway process is leaving. The same owe, stop, and sign rule applies.
/// A sign error is logged so the process still exits.
pub(super) async fn finish_gateway_stop(data_dir: &std::path::Path) {
    let data = data_dir.to_path_buf();
    if let Err(error) = finish_live_stop(
        data_dir,
        &StopRequest {
            actor: None,
            agent_id: None,
            session_id: None,
            cause: "gateway stopped",
            reason: None,
            sign_failed: false,
            idle_ok: false,
        },
        || Ok(()),
        || {
            let data = data.clone();
            async move {
                let (guests, closed) = crate::api::agent_plane::stop_running(&data).await;
                Ok((live_end_of_guests(guests), closed.err()))
            }
        },
    )
    .await
    {
        tracing::warn!("gateway stop did not finish: {error:#}");
    }
}

pub(super) async fn agents_disable(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let disabled = agents_set_enabled(&state, &headers, false);
    if disabled.is_ok() {
        let owner = agents_owner(&state, &headers).ok();
        let data = state.data_dir.clone();
        let ended = finish_live_stop(
            &state.data_dir,
            &StopRequest {
                actor: owner.as_ref(),
                agent_id: None,
                session_id: None,
                cause: "agents off",
                reason: None,
                sign_failed: true,
                idle_ok: false,
            },
            || Ok(()),
            || {
                let data = data.clone();
                async move {
                    let (guests, closed) = crate::api::agent_plane::stop_running(&data).await;
                    let plan = closed.err();
                    Ok((live_end_of_guests(guests), plan))
                }
            },
        )
        .await;
        let ended = match ended {
            Ok(ended) => ended,
            Err(error) => {
                crate::resource_bridge::notify_plan_waiters();
                return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
            }
        };
        if ended.runs.is_empty() {
            if let Err(error) = confirm_stopping_rows(&state.data_dir).await {
                crate::resource_bridge::notify_plan_waiters();
                return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
            }
        }
        if let Err(error) = recorded_plan_close(crate::api::gateway::close_home_plans(
            &state.data_dir,
            "agents off",
        )) {
            crate::resource_bridge::notify_plan_waiters();
            return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
        }
        crate::resource_bridge::notify_plan_waiters();
    }
    agents_response(disabled)
}

pub(super) async fn agents_create(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    agents_response(agents_owner(&state, &headers).and_then(|owner| {
        let request: CreateRequest = agents_request(&body)?;
        let admit = |agent_host: &str| {
            crate::agent_admission::verify_agent_host(&state.data_dir, agent_host)
        };
        crate::agents::create(&state.data_dir, &owner.caller(), &request, admit, now_ts())
    }))
}

pub(super) async fn agents_list(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    let owner = match agents_owner(&state, &headers) {
        Ok(owner) => owner,
        Err(error) => {
            return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
        }
    };
    let _ = confirm_stopping_rows(&state.data_dir).await;
    agents_response(
        crate::agents::list(&state.data_dir, &owner.caller())
            .map(|agents| serde_json::json!({ "agents": agents })),
    )
}

pub(super) async fn agents_retire(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        let owner = agents_owner(&state, &headers)?;
        let request: RetireRequest = agents_request(&body)?;
        // The other record routes answer "not turned on" before they look up
        // an id. Retire keeps that answer, and it does not stop a guest on
        // the way to it. Ownership is the next check, so another admin's
        // retire does not end this guest. The stop that follows is the same
        // stop Stop uses, so the guest ends and its asks settle once. The
        // record write then owns the tombstone and signs it once.
        //
        // Lock order, shared with Stop and with one live run: the runtime
        // takes `agent_launches`, then `stop_marks`, and admits or clears
        // `live_runs` only while `agent_launches` is already held. None of
        // those three is held across the record write. `agents.rs` `write`
        // then holds its own agent lock across the tombstone and its one
        // signed row. This route does not take that lock and does not append
        // a second row.
        //
        // The record write stores the tombstone and then appends
        // `agent.record.retire` (`agents.rs` `write`). A failed append leaves
        // the agent retired. The next open under the agent lock finds that
        // sequence without its audit event and appends the retire row once.
        // This route still answers "agent is already retired" on that call.
        crate::agents::list(&state.data_dir, &owner.caller())?;
        crate::agents::stored_agent_for_stop(
            &state.data_dir,
            &owner.principal.principal_id,
            &request.agent_id,
        )?;
        let ended = end_live_agent(&state.data_dir, &request.agent_id).await?;
        if ended.iter().any(|(_, result)| *result == "stopping") {
            return Err(Refused("this agent is still stopping; wait".to_string()).into());
        }
        recorded_plan_close(crate::api::gateway::close_agent_plans(
            &state.data_dir,
            &request.agent_id,
            "instance ended",
        ))?;
        crate::resource_bridge::notify_plan_waiters();
        crate::agents::retire(
            &state.data_dir,
            &owner.caller(),
            &request.agent_id,
            now_ts(),
        )
    }
    .await;
    agents_response(result)
}

/// Stop one live agent before its record is retired. The retire route checks
/// that the caller owns the agent before this stop. A Home with no agent
/// Runtime retires the record as before. A stop the Runtime refuses because
/// the agent is already stopped still retires the record.
pub(super) async fn end_live_agent(
    data_dir: &std::path::Path,
    agent_id: &str,
) -> anyhow::Result<Vec<(String, &'static str)>> {
    let owner = owner_signer(data_dir, agent_id, "retire")?;
    let data = data_dir.to_path_buf();
    let agent = agent_id.to_string();
    let report = finish_live_stop(
        data_dir,
        &StopRequest {
            actor: Some(&owner),
            agent_id: Some(agent_id),
            session_id: None,
            cause: "retire",
            reason: None,
            sign_failed: false,
            idle_ok: false,
        },
        || Ok(()),
        || {
            let data = data.clone();
            let agent = agent.clone();
            async move {
                match stop_runtime_agent(&data, &agent).await {
                    Ok(outcome) => plain_end(live_end(&agent, outcome)),
                    Err(error) if stop_is_a_refusal(&error) => plain_end(empty_end()),
                    Err(error) => Err(error),
                }
            }
        },
    )
    .await?;
    Ok(report
        .runs
        .into_iter()
        .map(|run| (run.session_id, run.result))
        .collect())
}

fn stop_found_no_live_guest(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CodedRefusal>().is_some_and(|coded| {
        coded.code == "agent_no_session" || coded.code == "agent_already_stopped"
    })
}

/// A stop that found nothing to end. That is a refusal, not a failed stop,
/// so the signed chain does not gain an `agent.stopped` result `failed`.
fn stop_is_a_refusal(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text == crate::api::agent_plane::TASK_ENDED
        || text == "agent runtime is not running"
        || stop_found_no_live_guest(error)
}

pub(super) async fn agents_rename(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    agents_response(agents_owner(&state, &headers).and_then(|owner| {
        let request: RenameRequest = agents_request(&body)?;
        crate::agents::rename(
            &state.data_dir,
            &owner.caller(),
            &request.agent_id,
            &request.display_name,
            now_ts(),
        )
    }))
}

pub(super) async fn agents_activate(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        let owner = agents_owner(&state, &headers)?;
        let request: ActiveRequest = agents_request(&body)?;
        let active = crate::agents::set_active(
            &state.data_dir,
            &owner.caller(),
            &request.agent_id,
            request.active,
            now_ts(),
        )?;
        if !request.active {
            // Turning this agent off ends its run. The owed stop is recorded
            // before the grant revoke, which can end the guest before Stop.
            let data = state.data_dir.clone();
            let agent = request.agent_id.clone();
            finish_live_stop(
                &state.data_dir,
                &StopRequest {
                    actor: Some(&owner),
                    agent_id: Some(&request.agent_id),
                    session_id: None,
                    cause: "agent off",
                    reason: None,
                    sign_failed: true,
                    idle_ok: false,
                },
                || Ok(()),
                || {
                    let data = data.clone();
                    let agent = agent.clone();
                    async move {
                        let prior = match crate::api::agent_plane::plane_runtime(&data) {
                            Some(runtime) => runtime.live_sessions_for_agent(&agent).await,
                            None => Vec::new(),
                        };
                        crate::api::agent_plane::revoke_agent_grants(&data, &agent).await;
                        let outcome = match stop_runtime_agent(&data, &agent).await {
                            Ok(outcome) => outcome,
                            Err(error) if stop_is_a_refusal(&error) => Default::default(),
                            Err(error) => {
                                tracing::warn!("agent off stop failed: {error:#}");
                                return Err(error);
                            }
                        };
                        if !outcome.stopped.is_empty() || !outcome.stopping.is_empty() {
                            return plain_end(live_end(&agent, outcome));
                        }
                        let Some(runtime) = crate::api::agent_plane::plane_runtime(&data) else {
                            return plain_end(empty_end());
                        };
                        let mut built = super::gateway_home_runtime::RuntimeAgentStop::default();
                        for session_id in prior {
                            let info = runtime.get_capsule(&session_id).await;
                            let ended = info.as_ref().is_none_or(|info| info.ended_at.is_some());
                            let inflight = runtime.plan_effect_inflight(&session_id);
                            let status = info
                                .map(|info| info.status)
                                .unwrap_or_else(|| "stopped".to_string());
                            let row = super::gateway_home_runtime::StoppedRuntimeAgent {
                                session_id,
                                status,
                                ended,
                            };
                            if ended && !inflight {
                                built.stopped.push(row);
                            } else {
                                built.stopping.push(row);
                            }
                        }
                        plain_end(live_end(&agent, built))
                    }
                },
            )
            .await?;
            recorded_plan_close(crate::api::gateway::close_agent_plans(
                &state.data_dir,
                &request.agent_id,
                "agent off",
            ))?;
            crate::resource_bridge::notify_plan_waiters();
        }
        Ok(active)
    }
    .await;
    agents_response(result)
}

/// The passkey step-up operation for one Start. The ceremony and the route
/// both name it, so a token minted for another action cannot start an agent.
const AGENT_START_OPERATION: &str = "agent.start";
/// How recently the passkey step must have finished. The token itself can
/// live 180 seconds, and wallet and other callers still allow that. Begin
/// and complete run immediately before Start, and this route has no caller
/// that needs the extra minute, so a Start older than two minutes is refused.
const AGENT_START_STEP_UP_MAX_AGE_SECS: u64 = 120;
/// The short named cause the settle path stores when the stop of an
/// unrecorded start's session failed: the failed row and the refusal carry
/// this cause, and the stop's own detail, which can name host paths, stays
/// in the log.
const SETTLE_STOP_FAILURE_CAUSE: &str =
    "the runtime did not stop the session of the unrecorded start";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentLaunchRequest {
    agent_id: String,
    step_up_token: String,
}

#[derive(Serialize)]
struct AgentLaunchResponse {
    agent_id: String,
    capsule_id: String,
    session_id: String,
    status: String,
}

pub(super) async fn agents_launch(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    agents_response(start_agent(&state, &headers, &body).await)
}

/// Owner check, then consume the one-use step-up for this agent, then mint
/// the short grant, then ask the Runtime to start the host. A missing,
/// replayed, expired, other-agent, or other-owner step-up returns before the
/// grant is minted and starts no guest.
async fn start_agent(
    state: &GatewayState,
    headers: &HeaderMap,
    body: &Bytes,
) -> anyhow::Result<AgentLaunchResponse> {
    let owner = agents_owner(state, headers)?;
    let request: AgentLaunchRequest = agents_request(body)?;
    let launch = require_home_launch_token_binding(&state.data_dir, headers, &[SYSTEM_CAPSULE_ID])?;
    // The stopping mark is in the Runtime. This route spends the step-up, then
    // the Runtime reads the mark. A read here would be a second call, and a
    // Stop between that call and the launch would still spend the token on
    // the refusal. Spending after a launch that has started the guest would
    // run the guest before the passkey is consumed. The identity comes back
    // so the signed start rows can name this challenge.
    let step_up = match consume_passkey_step_up_for_effect(
        &state.data_dir,
        request.step_up_token.trim(),
        &launch,
        AGENT_START_STEP_UP_MAX_AGE_SECS,
        AGENT_START_OPERATION,
        &serde_json::json!({ "agent_id": request.agent_id }),
        (false, |_| Ok(())),
    ) {
        Ok(step_up) => step_up,
        Err(error) => {
            let _ = append_agent_lifecycle_audit(
                &state.data_dir,
                "agent.start.denied",
                &owner,
                AgentAuditIds {
                    challenge_id: None,
                    capsule_id: Some(&request.agent_id),
                    session_id: None,
                },
                "denied",
                serde_json::json!({
                    "agent_id": request.agent_id,
                    "cause": "step-up failed",
                }),
            );
            return Err(error);
        }
    };
    let stored = crate::agents::stored_agent(
        &state.data_dir,
        &owner.principal.principal_id,
        &request.agent_id,
    )?;
    let host_name = stored
        .record
        .agent_host_package
        .as_ref()
        .map(|package| package.name.clone())
        .ok_or_else(|| anyhow::anyhow!("agent has no host package"))?;
    let host = crate::agent_admission::verify_agent_host(&state.data_dir, &host_name)?;
    let host_sha256 = host_package_sha256(&host)?;
    append_agent_lifecycle_audit(
        &state.data_dir,
        "agent.start.requested",
        &owner,
        AgentAuditIds {
            challenge_id: Some(&step_up.step_up_id),
            capsule_id: Some(host.package().name.as_str()),
            session_id: None,
        },
        "ok",
        agent_start_reason(&request.agent_id, &launch, &host, &host_sha256, None),
    )
    .map_err(|error| {
        // The append error can name the auth-state path, so it stays in
        // the log and the refusal carries the named outcome only.
        tracing::warn!(
            "signed start request row for agent '{}' was not recorded: {error:#}",
            request.agent_id
        );
        Refused(format!(
            "agent '{}' was not started: its signed start request was not recorded",
            request.agent_id
        ))
    })?;
    let grant = issue_home_agent_launch_token_with_context(
        &state.data_dir,
        &request.agent_id,
        host.package().name.as_str(),
        &owner.context,
    )?;
    let started =
        match launch_runtime_agent(&state.data_dir, host.directory(), &request.agent_id, &grant)
            .await
        {
            Ok(started) => started,
            Err(error) => {
                let outcome = append_agent_lifecycle_audit(
                    &state.data_dir,
                    "agent.start.completed",
                    &owner,
                    AgentAuditIds {
                        challenge_id: Some(&step_up.step_up_id),
                        capsule_id: Some(host.package().name.as_str()),
                        session_id: None,
                    },
                    "failed",
                    agent_start_reason(
                        &request.agent_id,
                        &launch,
                        &host,
                        &host_sha256,
                        Some(&error.to_string()),
                    ),
                );
                if let Err(audit_error) = outcome {
                    return Err(audit_error.context(format!("agent start failed: {error}")));
                }
                return Err(error);
            }
        };
    // A crash here leaves `agent.start.requested` as the only row. That row
    // is already on disk. No owner route serves the signed chain: the agent
    // list returns records, and `GET /api/audit` is the Runtime log. A new
    // process shows the gap by loading the auth file. The test seam returns
    // at this line and does not stop the guest.
    #[cfg(test)]
    if AGENT_AUDIT_CRASH_AFTER_LAUNCH
        .lock()
        .unwrap()
        .remove(state.data_dir.as_path())
    {
        return Err(Refused(format!(
            "agent '{}' was started and its signed completion row was not recorded",
            request.agent_id
        ))
        .into());
    }
    if let Err(audit_error) = append_agent_lifecycle_audit(
        &state.data_dir,
        "agent.start.completed",
        &owner,
        AgentAuditIds {
            challenge_id: Some(&step_up.step_up_id),
            capsule_id: Some(host.package().name.as_str()),
            session_id: Some(&started.session_id),
        },
        "ok",
        agent_start_reason(&request.agent_id, &launch, &host, &host_sha256, None),
    ) {
        // The launch succeeded and the completion row was not stored. The
        // settle stop ends only the session this Start made, named by
        // session id. An earlier session of the same agent, which already
        // has its own completion row, stays up and is never labelled
        // `unrecorded_start`.
        let data = state.data_dir.clone();
        let agent = request.agent_id.clone();
        let session = started.session_id.clone();
        let settled = finish_live_stop(
            &state.data_dir,
            &StopRequest {
                actor: Some(&owner),
                agent_id: Some(&request.agent_id),
                session_id: Some(&started.session_id),
                cause: "unrecorded_start",
                reason: None,
                sign_failed: false,
                idle_ok: false,
            },
            || Ok(()),
            || {
                let data = data.clone();
                let agent = agent.clone();
                let session = session.clone();
                async move {
                    stop_runtime_agent_session(&data, &agent, &session)
                        .await
                        .map(|outcome| (live_end(&agent, outcome), None))
                }
            },
        )
        .await;
        if let Err(stop_error) = settled {
            if !stop_error.to_string().contains("signed stop row") {
                // The stop of the unrecorded session failed, so the guest
                // may still be running. The named refusal is still returned,
                // and a `agent.start.completed` failed row recording the
                // stop failure is attempted; the stop's own detail, which
                // can name host paths, stays in the log.
                tracing::warn!(
                    "settle stop of agent '{}' session '{}' failed: {:#}",
                    request.agent_id,
                    started.session_id,
                    stop_error
                );
                let _ = append_agent_lifecycle_audit(
                    &state.data_dir,
                    "agent.start.completed",
                    &owner,
                    AgentAuditIds {
                        challenge_id: Some(&step_up.step_up_id),
                        capsule_id: Some(host.package().name.as_str()),
                        session_id: Some(&started.session_id),
                    },
                    "failed",
                    agent_start_reason(
                        &request.agent_id,
                        &launch,
                        &host,
                        &host_sha256,
                        Some(SETTLE_STOP_FAILURE_CAUSE),
                    ),
                );
                return Err(Refused(format!(
                    "agent '{}' was started but its signed completion row was not recorded and its session could not be stopped, so the guest may still be running",
                    request.agent_id
                ))
                .into());
            }
            tracing::warn!(
                "signed stop row for unrecorded start of agent '{}' was not recorded: {stop_error:#}",
                request.agent_id
            );
        }
        tracing::warn!(
            "agent '{}' start completion row was not recorded: {:#}",
            request.agent_id,
            audit_error
        );
        return Err(Refused(format!(
            "agent '{}' was started but its signed completion row was not recorded, so it was stopped",
            request.agent_id
        ))
        .into());
    }
    Ok(AgentLaunchResponse {
        agent_id: request.agent_id,
        capsule_id: started.capsule_id,
        session_id: started.session_id,
        status: started.status,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentStopRequest {
    agent_id: String,
}

#[derive(Serialize)]
struct AgentStoppedSession {
    session_id: String,
    status: String,
}

#[derive(Serialize)]
struct AgentUnknownStep {
    session_id: String,
    request_id: String,
    outcome: String,
}

#[derive(Serialize)]
struct AgentStopResponse {
    agent_id: String,
    stopped: Vec<AgentStoppedSession>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stopping: Vec<AgentStoppedSession>,
    /// Steps the Runtime named as unknown. The owner sees the same names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unknown: Vec<AgentUnknownStep>,
}

pub(super) async fn agents_stop(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match stop_agent(&state, &headers, &body).await {
        Ok(value) if !value.stopping.is_empty() => {
            (StatusCode::ACCEPTED, Json(value)).into_response()
        }
        other => agents_response(other),
    }
}

/// The owner gate. With no agent id this is the admin check. With an agent
/// id it is that check plus "this
/// owner owns this agent", or the owner is no longer an admin and this
/// caller is. The agent may be off or retired, and the Home may have turned
/// agents off. A guest fails the admin check. Another admin of a still-admin
/// owner fails the ownership check. Either refusal happens before the Runtime
/// is asked to stop anything. The checked caller comes back, so the stop it
/// authorized can be signed in its name.
fn owner_may_stop(
    state: &GatewayState,
    headers: &HeaderMap,
    agent_id: Option<&str>,
) -> anyhow::Result<AgentsOwner> {
    let owner = agents_owner(state, headers)?;
    if let Some(agent_id) = agent_id {
        if crate::agents::stored_agent_for_stop(
            &state.data_dir,
            &owner.principal.principal_id,
            agent_id,
        )
        .is_err()
        {
            let record_owner = crate::agents::owner_of(&state.data_dir, agent_id);
            let allowed = match record_owner.as_deref() {
                Some(record_owner) if record_owner != owner.principal.principal_id => {
                    !crate::agents::owner_is_admin_now(&state.data_dir, record_owner)?
                }
                _ => false,
            };
            if !allowed {
                crate::agents::stored_agent_for_stop(
                    &state.data_dir,
                    &owner.principal.principal_id,
                    agent_id,
                )?;
            }
        }
    }
    Ok(owner)
}

/// A demote that did not come through the route. Another remaining admin
/// signs the same stop. The route's own stop is claimed and does not reach here.
#[cfg(test)]
pub(super) fn schedule_demoted_owner_stop(data_dir: &std::path::Path, owner_id: &str) {
    let Some(other) = crate::agent_record_audit::another_live_admin(data_dir, owner_id) else {
        tracing::warn!("demoted owner '{owner_id}' still has agents and no admin to sign the stop");
        return;
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("demoted owner '{owner_id}' still has agents and no runtime to stop them");
        return;
    };
    let owner_id = owner_id.to_string();
    let data_dir = data_dir.to_path_buf();
    handle.spawn(async move {
        let Ok(root) =
            crate::auth::ResolvedPrincipalRoot::resolve(&data_dir, &data_dir, &other.principal_id)
        else {
            tracing::warn!("demoted owner '{owner_id}' has no admin root to sign the stop");
            return;
        };
        let context = super::gateway_home_token::agent_stop_signer_context(
            root,
            &other.principal_id,
            Some(other.proof_binding_id.clone()),
            "demote",
        );
        if let Err(error) =
            stop_agents_after_admin_lost(&data_dir, &context, &other, &owner_id, "owner demoted")
                .await
        {
            tracing::warn!("direct demote stop did not finish: {error:#}");
        }
    });
}

async fn agent_has_live_session(data_dir: &std::path::Path, agent_id: &str) -> bool {
    for runtime in crate::api::agent_plane::watched_runtimes(data_dir) {
        if !runtime.live_sessions_for_agent(agent_id).await.is_empty() {
            return true;
        }
    }
    false
}

/// Demotion and last-passkey revocation use Stop's signed rows. `signer` is
/// the admin who demoted or revoked. Open asks and plans close as `cause`.
/// Only an agent with a live session is stopped; an idle, off or retired
/// agent, or a build without agents, has nothing to stop and that is done.
pub(in crate::api) async fn stop_agents_after_admin_lost(
    data_dir: &std::path::Path,
    actor: &HomeLaunchTokenContext,
    principal: &crate::auth::PrincipalRecord,
    owner_id: &str,
    cause: &str,
) -> anyhow::Result<()> {
    if !crate::agents::build_allows() {
        return Ok(());
    }
    let signer = AgentsOwner {
        context: actor.clone(),
        principal: principal.clone(),
    };
    let mut failed: Option<anyhow::Error> = None;
    for agent_id in crate::agents::ids_owned_by(data_dir, owner_id) {
        // Plans close before Stop. Denying the ask here lets a parked guest
        // finish and leave Stop with no session, so the denial is inside Stop.
        let _ = crate::api::gateway::close_owner_open_plans(data_dir, &agent_id, cause);
        if !agent_has_live_session(data_dir, &agent_id).await {
            continue;
        }
        let reason = serde_json::json!({ "agent_id": agent_id, "cause": cause });
        let data = data_dir.to_path_buf();
        let agent_for_stop = agent_id.clone();
        let cause_for_stop = cause.to_string();
        if let Err(error) = finish_live_stop(
            data_dir,
            &StopRequest {
                actor: Some(&signer),
                agent_id: Some(&agent_id),
                session_id: None,
                cause,
                reason: Some(&reason),
                sign_failed: true,
                idle_ok: false,
            },
            || {
                let _ = append_agent_lifecycle_audit(
                    data_dir,
                    "agent.stop.requested",
                    &signer,
                    AgentAuditIds {
                        challenge_id: None,
                        capsule_id: Some(&agent_id),
                        session_id: None,
                    },
                    "ok",
                    reason.clone(),
                );
                Ok(())
            },
            || {
                let data = data.clone();
                let agent_for_stop = agent_for_stop.clone();
                let cause_for_stop = cause_for_stop.clone();
                async move {
                    match stop_runtime_agent_for_cause(&data, &agent_for_stop, &cause_for_stop)
                        .await
                    {
                        Ok(outcome) => plain_end(live_end(&agent_for_stop, outcome)),
                        Err(error) if stop_is_a_refusal(&error) => plain_end(empty_end()),
                        Err(error) => {
                            crate::api::agent_plane::deny_agent_asks(
                                &data,
                                &agent_for_stop,
                                &cause_for_stop,
                            )
                            .await;
                            tracing::warn!(
                                "stop of agent '{agent_for_stop}' after {cause_for_stop} did not finish: {error:#}"
                            );
                            Err(error)
                        }
                    }
                }
            },
        )
        .await
        {
            if failed.is_none() {
                failed = Some(error);
            }
        }
    }
    match failed {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Owner check, then ask the Runtime to stop the live row whose principal is
/// this agent. The request carries the agent id and no capsule name. The
/// requested row is appended before the Runtime is asked, so a crash or a
/// failed later row still leaves the owner's stop in the chain. Every
/// session the Runtime ended is signed into the audit chain in the owner's
/// name, with the result saying what is true: `ok` when the session really
/// ended, `stopping` while the Runtime is still ending it. Every row is
/// attempted even when one fails, and a failure is answered with an error
/// naming the sessions that were stopped and the ones with no row.
async fn stop_agent(
    state: &GatewayState,
    headers: &HeaderMap,
    body: &Bytes,
) -> anyhow::Result<AgentStopResponse> {
    let targeted = serde_json::from_slice::<AgentStopRequest>(body)
        .ok()
        .map(|request| request.agent_id);
    if let Some(agent_id) = targeted.as_deref() {
        if let Err(reason) = crate::auth::validate_agent_id(agent_id) {
            return Err(Refused(reason.to_string()).into());
        }
    }
    let caller = match owner_may_stop(state, headers, None) {
        Ok(owner) => owner,
        Err(error) => {
            record_caller_denial(state, headers, "agent.stop.denied", targeted.as_deref());
            return Err(error);
        }
    };
    let request = match targeted {
        Some(agent_id) => AgentStopRequest { agent_id },
        None => agents_request(body)?,
    };
    let owner = match owner_may_stop(state, headers, Some(&request.agent_id)) {
        Ok(owner) => owner,
        Err(error) => {
            if error.to_string() != "the owner's role could not be read" {
                let _ = append_agent_lifecycle_audit(
                    &state.data_dir,
                    "agent.stop.denied",
                    &caller,
                    AgentAuditIds {
                        challenge_id: None,
                        capsule_id: Some(&request.agent_id),
                        session_id: None,
                    },
                    "denied",
                    serde_json::json!({
                        "agent_id": request.agent_id,
                        "cause": "not the owner",
                    }),
                );
            }
            return Err(error);
        }
    };
    let _ = confirm_stopping_rows(&state.data_dir).await;
    let host = match crate::agents::stored_agent_for_stop(
        &state.data_dir,
        &owner.principal.principal_id,
        &request.agent_id,
    ) {
        Ok(host) => host,
        Err(error) => {
            crate::agents::agent_record(&state.data_dir, &request.agent_id).or(Err(error))?
        }
    };
    let capsule_id = host
        .record
        .agent_host_package
        .as_ref()
        .map(|package| package.name.as_str());
    // The requested row comes first: if the stop crashes or its later rows
    // fail, the owner's stop is still recorded. Its append error can name
    // the auth-state path, so it stays in the log and the refusal carries
    // the named outcome only.
    if let Err(error) = append_agent_lifecycle_audit(
        &state.data_dir,
        "agent.stop.requested",
        &owner,
        AgentAuditIds {
            challenge_id: None,
            capsule_id,
            session_id: None,
        },
        "ok",
        serde_json::json!({ "agent_id": request.agent_id, "cause": "owner" }),
    ) {
        tracing::warn!(
            "signed stop request row for agent '{}' was not recorded: {:#}",
            request.agent_id,
            error
        );
        return Err(Refused(format!(
            "agent '{}' was not stopped: its signed stop request was not recorded",
            request.agent_id
        ))
        .into());
    }
    let data = state.data_dir.clone();
    let agent = request.agent_id.clone();
    let outcome = finish_live_stop(
        &state.data_dir,
        &StopRequest {
            actor: Some(&owner),
            agent_id: Some(&request.agent_id),
            session_id: None,
            cause: "owner",
            reason: None,
            sign_failed: true,
            idle_ok: false,
        },
        || Ok(()),
        || {
            let data = data.clone();
            let agent = agent.clone();
            async move {
                stop_runtime_agent(&data, &agent)
                    .await
                    .map(|outcome| (live_end(&agent, outcome), None))
            }
        },
    )
    .await?
    .outcome;
    if outcome.stopped.is_empty() && outcome.stopping.is_empty() && outcome.unknown.is_empty() {
        if outcome.already.as_deref() == Some("ended") {
            return Ok(AgentStopResponse {
                agent_id: request.agent_id,
                stopped: Vec::new(),
                stopping: Vec::new(),
                unknown: Vec::new(),
            });
        }
        return Err(match outcome.already.as_deref() {
            Some("stopped") => CodedRefusal {
                code: "agent_already_stopped",
                reason: "this agent is already stopped",
            }
            .into(),
            _ => CodedRefusal {
                code: "agent_no_session",
                reason: "this agent has no running session",
            }
            .into(),
        });
    }
    let session = |session: super::gateway_home_runtime::StoppedRuntimeAgent| AgentStoppedSession {
        session_id: session.session_id,
        status: session.status,
    };
    Ok(AgentStopResponse {
        agent_id: request.agent_id,
        stopped: outcome.stopped.into_iter().map(&session).collect(),
        stopping: outcome.stopping.into_iter().map(&session).collect(),
        unknown: outcome
            .unknown
            .into_iter()
            .map(|step| AgentUnknownStep {
                session_id: step.session_id,
                request_id: step.request_id,
                outcome: step.outcome,
            })
            .collect(),
    })
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    #[test]
    fn the_next_agent_audit_failure_is_named() {
        let name: fn(&std::path::Path) = super::fail_next_agent_audit;
        let _ = name;
    }
}

/// Whether this stop left the session ended. `ended` is `ended_at`.
/// `stopped` and `failed` are the statuses set in the same write as
/// `ended_at`. Both have to say the session ended before a signed row
/// says `ok`.
fn session_ended(status: &str, ended: bool) -> bool {
    ended && (status == crate::runtime::CAPSULE_STOPPED || status == crate::runtime::CAPSULE_FAILED)
}
