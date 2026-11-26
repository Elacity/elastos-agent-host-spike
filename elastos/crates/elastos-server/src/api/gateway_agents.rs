//! The owner's agent routes: turn agents on or off for this Home, create,
//! list, rename, retire, turn one agent on or off, and start or stop one agent.
//! Start and Stop ask the Home Runtime to run or end the host. This route
//! does not admit the guest itself.
//!
//! Every route makes the same owner check as the System guest-registration
//! route: a Home launch token for System, on a proof binding that is stored,
//! not revoked and an admin's. Before that check each route refuses by name
//! in a build without agents, and on a Runtime that is not the Home.

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
    crate::auth::append_audit_event(
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

/// A `stopping` row is confirmed once the owner and the build have already
/// been checked. `ok` is written when the live plane and the retiring plane
/// both say the session ended and no plan effect is in flight, or when this
/// process has neither plane, which is a Home that restarted. A session that
/// is still running on either plane stays `stopping`. The retry of failed
/// stops runs under the same lock, so two list loads cannot both stop.
pub(in crate::api) async fn confirm_stopping_rows(
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    static CONFIRM: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _held = CONFIRM.lock().await;
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
        match super::gateway_home_runtime::stop_runtime_agent(data_dir, &agent_id).await {
            Ok(outcome) if outcome.stopped.is_empty() && outcome.stopping.is_empty() => {
                let _ = sign_stopped(data_dir, &owner, &agent_id, None, "ok", reason);
            }
            Ok(outcome) => {
                for session in outcome.stopped {
                    let result = if session_ended(&session.status, session.ended) {
                        "ok"
                    } else {
                        "stopping"
                    };
                    let _ = sign_stopped(
                        data_dir,
                        &owner,
                        &agent_id,
                        Some(&session.session_id),
                        result,
                        reason.clone(),
                    );
                }
                for session in outcome.stopping {
                    let _ = sign_stopped(
                        data_dir,
                        &owner,
                        &agent_id,
                        Some(&session.session_id),
                        "stopping",
                        reason.clone(),
                    );
                }
            }
            Err(error) if stop_is_a_refusal(&error) => {
                let _ = sign_stopped(data_dir, &owner, &agent_id, None, "ok", reason);
            }
            Err(error) => {
                tracing::warn!("retry of agent '{agent_id}' did not stop: {error:#}");
            }
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

pub(super) async fn agents_disable(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let disabled = agents_set_enabled(&state, &headers, false);
    if disabled.is_ok() {
        let (ended, closed) = crate::api::agent_plane::stop_running(&state.data_dir).await;
        if let Ok(owner) = agents_owner(&state, &headers) {
            for guest in &ended {
                if guest.agent_id.is_empty() || guest.session_id.is_empty() {
                    continue;
                }
                // `ok` only when the plane left the session ended and no
                // plan effect is still landing. Anything still running is
                // `stopping`, the same rule Stop uses.
                let result = if session_ended(&guest.status, guest.ended) && !guest.effect_inflight
                {
                    "ok"
                } else {
                    "stopping"
                };
                if let Err(error) = sign_stopped(
                    &state.data_dir,
                    &owner,
                    &guest.agent_id,
                    Some(&guest.session_id),
                    result,
                    serde_json::json!({ "agent_id": guest.agent_id, "cause": "agents off" }),
                ) {
                    crate::resource_bridge::notify_plan_waiters();
                    return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
                }
            }
        }
        if let Err(error) = recorded_plan_close(closed.map(|_| 0)) {
            crate::resource_bridge::notify_plan_waiters();
            return agents_response(Err(error) as anyhow::Result<serde_json::Value>);
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
        for (session_id, result) in &ended {
            sign_stopped(
                &state.data_dir,
                &owner,
                &request.agent_id,
                Some(session_id),
                result,
                serde_json::json!({ "agent_id": request.agent_id, "cause": "retire" }),
            )?;
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
    match super::gateway_home_runtime::stop_runtime_agent(data_dir, agent_id).await {
        Ok(outcome) => {
            let mut sessions = Vec::new();
            for session in outcome.stopped {
                let result = if session_ended(&session.status, session.ended) {
                    "ok"
                } else {
                    "stopping"
                };
                sessions.push((session.session_id, result));
            }
            for session in outcome.stopping {
                sessions.push((session.session_id, "stopping"));
            }
            Ok(sessions)
        }
        // A named refusal, including a plane that is down, still leaves the
        // record write to retire. A stop that failed for another reason does not.
        Err(error) if stop_is_a_refusal(&error) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn stop_found_no_live_guest(error: &anyhow::Error) -> bool {
    if error.downcast_ref::<Refused>().is_some() {
        return true;
    }
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
            // Turning this agent off ends its run: grants in this process,
            // then the guest, then the signed stop row. Plans close as
            // `agent off`. Revoking a parked ask can end the guest before
            // Stop sees it, so the sessions that were live are remembered
            // and still signed.
            let prior = match crate::api::agent_plane::plane_runtime(&state.data_dir) {
                Some(runtime) => runtime.live_sessions_for_agent(&request.agent_id).await,
                None => Vec::new(),
            };
            crate::api::agent_plane::revoke_agent_grants(&state.data_dir, &request.agent_id).await;
            match super::gateway_home_runtime::stop_runtime_agent(
                &state.data_dir,
                &request.agent_id,
            )
            .await
            {
                Ok(outcome) => {
                    for session in &outcome.stopped {
                        let result = if session_ended(&session.status, session.ended) {
                            "ok"
                        } else {
                            "stopping"
                        };
                        sign_stopped(
                            &state.data_dir,
                            &owner,
                            &request.agent_id,
                            Some(&session.session_id),
                            result,
                            serde_json::json!({
                                "agent_id": request.agent_id,
                                "cause": "agent off",
                            }),
                        )?;
                    }
                    for session in &outcome.stopping {
                        sign_stopped(
                            &state.data_dir,
                            &owner,
                            &request.agent_id,
                            Some(&session.session_id),
                            "stopping",
                            serde_json::json!({
                                "agent_id": request.agent_id,
                                "cause": "agent off",
                            }),
                        )?;
                    }
                }
                // No guest is running: the record is off, and that is the
                // whole effect. A session that was live before the grant
                // revoke is still signed. A runtime that failed while a
                // guest was up still signs `failed` and answers the error.
                Err(error) if stop_is_a_refusal(&error) => {
                    if let Some(runtime) = crate::api::agent_plane::plane_runtime(&state.data_dir) {
                        for session_id in prior {
                            let ended = runtime
                                .get_capsule(&session_id)
                                .await
                                .is_none_or(|info| info.ended_at.is_some());
                            let result = if ended && !runtime.plan_effect_inflight(&session_id) {
                                "ok"
                            } else {
                                "stopping"
                            };
                            sign_stopped(
                                &state.data_dir,
                                &owner,
                                &request.agent_id,
                                Some(&session_id),
                                result,
                                serde_json::json!({
                                    "agent_id": request.agent_id,
                                    "cause": "agent off",
                                }),
                            )?;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!("agent off stop failed: {error:#}");
                    sign_stopped(
                        &state.data_dir,
                        &owner,
                        &request.agent_id,
                        None,
                        "failed",
                        serde_json::json!({
                            "agent_id": request.agent_id,
                            "cause": "agent off",
                        }),
                    )?;
                    return Err(error);
                }
            }
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
        match stop_runtime_agent_session(&state.data_dir, &request.agent_id, &started.session_id)
            .await
        {
            Ok(outcome) => {
                for session in &outcome.stopped {
                    let result = if session_ended(&session.status, session.ended) {
                        "ok"
                    } else {
                        "stopping"
                    };
                    // An append error can name the auth-state path. The
                    // refusal below stays the named outcome either way.
                    if let Err(error) = append_agent_lifecycle_audit(
                        &state.data_dir,
                        "agent.stopped",
                        &owner,
                        AgentAuditIds {
                            challenge_id: None,
                            capsule_id: Some(host.package().name.as_str()),
                            session_id: Some(&session.session_id),
                        },
                        result,
                        serde_json::json!({
                            "agent_id": request.agent_id,
                            "cause": "unrecorded_start"
                        }),
                    ) {
                        tracing::warn!(
                            "signed stop row for unrecorded start of agent '{}' session '{}' was not recorded: {error:#}",
                            request.agent_id,
                            session.session_id
                        );
                    }
                }
                // The completion row's own append error can name the
                // auth-state path, so it stays in the log and the refusal
                // carries the named outcome only.
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
            Err(stop_error) => {
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
        }
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

/// The owner gate. With no agent id this is the admin check, and it runs
/// before the body is read. With an agent id it is that check plus "this
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
        match super::gateway_home_runtime::stop_runtime_agent_for_cause(data_dir, &agent_id, cause)
            .await
        {
            Ok(outcome) => {
                for session in &outcome.stopped {
                    let result = if session_ended(&session.status, session.ended) {
                        "ok"
                    } else {
                        "stopping"
                    };
                    let _ = sign_stopped(
                        data_dir,
                        &signer,
                        &agent_id,
                        Some(&session.session_id),
                        result,
                        reason.clone(),
                    );
                }
                for session in &outcome.stopping {
                    let _ = sign_stopped(
                        data_dir,
                        &signer,
                        &agent_id,
                        Some(&session.session_id),
                        "stopping",
                        reason.clone(),
                    );
                }
            }
            Err(error) if stop_is_a_refusal(&error) => {}
            Err(error) => {
                crate::api::agent_plane::deny_agent_asks(data_dir, &agent_id, cause).await;
                tracing::warn!(
                    "stop of agent '{agent_id}' after {cause} did not finish: {error:#}"
                );
                let signed =
                    sign_stopped(data_dir, &signer, &agent_id, None, "failed", reason.clone());
                if failed.is_none() {
                    failed = Some(
                        signed
                            .err()
                            .unwrap_or_else(|| anyhow::anyhow!("agent '{agent_id}' did not stop")),
                    );
                }
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
    let caller = match owner_may_stop(state, headers, None) {
        Ok(owner) => owner,
        Err(error) => {
            record_caller_denial(state, headers, "agent.stop.denied", None);
            return Err(error);
        }
    };
    let request: AgentStopRequest = agents_request(body)?;
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
    let outcome = match stop_runtime_agent(&state.data_dir, &request.agent_id).await {
        Ok(outcome) => outcome,
        // A refusal (no session, already stopped, the plane is down or its
        // task has ended) is not a failed stop. The requested row is already
        // signed. A runtime that failed while a guest was up still signs
        // `failed`.
        Err(error) if stop_is_a_refusal(&error) => return Err(error),
        Err(error) => {
            let _ = append_agent_lifecycle_audit(
                &state.data_dir,
                "agent.stopped",
                &owner,
                AgentAuditIds {
                    challenge_id: None,
                    capsule_id,
                    session_id: None,
                },
                "failed",
                serde_json::json!({ "agent_id": request.agent_id, "cause": "owner" }),
            );
            return Err(error);
        }
    };
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
    // A session the runtime still lists as stopping is signed `stopping`.
    // A session it lists as stopped is `ok` only when the row has ended.
    let mut recorded: Vec<String> = Vec::new();
    let mut unrecorded: Vec<String> = Vec::new();
    let mut sign = |session: &super::gateway_home_runtime::StoppedRuntimeAgent, result: &str| {
        match append_agent_lifecycle_audit(
            &state.data_dir,
            "agent.stopped",
            &owner,
            AgentAuditIds {
                challenge_id: None,
                capsule_id,
                session_id: Some(&session.session_id),
            },
            result,
            serde_json::json!({ "agent_id": request.agent_id, "cause": "owner" }),
        ) {
            Ok(()) => recorded.push(session.session_id.clone()),
            Err(error) => {
                // The append error can name the auth-state path. Try every
                // later session, then name both lists without that text.
                tracing::warn!(
                    "signed stop row for agent '{}' session '{}' was not recorded: {error:#}",
                    request.agent_id,
                    session.session_id
                );
                unrecorded.push(session.session_id.clone());
            }
        }
    };
    for session in &outcome.stopped {
        let result = if session_ended(&session.status, session.ended) {
            "ok"
        } else {
            "stopping"
        };
        sign(session, result);
    }
    for session in &outcome.stopping {
        sign(session, "stopping");
    }
    if !unrecorded.is_empty() {
        return Err(anyhow::anyhow!(
            "agent '{}' stopped session(s) {}; the signed stop row for session(s) {} was not recorded",
            request.agent_id,
            recorded.join(", "),
            unrecorded.join(", ")
        ));
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
